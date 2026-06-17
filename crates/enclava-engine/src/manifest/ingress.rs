//! Ingress ConfigMap: Caddyfile rendering with CAP routes.
//!
//! Generates the tenant-ingress ConfigMap containing a Caddyfile that:
//! - Terminates TLS inside the TEE via ACME TLS-ALPN-01
//! - Routes attestation + ownership endpoints to the proxy (8081)
//! - Routes /.well-known/confidential/* to the proxy (CAP-specific)
//! - Routes everything else to the app container
//!
//! Per Phase 4 mitigations: every value interpolated into the rendered
//! Caddyfile is either a constant or runs through a strict validator first
//! (FQDN / URL / numeric port). The renderer never performs raw
//! `format!("{user_input}")` of caller-supplied strings; that closes the
//! Caddyfile-injection vector flagged in the security review.

use enclava_common::validate::{ValidateError, validate_fqdn, validate_http_path};
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use super::containers::{
    CADDY_ACME_TLS_PORT, CADDY_BROKER_CERT_PATH, CADDY_BROKER_KEY_PATH,
    CADDY_INTERNAL_RUNTIME_PATH, CADDY_INTERNAL_TLS_PORT,
};
use crate::types::{CaddyTlsMode, ConfidentialApp};

#[derive(Debug, thiserror::Error)]
pub enum IngressRenderError {
    #[error("invalid hostname for Caddyfile: {0}")]
    InvalidHostname(#[from] ValidateError),
    #[error("invalid ACME CA URL: {0}")]
    InvalidAcmeUrl(String),
    #[error("invalid ACME contact email: {0}")]
    InvalidEmail(String),
    #[error("invalid health path for Caddyfile: {0}")]
    InvalidHealthPath(String),
}

/// Validated inputs ready to be rendered into a Caddyfile.
struct CaddyfileSpec {
    hosts: Vec<String>,
    app_port: u16,
    acme_ca: String,
    tls_mode: CaddyTlsMode,
    contact_email: String,
    health_path: String,
}

impl CaddyfileSpec {
    fn from_app(app: &ConfidentialApp) -> Result<Self, IngressRenderError> {
        let mut hosts: Vec<String> = Vec::new();
        let primary = app.domain.platform_domain.as_str();
        if !primary.is_empty() {
            validate_fqdn(primary)?;
            hosts.push(primary.to_string());
        }
        if let Some(custom) = app.domain.custom_domain.as_deref()
            && !custom.is_empty()
            && !hosts.iter().any(|h| h.as_str() == custom)
        {
            validate_fqdn(custom)?;
            hosts.push(custom.to_string());
        }
        if hosts.is_empty() {
            // Fall back to whatever primary_domain resolves to so we still emit
            // a well-formed Caddyfile -- validate_fqdn will catch bad input.
            let domain = app.primary_domain().to_string();
            validate_fqdn(&domain)?;
            hosts.push(domain);
        }
        let app_port = app.primary_container().and_then(|c| c.port).unwrap_or(8080);
        let acme_ca = app.attestation.acme_ca_url.trim().to_string();
        if app.attestation.caddy_tls_mode == CaddyTlsMode::Acme {
            validate_https_url(&acme_ca)?;
        }
        let contact_email = "infra@enclava.dev".to_string();
        validate_email(&contact_email)?;
        let health_path = app.health.path.clone();
        validate_http_path(&health_path)
            .map_err(|e| IngressRenderError::InvalidHealthPath(e.to_string()))?;
        Ok(Self {
            hosts,
            app_port,
            acme_ca,
            tls_mode: app.attestation.caddy_tls_mode,
            contact_email,
            health_path,
        })
    }
}

fn validate_https_url(url: &str) -> Result<(), IngressRenderError> {
    if !url.starts_with("https://") {
        return Err(IngressRenderError::InvalidAcmeUrl(
            "must start with https://".to_string(),
        ));
    }
    if url.bytes().any(|b| {
        b == b'\n'
            || b == b'\r'
            || b == b' '
            || b == b'\t'
            || b == 0
            || b == b'`'
            || b == b'"'
            || b == b'\''
            || b == b'{'
            || b == b'}'
            || b == b';'
    }) {
        return Err(IngressRenderError::InvalidAcmeUrl(
            "contains forbidden character".to_string(),
        ));
    }
    if !url.is_ascii() {
        return Err(IngressRenderError::InvalidAcmeUrl("must be ASCII".into()));
    }
    Ok(())
}

fn validate_email(s: &str) -> Result<(), IngressRenderError> {
    if !s.is_ascii() {
        return Err(IngressRenderError::InvalidEmail("must be ASCII".into()));
    }
    if s.bytes().any(|b| {
        b.is_ascii_whitespace()
            || b == 0
            || b == b'`'
            || b == b'\''
            || b == b'"'
            || b == b'{'
            || b == b'}'
            || b == b';'
    }) {
        return Err(IngressRenderError::InvalidEmail(
            "contains forbidden character".into(),
        ));
    }
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() {
        return Err(IngressRenderError::InvalidEmail(
            "must contain a local and domain part".into(),
        ));
    }
    validate_fqdn(domain).map_err(IngressRenderError::InvalidHostname)?;
    Ok(())
}

/// Generate the tenant-ingress ConfigMap with the rendered Caddyfile.
pub fn generate_ingress_configmap(app: &ConfidentialApp) -> ConfigMap {
    // We expose the infallible name in keeping with the rest of the manifest
    // builders. Validation failures here mean the app object never should
    // have been built — they indicate a bug, not a user error — so we panic
    // with a clear message that's always caught in tests.
    let caddyfile =
        render_caddyfile(app).expect("Caddyfile inputs must validate before manifest generation");

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    let mut data = BTreeMap::new();
    data.insert("Caddyfile".to_string(), caddyfile);

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{}-tenant-ingress", app.name)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Render the Caddyfile for a confidential app via a structured builder.
///
/// Only validated inputs reach the writer; constants are inlined.
pub fn render_caddyfile(app: &ConfidentialApp) -> Result<String, IngressRenderError> {
    let spec = CaddyfileSpec::from_app(app)?;
    Ok(render_caddyfile_from_spec(&spec))
}

fn render_caddyfile_from_spec(spec: &CaddyfileSpec) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  admin off\n");
    out.push_str("  persist_config off\n");
    out.push_str("  auto_https disable_redirects\n");
    out.push_str("  email ");
    out.push_str(&spec.contact_email);
    out.push('\n');
    out.push_str("  storage file_system ");
    match spec.tls_mode {
        CaddyTlsMode::Acme => {
            out.push_str(CADDY_INTERNAL_RUNTIME_PATH);
            out.push('\n');
        }
        CaddyTlsMode::Dns01Broker => {
            out.push_str(CADDY_INTERNAL_RUNTIME_PATH);
            out.push('\n');
        }
        CaddyTlsMode::Internal => {
            out.push_str(CADDY_INTERNAL_RUNTIME_PATH);
            out.push('\n');
        }
    }
    out.push_str("}\n");
    if spec.tls_mode == CaddyTlsMode::Internal {
        let hosts = spec
            .hosts
            .iter()
            .map(|host| format!("{host}:{CADDY_INTERNAL_TLS_PORT}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&hosts);
    } else {
        let hosts = spec
            .hosts
            .iter()
            .map(|host| format!("{host}:{CADDY_ACME_TLS_PORT}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&hosts);
    }
    out.push_str(" {\n");
    match spec.tls_mode {
        CaddyTlsMode::Acme => {
            // Phase 0/5: TLS-ALPN-01 only — DNS-01 / Cloudflare path is gone.
            // Caddy default ACME issuers cover ALPN; no per-app credentials needed.
            out.push_str("  tls {\n");
            out.push_str("    issuer acme {\n");
            out.push_str("      dir ");
            out.push_str(&spec.acme_ca);
            out.push('\n');
            out.push_str("      disable_http_challenge\n");
            out.push_str("    }\n");
            out.push_str("  }\n");
        }
        CaddyTlsMode::Dns01Broker => {
            out.push_str("  tls ");
            out.push_str(CADDY_BROKER_CERT_PATH);
            out.push(' ');
            out.push_str(CADDY_BROKER_KEY_PATH);
            out.push('\n');
        }
        CaddyTlsMode::Internal => {
            out.push_str("  tls internal\n");
        }
    }
    out.push_str("  @attestation-proxy path /v1/attestation /v1/attestation/* /unlock\n");
    out.push_str("  handle @attestation-proxy {\n");
    out.push_str("    reverse_proxy 127.0.0.1:8081\n");
    out.push_str("  }\n");
    out.push_str("  @confidential path /.well-known/confidential/*\n");
    out.push_str("  @confidential_preflight {\n");
    out.push_str("    method OPTIONS\n");
    out.push_str("    path /.well-known/confidential/*\n");
    out.push_str("  }\n");
    out.push_str("  handle @confidential_preflight {\n");
    out.push_str("    header Access-Control-Allow-Origin \"*\"\n");
    out.push_str("    header Access-Control-Allow-Methods \"GET, POST, PUT, DELETE, OPTIONS\"\n");
    out.push_str(
        "    header Access-Control-Allow-Headers \"Authorization, Content-Type, Accept\"\n",
    );
    out.push_str("    header Access-Control-Max-Age \"600\"\n");
    out.push_str("    respond \"\" 204\n");
    out.push_str("  }\n");
    out.push_str("  handle @confidential {\n");
    out.push_str("    header Access-Control-Allow-Origin \"*\"\n");
    out.push_str("    reverse_proxy 127.0.0.1:8081\n");
    out.push_str("  }\n");
    out.push_str("  handle /health {\n");
    if spec.health_path != "/health" {
        out.push_str("    rewrite * ");
        out.push_str(&spec.health_path);
        out.push('\n');
    }
    out.push_str("    reverse_proxy 127.0.0.1:");
    out.push_str(&spec.app_port.to_string());
    out.push('\n');
    out.push_str("  }\n");
    out.push_str("  handle {\n");
    out.push_str("    reverse_proxy 127.0.0.1:");
    out.push_str(&spec.app_port.to_string());
    out.push('\n');
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_email_rejects_injection() {
        for bad in [
            "user@host\n",
            "user@host;",
            "user`@host",
            "user@host}",
            "user@host{",
            "u s@h.com",
            "@host.com",
            "user@",
        ] {
            assert!(validate_email(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn validate_email_accepts_simple() {
        assert!(validate_email("infra@enclava.dev").is_ok());
    }

    #[test]
    fn validate_https_url_rejects_injection() {
        for bad in [
            "http://example.com",
            "https://example.com\n",
            "https://example.com;rm -rf",
            "https://example.com{",
            "https://example.com}",
            "https://example.com`",
            "https://example.com'",
            "https://example.com\"",
            "https://exámple.com",
        ] {
            assert!(
                validate_https_url(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }
}
