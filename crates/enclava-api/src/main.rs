use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use enclava_common::image::ImageRef;
use enclava_engine::types::{AttestationConfig, CaddyTlsMode};
use rand::rngs::OsRng;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use enclava_api::{
    acme::AcmeConfig,
    auth::jwt,
    build_router,
    dns::DnsConfig,
    platform_release::{PlatformRelease, PlatformReleaseEnvelope},
    state::{AppState, CapManagementMode, InternalAuthConfig},
};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn parse_fail_closed_switch(name: &str, value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => anyhow::bail!("{name} must be exactly `true` or `false`"),
    }
}

fn load_deployment_dispatch_enabled() -> anyhow::Result<bool> {
    match std::env::var("CAP_DEPLOYMENT_DISPATCH_ENABLED") {
        Ok(value) => {
            parse_fail_closed_switch("CAP_DEPLOYMENT_DISPATCH_ENABLED", Some(value.as_str()))
        }
        Err(std::env::VarError::NotPresent) => {
            parse_fail_closed_switch("CAP_DEPLOYMENT_DISPATCH_ENABLED", None)
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("CAP_DEPLOYMENT_DISPATCH_ENABLED must be valid UTF-8")
        }
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_list(name: &str) -> Vec<String> {
    env_nonempty(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn load_internal_auth_config() -> Option<InternalAuthConfig> {
    let mut tokens = Vec::new();
    if let Some(token) = env_nonempty("CAP_INTERNAL_SERVICE_TOKEN") {
        tokens.push(token);
    }
    if let Some(token) = env_nonempty("CAP_INTERNAL_SERVICE_TOKEN_NEXT") {
        tokens.push(token);
    }
    let allowed_client_sans = env_list("CAP_INTERNAL_ALLOWED_CLIENT_SANS");
    let trusted_proxy_secret = env_nonempty("CAP_INTERNAL_TRUSTED_PROXY_SECRET");
    if tokens.is_empty() && allowed_client_sans.is_empty() {
        return None;
    }
    Some(InternalAuthConfig::from_plaintext_token_strings(
        tokens,
        allowed_client_sans,
        trusted_proxy_secret,
    ))
}

fn load_management_mode() -> CapManagementMode {
    env_nonempty("CAP_MANAGEMENT_MODE")
        .as_deref()
        .unwrap_or("standalone")
        .parse()
        .expect("invalid CAP_MANAGEMENT_MODE")
}

fn load_caddy_tls_mode() -> anyhow::Result<CaddyTlsMode> {
    match env_nonempty("TENANT_CADDY_TLS_MODE") {
        Some(mode) => mode
            .parse::<CaddyTlsMode>()
            .map_err(|err| anyhow::anyhow!("TENANT_CADDY_TLS_MODE: {err}")),
        None => Ok(CaddyTlsMode::Acme),
    }
}

fn require_env_matches_release(
    name: &str,
    expected: &str,
    redact_values: bool,
) -> anyhow::Result<()> {
    let Some(actual) = env_nonempty(name) else {
        anyhow::bail!("{name} is required by signed platform release");
    };
    if actual.trim() != expected.trim() {
        if redact_values {
            anyhow::bail!("{name} conflicts with signed platform release");
        }
        anyhow::bail!(
            "{name} conflicts with signed platform release: env `{actual}` != release `{}`",
            expected.trim()
        );
    }
    Ok(())
}

fn trustee_kbs_url_matches_release(
    actual: &str,
    expected: &str,
    release_build: bool,
) -> anyhow::Result<Option<String>> {
    let url = validate_trustee_kbs_url(actual, release_build)?;
    if !release_build && url.scheme() == "http" {
        // Debug/local stacks intentionally use a local HTTP Trustee while still
        // consuming the bundled signed release for every immutable image and
        // policy setting. The effective value is advertised separately so a
        // debug CLI hashes the exact same cc_init_data; release binaries never
        // emit or accept this unsigned override.
        return Ok(Some(actual.trim().to_string()));
    }
    if actual.trim() != expected.trim() {
        anyhow::bail!(
            "TRUSTEE_KBS_URL conflicts with signed platform release: env `{actual}` != release `{}`",
            expected.trim()
        );
    }
    Ok(None)
}

fn require_trustee_kbs_url_matches_release(
    expected: &str,
    release_build: bool,
) -> anyhow::Result<Option<String>> {
    let actual = env_nonempty("TRUSTEE_KBS_URL")
        .ok_or_else(|| anyhow::anyhow!("TRUSTEE_KBS_URL is required by signed platform release"))?;
    trustee_kbs_url_matches_release(&actual, expected, release_build)
}

fn build_tenant_tee_http_client() -> anyhow::Result<reqwest::Client> {
    build_tenant_tee_http_client_with_env(|name| std::env::var(name).ok())
}

fn tenant_tee_root_certificate_from_pem(
    source: &'static str,
    cert_pem: &[u8],
) -> anyhow::Result<Vec<reqwest::Certificate>> {
    if !cert_pem
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----")
    {
        anyhow::bail!("{source} does not contain a PEM certificate");
    }
    reqwest::Certificate::from_pem_bundle(cert_pem)
        .map_err(|err| anyhow::anyhow!("invalid {source}: {err}"))
}

fn build_tenant_tee_http_client_with_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(
            lookup("TENANT_TEE_TLS_MODE")
                .map(|mode| matches!(mode.as_str(), "staging" | "insecure"))
                .unwrap_or(false)
                || lookup("TENANT_TEE_ACCEPT_INVALID_CERTS").is_some_and(|value| {
                    matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
                }),
        )
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .https_only(true);

    if let Some(cert_pem) = lookup("TENANT_TEE_CA_CERT_PEM") {
        let cert_pem = cert_pem.replace("\\n", "\n");
        for cert in
            tenant_tee_root_certificate_from_pem("TENANT_TEE_CA_CERT_PEM", cert_pem.as_bytes())?
        {
            builder = builder.add_root_certificate(cert);
        }
    }

    if let Some(cert_path) = lookup("TENANT_TEE_CA_CERT_PATH") {
        let cert_pem = std::fs::read(&cert_path)
            .map_err(|err| anyhow::anyhow!("failed to read TENANT_TEE_CA_CERT_PATH: {err}"))?;
        for cert in tenant_tee_root_certificate_from_pem("TENANT_TEE_CA_CERT_PATH", &cert_pem)? {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build tenant TEE HTTP client: {err}"))
}

fn build_trustee_http_client() -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15));

    if let Some(cert_pem) = env_nonempty("TRUSTEE_KBS_CA_CERT_PEM") {
        let cert_pem = cert_pem.replace("\\n", "\n");
        let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid TRUSTEE_KBS_CA_CERT_PEM: {err}"))?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some(cert_path) = env_nonempty("TRUSTEE_KBS_CA_CERT_PATH") {
        let cert_pem = std::fs::read(&cert_path)
            .map_err(|err| anyhow::anyhow!("failed to read TRUSTEE_KBS_CA_CERT_PATH: {err}"))?;
        let cert = reqwest::Certificate::from_pem(&cert_pem)
            .map_err(|err| anyhow::anyhow!("invalid TRUSTEE_KBS_CA_CERT_PATH PEM: {err}"))?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build Trustee HTTP client: {err}"))
}

async fn verify_trustee_kbs_connectivity(
    client: &reqwest::Client,
    required: bool,
) -> anyhow::Result<()> {
    if !required {
        return Ok(());
    }
    let raw_url = env_nonempty("TRUSTEE_KBS_URL")
        .ok_or_else(|| anyhow::anyhow!("TRUSTEE_KBS_URL is required"))?;
    let url = validate_trustee_kbs_url(&raw_url, !cfg!(debug_assertions))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| anyhow::anyhow!("trusted Trustee KBS request failed: {err}"))?;
    if response.status().is_server_error() {
        anyhow::bail!(
            "Trustee KBS returned an unhealthy HTTP status: {}",
            response.status()
        );
    }
    tracing::info!(
        status = %response.status(),
        "verified trusted TLS connectivity to Trustee KBS"
    );
    Ok(())
}

fn validate_trustee_kbs_url(raw_url: &str, release_build: bool) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|err| anyhow::anyhow!("invalid TRUSTEE_KBS_URL: {err}"))?;
    if release_build && url.scheme() != "https" {
        anyhow::bail!("TRUSTEE_KBS_URL must use https in release builds");
    }
    Ok(url)
}

fn read_key_file(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read key file {path}: {e}"))
}

fn load_signing_key() -> anyhow::Result<SigningKey> {
    if let Ok(path) = std::env::var("API_SIGNING_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PATH PKCS#8 key: {e}"));
    }

    if let Ok(b64) = std::env::var("API_SIGNING_KEY_PKCS8_BASE64") {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64: {e}"))?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64 key: {e}"));
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral API signing key");
        return Ok(SigningKey::generate(&mut OsRng));
    }

    anyhow::bail!(
        "missing API signing key: set API_SIGNING_KEY_PATH or API_SIGNING_KEY_PKCS8_BASE64"
    )
}

fn load_hmac_key() -> anyhow::Result<[u8; 32]> {
    if let Ok(path) = std::env::var("SESSION_HMAC_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        let text = std::str::from_utf8(&bytes)
            .map_err(|e| anyhow::anyhow!("SESSION_HMAC_KEY_PATH content is not UTF-8: {e}"))?;
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|e| {
                anyhow::anyhow!("SESSION_HMAC_KEY_PATH is neither raw 32 bytes nor base64: {e}")
            })?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_PATH must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if let Ok(b64) = std::env::var("SESSION_HMAC_KEY_BASE64") {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid SESSION_HMAC_KEY_BASE64: {e}"))?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_BASE64 must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral JWT HMAC key");
        return Ok(jwt::generate_hmac_key());
    }

    anyhow::bail!("missing session HMAC key: set SESSION_HMAC_KEY_PATH or SESSION_HMAC_KEY_BASE64")
}

fn parse_image_ref(name: &str, value: &str) -> anyhow::Result<ImageRef> {
    let image = ImageRef::parse(value)
        .map_err(|e| anyhow::anyhow!("invalid {name} image reference: {e}"))?;
    image
        .require_digest()
        .map_err(|e| anyhow::anyhow!("invalid {name}: {e}"))?;
    Ok(image)
}

fn load_url_env(env_name: &str, required: bool) -> anyhow::Result<Option<String>> {
    load_url_value(env_name, env_nonempty(env_name), required)
}

fn load_url_value(
    name: &str,
    value: Option<String>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        if required {
            anyhow::bail!("missing {name}");
        }
        return Ok(None);
    };
    let url =
        reqwest::Url::parse(&value).map_err(|e| anyhow::anyhow!("invalid {name} URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("invalid {name}: URL scheme must be http or https");
    }
    Ok(Some(value))
}

fn load_pubkey_hex_value(
    name: &str,
    value: Option<String>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        if required {
            anyhow::bail!("missing {name}");
        }
        return Ok(None);
    };
    let raw = hex::decode(&value).map_err(|e| anyhow::anyhow!("invalid {name}: {e}"))?;
    if raw.len() != 32 {
        anyhow::bail!("invalid {name}: expected 32-byte Ed25519 public key hex");
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn platform_release_enabled(trustee_policy_read_available: bool) -> bool {
    trustee_policy_read_available
        || env_flag("ENCLAVA_USE_PLATFORM_RELEASE")
        || env_nonempty("ENCLAVA_PLATFORM_RELEASE_PATH").is_some()
}

fn load_platform_release(enabled: bool) -> anyhow::Result<Option<PlatformReleaseEnvelope>> {
    if !enabled {
        return Ok(None);
    }
    let envelope = PlatformReleaseEnvelope::load_verified()
        .map_err(|e| anyhow::anyhow!("failed to load signed platform release: {e}"))?;
    let release = &envelope.payload;
    if release.expected_runtime_class
        != enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS
    {
        anyhow::bail!(
            "signed platform release runtime class `{}` does not match API runtime class `{}`",
            release.expected_runtime_class,
            enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS
        );
    }
    Ok(Some(envelope))
}

fn release_env_value(
    env_name: &str,
    release_value: Option<&str>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    match (env_nonempty(env_name), release_value) {
        (Some(value), Some(expected)) => {
            if value != expected {
                anyhow::bail!(
                    "{env_name} conflicts with signed platform release: env `{value}` != release `{expected}`"
                );
            }
            Ok(Some(value))
        }
        (Some(value), None) => Ok(Some(value)),
        (None, Some(expected)) => Ok(Some(expected.to_string())),
        (None, None) if required => anyhow::bail!("missing {env_name}"),
        (None, None) => Ok(None),
    }
}

fn load_attestation_config(
    platform_release: Option<&PlatformRelease>,
) -> anyhow::Result<Option<AttestationConfig>> {
    let trustee_policy_read_available = env_flag("TRUSTEE_POLICY_READ_AVAILABLE");
    let proxy_image_ref = release_env_value(
        "ATTESTATION_PROXY_IMAGE",
        platform_release.map(|release| release.attestation_proxy_image.as_str()),
        false,
    )?;
    let caddy_image_ref = release_env_value(
        "CADDY_INGRESS_IMAGE",
        platform_release.map(|release| release.caddy_ingress_image.as_str()),
        false,
    )?;
    let has_any = proxy_image_ref.is_some() || caddy_image_ref.is_some();
    if !has_any {
        if trustee_policy_read_available {
            anyhow::bail!(
                "TRUSTEE_POLICY_READ_AVAILABLE=true requires ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE"
            );
        }
        tracing::warn!(
            "ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE are unset; deploy requests will fail until configured"
        );
        return Ok(None);
    }
    let Some(proxy_image_ref) = proxy_image_ref else {
        anyhow::bail!("missing ATTESTATION_PROXY_IMAGE");
    };
    let Some(caddy_image_ref) = caddy_image_ref else {
        anyhow::bail!("missing CADDY_INGRESS_IMAGE");
    };

    let acme_ca_url = release_env_value(
        "TENANT_CADDY_ACME_CA",
        platform_release.map(|release| release.tenant_caddy_acme_ca.as_str()),
        false,
    )?
    .unwrap_or_else(enclava_engine::types::default_acme_ca_url);
    let caddy_tls_mode = match release_env_value(
        "TENANT_CADDY_TLS_MODE",
        platform_release.map(|release| release.tenant_caddy_tls_mode.as_str()),
        false,
    )? {
        Some(mode) => mode
            .parse::<CaddyTlsMode>()
            .map_err(|err| anyhow::anyhow!("TENANT_CADDY_TLS_MODE: {err}"))?,
        None => load_caddy_tls_mode()?,
    };
    let workload_artifacts_url =
        load_url_env("WORKLOAD_ARTIFACTS_URL", trustee_policy_read_available)?;
    let tls_certificate_broker_url = load_url_env(
        "TLS_CERTIFICATE_BROKER_URL",
        trustee_policy_read_available && caddy_tls_mode == CaddyTlsMode::Dns01Broker,
    )?;
    let trustee_policy_url = load_url_env("TRUSTEE_POLICY_URL", trustee_policy_read_available)?;
    let release_pubkey =
        platform_release.map(|release| release.signing_service_pubkey_hex.as_str());
    let platform_trustee_policy_pubkey_hex = load_pubkey_hex_value(
        "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX",
        release_env_value("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", release_pubkey, false)?,
        false,
    )?;
    let signing_service_pubkey_hex = load_pubkey_hex_value(
        "SIGNING_SERVICE_PUBKEY_HEX",
        release_env_value("SIGNING_SERVICE_PUBKEY_HEX", release_pubkey, false)?,
        false,
    )?;

    Ok(AttestationConfig {
        proxy_image: parse_image_ref("ATTESTATION_PROXY_IMAGE", &proxy_image_ref)?,
        caddy_image: parse_image_ref("CADDY_INGRESS_IMAGE", &caddy_image_ref)?,
        acme_ca_url,
        caddy_tls_mode,
        trustee_policy_read_available,
        workload_artifacts_url,
        tls_certificate_broker_url,
        trustee_policy_url,
        local_workload_artifacts_json: None,
        local_trustee_policy_json: None,
        platform_trustee_policy_pubkey_hex,
        signing_service_pubkey_hex,
    }
    .into())
}

fn load_dns_config() -> anyhow::Result<Option<DnsConfig>> {
    let required = env_flag("DNS_MANAGEMENT_REQUIRED");
    let cloudflare_api_token = match std::env::var("CLOUDFLARE_API_TOKEN") {
        Ok(token) if !token.trim().is_empty() => token,
        _ if required => anyhow::bail!("missing CLOUDFLARE_API_TOKEN"),
        _ => {
            tracing::warn!(
                "CLOUDFLARE_API_TOKEN is unset; CAP DNS management is disabled for this process"
            );
            return Ok(None);
        }
    };

    let cloudflare_zone_name =
        std::env::var("CLOUDFLARE_ZONE_NAME").unwrap_or_else(|_| "enclava.dev".to_string());
    let target = match std::env::var("TENANT_DNS_TARGET") {
        Ok(target) if !target.trim().is_empty() => target,
        _ if required => anyhow::bail!("missing TENANT_DNS_TARGET"),
        _ => {
            tracing::warn!(
                "TENANT_DNS_TARGET is unset; CAP DNS management is disabled for this process"
            );
            return Ok(None);
        }
    };

    Ok(Some(DnsConfig {
        cloudflare_api_token,
        cloudflare_api_base_url: std::env::var("CLOUDFLARE_API_BASE_URL")
            .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".to_string()),
        cloudflare_zone_id: std::env::var("CLOUDFLARE_ZONE_ID")
            .ok()
            .filter(|v| !v.trim().is_empty()),
        cloudflare_zone_name,
        target,
        required,
    }))
}

fn load_acme_config(attestation: Option<&AttestationConfig>) -> anyhow::Result<Option<AcmeConfig>> {
    let broker_enabled = attestation
        .and_then(|cfg| cfg.tls_certificate_broker_url.as_ref())
        .is_some()
        || env_nonempty("TLS_CERTIFICATE_BROKER_URL").is_some();
    if !broker_enabled {
        return Ok(None);
    }
    let (directory_url_source, directory_url) =
        if let Some(directory_url) = env_nonempty("ACME_DIRECTORY_URL") {
            ("ACME_DIRECTORY_URL", directory_url)
        } else if let Some(cfg) = attestation {
            ("TENANT_CADDY_ACME_CA", cfg.acme_ca_url.clone())
        } else {
            (
                "ACME_DIRECTORY_URL default",
                enclava_engine::types::default_acme_ca_url(),
            )
        };
    enclava_api::env_gates::ensure_acme_directory_allowed(directory_url_source, &directory_url)
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    reqwest::Url::parse(&directory_url)
        .map_err(|err| anyhow::anyhow!("invalid ACME_DIRECTORY_URL: {err}"))?;
    let account_credentials_path =
        env_nonempty("ACME_ACCOUNT_CREDENTIALS_PATH").map(std::path::PathBuf::from);
    let dns_propagation_wait = std::env::var("ACME_DNS_PROPAGATION_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| std::time::Duration::from_secs(30));
    Ok(Some(AcmeConfig {
        directory_url,
        account_credentials_path,
        dns_propagation_wait,
    }))
}

fn load_trustee_attestation_verify_bearer_token(
    verify_url: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let token = env_nonempty("TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN");
    if verify_url.is_some() && token.is_none() {
        anyhow::bail!(
            "TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN is required when \
             TRUSTEE_ATTESTATION_VERIFY_URL is set"
        );
    }

    Ok(token)
}

fn install_default_rustls_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[tokio::main]
async fn main() {
    install_default_rustls_crypto_provider();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclava_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(e) = enclava_api::env_gates::enforce_production_env_gates() {
        eprintln!("startup refused: {e}");
        std::process::exit(1);
    }
    let haproxy_integration_enabled = match enclava_api::edge::haproxy_integration_enabled() {
        Ok(enabled) => enabled,
        Err(error) => {
            eprintln!("startup refused: invalid HAProxy integration configuration: {error}");
            std::process::exit(1);
        }
    };
    let deployment_dispatch_enabled = match load_deployment_dispatch_enabled() {
        Ok(enabled) => enabled,
        Err(error) => {
            eprintln!("startup refused: invalid deployment dispatch configuration: {error}");
            std::process::exit(1);
        }
    };
    if deployment_dispatch_enabled && !haproxy_integration_enabled {
        eprintln!(
            "startup refused: CAP_DEPLOYMENT_DISPATCH_ENABLED=true requires tenant HAProxy integration"
        );
        std::process::exit(1);
    }

    let trustee_policy_read_available = env_flag("TRUSTEE_POLICY_READ_AVAILABLE");
    let platform_release_envelope =
        match load_platform_release(platform_release_enabled(trustee_policy_read_available)) {
            Ok(release) => release,
            Err(e) => {
                eprintln!("startup refused: {e}");
                std::process::exit(1);
            }
        };
    let mut debug_trustee_kbs_url_override = None;
    let mut debug_trustee_kbs_ca_cert_pem_override = None;
    if let Some(envelope) = &platform_release_envelope {
        let release = &envelope.payload;
        tracing::info!(
            platform_release_version = %release.platform_release_version,
            genpolicy_version = %release.genpolicy_version,
            "signed platform release loaded"
        );
        match require_trustee_kbs_url_matches_release(
            &release.trustee_kbs_url,
            !cfg!(debug_assertions),
        ) {
            Ok(debug_override) => {
                debug_trustee_kbs_url_override = debug_override;
                if debug_trustee_kbs_url_override.is_some() {
                    debug_trustee_kbs_ca_cert_pem_override =
                        env_nonempty("TRUSTEE_KBS_CA_CERT_PEM")
                            .map(|value| value.replace("\\n", "\n"));
                }
            }
            Err(e) => {
                eprintln!("startup refused: {e}");
                std::process::exit(1);
            }
        }
        for (name, expected) in [
            (
                "TENANT_CADDY_TLS_MODE",
                release.tenant_caddy_tls_mode.as_str(),
            ),
            (
                "TENANT_CADDY_ACME_CA",
                release.tenant_caddy_acme_ca.as_str(),
            ),
        ] {
            if let Err(e) = require_env_matches_release(name, expected, false) {
                eprintln!("startup refused: {e}");
                std::process::exit(1);
            }
        }
        if debug_trustee_kbs_url_override.is_none()
            && !release.trustee_kbs_ca_cert_pem.trim().is_empty()
            && let Err(e) = require_env_matches_release(
                "TRUSTEE_KBS_CA_CERT_PEM",
                &release.trustee_kbs_ca_cert_pem,
                true,
            )
        {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    }

    let startup_proxy_image = match release_env_value(
        "ATTESTATION_PROXY_IMAGE",
        platform_release_envelope
            .as_ref()
            .map(|envelope| envelope.payload.attestation_proxy_image.as_str()),
        false,
    ) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    };
    let startup_caddy_image = match release_env_value(
        "CADDY_INGRESS_IMAGE",
        platform_release_envelope
            .as_ref()
            .map(|envelope| envelope.payload.caddy_ingress_image.as_str()),
        false,
    ) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    };
    match enclava_api::cosign::sidecar_pins_from_images(
        startup_proxy_image.as_deref(),
        startup_caddy_image.as_deref(),
    ) {
        Ok(Some(pins)) => match enclava_api::cosign::verify_sidecars_at_startup(&pins).await {
            Ok(v) => tracing::info!(
                attestation_proxy = %v.attestation_proxy,
                caddy_ingress = %v.caddy_ingress,
                "platform sidecar images verified"
            ),
            Err(e) => {
                eprintln!("startup refused: sidecar cosign verification failed: {e}");
                std::process::exit(1);
            }
        },
        Ok(None) => tracing::warn!(
            "no sidecar images configured; deploy requests will fail until \
             ATTESTATION_PROXY_IMAGE/CADDY_INGRESS_IMAGE are set"
        ),
        Err(e) => {
            eprintln!("startup refused: invalid sidecar pin configuration: {e}");
            std::process::exit(1);
        }
    }

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let database_restore_generation = std::env::var("CAP_DATABASE_RESTORE_GENERATION")
        .expect(
            "CAP_DATABASE_RESTORE_GENERATION must be set to the out-of-database restore generation",
        )
        .parse::<i64>()
        .ok()
        .filter(|generation| *generation > 0)
        .expect("CAP_DATABASE_RESTORE_GENERATION must be a positive integer");
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let dashboard_url = env_nonempty("ENCLAVA_DASHBOARD_URL");
    let platform_domain =
        std::env::var("PLATFORM_DOMAIN").unwrap_or_else(|_| "enclava.dev".to_string());
    let tee_domain_suffix =
        std::env::var("TEE_DOMAIN_SUFFIX").unwrap_or_else(|_| format!("tee.{platform_domain}"));

    let pool = enclava_api::db::pool::create_pool(&database_url)
        .await
        .expect("failed to connect to database");

    enclava_api::db::pool::run_migrations(&pool)
        .await
        .expect("failed to run migrations");

    let runtime_authority =
        enclava_api::runtime_authority::establish_epoch(&pool, database_restore_generation)
            .await
            .expect("failed to establish runtime authority");
    tracing::info!(
        authority_epoch = %runtime_authority.epoch,
        restore_generation = runtime_authority.restore_generation,
        "established runtime authority before provider reconciliation"
    );

    let signing_key = load_signing_key().expect("failed to load API signing key");
    tracing::info!(
        "API signing public key (base64): {}",
        enclava_api::auth::jwt::public_key_base64(&signing_key)
    );

    let hmac_key = load_hmac_key().expect("failed to load session HMAC key");
    tracing::info!("Loaded session HMAC key");
    let attestation = load_attestation_config(
        platform_release_envelope
            .as_ref()
            .map(|envelope| &envelope.payload),
    )
    .expect("failed to load attestation config");
    let dns = load_dns_config().expect("failed to load DNS config");
    let acme = load_acme_config(attestation.as_ref()).expect("failed to load ACME config");
    let kbs_policy = enclava_api::kbs::config_from_env();
    let trustee_required = attestation
        .as_ref()
        .map(|cfg| cfg.trustee_policy_read_available)
        .unwrap_or(false);
    let trustee_attestation_verify_url =
        load_url_env("TRUSTEE_ATTESTATION_VERIFY_URL", trustee_required)
            .expect("failed to load Trustee attestation verify URL");
    let trustee_attestation_verify_bearer_token =
        load_trustee_attestation_verify_bearer_token(trustee_attestation_verify_url.as_deref())
            .expect("failed to load Trustee attestation verify bearer token");
    let signing_service_url = load_url_value(
        "PLATFORM_SIGNING_SERVICE_URL",
        release_env_value(
            "PLATFORM_SIGNING_SERVICE_URL",
            platform_release_envelope
                .as_ref()
                .map(|envelope| envelope.payload.signing_service_url.as_str()),
            trustee_required,
        )
        .expect("failed to load platform signing service URL"),
        trustee_required,
    )
    .expect("failed to load platform signing service URL");
    let signing_service = signing_service_url.map(|url| {
        enclava_api::signing_service::SigningServiceClient::new(
            url,
            env_nonempty("PLATFORM_SIGNING_SERVICE_TOKEN"),
        )
        .expect("failed to configure platform signing service client")
    });
    let require_customer_signed_policy_artifact =
        env_flag("REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT");
    let max_concurrent_applies = std::env::var("CAP_MAX_CONCURRENT_APPLIES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    tracing::info!(
        max_concurrent_applies,
        "configured deployment apply concurrency"
    );
    let management_mode = load_management_mode();
    let internal_auth = load_internal_auth_config();
    if management_mode == CapManagementMode::PaasManaged
        && !internal_auth
            .as_ref()
            .is_some_and(|config| config.is_usable())
    {
        panic!(
            "CAP_MANAGEMENT_MODE=paas_managed requires usable CAP_INTERNAL_SERVICE_TOKEN and CAP_INTERNAL_ALLOWED_CLIENT_SANS"
        );
    }
    if management_mode == CapManagementMode::Standalone && internal_auth.is_some() {
        tracing::warn!(
            "CAP internal PaaS auth is configured but CAP_MANAGEMENT_MODE=standalone; /internal/paas routes are disabled"
        );
    }
    if management_mode == CapManagementMode::PaasManaged {
        tracing::info!("CAP internal PaaS routes configured");
    }
    let tee_http_client =
        build_tenant_tee_http_client().expect("failed to build tenant TEE HTTP client");

    let outbound_config = enclava_api::clients::ClientConfig::from_env();
    let http_client = enclava_api::clients::build_guarded_client(&outbound_config)
        .expect("failed to build SSRF-defended outbound HTTP client");
    let registry_client =
        enclava_api::clients::RegistryClient::from_env().expect("failed to build registry client");
    let trustee_http_client =
        build_trustee_http_client().expect("failed to build Trustee HTTP client");

    let side_effect_admission = enclava_api::state::side_effect_admission_for_pool(&pool);
    let state = AppState {
        db: pool,
        runtime_authority,
        management_mode,
        edge_integration_enabled: haproxy_integration_enabled,
        deployment_dispatch_enabled,
        startup_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        signing_key: Arc::new(signing_key),
        hmac_key: Arc::new(hmac_key),
        api_url,
        dashboard_url,
        platform_domain,
        tee_domain_suffix,
        http_client,
        registry_client,
        trustee_http_client,
        tee_http_client,
        attestation,
        platform_release_envelope,
        debug_trustee_kbs_url_override,
        debug_trustee_kbs_ca_cert_pem_override,
        dns,
        acme,
        kbs_policy,
        trustee_attestation_verify_url,
        trustee_attestation_verify_bearer_token,
        signing_service,
        require_customer_signed_policy_artifact,
        deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_applies)),
        side_effect_admission,
        internal_auth,
    };

    // Bind before provider reconciliation so Kubernetes can probe process
    // liveness during a bounded, potentially long database-restore recovery.
    // Router middleware exposes only /livez until every startup authority has
    // converged; /health, /readyz, and all API routes remain unavailable.
    let app = build_router(state.clone());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind");
    tracing::info!("startup liveness listening on {}", bind_addr);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });

    if let Err(error) =
        enclava_api::deployment_jobs::validate_clean_cut_authority_at_startup(&state).await
    {
        eprintln!(
            "startup refused: legacy or unsigned deployment authority remains: error_code={}",
            error.code()
        );
        std::process::exit(1);
    }
    if let Err(error) =
        enclava_api::deployment_jobs::reconcile_failed_rollout_cleanup_at_startup(&state).await
    {
        eprintln!(
            "startup refused: failed-rollout cleanup reconciliation failed: error_code={}",
            error.code()
        );
        std::process::exit(1);
    }
    if let Err(error) =
        enclava_api::deployment_jobs::reconcile_kubernetes_after_restore_at_startup(&state).await
    {
        eprintln!(
            "startup refused: restored Kubernetes reconciliation failed: error_code={}",
            error.code()
        );
        std::process::exit(1);
    }
    if let Err(error) = enclava_api::kbs::reconcile_policy_at_startup(&state).await {
        eprintln!("startup refused: KBS policy reconciliation failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) =
        verify_trustee_kbs_connectivity(&state.trustee_http_client, trustee_required).await
    {
        eprintln!("startup refused: Trustee KBS connectivity check failed: {error}");
        std::process::exit(1);
    }
    if haproxy_integration_enabled {
        if let Err(error) = enclava_api::edge::reconcile_all_haproxy_routes_at_startup(&state).await
        {
            eprintln!("startup refused: HAProxy route reconciliation failed: {error}");
            std::process::exit(1);
        }
    } else {
        tracing::info!(
            "tenant HAProxy integration is disabled; HAProxy-dependent mutations will fail closed"
        );
    }

    enclava_api::kbs::spawn_signed_policy_reconciler(state.clone());
    if deployment_dispatch_enabled {
        enclava_api::deployment_jobs::spawn_deployment_dispatcher(state.clone());
    } else {
        tracing::info!(
            "durable deployment acceptance and dispatch are disabled by CAP_DEPLOYMENT_DISPATCH_ENABLED"
        );
    }
    if haproxy_integration_enabled {
        enclava_api::edge::spawn_haproxy_reconciler(state.clone());
    } else {
        tracing::info!(
            "tenant HAProxy integration and background route reconciliation are disabled"
        );
    }
    state.mark_startup_ready();
    tracing::info!("startup reconciliation complete; API is ready");

    server
        .await
        .expect("server task panicked")
        .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_startup_installs_rustls_crypto_provider() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let expected = concat!("install_default", "_rustls_crypto_provider();");
        assert!(
            main_body.contains(expected),
            "API startup must install a rustls CryptoProvider before building ACME/HTTP clients"
        );
    }

    #[test]
    fn provider_authority_converges_before_deployment_dispatch_starts() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let dispatch = main_body
            .find("spawn_deployment_dispatcher")
            .expect("deployment dispatcher startup");
        for prerequisite in [
            "runtime_authority::establish_epoch",
            "reconcile_failed_rollout_cleanup_at_startup",
            "validate_clean_cut_authority_at_startup",
            "reconcile_policy_at_startup",
            "reconcile_kubernetes_after_restore_at_startup",
            "verify_trustee_kbs_connectivity",
            "reconcile_all_haproxy_routes",
        ] {
            assert!(
                main_body
                    .find(prerequisite)
                    .is_some_and(|index| index < dispatch),
                "{prerequisite} must complete before durable deployment dispatch"
            );
        }
    }

    #[test]
    fn startup_listener_serves_separate_liveness_until_authority_is_ready() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let bind = main_body
            .find("TcpListener::bind")
            .expect("startup listener bind");
        let first_reconciliation = main_body
            .find("reconcile_failed_rollout_cleanup_at_startup")
            .expect("first startup reconciliation");
        let ready = main_body
            .find("mark_startup_ready")
            .expect("startup readiness publication");
        let dispatch = main_body
            .find("spawn_deployment_dispatcher")
            .expect("deployment dispatcher startup");
        assert!(
            bind < first_reconciliation,
            "liveness listener must bind before potentially long restore reconciliation"
        );
        assert!(
            dispatch < ready,
            "readiness must remain closed until provider convergence and dispatcher startup"
        );

        let deployment = include_str!("../../../deploy/api/deployment.yaml");
        assert!(
            deployment.contains("startupProbe:\n          httpGet:\n            path: /livez")
                && deployment.contains("failureThreshold: 180"),
            "Kubernetes startup must allow a bounded migration-safe window before /livez exists"
        );
        assert!(
            deployment.contains("livenessProbe:\n          httpGet:\n            path: /livez"),
            "Kubernetes liveness must use the startup-safe endpoint"
        );
        assert!(
            deployment.contains("readinessProbe:\n          httpGet:\n            path: /readyz"),
            "Kubernetes readiness must remain distinct from process liveness"
        );
    }

    #[test]
    fn haproxy_flag_is_validated_before_database_or_provider_authority() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let haproxy_flag = main_body
            .find("edge::haproxy_integration_enabled")
            .expect("HAProxy integration flag validation");
        let dispatch_flag = main_body
            .find("load_deployment_dispatch_enabled")
            .expect("deployment dispatch flag validation");
        for side_effect in [
            "db::pool::create_pool",
            "db::pool::run_migrations",
            "runtime_authority::establish_epoch",
            "reconcile_failed_rollout_cleanup_at_startup",
            "reconcile_policy_at_startup",
            "reconcile_kubernetes_after_restore_at_startup",
        ] {
            assert!(
                haproxy_flag < main_body.find(side_effect).expect(side_effect),
                "HAProxy integration config must be valid before {side_effect}"
            );
            assert!(
                dispatch_flag < main_body.find(side_effect).expect(side_effect),
                "deployment dispatch config must be valid before {side_effect}"
            );
        }
        assert!(
            main_body.contains("if deployment_dispatch_enabled && !haproxy_integration_enabled"),
            "dispatch activation must require a configured edge integration"
        );
    }

    #[test]
    fn restore_specific_kbs_fence_precedes_generic_provider_reconciliation() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let cleanup = main_body
            .find("reconcile_failed_rollout_cleanup_at_startup")
            .expect("failed-rollout cleanup startup");
        let clean_cut = main_body
            .find("validate_clean_cut_authority_at_startup")
            .expect("signed-only clean-cut startup validation");
        let kubernetes_restore = main_body
            .find("reconcile_kubernetes_after_restore_at_startup")
            .expect("restored Kubernetes reconciliation startup");
        let generic_kbs = main_body
            .find("reconcile_policy_at_startup")
            .expect("generic KBS reconciliation startup");
        assert!(
            cleanup < kubernetes_restore,
            "exact failed-rollout cleanup must precede restored Kubernetes reconciliation"
        );
        assert!(
            clean_cut < cleanup && cleanup < kubernetes_restore,
            "clean-cut validation must reject unsupported authority before cleanup can reach Trustee"
        );
        assert!(
            kubernetes_restore < generic_kbs,
            "restore reconciliation must acquire and normalize its continuous KBS fence before generic reconciliation"
        );
        let edge_restore = main_body
            .find("reconcile_all_haproxy_routes_at_startup")
            .expect("restored HAProxy reconciliation startup");
        assert!(
            kubernetes_restore < edge_restore,
            "restored Kubernetes state must converge before HAProxy routes"
        );
    }

    #[test]
    fn edge_reconciliation_and_dispatch_activation_are_independent() {
        let source = include_str!("main.rs");
        let main_body = source
            .split("#[tokio::main]")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("main body");
        let reconcile = main_body
            .find("reconcile_all_haproxy_routes_at_startup")
            .expect("HAProxy startup reconciliation");
        let dispatch = main_body
            .find("spawn_deployment_dispatcher")
            .expect("deployment dispatcher startup");
        assert!(reconcile < dispatch);
        assert!(
            !main_body.contains("TENANT_HAPROXY_RECONCILIATION_REQUIRED"),
            "reconciliation must be tied to the integration itself, not management mode"
        );
        assert!(
            main_body.contains("haproxy_integration_enabled"),
            "optional API deployments must be able to start without HAProxy credentials"
        );
        let background_workers = main_body
            .split("enclava_api::kbs::spawn_signed_policy_reconciler")
            .nth(1)
            .and_then(|body| body.split("let app = build_router").next())
            .expect("background worker startup block");
        let dispatch_branch = background_workers
            .split("if deployment_dispatch_enabled {")
            .nth(1)
            .and_then(|body| body.split("if haproxy_integration_enabled {").next())
            .expect("deployment-dispatch worker branch");
        assert!(
            dispatch_branch.contains("spawn_deployment_dispatcher"),
            "durable deployment dispatch must require explicit activation"
        );
        let edge_branch = background_workers
            .split("if haproxy_integration_enabled {")
            .nth(1)
            .expect("HAProxy-enabled worker branch");
        assert!(
            edge_branch.contains("spawn_haproxy_reconciler")
                && !edge_branch.contains("spawn_deployment_dispatcher"),
            "edge reconciliation must remain active without enabling deployment dispatch"
        );
    }

    #[test]
    fn deployment_dispatch_switch_is_strict_and_fail_closed() {
        assert!(!parse_fail_closed_switch("SWITCH", None).unwrap());
        assert!(!parse_fail_closed_switch("SWITCH", Some("false")).unwrap());
        assert!(parse_fail_closed_switch("SWITCH", Some("true")).unwrap());
        for invalid in ["", "1", "TRUE", "yes", " true", "false "] {
            assert!(
                parse_fail_closed_switch("SWITCH", Some(invalid)).is_err(),
                "{invalid:?} must not activate dispatch"
            );
        }
    }

    #[test]
    fn tenant_tee_http_client_reads_configured_ca_pem() {
        let err = build_tenant_tee_http_client_with_env(|name| match name {
            "TENANT_TEE_CA_CERT_PEM" => Some("not a pem certificate".to_string()),
            _ => None,
        })
        .expect_err("invalid configured tenant TEE CA PEM should be rejected");

        assert!(
            err.to_string().contains("TENANT_TEE_CA_CERT_PEM"),
            "error should name the invalid tenant TEE CA env var: {err}"
        );
    }

    #[test]
    fn debug_build_allows_http_trustee_for_local_stacks() {
        let url = validate_trustee_kbs_url("http://trustee.example.test:8080", false)
            .expect("debug builds retain documented local HTTP Trustee support");
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn debug_http_trustee_can_override_bundled_release_url() {
        assert_eq!(
            trustee_kbs_url_matches_release(
                "http://trustee.example.test:8080",
                "https://trustee.preprod.example.test:8443",
                false,
            )
            .expect("debug HTTP Trustee must remain reachable with the bundled signed release"),
            Some("http://trustee.example.test:8080".to_string())
        );
    }

    #[test]
    fn release_trustee_must_match_signed_release() {
        let error = trustee_kbs_url_matches_release(
            "https://other-trustee.example.test:8443",
            "https://trustee.preprod.example.test:8443",
            true,
        )
        .expect_err("release Trustee authority cannot override the signed release");
        assert!(
            error
                .to_string()
                .contains("conflicts with signed platform release")
        );
    }

    #[test]
    fn release_build_requires_https_trustee() {
        let error = validate_trustee_kbs_url("http://trustee.example.test:8080", true)
            .expect_err("release builds must reject plaintext Trustee");
        assert!(error.to_string().contains("release builds"));
        validate_trustee_kbs_url("https://trustee.example.test:8443", true)
            .expect("release builds accept HTTPS Trustee");
    }
}
