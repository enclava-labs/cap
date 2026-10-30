use anyhow::Context as _;
use axum::Extension;
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
    let value = match std::env::var("CAP_DEPLOYMENT_DISPATCH_ENABLED") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("CAP_DEPLOYMENT_DISPATCH_ENABLED must be valid UTF-8")
        }
    };
    parse_fail_closed_switch("CAP_DEPLOYMENT_DISPATCH_ENABLED", value.as_deref())
}

fn validate_edge_reconciliation_mode(
    deployment_dispatch_enabled: bool,
    edge_reconciliation_disabled: bool,
) -> anyhow::Result<()> {
    if deployment_dispatch_enabled && edge_reconciliation_disabled {
        anyhow::bail!(
            "CAP_DISABLE_EDGE_RECONCILIATION cannot be enabled while deployment dispatch is enabled"
        );
    }
    Ok(())
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

fn load_management_mode() -> Result<CapManagementMode, String> {
    load_management_mode_with_env(|name| std::env::var(name).ok())
}

fn load_management_mode_with_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<CapManagementMode, String> {
    lookup("CAP_MANAGEMENT_MODE")
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("standalone")
        .parse()
        .map_err(|err| format!("invalid CAP_MANAGEMENT_MODE: {err}"))
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
        .timeout(std::time::Duration::from_secs(15))
        // TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN must never transit
        // cleartext: the trustee client only talks to
        // TRUSTEE_ATTESTATION_VERIFY_URL, which is HTTPS-gated in
        // env_gates for release builds. https_only is the belt to that
        // suspenders, and also covers debug builds where the gate is off.
        .https_only(true);

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
    // Same parse enclava-init applies (VerifyingKey::from_bytes): a pin that
    // is not a valid Ed25519 point would abort in-TEE verification and brick
    // every workload, so fail startup instead (codex cap#218 P2).
    let arr: [u8; 32] = raw.try_into().expect("length checked above");
    let key = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("invalid {name}: not a valid Ed25519 public key: {e}"))?;
    // Small-order keys provide no unforgeability: policy acceptance uses
    // verify(), not verify_strict(), and a zero signature verifies against a
    // small-order key for a large share of messages.
    if key.is_weak() {
        anyhow::bail!(
            "invalid {name}: Ed25519 public key has small order and provides no unforgeability"
        );
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn platform_release_enabled(trustee_policy_read_available: bool) -> bool {
    trustee_policy_read_available
        || env_flag("ENCLAVA_USE_PLATFORM_RELEASE")
        || env_nonempty("ENCLAVA_PLATFORM_RELEASE_PATH").is_some()
}

fn validate_platform_release_runtime_class(
    release_runtime_class: &str,
    effective_runtime_class: &str,
) -> anyhow::Result<()> {
    if release_runtime_class != effective_runtime_class {
        anyhow::bail!(
            "signed platform release runtime class `{release_runtime_class}` does not match API runtime class `{effective_runtime_class}`"
        );
    }
    Ok(())
}

fn load_platform_release(
    enabled: bool,
    effective_runtime_class: &str,
) -> anyhow::Result<Option<PlatformReleaseEnvelope>> {
    if !enabled {
        return Ok(None);
    }
    let envelope = PlatformReleaseEnvelope::load_verified()
        .map_err(|e| anyhow::anyhow!("failed to load signed platform release: {e}"))?;
    let release = &envelope.payload;
    validate_platform_release_runtime_class(
        &release.expected_runtime_class,
        effective_runtime_class,
    )?;
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

/// Loads the two policy-authority pubkeys, each from its own signed release
/// field (env values must match the signed field exactly). The platform
/// trustee policy key and the signing-service key are distinct trust
/// domains: collapsing them into one key is an error, not a fallback
/// (cap#118).
fn load_policy_authority_pubkeys(
    platform_release: Option<&PlatformRelease>,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let platform_trustee_policy_pubkey_hex = load_pubkey_hex_value(
        "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX",
        release_env_value(
            "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX",
            platform_release.map(|release| release.platform_trustee_policy_pubkey_hex.as_str()),
            false,
        )?,
        false,
    )?;
    let signing_service_pubkey_hex = load_pubkey_hex_value(
        "SIGNING_SERVICE_PUBKEY_HEX",
        release_env_value(
            "SIGNING_SERVICE_PUBKEY_HEX",
            platform_release.map(|release| release.signing_service_pubkey_hex.as_str()),
            false,
        )?,
        false,
    )?;
    if let (Some(trustee_key), Some(signing_key)) = (
        &platform_trustee_policy_pubkey_hex,
        &signing_service_pubkey_hex,
    ) {
        // Nested if (not a let chain): let chains need Rust 1.88, workspace
        // MSRV is 1.85.
        if trustee_key == signing_key {
            anyhow::bail!(
                "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX and SIGNING_SERVICE_PUBKEY_HEX must be distinct keys (in-TEE policy authority vs signing service); collapsing them is not allowed"
            );
        }
    }
    Ok((
        platform_trustee_policy_pubkey_hex,
        signing_service_pubkey_hex,
    ))
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
    let amd_kds_base_url = load_url_env("AMD_KDS_BASE_URL", true)?;
    let trustee_policy_url = load_url_env("TRUSTEE_POLICY_URL", trustee_policy_read_available)?;
    // The platform trustee policy key and the signing-service key are two
    // distinct trust domains (in-TEE policy authority vs off-cluster signing
    // service). Each comes from its own signed release field; a release (or
    // env override) that collapses them into one key is an error, not a
    // fallback — compromise or revocation of either must not collapse both.
    let (platform_trustee_policy_pubkey_hex, signing_service_pubkey_hex) =
        load_policy_authority_pubkeys(platform_release)?;

    Ok(AttestationConfig {
        proxy_image: parse_image_ref("ATTESTATION_PROXY_IMAGE", &proxy_image_ref)?,
        caddy_image: parse_image_ref("CADDY_INGRESS_IMAGE", &caddy_image_ref)?,
        acme_ca_url,
        caddy_tls_mode,
        trustee_policy_read_available,
        workload_artifacts_url,
        tls_certificate_broker_url,
        amd_kds_base_url,
        trustee_policy_url,
        local_workload_artifacts_json: None,
        local_trustee_policy_json: None,
        platform_trustee_policy_pubkey_hex,
        signing_service_pubkey_hex,
        verification_material: None,
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
    let prefer_system = match std::env::var("ACME_DNS_LOOKUP_PREFER_SYSTEM") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => anyhow::bail!("ACME_DNS_LOOKUP_PREFER_SYSTEM must be valid UTF-8"),
    };
    let timeout_seconds = match std::env::var("ACME_DNS_LOOKUP_TIMEOUT_SECONDS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => anyhow::bail!("ACME_DNS_LOOKUP_TIMEOUT_SECONDS must be valid UTF-8"),
    };
    let (dns_lookup_prefer_system, dns_lookup_timeout) =
        parse_acme_dns_lookup_settings(prefer_system.as_deref(), timeout_seconds.as_deref())?;
    Ok(Some(AcmeConfig {
        directory_url,
        account_credentials_path,
        dns_propagation_wait,
        dns_lookup_prefer_system,
        dns_lookup_timeout,
    }))
}

fn parse_acme_dns_lookup_settings(
    prefer_system: Option<&str>,
    timeout_seconds: Option<&str>,
) -> anyhow::Result<(bool, Option<std::time::Duration>)> {
    let prefer_system = parse_fail_closed_switch("ACME_DNS_LOOKUP_PREFER_SYSTEM", prefer_system)?;
    let timeout = timeout_seconds
        .map(|value| {
            let seconds = value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("ACME_DNS_LOOKUP_TIMEOUT_SECONDS must be a positive integer")
            })?;
            anyhow::ensure!(
                seconds > 0,
                "ACME_DNS_LOOKUP_TIMEOUT_SECONDS must be positive"
            );
            let duration = std::time::Duration::from_secs(seconds);
            anyhow::ensure!(
                std::time::Instant::now().checked_add(duration).is_some(),
                "ACME_DNS_LOOKUP_TIMEOUT_SECONDS is too large"
            );
            Ok::<_, anyhow::Error>(duration)
        })
        .transpose()?;
    Ok((prefer_system, timeout))
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

// rustls cannot infer a provider when both ring and aws-lc-rs are enabled.
fn bootstrap_runtime_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// Both authority barriers must complete before dispatch or readiness opens.
async fn run_startup_convergence<K, E, D, R>(
    kbs_reconcile: K,
    edge_reconcile: Option<E>,
    spawn_dispatcher: Option<D>,
    mark_ready: R,
) -> anyhow::Result<()>
where
    K: Future<Output = anyhow::Result<()>>,
    E: Future<Output = anyhow::Result<()>>,
    D: FnOnce(),
    R: FnOnce(),
{
    kbs_reconcile
        .await
        .context("KBS policy reconciliation failed")?;
    if let Some(edge_reconcile) = edge_reconcile {
        edge_reconcile
            .await
            .context("HAProxy route reconciliation failed")?;
    }
    if let Some(spawn_dispatcher) = spawn_dispatcher {
        spawn_dispatcher();
    }
    mark_ready();
    Ok(())
}

#[tokio::main]
async fn main() {
    bootstrap_runtime_crypto_provider();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclava_api=debug,enclava_snp=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(e) = enclava_api::env_gates::enforce_production_env_gates() {
        eprintln!("startup refused: {e}");
        std::process::exit(1);
    }
    // Issue #225 fail-closed gates: platform registry credentials must be
    // explicitly scoped before they may be forwarded anywhere.
    if let Some(error) = enclava_api::cosign::cosign_registry_credentials_startup_error() {
        eprintln!("startup refused: {error}");
        std::process::exit(1);
    }
    if let Some(error) = enclava_api::deploy::tenant_image_pull_secret_startup_error() {
        eprintln!("startup refused: {error}");
        std::process::exit(1);
    }
    let deployment_dispatch_enabled = match load_deployment_dispatch_enabled() {
        Ok(enabled) => enabled,
        Err(error) => {
            eprintln!("startup refused: invalid deployment dispatch configuration: {error}");
            std::process::exit(1);
        }
    };
    let edge_reconciliation_disabled = env_flag("CAP_DISABLE_EDGE_RECONCILIATION");
    if let Err(error) =
        validate_edge_reconciliation_mode(deployment_dispatch_enabled, edge_reconciliation_disabled)
    {
        eprintln!("startup refused: invalid edge reconciliation configuration: {error}");
        std::process::exit(1);
    }

    let trustee_policy_read_available = env_flag("TRUSTEE_POLICY_READ_AVAILABLE");
    let effective_runtime_class = match enclava_engine::manifest::cc_init_data::try_runtime_class()
    {
        Ok(runtime_class) => runtime_class,
        Err(e) => {
            eprintln!("startup refused: invalid runtime class configuration: {e}");
            std::process::exit(1);
        }
    };
    let platform_release_envelope = match load_platform_release(
        platform_release_enabled(trustee_policy_read_available),
        &effective_runtime_class,
    ) {
        Ok(release) => release,
        Err(e) => {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    };
    if let Some(envelope) = &platform_release_envelope {
        let release = &envelope.payload;
        tracing::info!(
            platform_release_version = %release.platform_release_version,
            genpolicy_version = %release.genpolicy_version,
            "signed platform release loaded"
        );
        for (name, expected) in [
            ("TRUSTEE_KBS_URL", release.trustee_kbs_url.as_str()),
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
        if !release.trustee_kbs_ca_cert_pem.trim().is_empty()
            && let Err(e) = require_env_matches_release(
                "TRUSTEE_KBS_CA_CERT_PEM",
                &release.trustee_kbs_ca_cert_pem,
                true,
            )
        {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
        // LUKS2 header-seal rollout claim (cap#244 review): the value is
        // rendered into every cc_init_data from the SIGNED release, so the
        // API render always matches the CLI's signed hash. An
        // ENCLAVA_LUKS2_HEADER_SEAL leftover that disagrees with the signed
        // value is a misconfiguration and refuses startup: silently
        // rendering either side's private value would let the signed
        // `expected_cc_init_data_hash` diverge from the actual rollout
        // state.
        let seal_claim = release.luks2_header_seal_claim();
        if let Some(env) = env_nonempty("ENCLAVA_LUKS2_HEADER_SEAL")
            && env.trim() != seal_claim
        {
            eprintln!(
                "startup refused: ENCLAVA_LUKS2_HEADER_SEAL conflicts with signed platform \
                 release: env `{env}` != release `{seal_claim}`; the rollout value is sourced \
                 from the signed platform release (luks2_header_seal), remove the environment \
                 variable or sign a release carrying the intended value"
            );
            std::process::exit(1);
        }
        enclava_engine::manifest::cc_init_data::set_luks2_header_seal_claim(&seal_claim);

        // Log-spool state-bind deployment gate (cap#290 review): NOT signed
        // release metadata — a canonical field would break release-signature
        // verification on previously released CLIs, so it is a deployment
        // capability only. Ops sets ENCLAVA_LOG_SPOOL_STORAGE only in the
        // same package that pins the bind-capable ENCLAVA_INIT_IMAGE; under
        // a signed release its absence is the unsupported sentinel and must
        // be installed verbatim so neither the env fallback nor the dev
        // default can resurrect the claim. A value other than
        // "state-bind-v1" refuses startup rather than rendering an
        // unverifiable claim.
        let spool_claim = env_nonempty("ENCLAVA_LOG_SPOOL_STORAGE").unwrap_or_default();
        if !matches!(spool_claim.as_str(), "" | "state-bind-v1") {
            eprintln!(
                "startup refused: ENCLAVA_LOG_SPOOL_STORAGE {spool_claim:?} is not a valid \
                 log-spool storage claim (expected unset or \"state-bind-v1\"); it must be set \
                 only together with the bind-capable ENCLAVA_INIT_IMAGE pin"
            );
            std::process::exit(1);
        }
        enclava_engine::manifest::cc_init_data::set_log_spool_storage_claim(&spool_claim);
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
        Ok(Some(pins)) => match enclava_api::cosign::verify_sidecars_at_startup(
            &enclava_api::clients::EgressGuard::from_env(),
            &pins,
        )
        .await
        {
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
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let dashboard_url = env_nonempty("ENCLAVA_DASHBOARD_URL");
    let platform_domain =
        std::env::var("PLATFORM_DOMAIN").unwrap_or_else(|_| "enclava.dev".to_string());
    let tee_domain_suffix =
        std::env::var("TEE_DOMAIN_SUFFIX").unwrap_or_else(|_| format!("tee.{platform_domain}"));

    let pool = enclava_api::db::pool::create_pool(&database_url)
        .await
        .expect("failed to connect to database");

    let migration_mode =
        enclava_api::db::pool::MigrationMode::from_env().expect("invalid database migration mode");
    enclava_api::db::pool::prepare_schema(&pool, migration_mode)
        .await
        .expect("database schema is not ready for this binary");

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
    let management_mode = match load_management_mode() {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("startup refused: {error}");
            std::process::exit(1);
        }
    };
    let internal_auth = load_internal_auth_config();
    if management_mode == CapManagementMode::PaasManaged
        && !internal_auth
            .as_ref()
            .is_some_and(|config| config.is_usable())
    {
        panic!(
            "CAP_MANAGEMENT_MODE=paas_managed requires CAP_INTERNAL_SERVICE_TOKEN, CAP_INTERNAL_ALLOWED_CLIENT_SANS and CAP_INTERNAL_TRUSTED_PROXY_SECRET"
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
    let outbound_body_limit = outbound_config.body_limit_bytes;
    let registry_client =
        enclava_api::clients::RegistryClient::from_env().expect("failed to build registry client");
    let cosign_egress = enclava_api::clients::EgressGuard::from_env();
    let trustee_http_client =
        build_trustee_http_client().expect("failed to build Trustee HTTP client");

    let side_effect_admission = enclava_api::state::side_effect_admission_for_pool(&pool);
    // Construct the router with workload admission CLOSED. Bind liveness
    // before the potentially serial, per-namespace Kubernetes sweep: a stalled
    // cluster must not make startup probes restart us before /livez exists.
    // The shared atomic is opened only after the initial sweep converges.
    let mut dispatch_admission = false;
    let state = AppState {
        db: pool,
        management_mode,
        deployment_dispatch_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
            dispatch_admission,
        )),
        startup_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        signing_key: Arc::new(signing_key),
        hmac_key: Arc::new(hmac_key),
        api_url,
        dashboard_url,
        platform_domain,
        tee_domain_suffix,
        http_client,
        outbound_body_limit,
        registry_client,
        cosign_egress,
        trustee_http_client,
        tee_http_client,
        recent_tee_probe_failures: std::sync::Arc::new(std::sync::Mutex::new(
            enclava_api::state::TeeProbeFailureCache::default(),
        )),
        attestation,
        platform_release_envelope,
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

    let desired_state_engine = if management_mode == CapManagementMode::PaasManaged {
        Some(Arc::new(
            enclava_engine::apply::engine::ApplyEngine::try_default()
                .await
                .expect("failed to configure Kubernetes client for PaaS desired-state routes"),
        ))
    } else {
        None
    };
    let app = build_router(state.clone());
    let app = match desired_state_engine {
        Some(engine) => app.layer(Extension(engine)),
        None => app,
    };
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

    let pull_secret_sweep_converged =
        enclava_api::deploy::cleanup_stale_tenant_image_pull_secrets_at_startup(&state.db).await;
    dispatch_admission = deployment_dispatch_enabled && pull_secret_sweep_converged;
    if dispatch_admission {
        state.set_deployment_dispatch_enabled(true);
    } else if deployment_dispatch_enabled {
        tracing::error!(
            "workload admission closed: pull secret cleanup did not converge; background retry scheduled"
        );
    }
    if edge_reconciliation_disabled {
        tracing::warn!("tenant HAProxy reconciliation disabled for local development");
    }
    // The pull-secret cleanup sweep already ran before router construction;
    // `dispatch_admission` encodes its result together with the operator's
    // CAP_DEPLOYMENT_DISPATCH_ENABLED intent. The deployment dispatcher is
    // spawned only when the operator enabled dispatch (review finding on
    // #243) — and only once, in lockstep with opening workload admission.
    if let Err(error) = run_startup_convergence(
        async {
            enclava_api::kbs::reconcile_signed_policy_at_startup(&state)
                .await
                .map_err(anyhow::Error::from)
        },
        (!edge_reconciliation_disabled).then_some(async {
            enclava_api::edge::reconcile_all_haproxy_routes_at_startup(&state)
                .await
                .map_err(anyhow::Error::from)
        }),
        (deployment_dispatch_enabled && dispatch_admission)
            .then_some(|| enclava_api::deployment_jobs::spawn_deployment_dispatcher(state.clone())),
        || state.mark_startup_ready(),
    )
    .await
    {
        eprintln!("startup refused: {error:#}");
        std::process::exit(1);
    }
    if !edge_reconciliation_disabled {
        enclava_api::edge::spawn_haproxy_reconciler(state.clone());
    }
    enclava_api::kbs::spawn_signed_policy_reconciler(state.clone());
    enclava_api::routes::auth::spawn_device_login_reaper(state.db.clone());
    enclava_api::auth::nostr::spawn_nip98_replay_cache_reaper(state.db.clone());
    if !deployment_dispatch_enabled {
        tracing::info!(
            "workload mutation and durable deployment dispatch are disabled \
             (CAP_DEPLOYMENT_DISPATCH_ENABLED=false)"
        );
    }
    // The sweep keeps running for the process lifetime regardless of the
    // dispatch flag (review finding on #243): converged is not a one-shot
    // property — an older revision rolling out alongside this one can
    // re-materialize a managed pull secret into a tenant namespace after the
    // first sweep converged, and a dispatch-disabled (frozen) process must
    // still reap such residue instead of leaving it until the next restart.
    spawn_pull_secret_sweep_reconciler(
        state.clone(),
        deployment_dispatch_enabled,
        dispatch_admission,
    );
    tracing::info!("startup reconciliation complete; API is ready");

    server
        .await
        .expect("server task panicked")
        .expect("server error");
}

/// Bounded backoff between cleanup-sweep retries: doubles up to one minute,
/// so a Kubernetes outage cannot make the retry loop hammer the API server,
/// while a recovery is noticed within at most a minute.
fn sweep_retry_backoff(previous: std::time::Duration) -> std::time::Duration {
    (previous * 2).min(std::time::Duration::from_secs(60))
}

/// Slow interval between converged cleanup sweeps. After the first
/// convergence the sweep is no longer latency-critical (review finding on
/// #243): its job is to reap pull secrets an older revision re-materializes
/// into tenant namespaces during a rolling update, so a converged sweep is
/// re-run periodically instead of being a one-shot — long enough to stay off
/// the API server's back, short enough to reap residue within minutes.
fn sweep_periodic_interval() -> std::time::Duration {
    std::time::Duration::from_secs(600)
}

/// Keep the tenant image pull secret cleanup sweep running for the process
/// lifetime (review finding on #243). While dispatch is operator-enabled and
/// no sweep has converged yet, the dispatch-freeze middleware keeps rejecting
/// workload mutations and the deployment dispatcher stays unspawned; the
/// first convergence opens them exactly once, dispatcher first and admission
/// second. After that — and with the operator flag off entirely — the sweep
/// keeps re-running on a slow interval, because converged is not forever: an
/// older revision rolling out alongside this one can re-materialize a managed
/// pull secret after the first sweep converged, and a frozen process must
/// still reap such residue instead of leaving it until the next restart.
fn spawn_pull_secret_sweep_reconciler(
    state: AppState,
    deployment_dispatch_enabled: bool,
    dispatch_admission: bool,
) {
    tokio::spawn(async move {
        let mut backoff = std::time::Duration::from_secs(2);
        // The startup sweep already converged: the dispatcher is running and
        // admission is open.
        let mut dispatcher_spawned = dispatch_admission;
        loop {
            tokio::time::sleep(backoff).await;
            if enclava_api::deploy::cleanup_stale_tenant_image_pull_secrets_at_startup(&state.db)
                .await
            {
                if deployment_dispatch_enabled && !dispatcher_spawned {
                    // Dispatcher first, admission second: whenever a workload
                    // mutation is admitted, the dispatcher is already running.
                    enclava_api::deployment_jobs::spawn_deployment_dispatcher(state.clone());
                    state.set_deployment_dispatch_enabled(true);
                    dispatcher_spawned = true;
                    tracing::info!(
                        "tenant image pull secret cleanup sweep converged; \
                         workload admission and deployment dispatch enabled"
                    );
                }
                backoff = sweep_periodic_interval();
            } else {
                if dispatcher_spawned {
                    // Admission is already open and stays open: the per-deploy
                    // cleanup is the hard gate for every deploy, so a failure
                    // of this periodic re-sweep must not flap deployments
                    // closed — log loudly and retry.
                    tracing::error!(
                        "tenant image pull secret cleanup sweep did not converge; a stale \
                         platform pull secret may still be out there (per-deploy cleanup \
                         still gates every deploy), retrying"
                    );
                } else {
                    tracing::warn!(
                        backoff_secs = backoff.as_secs(),
                        "tenant image pull secret cleanup sweep did not converge; \
                         workload admission stays closed, retrying"
                    );
                }
                backoff = sweep_retry_backoff(backoff);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_retry_backoff_is_bounded() {
        // The cleanup-sweep reconciler retries with exponential backoff that
        // must stay bounded (review finding on #243): a long Kubernetes
        // outage must not hammer the API server, and recovery is noticed
        // within at most the cap.
        let mut backoff = std::time::Duration::from_secs(2);
        let mut steps = Vec::new();
        for _ in 0..10 {
            backoff = sweep_retry_backoff(backoff);
            steps.push(backoff);
        }
        assert_eq!(
            steps[..5],
            [
                std::time::Duration::from_secs(4),
                std::time::Duration::from_secs(8),
                std::time::Duration::from_secs(16),
                std::time::Duration::from_secs(32),
                std::time::Duration::from_secs(60),
            ]
        );
        assert!(
            steps
                .iter()
                .all(|step| *step <= std::time::Duration::from_secs(60)),
            "backoff must never exceed the cap: {steps:?}"
        );
    }

    #[test]
    fn converged_sweeps_keep_running_on_a_slow_interval() {
        // Converged is not a one-shot (review finding on #243): after the
        // first convergence the sweep re-runs periodically to reap pull
        // secrets an older revision re-materializes during a rolling update.
        // The interval must be slow (not hammering the API server) but finite
        // (residue reaped within minutes).
        let interval = sweep_periodic_interval();
        assert!(
            interval >= std::time::Duration::from_secs(60),
            "periodic sweeps must not hammer the API server: {interval:?}"
        );
        assert!(
            interval <= std::time::Duration::from_secs(3600),
            "periodic sweeps must reap rolling-update residue within minutes: {interval:?}"
        );
    }

    #[test]
    fn acme_dns_settings_preserve_defaults_and_validate_explicit_values() {
        assert_eq!(
            parse_acme_dns_lookup_settings(None, None).unwrap(),
            (false, None)
        );
        assert_eq!(
            parse_acme_dns_lookup_settings(Some("true"), Some("2")).unwrap(),
            (true, Some(std::time::Duration::from_secs(2)))
        );
        assert_eq!(
            parse_acme_dns_lookup_settings(Some("false"), None).unwrap(),
            (false, None)
        );
        for invalid in ["", "1", "TRUE", "yes", " true "] {
            assert!(parse_acme_dns_lookup_settings(Some(invalid), None).is_err());
        }
        for invalid in [
            "",
            "0",
            "-1",
            "1.5",
            "two",
            " 2 ",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            assert!(parse_acme_dns_lookup_settings(None, Some(invalid)).is_err());
        }
    }

    /// Serializes tests that read or mutate the POLICY_*PUBKEY_HEX process
    /// env (tests run in parallel threads; an env-mutating test racing an
    /// env-reading one produces flaky conflicts).
    static POLICY_ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Isolates the POLICY_*PUBKEY_HEX process env for one test: captures
    /// the prior values, clears both vars, and on drop restores the exact
    /// prior state (value or unset). A panic mid-test cannot leak mutations
    /// into other tests in this binary, and operator-provided values in the
    /// test environment are preserved instead of erased.
    struct EnvGuard {
        prior_trustee: Option<std::ffi::OsString>,
        prior_signing: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn new() -> Self {
            let guard = Self {
                prior_trustee: std::env::var_os("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX"),
                prior_signing: std::env::var_os("SIGNING_SERVICE_PUBKEY_HEX"),
            };
            unsafe {
                std::env::remove_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX");
                std::env::remove_var("SIGNING_SERVICE_PUBKEY_HEX");
            }
            guard
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prior_trustee {
                    Some(value) => std::env::set_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", value),
                    None => std::env::remove_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX"),
                }
                match &self.prior_signing {
                    Some(value) => std::env::set_var("SIGNING_SERVICE_PUBKEY_HEX", value),
                    None => std::env::remove_var("SIGNING_SERVICE_PUBKEY_HEX"),
                }
            }
        }
    }

    #[test]
    fn policy_authority_pubkeys_reject_collapse_to_one_key() {
        // cap#118: the platform trustee policy key and the signing-service
        // key are two trust domains. Without a signed release they may come
        // from env; an operator (or legacy config) that sets both to the
        // same hex must fail startup instead of silently collapsing the
        // domains.
        let _env_mutex = POLICY_ENV_TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new();
        let key = "11".repeat(32);
        unsafe {
            std::env::set_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", &key);
            std::env::set_var("SIGNING_SERVICE_PUBKEY_HEX", &key);
        }
        let err = load_policy_authority_pubkeys(None).unwrap_err();
        assert!(err.to_string().contains("must be distinct keys"));

        // Case variants of the same key must not sneak past the check.
        unsafe {
            std::env::set_var(
                "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX",
                key.to_ascii_uppercase(),
            );
        }
        let err = load_policy_authority_pubkeys(None).unwrap_err();
        assert!(err.to_string().contains("must be distinct keys"));
    }

    #[test]
    fn policy_authority_pubkeys_reject_non_point_encoding() {
        // codex cap#218 P2: enclava-init parses both pins with
        // VerifyingKey::from_bytes and aborts verification on failure, so a
        // pin that is not a valid Ed25519 point would brick every workload.
        // Startup must reject it instead. The compressed encoding of a y
        // with no Edwards point on the curve (e.g. y = 2 for edwards25519)
        // is the canonical rejection case.
        let _env_mutex = POLICY_ENV_TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new();
        let non_point = format!("02{}", "00".repeat(31));
        unsafe {
            std::env::set_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", &non_point);
        }
        let err = load_policy_authority_pubkeys(None).unwrap_err();
        assert!(
            err.to_string().contains("not a valid Ed25519 public key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn policy_authority_pubkeys_reject_small_order_encoding() {
        // cap#218 follow-up: policy acceptance uses verify(), not
        // verify_strict(), and a zero signature verifies against a
        // small-order key (e.g. 00*32) for a large share of messages — a
        // small-order pin would accept forged policy artifacts. Fail
        // startup instead.
        let _env_mutex = POLICY_ENV_TEST_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new();
        unsafe {
            std::env::set_var("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", "00".repeat(32));
            std::env::set_var("SIGNING_SERVICE_PUBKEY_HEX", "11".repeat(32));
        }
        let err = load_policy_authority_pubkeys(None).unwrap_err();
        assert!(
            err.to_string().contains("small order"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn policy_authority_pubkeys_load_distinct_release_fields() {
        // The original bug: both slots were filled from
        // release.signing_service_pubkey_hex. A release with the new signed
        // field must supply each slot from its own field (the bundled
        // envelope's own distinct keys are proven in the lib tests).
        let _env_mutex = POLICY_ENV_TEST_MUTEX.lock().unwrap();
        // Clear inherited env too: operator-provided POLICY_*PUBKEY_HEX
        // values would conflict with the release fields under test.
        let _guard = EnvGuard::new();
        let release = PlatformRelease {
            schema_version: "v1".into(),
            platform_release_version: "test".into(),
            signing_service_url: "https://signing.example".into(),
            signing_service_pubkey_hex: "11".repeat(32),
            platform_trustee_policy_pubkey_hex: "33".repeat(32),
            policy_template_id: "t".into(),
            policy_template_sha256: "00".repeat(32),
            policy_template_text: String::new(),
            attestation_proxy_image: "img".into(),
            caddy_ingress_image: "img".into(),
            trustee_kbs_url: "https://kbs.example".into(),
            trustee_kbs_ca_cert_pem: String::new(),
            tenant_caddy_tls_mode: "acme".into(),
            tenant_caddy_acme_ca: "https://acme.example".into(),
            expected_firmware_measurement: "00".repeat(32),
            expected_runtime_class: "kata-qemu-snp".into(),
            genpolicy_version: "test".into(),
            luks2_header_seal: String::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let (trustee, signing) =
            load_policy_authority_pubkeys(Some(&release)).expect("distinct keys load");
        assert_eq!(
            trustee.as_deref(),
            Some(release.platform_trustee_policy_pubkey_hex.as_str())
        );
        assert_eq!(
            signing.as_deref(),
            Some(release.signing_service_pubkey_hex.as_str())
        );
        assert_ne!(trustee, signing);
    }

    #[test]
    fn release_runtime_class_binding_uses_the_resolved_class() {
        // A signed release pins the runtime class its measurements describe,
        // so the CAP_ALLOW_DEV_RUNTIME_CLASS hatch cannot coexist with an
        // enabled release: a mismatch between the expected class and the
        // effective (env-resolved) class must fail. Resolution happens in the
        // caller, which passes the resolved class in — the signature makes a
        // DEFAULT_RUNTIME_CLASS fallback impossible.
        validate_platform_release_runtime_class("kata-qemu-snp", "kata-qemu-snp").unwrap();
        assert!(
            validate_platform_release_runtime_class("kata-qemu-snp", "kata-qemu-coco-dev").is_err()
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
    fn edge_reconciliation_can_only_be_disabled_without_dispatch() {
        validate_edge_reconciliation_mode(false, false).unwrap();
        validate_edge_reconciliation_mode(true, false).unwrap();
        validate_edge_reconciliation_mode(false, true).unwrap();
        assert!(validate_edge_reconciliation_mode(true, true).is_err());
    }

    #[test]
    fn startup_convergence_blocks_dispatch_and_readiness_while_kbs_pending() {
        use futures::FutureExt as _;

        let events = std::cell::RefCell::new(Vec::new());
        let pending = run_startup_convergence(
            std::future::pending(),
            Some(async {
                events.borrow_mut().push("edge");
                Ok(())
            }),
            Some(|| events.borrow_mut().push("dispatch")),
            || events.borrow_mut().push("ready"),
        );
        assert!(
            pending.now_or_never().is_none(),
            "a still-running KBS reconcile must hold dispatch and readiness"
        );
        assert_eq!(*events.borrow(), Vec::<&'static str>::new());
    }

    #[test]
    fn startup_convergence_blocks_dispatch_and_readiness_while_edge_pending() {
        use futures::FutureExt as _;

        let events = std::cell::RefCell::new(Vec::new());
        let pending = run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                Ok(())
            },
            Some(std::future::pending()),
            Some(|| events.borrow_mut().push("dispatch")),
            || events.borrow_mut().push("ready"),
        );
        assert!(
            pending.now_or_never().is_none(),
            "a still-running edge reconcile must hold dispatch and readiness"
        );
        assert_eq!(
            *events.borrow(),
            vec!["kbs"],
            "dispatch/readiness must not run while the edge reconcile pends"
        );
    }

    #[test]
    fn startup_convergence_fails_before_dispatch_and_readiness_on_kbs_error() {
        use futures::FutureExt as _;

        let events = std::cell::RefCell::new(Vec::new());
        let _ = run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                anyhow::bail!("kbs fence lost")
            },
            Some(async {
                events.borrow_mut().push("edge");
                Ok(())
            }),
            Some(|| events.borrow_mut().push("dispatch")),
            || events.borrow_mut().push("ready"),
        )
        .now_or_never()
        .expect("a failed reconcile resolves immediately")
        .expect_err("a failed KBS reconcile must abort startup convergence");
        assert_eq!(
            *events.borrow(),
            vec!["kbs"],
            "edge/dispatch/readiness must not run after the KBS reconcile fails"
        );
    }

    #[test]
    fn startup_convergence_fails_before_dispatch_and_readiness_on_edge_error() {
        use futures::FutureExt as _;

        let events = std::cell::RefCell::new(Vec::new());
        let _ = run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                Ok(())
            },
            Some(async {
                events.borrow_mut().push("edge");
                anyhow::bail!("edge rollout timed out")
            }),
            Some(|| events.borrow_mut().push("dispatch")),
            || events.borrow_mut().push("ready"),
        )
        .now_or_never()
        .expect("a failed reconcile resolves immediately")
        .expect_err("a failed edge reconcile must abort startup convergence");
        assert_eq!(
            *events.borrow(),
            vec!["kbs", "edge"],
            "dispatch/readiness must not run after the edge reconcile fails"
        );
    }

    #[test]
    fn startup_convergence_dispatches_then_opens_readiness_once_converged() {
        use futures::FutureExt as _;

        let events = std::cell::RefCell::new(Vec::new());
        run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                Ok(())
            },
            Some(async {
                events.borrow_mut().push("edge");
                Ok(())
            }),
            Some(|| events.borrow_mut().push("dispatch")),
            || events.borrow_mut().push("ready"),
        )
        .now_or_never()
        .expect("converged reconciles resolve immediately")
        .expect("converged reconciles must not fail startup");
        assert_eq!(*events.borrow(), vec!["kbs", "edge", "dispatch", "ready"]);
    }

    #[test]
    fn startup_convergence_respects_disabled_edge_and_dispatch() {
        use futures::FutureExt as _;

        // Dispatch disabled (CAP_DEPLOYMENT_DISPATCH_ENABLED=false): startup
        // still converges and opens readiness without a dispatcher.
        let events = std::cell::RefCell::new(Vec::new());
        run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                Ok(())
            },
            Some(async {
                events.borrow_mut().push("edge");
                Ok(())
            }),
            None::<fn()>,
            || events.borrow_mut().push("ready"),
        )
        .now_or_never()
        .expect("converged reconciles resolve immediately")
        .expect("disabled dispatch must not fail startup");
        assert_eq!(*events.borrow(), vec!["kbs", "edge", "ready"]);

        // Edge disabled (CAP_DISABLE_EDGE_RECONCILIATION, only valid with
        // dispatch off — the pairing is proven by
        // edge_reconciliation_can_only_be_disabled_without_dispatch): no edge
        // reconcile runs at all.
        let events = std::cell::RefCell::new(Vec::new());
        run_startup_convergence(
            async {
                events.borrow_mut().push("kbs");
                Ok(())
            },
            None::<std::future::Ready<anyhow::Result<()>>>,
            None::<fn()>,
            || events.borrow_mut().push("ready"),
        )
        .now_or_never()
        .expect("converged reconciles resolve immediately")
        .expect("disabled edge must not fail startup");
        assert_eq!(*events.borrow(), vec!["kbs", "ready"]);
    }

    // A fresh process prevents other TLS tests from masking a missing install.
    #[test]
    fn tls_provider_bootstrap_smoke_child() {
        if std::env::var_os("CAP_TLS_BOOTSTRAP_SMOKE_CHILD").is_none() {
            return;
        }
        bootstrap_runtime_crypto_provider();
        let _ = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }

    #[test]
    fn tls_provider_bootstrap_installs_provider_in_a_fresh_process() {
        let status = std::process::Command::new(std::env::current_exe().expect("test binary path"))
            .arg("tests::tls_provider_bootstrap_smoke_child")
            .arg("--exact")
            .env("CAP_TLS_BOOTSTRAP_SMOKE_CHILD", "1")
            .status()
            .expect("failed to spawn TLS bootstrap smoke child");
        assert!(
            status.success(),
            "fresh-process TLS bootstrap failed: {status}"
        );
    }

    #[test]
    fn platform_release_accepts_policy_validated_coco_dev_runtime_class() {
        let runtime_class =
            enclava_engine::manifest::cc_init_data::resolve_runtime_class_with_env(false, |name| {
                match name {
                    enclava_engine::manifest::cc_init_data::RUNTIME_CLASS_ENV => {
                        Some("kata-qemu-coco-dev".to_string())
                    }
                    enclava_engine::manifest::cc_init_data::ALLOW_DEV_RUNTIME_CLASS_ENV => {
                        Some("true".to_string())
                    }
                    _ => None,
                }
            })
            .expect("explicit coco-dev policy permits the simulated runtime class");

        validate_platform_release_runtime_class("kata-qemu-coco-dev", &runtime_class).unwrap();
    }

    #[test]
    fn platform_release_runtime_class_mismatch_fails_closed() {
        let error = validate_platform_release_runtime_class(
            "kata-qemu-coco-dev",
            enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS,
        )
        .expect_err("a signed release cannot select a different runtime class");

        assert!(
            error
                .to_string()
                .contains("does not match API runtime class")
        );
    }

    #[test]
    fn platform_release_accepts_production_default_runtime_class() {
        let runtime_class =
            enclava_engine::manifest::cc_init_data::resolve_runtime_class_with_env(false, |_| None)
                .expect("production default runtime class");

        assert_eq!(
            runtime_class,
            enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS
        );
        validate_platform_release_runtime_class(
            enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS,
            &runtime_class,
        )
        .unwrap();
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
    fn trustee_http_client_is_https_only() {
        // Regression for cap#117: the trustee client carries
        // TRUSTEE_ATTESTATION_VERIFY_BEARER_TOKEN, so it must refuse to
        // send over cleartext http even in debug builds where the env
        // gate is relaxed.
        let client = build_trustee_http_client().expect("trustee client should build");

        let http_err = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(
                client
                    .get("http://kbs.example.test:8080/kbs/v0/attestation/verify")
                    .send(),
            )
            .expect_err("https_only client must refuse http:// requests");
        assert!(
            http_err.is_builder(),
            "expected a builder-stage rejection, got: {http_err}"
        );
    }

    #[test]
    fn management_mode_resolves_documented_values_and_rejects_typos() {
        assert_eq!(
            load_management_mode_with_env(|name| match name {
                "CAP_MANAGEMENT_MODE" => None,
                _ => None,
            })
            .unwrap(),
            CapManagementMode::Standalone
        );
        for value in [
            "standalone",
            "self_service",
            "paas_managed",
            "paas",
            "paas-managed",
        ] {
            let mode = load_management_mode_with_env(|name| match name {
                "CAP_MANAGEMENT_MODE" => Some(value.to_string()),
                _ => None,
            })
            .unwrap_or_else(|e| panic!("`{value}` must parse: {e}"));
            assert_eq!(mode.as_str(), {
                if value.starts_with("paas") {
                    "paas_managed"
                } else {
                    "standalone"
                }
            });
        }
        for invalid in ["managed", "PAAS_MANAGED", "paas managed"] {
            assert!(
                load_management_mode_with_env(|name| match name {
                    "CAP_MANAGEMENT_MODE" => Some(invalid.to_string()),
                    _ => None,
                })
                .is_err(),
                "`{invalid:?}` must be rejected instead of panicking at startup (issue #140)"
            );
        }
        // Whitespace-only and unset fall back to the documented default,
        // matching env_nonempty semantics (trim, empty == unset).
        for unset_like in [None, Some(""), Some("   ")] {
            assert_eq!(
                load_management_mode_with_env(|name| match name {
                    "CAP_MANAGEMENT_MODE" => unset_like.map(str::to_string),
                    _ => None,
                })
                .unwrap(),
                CapManagementMode::Standalone
            );
        }
    }
}
