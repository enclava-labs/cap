//! Cosign signature verification with per-app Fulcio identity policies.
//!
//! Verification model:
//! - Each app pins a `VerificationPolicy` (Fulcio URL/email identity, or a
//!   raw public key for advanced offline-signing users).
//! - The customer signs their own image — typically inside their own
//!   GitHub Actions runner via cosign keyless — and we verify the resulting
//!   signature against the app's pinned policy.
//! - Rekor inclusion is required: the trust root carries Rekor pubkeys, so
//!   `trusted_signature_layers` only returns layers whose Rekor bundle
//!   verifies. Signatures without Rekor evidence yield zero trusted layers
//!   and we reject.
//!
//! Trust root pinning:
//! - In production we pin to a TUF metadata snapshot bundled with the CAP
//!   release. Set `SIGSTORE_TUF_ROOT_PATH` to a trusted_root.json file
//!   shipped with the release artifact. Without that env var, the verifier
//!   falls back to the Sigstore Public Good Instance via TUF, which performs
//!   a network fetch — acceptable in dev, refused in production deployments
//!   by the surrounding ops policy.
//! - Refresh process: build a new CAP release with an updated bundled
//!   trusted_root.json fetched from the official Sigstore TUF repo, signed
//!   into the release artifact like any other dependency.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use futures::StreamExt as _;
use serde::Serialize;
use sigstore::cosign::CosignCapabilities;
use sigstore::cosign::verification_constraint::{
    CertSubjectEmailVerifier, CertSubjectUrlVerifier, PublicKeyVerifier, VerificationConstraintVec,
    cert_subject_email_verifier::StringVerifier,
};
use sigstore::cosign::{ClientBuilder, verify_constraints};
use sigstore::crypto::SigningScheme;
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::clients::EgressGuard;
use crate::registry::registry_base_url;

const MAX_SIGSTORE_MATERIAL_BYTES: usize = 196_608;
const MAX_PROVENANCE_MATERIAL_BYTES: usize = 311_296;

#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    #[error("cosign verification failed: {0}")]
    VerificationFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image is not signed: {0}")]
    NotSigned(String),
    #[error("signer policy is not configured for this app")]
    PolicyNotConfigured,
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("trust root error: {0}")]
    TrustRoot(String),
}

/// Per-app verification policy.
///
/// `FulcioUrlIdentity` matches GitHub Actions OIDC subjects, which are URL-
/// shaped (e.g. `https://github.com/<org>/<repo>/.github/workflows/...`).
/// `FulcioEmailIdentity` is for OIDC issuers using email subjects (Google,
/// generic OIDC). `PublicKey` is for advanced users who sign offline.
#[derive(Debug, Clone)]
pub enum VerificationPolicy {
    FulcioUrlIdentity {
        fulcio_subject_url: String,
        fulcio_issuer: String,
    },
    FulcioEmailIdentity {
        email: String,
        fulcio_issuer: String,
    },
    PublicKey {
        pem: String,
    },
}

/// Result of a successful verification, recorded for audit/deployment.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedSignature {
    pub digest: String,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub rekor_log_index: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PortableVerificationMaterial {
    pub sigstore: Vec<u8>,
    pub provenance_oci: Vec<u8>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

const COSIGN_REGISTRY_ALLOWED_HOSTS_ENV: &str = "COSIGN_REGISTRY_ALLOWED_HOSTS";

/// Hosts the operator has explicitly allowlisted to receive the platform
/// `COSIGN_*` registry credentials (issue #225). An unset or empty list
/// means no host is trusted, so the credentials are never attached.
pub fn cosign_registry_allowed_hosts_from_env() -> Vec<String> {
    env_nonempty(COSIGN_REGISTRY_ALLOWED_HOSTS_ENV)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default()
}

/// True when any platform `COSIGN_*` registry credential is configured.
pub fn cosign_registry_credentials_configured() -> bool {
    CosignRegistryCredentials::from_env().is_configured()
}

/// Canonical host form for exact-match allowlist comparison. `docker.io` and
/// `index.docker.io` are the same registry — OCI clients rewrite the former to
/// the latter at dial time (`resolve_registry`), so a `docker.io` allowlist
/// entry must describe the endpoint that actually receives the credentials.
fn canonical_registry_host(host: &str) -> &str {
    if host == "docker.io" {
        "index.docker.io"
    } else {
        host
    }
}

/// Exact or leading-wildcard host match against an allowlist pattern.
///
/// Patterns: `host[:port]` matches exactly (case-insensitive), `*.example.com`
/// matches `example.com` and any dot-separated subdomain of it, and the bare
/// pattern `*` is an explicit operator opt-in matching every host. A wildcard
/// never matches across a partial label (`*.example.com` does not match
/// `notexample.com`). The host must be the one the registry client actually
/// dials (`resolve_registry`), not a re-parse of the image reference.
fn host_matches_allowed_pattern(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if host == pattern || canonical_registry_host(&host) == canonical_registry_host(&pattern) {
        return true;
    }
    pattern.strip_prefix("*.").is_some_and(|base| {
        host == base
            || host
                .strip_suffix(&format!(".{base}"))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    })
}

/// Platform `COSIGN_*` registry credentials read once from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CosignRegistryCredentials {
    bearer_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

impl CosignRegistryCredentials {
    fn from_env() -> Self {
        Self {
            bearer_token: env_nonempty("COSIGN_REGISTRY_BEARER_TOKEN"),
            username: env_nonempty("COSIGN_REGISTRY_USERNAME"),
            password: env_nonempty("COSIGN_REGISTRY_PASSWORD"),
        }
    }

    #[cfg(test)]
    fn basic(username: &str, password: &str) -> Self {
        Self {
            bearer_token: None,
            username: Some(username.to_string()),
            password: Some(password.to_string()),
        }
    }

    fn is_configured(&self) -> bool {
        self.bearer_token.is_some() || (self.username.is_some() && self.password.is_some())
    }

    fn auth(&self) -> Option<Auth> {
        if let Some(token) = &self.bearer_token {
            return Some(Auth::Bearer(token.clone()));
        }
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            return Some(Auth::Basic(username.clone(), password.clone()));
        }
        None
    }
}

/// Pure decision core of the credential-forwarding gate: platform registry
/// credentials are only attached for allowlisted destination hosts.
fn registry_auth_with_allowlist(
    registry: &str,
    credentials: Option<&CosignRegistryCredentials>,
    allowed_hosts: &[String],
) -> Auth {
    // Platform registry credentials must never be forwarded to a host the
    // tenant picked (issue #225): image references — including digest-pinned
    // ones, which skip the registry allowlist — are attacker-controlled
    // input, so the COSIGN_* credentials are only attached when the operator
    // explicitly listed the destination host in COSIGN_REGISTRY_ALLOWED_HOSTS.
    // An unset/empty allowlist fails closed to anonymous access.
    if let Some(credentials) = credentials {
        let allow_http = env_flag("COSIGN_ALLOW_HTTP_REGISTRY");
        let scheme = if allow_http { "http" } else { "https" };
        let host_allowed = realm_host_allowed(
            &format!("{scheme}://{registry}/"),
            allowed_hosts,
            allow_http,
        );
        match (credentials.auth(), host_allowed) {
            (Some(auth), true) => return auth,
            (Some(_), false) => {
                tracing::warn!(
                    registry = %registry,
                    env = COSIGN_REGISTRY_ALLOWED_HOSTS_ENV,
                    "platform registry credentials not attached: registry host is not allowlisted"
                );
            }
            (None, _) => {}
        }
    }

    // Token-only GHCR authentication is valid for VERIFICATION — Basic auth
    // against ghcr.io with the conventional `oauth2` username. The
    // enclava-api startup gate (`deploy::tenant_image_pull_secret_startup_error`)
    // still requires both GHCR_USERNAME and GHCR_TOKEN: the tenant pull
    // secret needs both, and a half-rotated pair must never reach the startup
    // cleanup sweep (Devin review on #276). This fallback keeps the module
    // usable for verification-only embedders and tests; a running enclava-api
    // never sees token-only environment because the startup gate exits first.
    if registry == "ghcr.io"
        && let Some(token) = env_nonempty("GHCR_TOKEN")
    {
        let username = env_nonempty("GHCR_USERNAME").unwrap_or_else(|| "oauth2".to_string());
        return Auth::Basic(username, token);
    }

    Auth::Anonymous
}

fn registry_auth_from_env(registry: &str) -> Auth {
    let credentials = CosignRegistryCredentials::from_env();
    registry_auth_with_allowlist(
        registry,
        credentials.is_configured().then_some(&credentials),
        &cosign_registry_allowed_hosts_from_env(),
    )
}

/// A bare allowlist host authorizes the scheme's default port, not arbitrary
/// services on that host. Explicit :443 also matches implicit HTTPS port 443.
fn realm_host_allowed(realm: &str, allowed_hosts: &[String], allow_http: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(realm) else {
        return false;
    };
    if !(url.scheme() == "https" || (allow_http && url.scheme() == "http"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    allowed_hosts.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        let (pattern_host, pattern_port) = match pattern.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().ok()),
            None => (
                pattern.as_str(),
                Some(if url.scheme() == "https" { 443 } else { 80 }),
            ),
        };
        pattern_port == url.port_or_known_default()
            && host_matches_allowed_pattern(host, pattern_host)
    })
}

/// Raw Basic credentials are used ONLY here, never passed to OCI. In
/// oci-client 0.17, _auth returns immediately for RegistryAuth::Bearer. Later
/// requests therefore cannot replay our password to a changed /v2/ challenge.
/// This is not an advisory preflight. Token redirects are disabled, including
/// same-host redirects that could change ports or downgrade HTTPS. Both
/// requests still traverse the SSRF-guarded egress proxy.
async fn exchange_registry_basic_auth(
    proxy_url: Option<&str>,
    registry_base: &str,
    repository: &str,
    auth: Auth,
    allowed_hosts: &[String],
    allow_http: bool,
) -> Result<Auth, CosignError> {
    let Auth::Basic(username, password) = auth else {
        return Ok(auth);
    };
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(proxy) = proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    let client = builder.build()?;
    let response = client
        .get(format!("{}/v2/", registry_base.trim_end_matches('/')))
        .send()
        .await?;
    let challenge = enclava_common::registry::select_bearer_challenge(
        response
            .headers()
            .get_all(reqwest::header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
    .ok_or_else(|| {
        CosignError::VerificationFailed(
            "credentialed registry requires a Bearer challenge; unsafe OCI Basic fallback is disabled".into(),
        )
    })?;
    let realm = &challenge.realm;
    if !realm_host_allowed(realm, allowed_hosts, allow_http) {
        return Err(CosignError::VerificationFailed(
            "registry token realm rejected by credential host/port/HTTPS policy".into(),
        ));
    }
    let mut token_url = reqwest::Url::parse(realm)
        .map_err(|_| CosignError::VerificationFailed("invalid registry token realm".into()))?;
    // The realm is registry-controlled. Remove every preexisting scope and
    // service (including percent-encoded keys), then supply exactly our pull
    // scope and the selected challenge's service. Preserve unrelated routing
    // parameters required by token services.
    let retained: Vec<(String, String)> = token_url
        .query_pairs()
        .filter(|(key, _)| {
            !key.eq_ignore_ascii_case("scope") && !key.eq_ignore_ascii_case("service")
        })
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    token_url.set_query(None);
    {
        let mut query = token_url.query_pairs_mut();
        query.extend_pairs(retained);
        query.append_pair("scope", &format!("repository:{repository}:pull"));
        if let Some(service) = challenge.service {
            query.append_pair("service", &service);
        }
    }
    let response = client
        .get(token_url)
        .basic_auth(username, Some(password))
        .send()
        .await?;
    if !response.status().is_success() {
        // Server bodies might echo secrets: report status only.
        return Err(CosignError::VerificationFailed(format!(
            "registry token exchange failed with status {}",
            response.status()
        )));
    }
    let bytes = crate::clients::read_body_capped(response, 65_536)
        .await
        .map_err(|_| CosignError::VerificationFailed("invalid registry token response".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| CosignError::VerificationFailed("invalid registry token JSON".into()))?;
    let token = value
        .get("token")
        .or_else(|| value.get("access_token"))
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            CosignError::VerificationFailed("registry token response has no token".into())
        })?;
    Ok(Auth::Bearer(token.to_string()))
}

fn registry_realm_allowed_hosts(
    registry: &str,
    mut allowed_hosts: Vec<String>,
    legacy_ghcr_token_configured: bool,
) -> Vec<String> {
    // Legacy GHCR credentials are independently scoped to ghcr.io, including
    // GHCR's same-host token service; they do not require the COSIGN_* list.
    if registry == "ghcr.io" && legacy_ghcr_token_configured {
        allowed_hosts.push("ghcr.io".into());
    }
    allowed_hosts
}

async fn registry_auth_from_env_with_realm_policy(
    proxy_url: Option<&str>,
    registry_base: &str,
    image: &OciReference,
) -> Result<Auth, CosignError> {
    let auth = registry_auth_from_env(image.resolve_registry());
    let allowed_hosts = registry_realm_allowed_hosts(
        image.resolve_registry(),
        cosign_registry_allowed_hosts_from_env(),
        env_nonempty("GHCR_TOKEN").is_some(),
    );
    exchange_registry_basic_auth(
        proxy_url,
        registry_base,
        image.repository(),
        auth,
        &allowed_hosts,
        env_flag("COSIGN_ALLOW_HTTP_REGISTRY"),
    )
    .await
}

/// The OCI parser calls Hub index.docker.io, while the guarded public
/// distribution endpoint is registry-1.docker.io. Use the same mapping for
/// prechecks and token discovery regardless of the user's Hub spelling.
fn cosign_registry_base_url(registry: &str) -> Result<String, CosignError> {
    let registry = if registry == "index.docker.io" {
        "docker.io"
    } else {
        registry
    };
    let base = registry_base_url(registry)
        .map_err(|e| CosignError::VerificationFailed(format!("unsupported registry: {e}")))?;
    Ok(if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        base.replacen("https://", "http://", 1)
    } else {
        base
    })
}

/// Entry grammar for `COSIGN_REGISTRY_ALLOWED_HOSTS`: exactly `*`,
/// `host[:port]`, or `*.host[:port]` over DNS labels / IPv4. Anything else
/// (partial-label wildcards like `*ghcr.io`, repeated wildcards like
/// `**.host`, empty labels like `ghcr..io`, paths, out-of-range ports) can
/// never match a parsed registry name, so it is refused at startup: a typo'd
/// pattern must fail loudly instead of quietly withholding the platform
/// credentials from the host the operator meant to allow (same rationale as
/// the strict tenant pull-secret scope collector).
fn cosign_registry_host_pattern_error(pattern: &str) -> Option<&'static str> {
    if pattern == "*" {
        return None;
    }
    if pattern.is_empty() {
        return Some("entry is empty");
    }
    let host = match pattern.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            match port.parse::<u16>() {
                Ok(port) if port != 0 => host,
                _ => return Some("port must be in 1..=65535"),
            }
        }
        _ => pattern,
    };
    let base = host.strip_prefix("*.").unwrap_or(host);
    // OCI treats bare single-label prefixes as Docker Hub namespaces, not
    // registry endpoints; only localhost or an explicit port is addressable.
    if !base.contains('.') && base != "localhost" && !pattern.contains(':') {
        return Some("single-label registry hosts require an explicit port (except localhost)");
    }
    if base.is_empty() || base.starts_with('.') || base.ends_with('.') || base.contains("..") {
        return Some("host must be a DNS name or IPv4 address without empty labels");
    }
    if !base.split('.').all(|label| {
        !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Some("host must be a DNS name or IPv4 address (labels of letters, digits, '-')");
    }
    None
}

/// Codex review on #243, P2: only one of
/// `COSIGN_REGISTRY_USERNAME`/`COSIGN_REGISTRY_PASSWORD` being set attaches no
/// credential at all (`is_configured` stays false), so every private-registry
/// verification silently runs anonymously — fail fast at startup instead.
fn incomplete_basic_pair_error(username: Option<&str>, password: Option<&str>) -> Option<String> {
    (username.is_some() != password.is_some()).then(|| {
        "COSIGN_REGISTRY_USERNAME and COSIGN_REGISTRY_PASSWORD must be set together: an \
         incomplete pair attaches no registry credential, so every private-registry \
         verification would silently run anonymously"
            .to_string()
    })
}

/// Startup validation (issue #225): platform `COSIGN_*` registry credentials
/// without an explicit `COSIGN_REGISTRY_ALLOWED_HOSTS` scope are refused —
/// silently downgrading every registry to anonymous would break private-
/// registry verification in confusing ways, so misconfiguration must be loud.
pub fn cosign_registry_credentials_startup_error() -> Option<String> {
    let patterns = cosign_registry_allowed_hosts_from_env();
    if let Some(raw) = env_nonempty(COSIGN_REGISTRY_ALLOWED_HOSTS_ENV) {
        let invalid: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter_map(|pattern| {
                cosign_registry_host_pattern_error(pattern)
                    .map(|reason| format!("{pattern:?} ({reason})"))
            })
            .collect();
        if !invalid.is_empty() {
            return Some(format!(
                "COSIGN_REGISTRY_ALLOWED_HOSTS contains entries outside the allowed grammar \
                 `*`, `host[:port]`, or `*.host[:port]`: {}; such a pattern can never match a \
                 registry host, so startup is refused instead of silently withholding the \
                 platform registry credentials",
                invalid.join(", ")
            ));
        }
    }
    // Codex review on #243, P2: an incomplete basic pair attaches no
    // credential at all (every private-registry verification would silently
    // run anonymously), so it must surface as the fail-fast configuration
    // error this gate exists for — not as "no credential configured".
    if let Some(error) = incomplete_basic_pair_error(
        env_nonempty("COSIGN_REGISTRY_USERNAME").as_deref(),
        env_nonempty("COSIGN_REGISTRY_PASSWORD").as_deref(),
    ) {
        return Some(error);
    }
    if patterns.iter().any(|pattern| pattern == "*") {
        tracing::warn!(
            env = COSIGN_REGISTRY_ALLOWED_HOSTS_ENV,
            "allowlist contains bare `*`: platform registry credentials will be forwarded to \
             every registry host named by tenant-supplied image references"
        );
    }
    if !cosign_registry_credentials_configured() {
        return None;
    }
    if patterns.is_empty() {
        return Some(
            "COSIGN_REGISTRY_BEARER_TOKEN or COSIGN_REGISTRY_USERNAME/COSIGN_REGISTRY_PASSWORD \
             is set but COSIGN_REGISTRY_ALLOWED_HOSTS is unset or empty; platform registry \
             credentials are never forwarded to tenant-chosen registry hosts (issue #225), so \
             set COSIGN_REGISTRY_ALLOWED_HOSTS to the hosts that should receive them"
                .to_string(),
        );
    }
    None
}

fn looks_like_not_signed_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("manifest unknown")
        || lower.contains("name unknown")
        || lower.contains("not found")
        || lower.contains("404")
}

/// Convert a digest like "sha256:abcdef..." to the cosign tag format "sha256-abcdef..."
fn digest_to_cosign_tag(digest: &str, suffix: &str) -> String {
    let tag = digest.replace(':', "-");
    format!("{tag}.{suffix}")
}

/// Parse an image reference into (registry, repository) components.
/// Public for the deploy route's digest-pinned pre-flight egress check
/// (issue #224); the parsing itself performs no I/O.
pub fn parse_image_parts(image_ref: &str) -> Result<(String, String), CosignError> {
    let base = image_ref.split('@').next().unwrap_or(image_ref);
    let base = match (base.rfind('/'), base.rfind(':')) {
        (slash, Some(colon)) if slash.is_none_or(|slash| colon > slash) => &base[..colon],
        _ => base,
    };

    let parts: Vec<&str> = base.splitn(3, '/').collect();
    match parts.len() {
        1 => Ok(("docker.io".to_string(), format!("library/{}", parts[0]))),
        2 => {
            if parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost" {
                Ok((parts[0].to_string(), parts[1].to_string()))
            } else {
                Ok((
                    "docker.io".to_string(),
                    format!("{}/{}", parts[0], parts[1]),
                ))
            }
        }
        3 => Ok((parts[0].to_string(), format!("{}/{}", parts[1], parts[2]))),
        _ => Err(CosignError::VerificationFailed(format!(
            "cannot parse image reference: {image_ref}"
        ))),
    }
}

/// Build a sigstore trust root, preferring a bundled TUF snapshot when
/// `SIGSTORE_TUF_ROOT_PATH` is set.
async fn load_trust_root() -> Result<Arc<SigstoreTrustRoot>, CosignError> {
    // Note: an EMPTY SIGSTORE_TUF_ROOT_PATH fails closed below (read error),
    // which is deliberate — do not "helpfully" treat empty as unset.
    if let Ok(path) = std::env::var("SIGSTORE_TUF_ROOT_PATH") {
        let data = std::fs::read(&path).map_err(|e| {
            CosignError::TrustRoot(format!("failed to read SIGSTORE_TUF_ROOT_PATH {path}: {e}"))
        })?;
        let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(&data).map_err(|e| {
            CosignError::TrustRoot(format!("invalid bundled trusted_root.json: {e}"))
        })?;
        return Ok(Arc::new(root));
    }

    // Release builds must not bootstrap sigstore trust from the network at
    // runtime: a MITM'd first TUF fetch would anchor all subsequent cosign
    // verification (issue #140). Production deployments ship a pinned
    // trusted_root.json and set SIGSTORE_TUF_ROOT_PATH; the network fallback
    // remains available for debug/dev builds only. Both signals are checked:
    // debug_assertions (off in standard release profiles) and the prod-strict
    // feature (the explicit release-hardening contract used by release image
    // builds), so a custom profile with debug assertions cannot silently
    // re-enable the fallback in a production binary.
    if cfg!(any(not(debug_assertions), feature = "prod-strict",)) {
        return Err(CosignError::TrustRoot(
            "SIGSTORE_TUF_ROOT_PATH is not set; release builds must pin a bundled \
             trusted_root.json instead of fetching the sigstore TUF root from the network"
                .to_string(),
        ));
    }

    let root = SigstoreTrustRoot::new(None)
        .await
        .map_err(|e| CosignError::TrustRoot(format!("sigstore TUF fetch failed: {e}")))?;
    Ok(Arc::new(root))
}

fn build_constraints(
    policy: &VerificationPolicy,
) -> Result<VerificationConstraintVec, CosignError> {
    let constraints: VerificationConstraintVec = match policy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url,
            fulcio_issuer,
        } => {
            if fulcio_subject_url.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio subject and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectUrlVerifier {
                url: fulcio_subject_url.clone(),
                issuer: fulcio_issuer.clone(),
            })]
        }
        VerificationPolicy::FulcioEmailIdentity {
            email,
            fulcio_issuer,
        } => {
            if email.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio email and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectEmailVerifier {
                email: StringVerifier::ExactMatch(email.clone()),
                issuer: Some(StringVerifier::ExactMatch(fulcio_issuer.clone())),
            })]
        }
        VerificationPolicy::PublicKey { pem } => {
            let verifier = PublicKeyVerifier::new(pem.as_bytes(), &SigningScheme::default())
                .map_err(|e| CosignError::InvalidPolicy(format!("invalid public key PEM: {e}")))?;
            vec![Box::new(verifier)]
        }
    };
    Ok(constraints)
}

/// Verify that a cosign signature exists for the given image digest and
/// satisfies the app's pinned verification policy.
///
/// `egress` is the pre-flight destination guard (issue #224): the sigstore
/// client builds its own reqwest transport internally (no resolver or
/// redirect-policy injection point), so the registry host — which for a
/// tenant-supplied, digest-pinned reference is attacker-chosen — is checked
/// against the allowlist, the literal-IP blocklist, and DNS before the
/// unguarded transport dials anything.
pub async fn verify_image(
    egress: &EgressGuard,
    image_ref: &str,
    image_digest: &str,
    policy: &VerificationPolicy,
) -> Result<VerifiedSignature, CosignError> {
    // Guard the sigstore client's egress before anything else (issue #224):
    // the sigstore transport is unguarded, so the registry host — which for
    // a tenant-supplied, digest-pinned reference is attacker-chosen — is
    // checked against the allowlist, the literal-IP blocklist, and DNS
    // before any network I/O (including the dev TUF fallback below).
    let (registry, _) = parse_image_parts(image_ref)?;
    let base_url = cosign_registry_base_url(&registry)?;
    let registry_url = reqwest::Url::parse(&base_url)
        .map_err(|e| CosignError::VerificationFailed(format!("invalid registry URL: {e}")))?;
    egress
        .check_cosign_registry_url(&registry_url, env_flag("COSIGN_ALLOW_HTTP_REGISTRY"))
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("registry destination rejected: {e}"))
        })?;

    let trust_root = load_trust_root().await?;

    let image: OciReference = image_ref
        .parse()
        .map_err(|e| CosignError::VerificationFailed(format!("invalid image reference: {e}")))?;

    let mut oci_client_config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        oci_client_config.protocol = ClientProtocol::Http;
    }
    // Route the sigstore/oci transports through the loopback egress proxy
    // (cap#241 review): those stacks build their own reqwest clients with
    // their own resolvers and the default follow-redirect policy, so a
    // pre-flight check alone leaves a DNS-rebinding window and unvalidated
    // redirect/token-realm destinations. Through the proxy, every dialed
    // destination — initial host, each redirect hop, each bearer realm —
    // is resolved and blocklist-checked by the proxy itself, and the proxy
    // dials the validated answers (no second resolution).
    let proxy_url = egress
        .proxy
        .url()
        .map_err(|e| CosignError::VerificationFailed(format!("egress proxy unavailable: {e}")))?;
    let realm_policy_proxy = proxy_url.clone();
    oci_client_config.https_proxy = Some(proxy_url.clone());
    oci_client_config.http_proxy = Some(proxy_url.clone());

    let mut cosign_client = ClientBuilder::default()
        .with_oci_client_config(oci_client_config)
        .with_trust_repository(trust_root.as_ref())
        .map_err(|e| CosignError::TrustRoot(format!("trust repository setup failed: {e}")))?
        .build()
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to initialize sigstore client: {e}"))
        })?;

    // Gate the credentials on the host the client will actually dial
    // (`resolve_registry` — the same value sigstore's OciReference uses to
    // connect), never on `parse_image_parts`' host: the two parsers disagree
    // on single-label three-component references (`registry/foo/bar` is
    // Docker Hub `registry/foo/bar` to the OCI parser but host `registry` to
    // the custom parser), and the allowlist must describe the dialed host or
    // a tenant-chosen ref still routes the platform password somewhere the
    // operator never allowlisted (review finding).
    let auth = registry_auth_from_env_with_realm_policy(
        Some(realm_policy_proxy.as_str()),
        &base_url,
        &image,
    )
    .await?;
    let (_, source_image_digest) = cosign_client
        .triangulate(&image, &auth)
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to triangulate signature image: {e}"))
        })?;

    if source_image_digest != image_digest {
        return Err(CosignError::VerificationFailed(format!(
            "image digest mismatch: resolved {source_image_digest}, expected {image_digest}"
        )));
    }

    let signature_lookup_image = signature_lookup_source_image(&image, image_digest);
    let trusted_layers = cosign_client
        .trusted_signature_layers(&auth, &signature_lookup_image)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if looks_like_not_signed_error(&msg) {
                CosignError::NotSigned(format!("no cosign signature found for {image_digest}"))
            } else {
                CosignError::VerificationFailed(format!(
                    "failed to fetch/verify signature layers: {msg}"
                ))
            }
        })?;

    if trusted_layers.is_empty() {
        return Err(CosignError::NotSigned(format!(
            "no Rekor-attested signature layers for {image_digest}"
        )));
    }

    let constraints = build_constraints(policy)?;
    verify_constraints(&trusted_layers, constraints.iter()).map_err(|e| {
        CosignError::VerificationFailed(format!(
            "signature did not satisfy app's verification policy: {e}"
        ))
    })?;

    let (signer_subject, signer_issuer, rekor_log_index) =
        extract_signer_metadata(&trusted_layers, policy);

    Ok(VerifiedSignature {
        digest: image_digest.to_string(),
        signer_subject,
        signer_issuer,
        verified_at: Utc::now(),
        rekor_log_index,
    })
}

fn signature_lookup_source_image(image: &OciReference, image_digest: &str) -> OciReference {
    OciReference::with_digest(
        image.registry().to_string(),
        image.repository().to_string(),
        image_digest.to_string(),
    )
}

fn extract_signer_metadata(
    layers: &[sigstore::cosign::SignatureLayer],
    policy: &VerificationPolicy,
) -> (Option<String>, Option<String>, Option<i64>) {
    use sigstore::cosign::signature_layers::CertificateSubject;

    let layer = layers.iter().find(|l| l.certificate_signature.is_some());
    let mut subject: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut rekor_index: Option<i64> = None;

    if let Some(layer) = layer
        && let Some(cert) = &layer.certificate_signature
    {
        subject = match &cert.subject {
            CertificateSubject::Email(e) => Some(e.clone()),
            CertificateSubject::Uri(u) => Some(u.clone()),
        };
        issuer = cert.issuer.clone();
    }

    if let Some(layer) = layers.iter().find(|l| l.bundle.is_some())
        && let Some(bundle) = &layer.bundle
    {
        rekor_index = match bundle {
            sigstore::cosign::bundle_content::BundleContent::RekorBundle(bundle) => {
                Some(bundle.payload.log_index)
            }
            sigstore::cosign::bundle_content::BundleContent::SigstoreBundle(entry) => {
                Some(entry.log_index)
            }
        };
    }

    if subject.is_none() {
        match policy {
            VerificationPolicy::FulcioUrlIdentity {
                fulcio_subject_url,
                fulcio_issuer,
            } => {
                subject = Some(fulcio_subject_url.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::FulcioEmailIdentity {
                email,
                fulcio_issuer,
            } => {
                subject = Some(email.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::PublicKey { .. } => {}
        }
    }

    (subject, issuer, rekor_index)
}

/// Fetch provenance attestation and SBOM from OCI registry attestation tags.
///
/// `body_limit` caps how many manifest bytes a registry response may carry
/// before the read is aborted (see `clients::read_body_capped`); callers
/// should pass the outbound client's `ClientConfig::body_limit_bytes`.
///
/// `egress` pre-checks the registry host (issue #224): the caller's client
/// is the guarded `state.http_client` (resolver-backed), but reqwest never
/// consults a custom resolver for literal-IP hosts, so a literal registry
/// host must be rejected explicitly before the first request.
pub async fn fetch_attestations(
    egress: &EgressGuard,
    client: &reqwest::Client,
    image_ref: &str,
    digest: &str,
    body_limit: u64,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>), CosignError> {
    let (registry, repository) = parse_image_parts(image_ref)?;
    let base_url = registry_base_url(&registry)
        .map_err(|e| CosignError::VerificationFailed(format!("unsupported registry: {e}")))?;
    let registry_url = reqwest::Url::parse(&base_url)
        .map_err(|e| CosignError::VerificationFailed(format!("invalid registry URL: {e}")))?;
    egress
        .check_registry_url(&registry_url)
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("registry destination rejected: {e}"))
        })?;

    // Attestation manifests are provenance material: bound the read by the
    // same cap the portable-material checks enforce, so a malicious registry
    // cannot force multi-megabyte JSON (and serde_json Value amplification
    // beyond it) past this fetch even when the generic outbound limit is
    // higher.
    let body_limit = body_limit.min(MAX_PROVENANCE_MATERIAL_BYTES as u64);
    let provenance =
        fetch_attestation_tag(client, &base_url, &repository, digest, "att", body_limit).await?;
    let sbom =
        fetch_attestation_tag(client, &base_url, &repository, digest, "sbom", body_limit).await?;

    Ok((provenance, sbom))
}

/// Preserve the exact OCI manifests and signed layers needed for offline replay.
///
/// `egress` guards the oci-client transport the same way `verify_image`
/// guards the sigstore one (issue #224): `oci_client::client::Client`
/// builds its own reqwest stack with the default (follow) redirect policy
/// and no custom resolver, so the tenant-chosen registry host is validated
/// before any manifest, blob, or referrers request is issued.
pub async fn fetch_portable_verification_material(
    egress: &EgressGuard,
    image_ref: &str,
    image_digest: &str,
) -> Result<PortableVerificationMaterial, CosignError> {
    use oci_client::client::{Client, ClientConfig};
    use oci_client::secrets::RegistryAuth;

    const MANIFEST_TYPES: &[&str] = &[
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    // Parse with the same OCI reference grammar the client dials with (not
    // `parse_image_parts`): the two disagree on single-label three-component
    // references, and this path must fetch — and authenticate to — exactly
    // the host/repository `verify_image` verified (review finding).
    let image: OciReference = image_ref
        .parse()
        .map_err(|e| CosignError::VerificationFailed(format!("invalid image reference: {e}")))?;
    let registry = image.resolve_registry().to_string();
    let repository = image.repository().to_string();
    let base_url = cosign_registry_base_url(&registry)?;
    let registry_url = reqwest::Url::parse(&base_url)
        .map_err(|e| CosignError::VerificationFailed(format!("invalid registry URL: {e}")))?;
    egress
        .check_cosign_registry_url(&registry_url, env_flag("COSIGN_ALLOW_HTTP_REGISTRY"))
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("registry destination rejected: {e}"))
        })?;
    // Resolve credentials only after the egress proxy URL is known: the
    // guarded Basic-to-Bearer exchange uses that proxy too.
    let mut config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        config.protocol = oci_client::client::ClientProtocol::Http;
    }
    // Same proxy routing as `verify_image`: bind the guarded resolution to
    // the actual connection and re-validate every redirect/token-realm
    // destination the oci-client transport follows (cap#241 review).
    let proxy_url = egress
        .proxy
        .url()
        .map_err(|e| CosignError::VerificationFailed(format!("egress proxy unavailable: {e}")))?;
    let realm_policy_proxy = proxy_url.clone();
    config.https_proxy = Some(proxy_url.clone());
    config.http_proxy = Some(proxy_url);
    let client = Client::try_from(config)
        .map_err(|e| CosignError::VerificationFailed(format!("OCI client setup failed: {e}")))?;
    let auth: RegistryAuth = (&registry_auth_from_env_with_realm_policy(
        Some(realm_policy_proxy.as_str()),
        &base_url,
        &image,
    )
    .await?)
        .into();
    let source = oci_client::Reference::with_digest(
        registry.clone(),
        repository.clone(),
        image_digest.to_string(),
    );
    let signature = oci_client::Reference::with_tag(
        registry.clone(),
        repository.clone(),
        digest_to_cosign_tag(image_digest, "sig"),
    );

    let (source_manifest, source_resolved) = client
        .pull_manifest_raw(&source, &auth, MANIFEST_TYPES)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    if source_resolved != image_digest {
        return Err(CosignError::VerificationFailed(
            "source manifest digest mismatch".into(),
        ));
    }
    let signature_objects =
        pull_signature_objects(&client, &source, &signature, &auth, MANIFEST_TYPES).await?;
    let provenance_objects = pull_provenance_objects(
        &client,
        &source_manifest,
        image_digest,
        &registry,
        &repository,
        &auth,
        MANIFEST_TYPES,
    )
    .await?;

    let mut sigstore_records = vec![
        ("purpose", b"enclava-sigstore-material-v1".as_slice()),
        ("image_digest", image_digest.as_bytes()),
    ];
    for (manifest, blobs) in &signature_objects {
        sigstore_records.push(("signature_manifest", manifest.as_slice()));
        sigstore_records.extend(blobs.iter().map(|blob| ("signature_blob", blob.as_slice())));
    }
    let sigstore = enclava_common::canonical::ce_v1_bytes(&sigstore_records);

    let mut provenance_records = vec![
        ("purpose", b"enclava-provenance-oci-material-v1".as_slice()),
        ("image_digest", image_digest.as_bytes()),
        ("image_manifest", source_manifest.as_ref()),
    ];
    for (manifest, blobs) in &provenance_objects {
        provenance_records.push(("provenance_manifest", manifest.as_slice()));
        provenance_records.extend(
            blobs
                .iter()
                .map(|blob| ("provenance_blob", blob.as_slice())),
        );
    }
    let provenance_oci = enclava_common::canonical::ce_v1_bytes(&provenance_records);

    if sigstore.len() > MAX_SIGSTORE_MATERIAL_BYTES
        || provenance_oci.len() > MAX_PROVENANCE_MATERIAL_BYTES
    {
        return Err(CosignError::VerificationFailed(
            "portable verification material exceeds v1 limits".into(),
        ));
    }
    Ok(PortableVerificationMaterial {
        sigstore,
        provenance_oci,
    })
}

async fn pull_signature_objects(
    client: &oci_client::client::Client,
    source: &oci_client::Reference,
    legacy_signature: &oci_client::Reference,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
) -> Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>, CosignError> {
    if let Ok(object) = pull_oci_object(
        client,
        legacy_signature,
        auth,
        accepted_media_types,
        MAX_SIGSTORE_MATERIAL_BYTES,
    )
    .await
        && object.1.iter().any(|blob| is_portable_signature_blob(blob))
    {
        return Ok(vec![object]);
    }
    let referrers = client
        .pull_referrers(source, None)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    let mut objects = Vec::new();
    for descriptor in referrers.manifests {
        let reference = oci_client::Reference::with_digest(
            source.resolve_registry().to_string(),
            source.repository().to_string(),
            descriptor.digest,
        );
        let Ok(object) = pull_oci_object(
            client,
            &reference,
            auth,
            accepted_media_types,
            MAX_SIGSTORE_MATERIAL_BYTES,
        )
        .await
        else {
            continue;
        };
        let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&object.0) else {
            continue;
        };
        if manifest
            .pointer("/annotations/dev.sigstore.bundle.predicateType")
            .and_then(serde_json::Value::as_str)
            == Some("https://sigstore.dev/cosign/sign/v1")
            && object.1.iter().any(|blob| is_portable_signature_blob(blob))
        {
            if objects.iter().map(oci_object_size).sum::<usize>() + oci_object_size(&object)
                > MAX_SIGSTORE_MATERIAL_BYTES
            {
                return Err(portable_material_too_large());
            }
            objects.push(object);
        }
    }
    if objects.is_empty() {
        return Err(CosignError::NotSigned(
            "no portable Sigstore signature object found".into(),
        ));
    }
    Ok(objects)
}

fn is_portable_signature_blob(blob: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(blob).is_ok_and(|bundle| {
        bundle.get("dsseEnvelope").is_some()
            && bundle
                .pointer("/verificationMaterial/certificate/rawBytes")
                .is_some()
            && bundle
                .pointer("/verificationMaterial/tlogEntries")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|entries| !entries.is_empty())
    })
}

async fn pull_provenance_objects(
    client: &oci_client::client::Client,
    source_manifest: &[u8],
    _image_digest: &str,
    registry: &str,
    repository: &str,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
) -> Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>, CosignError> {
    use oci_client::manifest::OciManifest;

    let source: OciManifest = serde_json::from_slice(source_manifest).map_err(|error| {
        CosignError::VerificationFailed(format!("invalid source OCI manifest: {error}"))
    })?;
    let references = match source {
        OciManifest::ImageIndex(index) => index
            .manifests
            .into_iter()
            .filter(|descriptor| {
                descriptor
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get("vnd.docker.reference.type"))
                    .is_some_and(|kind| kind == "attestation-manifest")
            })
            .map(|descriptor| {
                oci_client::Reference::with_digest(
                    registry.to_string(),
                    repository.to_string(),
                    descriptor.digest,
                )
            })
            .collect::<Vec<_>>(),
        // A single-image manifest cannot bind an external digest-derived .att
        // tag. A registry (or an attacker with tag-write access) may replace
        // it without changing the already signed image digest. Until signed
        // single-image attestations are verified against the app's policy,
        // never collect such bytes as portable provenance evidence.
        OciManifest::Image(_) => {
            return Err(CosignError::VerificationFailed(
                "single-image provenance tag is not signed or bound to the source manifest".into(),
            ));
        }
    };
    if references.is_empty() {
        return Err(CosignError::VerificationFailed(
            "source index has no bound provenance manifests".into(),
        ));
    }
    let mut objects = Vec::with_capacity(references.len());
    for reference in references {
        let object = pull_oci_object(
            client,
            &reference,
            auth,
            accepted_media_types,
            MAX_PROVENANCE_MATERIAL_BYTES,
        )
        .await?;
        if objects.iter().map(oci_object_size).sum::<usize>() + oci_object_size(&object)
            > MAX_PROVENANCE_MATERIAL_BYTES
        {
            return Err(portable_material_too_large());
        }
        objects.push(object);
    }
    Ok(objects)
}

async fn pull_oci_object(
    client: &oci_client::client::Client,
    reference: &oci_client::Reference,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
    maximum_bytes: usize,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), CosignError> {
    use oci_client::manifest::OciManifest;

    let (raw, _) = client
        .pull_manifest_raw(reference, auth, accepted_media_types)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    let manifest: OciManifest = serde_json::from_slice(&raw).map_err(|error| {
        CosignError::VerificationFailed(format!("invalid OCI manifest: {error}"))
    })?;
    let OciManifest::Image(manifest) = manifest else {
        return Err(CosignError::VerificationFailed(
            "verification object is not an OCI image manifest".into(),
        ));
    };
    let mut total = raw.len();
    let mut blobs = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let declared_size =
            usize::try_from(layer.size).map_err(|_| portable_material_too_large())?;
        if total.saturating_add(declared_size) > maximum_bytes {
            return Err(portable_material_too_large());
        }
        let mut bytes = Vec::new();
        let mut stream = client
            .pull_blob_stream(reference, layer)
            .await
            .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
            extend_bounded(&mut bytes, &chunk, total, maximum_bytes)?;
        }
        total += bytes.len();
        blobs.push(bytes);
    }
    Ok((raw.to_vec(), blobs))
}

fn oci_object_size((manifest, blobs): &(Vec<u8>, Vec<Vec<u8>>)) -> usize {
    manifest.len() + blobs.iter().map(Vec::len).sum::<usize>()
}

fn portable_material_too_large() -> CosignError {
    CosignError::VerificationFailed("portable verification material exceeds v1 limits".into())
}

fn extend_bounded(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    previous_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), CosignError> {
    if previous_bytes
        .saturating_add(bytes.len())
        .saturating_add(chunk.len())
        > maximum_bytes
    {
        return Err(portable_material_too_large());
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

async fn fetch_attestation_tag(
    client: &reqwest::Client,
    base_url: &str,
    repository: &str,
    digest: &str,
    suffix: &str,
    body_limit: u64,
) -> Result<Option<serde_json::Value>, CosignError> {
    let tag = digest_to_cosign_tag(digest, suffix);
    let url = format!("{base_url}/v2/{repository}/manifests/{tag}");

    let response = client
        .get(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        tracing::warn!(
            "registry returned {} when fetching {}.{} attestation",
            response.status(),
            digest,
            suffix
        );
        return Ok(None);
    }

    // Cap the manifest read: a malicious registry must not be able to
    // exhaust API memory before the provenance size checks apply.
    let Some(body) = read_attestation_body(response, body_limit, suffix).await? else {
        return Ok(None);
    };
    match serde_json::from_str(&body) {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            tracing::warn!("failed to parse {} attestation as JSON: {}", suffix, e);
            Ok(None)
        }
    }
}

/// Capped read of an attestation manifest body. Returns `Ok(None)`
/// (treated as "attestation absent") when the body exceeds `body_limit`
/// or is not valid UTF-8; transport errors propagate as `Err`.
async fn read_attestation_body(
    response: reqwest::Response,
    body_limit: u64,
    suffix: &str,
) -> Result<Option<String>, CosignError> {
    match crate::clients::read_body_capped(response, body_limit).await {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) => Ok(Some(text.to_string())),
            Err(e) => {
                tracing::warn!("failed to decode {} attestation as UTF-8: {}", suffix, e);
                Ok(None)
            }
        },
        Err(crate::clients::ClientError::BodyTooLarge { limit }) => {
            tracing::warn!(
                "{} attestation manifest exceeded {} byte body limit",
                suffix,
                limit
            );
            // Degrade to "absent": an oversized or undecodable manifest is
            // not usable evidence, and the fetch path treats missing
            // attestations as non-fatal.
            Ok(None)
        }
        Err(crate::clients::ClientError::Http(e)) => Err(CosignError::Http(e)),
        Err(e) => Err(CosignError::VerificationFailed(e.to_string())),
    }
}

/// Per-sidecar pinned signer identity (Phase 11).
#[derive(Debug, Clone)]
pub struct SidecarPin {
    pub label: &'static str,
    pub image_ref: String,
    pub image_digest: String,
    pub policy: VerificationPolicy,
}

/// Verified sidecar digests, returned in fixed sidecar-name order so they can
/// be bound into `cc_init_data.sidecar_digests` and the KBS Rego.
#[derive(Debug, Clone)]
pub struct VerifiedSidecars {
    pub attestation_proxy: String,
    pub caddy_ingress: String,
}

/// Verify the platform-controlled sidecar images at API startup. Refuses to
/// return Ok unless every configured sidecar has a Rekor-attested cosign
/// signature satisfying the pinned signer identity.
///
/// `SKIP_COSIGN_VERIFY` (debug builds only — release rejects via env_gates)
/// short-circuits this check. Production must always verify.
pub async fn verify_sidecars_at_startup(
    egress: &EgressGuard,
    pins: &[SidecarPin],
) -> Result<VerifiedSidecars, CosignError> {
    if std::env::var("SKIP_COSIGN_VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
    {
        tracing::warn!("SKIP_COSIGN_VERIFY: sidecar startup verification bypassed (debug only)");
        let mut ap = String::new();
        let mut ca = String::new();
        for p in pins {
            match p.label {
                "attestation_proxy" => ap = p.image_digest.clone(),
                "caddy_ingress" => ca = p.image_digest.clone(),
                _ => {}
            }
        }
        return Ok(VerifiedSidecars {
            attestation_proxy: ap,
            caddy_ingress: ca,
        });
    }

    let mut ap = String::new();
    let mut ca = String::new();
    for pin in pins {
        let v = verify_image(egress, &pin.image_ref, &pin.image_digest, &pin.policy).await?;
        tracing::info!(
            sidecar = %pin.label,
            digest = %v.digest,
            subject = ?v.signer_subject,
            issuer = ?v.signer_issuer,
            "sidecar cosign verified at startup"
        );
        match pin.label {
            "attestation_proxy" => ap = v.digest,
            "caddy_ingress" => ca = v.digest,
            _ => {}
        }
    }
    if ap.is_empty() || ca.is_empty() {
        return Err(CosignError::PolicyNotConfigured);
    }
    Ok(VerifiedSidecars {
        attestation_proxy: ap,
        caddy_ingress: ca,
    })
}

/// Build sidecar pins from environment variables. Returns `None` if neither
/// sidecar image is configured (developer mode); returns an error if the
/// signer-identity vars are missing for a configured image.
pub fn sidecar_pins_from_env() -> Result<Option<Vec<SidecarPin>>, CosignError> {
    let proxy_image = std::env::var("ATTESTATION_PROXY_IMAGE").ok();
    let caddy_image = std::env::var("CADDY_INGRESS_IMAGE").ok();
    sidecar_pins_from_images(proxy_image.as_deref(), caddy_image.as_deref())
}

/// Build sidecar pins from resolved image references while still reading the
/// signer policy from environment. This lets the API use signed platform
/// release image anchors instead of trusting image refs only from env.
pub fn sidecar_pins_from_images(
    proxy_image: Option<&str>,
    caddy_image: Option<&str>,
) -> Result<Option<Vec<SidecarPin>>, CosignError> {
    if proxy_image.is_none() && caddy_image.is_none() {
        return Ok(None);
    }

    let mut pins = Vec::new();
    if let Some(image) = proxy_image {
        pins.push(build_pin_from_env(
            "attestation_proxy",
            image,
            "ATTESTATION_PROXY_SIGNER_PUBLIC_KEY_BASE64",
            "ATTESTATION_PROXY_SIGNER_PUBLIC_KEY_PEM",
            "ATTESTATION_PROXY_SIGNER_SUBJECT",
            "ATTESTATION_PROXY_SIGNER_ISSUER",
        )?);
    }
    if let Some(image) = caddy_image {
        pins.push(build_pin_from_env(
            "caddy_ingress",
            image,
            "CADDY_INGRESS_SIGNER_PUBLIC_KEY_BASE64",
            "CADDY_INGRESS_SIGNER_PUBLIC_KEY_PEM",
            "CADDY_INGRESS_SIGNER_SUBJECT",
            "CADDY_INGRESS_SIGNER_ISSUER",
        )?);
    }
    Ok(Some(pins))
}

fn build_pin_from_env(
    label: &'static str,
    image_ref: &str,
    public_key_b64_var: &str,
    public_key_pem_var: &str,
    subject_var: &str,
    issuer_var: &str,
) -> Result<SidecarPin, CosignError> {
    let digest = image_ref
        .split('@')
        .nth(1)
        .ok_or_else(|| {
            CosignError::InvalidPolicy(format!("{label} image is not digest-pinned: {image_ref}"))
        })?
        .to_string();

    if let Some(pem) = read_public_key_policy(public_key_b64_var, public_key_pem_var)? {
        return Ok(SidecarPin {
            label,
            image_ref: image_ref.to_string(),
            image_digest: digest,
            policy: VerificationPolicy::PublicKey { pem },
        });
    }

    let subject = std::env::var(subject_var).map_err(|_| {
        CosignError::InvalidPolicy(format!("missing {subject_var} for sidecar {label}"))
    })?;
    let issuer = std::env::var(issuer_var).map_err(|_| {
        CosignError::InvalidPolicy(format!("missing {issuer_var} for sidecar {label}"))
    })?;

    let policy = if subject.starts_with("https://") {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: subject,
            fulcio_issuer: issuer,
        }
    } else {
        VerificationPolicy::FulcioEmailIdentity {
            email: subject,
            fulcio_issuer: issuer,
        }
    };
    Ok(SidecarPin {
        label,
        image_ref: image_ref.to_string(),
        image_digest: digest,
        policy,
    })
}

fn read_public_key_policy(
    public_key_b64_var: &str,
    public_key_pem_var: &str,
) -> Result<Option<String>, CosignError> {
    for name in [
        public_key_b64_var,
        "PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64",
    ] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            let decoded = B64
                .decode(value.trim())
                .map_err(|e| CosignError::InvalidPolicy(format!("invalid {name}: {e}")))?;
            let pem = String::from_utf8(decoded)
                .map_err(|e| CosignError::InvalidPolicy(format!("{name} is not UTF-8: {e}")))?;
            return Ok(Some(pem));
        }
    }

    for name in [public_key_pem_var, "PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM"] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return Ok(Some(value));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::EgressGuard;

    fn hermetic_egress_guard() -> EgressGuard {
        let blocked =
            std::sync::Arc::new(enclava_common::outbound_http::BlockedNetworks::defaults());
        EgressGuard {
            proxy: crate::egress_proxy::EgressProxy::new(std::sync::Arc::clone(&blocked)),
            blocked,
            allowlist: crate::clients::AllowList::from_env_or_default(None),
        }
    }

    #[tokio::test]
    async fn verify_image_rejects_literal_ip_registry_before_any_io() {
        // The sigstore transport is unguarded; the pre-flight guard must
        // reject a tenant-chosen literal-IP registry host (issue #224)
        // before the sigstore client dials anything. SIGSTORE_TUF_ROOT_PATH
        // must be set so load_trust_root does not hit the network first.
        let root =
            std::env::temp_dir().join(format!("cap-224-trusted-root-{}.json", std::process::id()));
        std::fs::write(&root, b"{}").unwrap();
        unsafe {
            std::env::set_var("SIGSTORE_TUF_ROOT_PATH", &root);
        }
        let guard = hermetic_egress_guard();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = verify_image(
            &guard,
            "10.0.5.7/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            digest,
            &url_policy(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("registry destination rejected"),
            "literal-IP registry must be rejected, got: {err}"
        );
        // ::/96 spelling must fail identically.
        let err = verify_image(
            &guard,
            "[::10.0.5.7]/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            digest,
            &url_policy(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("registry destination rejected"),
            "IPv4-compatible v6 registry must be rejected, got: {err}"
        );
        unsafe {
            std::env::remove_var("SIGSTORE_TUF_ROOT_PATH");
        }
        let _ = std::fs::remove_file(&root);
    }

    #[tokio::test]
    async fn verify_image_rejects_unallowlisted_registry_before_any_io() {
        let root =
            std::env::temp_dir().join(format!("cap-224-trusted-root-{}.json", std::process::id()));
        std::fs::write(&root, b"{}").unwrap();
        unsafe {
            std::env::set_var("SIGSTORE_TUF_ROOT_PATH", &root);
        }
        let guard = hermetic_egress_guard();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = verify_image(
            &guard,
            "internal.svc.cluster.local/repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            digest,
            &url_policy(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("registry destination rejected"),
            "cluster-internal registry host must be rejected, got: {err}"
        );
        unsafe {
            std::env::remove_var("SIGSTORE_TUF_ROOT_PATH");
        }
        let _ = std::fs::remove_file(&root);
    }

    #[tokio::test]
    async fn fetch_attestations_rejects_unguarded_destinations() {
        let guard = hermetic_egress_guard();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let client = reqwest::Client::new();
        for image in [
            "10.0.5.7/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "internal.svc.cluster.local/repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let err = fetch_attestations(&guard, &client, image, digest, 1024)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("registry destination rejected"),
                "{image} must be rejected, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn fetch_portable_verification_material_rejects_unguarded_destinations() {
        let guard = hermetic_egress_guard();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // Refs that parse under the OCI grammar must be stopped by the egress
        // guard before any request is issued.
        for image in [
            "169.254.169.254/repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "evil.example/repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let err = fetch_portable_verification_material(&guard, image, digest)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("registry destination rejected"),
                "{image} must be rejected, got: {err}"
            );
        }
        // A bracket-IPv6 literal fails the OCI reference grammar (the same
        // parser the dialing client uses) before the egress check — still
        // fail closed, just with the parse error.
        let err = fetch_portable_verification_material(
            &guard,
            "[::ffff:10.0.5.7]/repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            digest,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid image reference")
                || err.to_string().contains("registry destination rejected"),
            "bracket-IPv6 image ref must be rejected, got: {err}"
        );
    }

    fn url_policy() -> VerificationPolicy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url:
                "https://github.com/example/repo/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    /// The allowlist must describe the host the registry client actually
    /// dials. `parse_image_parts` and the OCI reference parser disagree on
    /// single-label three-component refs (`registry/foo/bar` is host
    /// `registry` to the custom parser but Docker Hub's `index.docker.io` to
    /// the OCI parser), and a custom-parser allowlist match must never leak
    /// the platform password to the host the client really connects to
    /// (review finding on #243).
    #[test]
    fn allowlist_gates_the_dialed_registry_host_not_the_custom_parser() {
        let image: OciReference = "registry/foo/bar@sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        assert_eq!(image.resolve_registry(), "index.docker.io");
        let creds = CosignRegistryCredentials::basic("cap-bot", "platform-token");
        let allowed = ["registry".to_string()];
        // The custom parser's host matches the allowlist (the pre-fix
        // behavior)...
        assert!(matches!(
            registry_auth_with_allowlist("registry", Some(&creds), &allowed),
            Auth::Basic(..)
        ));
        // ...but the client dials the OCI-resolved host, which must NOT
        // receive the platform credentials.
        assert!(matches!(
            registry_auth_with_allowlist(image.resolve_registry(), Some(&creds), &allowed),
            Auth::Anonymous
        ));
    }

    /// `docker.io` is rewritten to `index.docker.io` at dial time, so a
    /// `docker.io` allowlist entry must describe that real endpoint instead
    /// of never matching (or matching some other host).
    #[test]
    fn docker_io_allowlist_entry_matches_the_real_hub_endpoint() {
        let creds = CosignRegistryCredentials::basic("cap-bot", "platform-token");
        assert!(matches!(
            registry_auth_with_allowlist(
                "index.docker.io",
                Some(&creds),
                &["docker.io".to_string()]
            ),
            Auth::Basic(..)
        ));
        assert!(matches!(
            registry_auth_with_allowlist(
                "index.docker.io",
                Some(&creds),
                &["*.docker.io".to_string()]
            ),
            Auth::Basic(..)
        ));
        assert!(matches!(
            registry_auth_with_allowlist("notdocker.io", Some(&creds), &["docker.io".to_string()]),
            Auth::Anonymous
        ));
    }

    /// Issue #225 hardening: allowlist entries outside the grammar can never
    /// match a parsed registry name and must be refused at startup, not
    /// silently ignored (same strictness as the pull-secret scope collector).
    #[test]
    fn cosign_registry_host_pattern_grammar_accepts_matchable_entries() {
        for pattern in [
            "*",
            "ghcr.io",
            "ghcr.io:5000",
            "registry:5000",
            "localhost",
            "localhost:5000",
            "10.0.0.1:5000",
            "*.corp.example",
            "*.corp.example:5000",
        ] {
            assert_eq!(
                cosign_registry_host_pattern_error(pattern),
                None,
                "pattern {pattern:?} must be accepted"
            );
        }
    }

    #[test]
    fn cosign_registry_host_pattern_grammar_rejects_never_matching_entries() {
        for pattern in [
            "",                // empty entry (e.g. a trailing comma)
            "*ghcr.io",        // partial-label wildcard never matches
            "**.corp.example", // repeated wildcard never matches
            "*.",              // empty wildcard base
            "ghcr..io",        // empty label
            ".ghcr.io",        // leading dot
            "ghcr.io.",        // trailing dot
            "ghcr.io/path",    // path, not a host
            "registry",        // OCI interprets it as a Docker Hub namespace
            "*.registry",      // wildcard base is not a registry endpoint
            "ghcr.io:",        // empty port
            "ghcr.io:0",       // port zero
            "ghcr.io:99999",   // port out of range
            "-bad.example",    // leading-hyphen label
            "bad-.example",    // trailing-hyphen label
        ] {
            assert!(
                cosign_registry_host_pattern_error(pattern).is_some(),
                "pattern {pattern:?} must be rejected"
            );
        }
    }

    #[test]
    fn signature_lookup_source_is_digest_pinned_for_mutable_tags() {
        let image: OciReference = "registry.example.test/team/app:latest".parse().unwrap();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let lookup = signature_lookup_source_image(&image, digest);

        assert_eq!(
            lookup.whole(),
            format!("registry.example.test/team/app@{digest}")
        );
        assert_eq!(lookup.digest(), Some(digest));
        assert_eq!(lookup.tag(), None);
    }

    #[test]
    fn build_pin_from_env_rejects_non_digest_image() {
        let err = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y:tag",
            "TEST_PUBLIC_KEY_BASE64",
            "TEST_PUBLIC_KEY_PEM",
            "TEST_SUBJECT_VAR",
            "TEST_ISSUER_VAR",
        )
        .unwrap_err();
        assert!(matches!(err, CosignError::InvalidPolicy(msg) if msg.contains("digest-pinned")));
    }

    #[test]
    fn build_pin_from_env_url_subject_picks_url_policy() {
        unsafe {
            std::env::set_var(
                "TEST_SIDECAR_SUBJECT_URL",
                "https://github.com/x/y/.github/workflows/build.yml@refs/heads/main",
            );
            std::env::set_var(
                "TEST_SIDECAR_ISSUER_URL",
                "https://token.actions.githubusercontent.com",
            );
        }
        let pin = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_PUBLIC_KEY_BASE64",
            "TEST_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_SUBJECT_URL",
            "TEST_SIDECAR_ISSUER_URL",
        )
        .expect("pin");
        assert!(matches!(
            pin.policy,
            VerificationPolicy::FulcioUrlIdentity { .. }
        ));
        assert_eq!(
            pin.image_digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn build_pin_from_env_public_key_overrides_fulcio_vars() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeDjxjxz1f2yWqSX+F2TSLujEc5tMLMMIRxI2CPOXKv8=\n-----END PUBLIC KEY-----\n";
        unsafe {
            std::env::set_var("TEST_SIDECAR_PUBLIC_KEY_B64", B64.encode(pem));
            std::env::remove_var("TEST_SIDECAR_PUBLIC_KEY_PEM");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM");
        }
        let pin = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_SIDECAR_PUBLIC_KEY_B64",
            "TEST_SIDECAR_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_MISSING_SUBJECT",
            "TEST_SIDECAR_MISSING_ISSUER",
        )
        .expect("pin");
        assert!(matches!(pin.policy, VerificationPolicy::PublicKey { .. }));
    }

    #[test]
    fn build_pin_from_env_rejects_invalid_public_key_base64() {
        unsafe {
            std::env::set_var("TEST_SIDECAR_BAD_PUBLIC_KEY_B64", "not base64");
            std::env::remove_var("TEST_SIDECAR_BAD_PUBLIC_KEY_PEM");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM");
        }
        let err = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_SIDECAR_BAD_PUBLIC_KEY_B64",
            "TEST_SIDECAR_BAD_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_MISSING_SUBJECT",
            "TEST_SIDECAR_MISSING_ISSUER",
        )
        .unwrap_err();
        assert!(
            matches!(err, CosignError::InvalidPolicy(msg) if msg.contains("TEST_SIDECAR_BAD_PUBLIC_KEY_B64"))
        );
    }

    #[test]
    fn build_constraints_url_policy_ok() {
        let c = build_constraints(&url_policy()).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_email_policy_ok() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: "https://accounts.google.com".to_string(),
        };
        let c = build_constraints(&policy).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_rejects_empty_url_subject() {
        let policy = VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: String::new(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_empty_email_issuer() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: String::new(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_invalid_public_key() {
        let policy = VerificationPolicy::PublicKey {
            pem: "not a real PEM".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn parse_image_parts_handles_common_shapes() {
        assert_eq!(
            parse_image_parts("nginx").unwrap(),
            ("docker.io".to_string(), "library/nginx".to_string())
        );
        assert_eq!(
            parse_image_parts("ghcr.io/org/repo:v1").unwrap(),
            ("ghcr.io".to_string(), "org/repo".to_string())
        );
        assert_eq!(
            parse_image_parts("user/repo:tag").unwrap(),
            ("docker.io".to_string(), "user/repo".to_string())
        );
        assert_eq!(
            parse_image_parts("registry.example:5000/org/repo:tag").unwrap(),
            ("registry.example:5000".to_string(), "org/repo".to_string())
        );
    }

    #[test]
    fn portable_signature_blobs_require_bundle_material() {
        assert!(!is_portable_signature_blob(
            br#"{"critical":{"image":{"docker-manifest-digest":"sha256:00"}}}"#
        ));
        assert!(is_portable_signature_blob(
            br#"{"dsseEnvelope":{},"verificationMaterial":{"certificate":{"rawBytes":"AA=="},"tlogEntries":[{}]}}"#
        ));
    }

    #[test]
    fn portable_blob_buffer_stops_at_limit() {
        let mut bytes = vec![1; 2];
        extend_bounded(&mut bytes, &[2, 3], 1, 5).unwrap();
        assert!(extend_bounded(&mut bytes, &[4], 1, 5).is_err());
    }

    #[test]
    fn registry_auth_from_env_uses_basic_credentials() {
        unsafe {
            std::env::set_var("COSIGN_REGISTRY_USERNAME", "cap-bot");
            std::env::set_var("COSIGN_REGISTRY_PASSWORD", "ghp_example");
            std::env::remove_var("COSIGN_REGISTRY_BEARER_TOKEN");
            std::env::remove_var("GHCR_USERNAME");
            std::env::remove_var("GHCR_TOKEN");
            std::env::set_var("COSIGN_REGISTRY_ALLOWED_HOSTS", "ghcr.io");
        }

        let auth = registry_auth_from_env("ghcr.io");

        assert!(matches!(
            auth,
            Auth::Basic(username, password) if username == "cap-bot" && password == "ghp_example"
        ));
    }

    /// Devin review on #276: token-only GHCR authentication is deliberately
    /// accepted here for verification — Basic auth against ghcr.io with the
    /// conventional `oauth2` username. The startup gate in deploy.rs is what
    /// keeps this configuration out of a running enclava-api (whose
    /// pull-secret machinery needs both values); this pins the documented
    /// cosign-vs-startup asymmetry as intended. Runs in a child process so
    /// the process-global env mutation cannot race the other env-reading
    /// tests in this binary.
    #[test]
    fn ghcr_token_only_auth_is_valid_for_verification_only() {
        const CHILD: &str = "CAP_COSIGN_GHCR_TOKEN_ONLY";
        if std::env::var(CHILD).is_ok() {
            let auth = registry_auth_with_allowlist("ghcr.io", None, &[]);
            assert!(
                matches!(auth, Auth::Basic(username, token)
                    if username == "oauth2" && token == "ghp_token_only"),
                "token-only must authenticate ghcr.io verification with the oauth2 username"
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cosign::tests::ghcr_token_only_auth_is_valid_for_verification_only",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("GHCR_USERNAME")
            .env("GHCR_TOKEN", "ghp_token_only")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Codex review on #243, P2: only one of USERNAME/PASSWORD being set
    /// attaches no credential at all (`is_configured` stays false), so every
    /// private-registry verification would silently run anonymously — the
    /// startup gate must refuse the incomplete pair instead.
    #[test]
    fn incomplete_basic_credentials_are_a_startup_error() {
        assert!(incomplete_basic_pair_error(Some("cap-bot"), None).is_some());
        assert!(incomplete_basic_pair_error(None, Some("ghp_example")).is_some());
        assert!(incomplete_basic_pair_error(None, None).is_none());
        assert!(incomplete_basic_pair_error(Some("cap-bot"), Some("ghp_example")).is_none());
    }

    /// Issue #225: platform COSIGN_* credentials must never be forwarded to a
    /// registry host the tenant picked. The allowlist gate is exercised
    /// through the pure decision core so the env-dependent happy path above
    /// stays the only test touching process-global environment state here.
    #[test]
    fn registry_credentials_are_not_forwarded_to_unlisted_hosts() {
        let allowed = vec!["ghcr.io".to_string(), "*.corp.example".to_string()];
        let credentials = CosignRegistryCredentials::basic("cap-bot", "ghp_example");

        // Allowlisted hosts receive the credentials.
        assert!(matches!(
            registry_auth_with_allowlist("ghcr.io", Some(&credentials), &allowed),
            Auth::Basic(..)
        ));
        assert!(matches!(
            registry_auth_with_allowlist("registry.corp.example", Some(&credentials), &allowed),
            Auth::Basic(..)
        ));

        // Tenant-chosen hosts do not — the exact attack from the issue.
        for host in [
            "attacker.example.com",
            "evil.example.com:5000",
            // wildcard must not leak into sibling domains
            "notcorp.example",
            "deep.sub.corp.example",
        ] {
            assert!(
                matches!(
                    registry_auth_with_allowlist(host, Some(&credentials), &allowed),
                    Auth::Anonymous
                ),
                "credentials must not attach to {host}"
            );
        }

        // Unset allowlist fails closed for every host.
        assert!(matches!(
            registry_auth_with_allowlist("ghcr.io", Some(&credentials), &[]),
            Auth::Anonymous
        ));

        // Without credentials configured the gate is inert (anonymous anyway
        // unless GHCR_* applies, which is separately host-bound).
        assert!(matches!(
            registry_auth_with_allowlist("attacker.example.com", None, &allowed),
            Auth::Anonymous
        ));
    }

    #[test]
    fn host_allowlist_patterns_match_exact_and_single_level_wildcards() {
        assert!(host_matches_allowed_pattern("ghcr.io", "ghcr.io"));
        assert!(host_matches_allowed_pattern("GHCR.IO", "ghcr.io"));
        assert!(host_matches_allowed_pattern(
            "reg.example:5000",
            "reg.example:5000"
        ));
        assert!(host_matches_allowed_pattern(
            "a.corp.example",
            "*.corp.example"
        ));
        assert!(host_matches_allowed_pattern(
            "corp.example",
            "*.corp.example"
        ));
        assert!(host_matches_allowed_pattern("any.host.example", "*"));
        assert!(!host_matches_allowed_pattern(
            "notexample.com",
            "*.example.com"
        ));
        assert!(!host_matches_allowed_pattern(
            "a.b.corp.example",
            "*.corp.example"
        ));
        assert!(!host_matches_allowed_pattern("ghcr.io.evil.com", "ghcr.io"));
    }

    /// Codex review on #243, round 3, P1 "Validate token realms before
    /// forwarding basic credentials": the `realm` URL must be extracted from
    /// a `WWW-Authenticate: Bearer` challenge (quoted, bare, scheme-prefixed)
    /// and its host checked against the same allowlist grammar as registry
    /// hosts — unparseable or unlisted realms are NOT allowed.
    #[test]
    fn legacy_ghcr_realms_work_without_cosign_allowlist() {
        let allowed = registry_realm_allowed_hosts("ghcr.io", vec![], true);
        assert!(realm_host_allowed("https://ghcr.io/token", &allowed, false));
        for realm in [
            "https://evil.example/token",
            "https://ghcr.io:8443/token",
            "http://ghcr.io/token",
        ] {
            assert!(!realm_host_allowed(realm, &allowed, false));
        }
        assert!(registry_realm_allowed_hosts("evil.example", vec![], true).is_empty());
        assert!(registry_realm_allowed_hosts("ghcr.io", vec![], false).is_empty());
    }

    #[test]
    fn registry_default_https_ports_match_allowlist() {
        let creds = CosignRegistryCredentials::basic("test-user", "test-password");
        for (registry, pattern) in [
            ("reg.example", "reg.example:443"),
            ("reg.example:443", "reg.example"),
            ("docker.io:443", "index.docker.io"),
        ] {
            assert!(matches!(
                registry_auth_with_allowlist(registry, Some(&creds), &[pattern.into()]),
                Auth::Basic(..)
            ));
        }
        assert!(matches!(
            registry_auth_with_allowlist("reg.example:8443", Some(&creds), &["reg.example".into()]),
            Auth::Anonymous
        ));
    }

    #[test]
    fn realm_policy_preserves_ports_and_requires_https() {
        for (realm, pattern, http, expected) in [
            ("https://auth.example/token", "auth.example", false, true),
            (
                "https://auth.example:443/token",
                "auth.example",
                false,
                true,
            ),
            (
                "https://auth.example/token",
                "auth.example:443",
                false,
                true,
            ),
            (
                "https://auth.example:8443/token",
                "auth.example",
                false,
                false,
            ),
            (
                "https://auth.example:8443/token",
                "auth.example:8443",
                false,
                true,
            ),
            (
                "https://auth.example:8443/token",
                "*.example:8443",
                false,
                true,
            ),
            (
                "https://auth.example:8443/token",
                "*.example:443",
                false,
                false,
            ),
            ("http://auth.example/token", "auth.example", false, false),
            ("http://auth.example/token", "*", false, false),
            ("http://auth.example/token", "auth.example", true, true),
            (
                "http://auth.example:8080/token",
                "auth.example",
                true,
                false,
            ),
            (
                "http://auth.example:8080/token",
                "auth.example:8080",
                true,
                true,
            ),
            (
                "https://auth.example.evil/token",
                "auth.example",
                false,
                false,
            ),
            (
                "https://user@auth.example/token",
                "auth.example",
                false,
                false,
            ),
            ("ftp://auth.example/token", "*", true, false),
            ("not a URL", "*", true, false),
        ] {
            assert_eq!(
                realm_host_allowed(realm, &[pattern.into()], http),
                expected,
                "realm={realm}, pattern={pattern}, http={http}"
            );
        }
    }

    async fn auth_test_server(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (base, task)
    }

    #[tokio::test]
    async fn actual_oci_requests_never_replay_basic_to_changed_challenges() {
        use axum::{
            Router,
            http::{HeaderMap, StatusCode},
            routing::get,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let evil_hits = Arc::new(AtomicUsize::new(0));
        let hits = evil_hits.clone();
        let (evil, evil_task) = auth_test_server(Router::new().fallback(move || {
            hits.fetch_add(1, Ordering::SeqCst);
            async { "stolen" }
        }))
        .await;
        let registry_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registry = registry_listener.local_addr().unwrap().to_string();
        let base = format!("http://{registry}");
        let v2_hits = Arc::new(AtomicUsize::new(0));
        let count = v2_hits.clone();
        let token_hits = Arc::new(AtomicUsize::new(0));
        let tokens = token_hits.clone();
        let safe_realm = format!("{base}/token");
        let bad_challenge = format!("Bearer realm=\"{evil}/token\"");
        let later = bad_challenge.clone();
        let router = Router::new()
            .route(
                "/v2/",
                get(move |headers: HeaderMap| {
                    assert!(!headers.contains_key("authorization"));
                    let realm = if count.fetch_add(1, Ordering::SeqCst) == 0 {
                        format!("Bearer realm=\"{safe_realm}\",service=\"test\"")
                    } else {
                        bad_challenge.clone()
                    };
                    async move { (StatusCode::UNAUTHORIZED, [("www-authenticate", realm)]) }
                }),
            )
            .route(
                "/token",
                get(move |headers: HeaderMap, uri: axum::http::Uri| {
                    tokens.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        headers["authorization"],
                        format!("Basic {}", B64.encode("test-user:test-password"))
                    );
                    assert!(
                        uri.query()
                            .unwrap()
                            .contains("scope=repository%3Ateam%2Fapp%3Apull")
                    );
                    assert!(uri.query().unwrap().contains("service=test"));
                    async { r#"{"token":"short-lived-test-token"}"# }
                }),
            )
            .fallback(move |headers: HeaderMap| {
                assert_eq!(headers["authorization"], "Bearer short-lived-test-token");
                let challenge = later.clone();
                async move { (StatusCode::UNAUTHORIZED, [("www-authenticate", challenge)]) }
            });
        let registry_task = tokio::spawn(async move {
            axum::serve(registry_listener, router).await.unwrap();
        });
        let auth = exchange_registry_basic_auth(
            None,
            &base,
            "team/app",
            Auth::Basic("test-user".into(), "test-password".into()),
            std::slice::from_ref(&registry),
            true,
        )
        .await
        .unwrap();
        assert!(matches!(&auth, Auth::Bearer(token) if token == "short-lived-test-token"));
        let client = oci_client::client::Client::try_from(oci_client::client::ClientConfig {
            protocol: oci_client::client::ClientProtocol::Http,
            ..Default::default()
        })
        .unwrap();
        let image = oci_client::Reference::with_tag(registry, "team/app".into(), "latest".into());
        let auth = (&auth).into();
        // Exercise both explicit auth and real manifest/blob/referrers paths.
        client
            .auth(&image, &auth, oci_client::RegistryOperation::Pull)
            .await
            .unwrap();
        assert!(
            client
                .pull_manifest_raw(
                    &image,
                    &auth,
                    &["application/vnd.oci.image.manifest.v1+json"]
                )
                .await
                .is_err()
        );
        assert!(client.pull_referrers(&image, None).await.is_err());
        let layer = oci_client::manifest::OciDescriptor {
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            media_type: "application/octet-stream".into(),
            size: 1,
            urls: None,
            annotations: None,
            artifact_type: None,
        };
        assert!(client.pull_blob_stream(&image, &layer).await.is_err());
        assert_eq!(
            v2_hits.load(Ordering::SeqCst),
            1,
            "OCI must never discover a second realm"
        );
        assert_eq!(token_hits.load(Ordering::SeqCst), 1);
        assert_eq!(evil_hits.load(Ordering::SeqCst), 0);
        registry_task.abort();
        evil_task.abort();
    }

    #[tokio::test]
    async fn basic_first_challenges_exchange_only_the_requested_pull_scope() {
        use axum::{
            Router,
            http::{HeaderMap, HeaderValue, StatusCode},
            routing::get,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Exercise separate/joined headers and service present/absent. Even
        // encoded and duplicated query keys must not survive the exchange.
        for joined in [false, true] {
            for service in [None, Some("selected,service")] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let realm = format!(
                    "http://{addr}/token?scope=repository:other:push&%73cope=registry:catalog:*&SCOPE=bad&service=evil&%73ervice=evil2&route=keep"
                );
                let mut bearer =
                    format!("Bearer realm=\"{realm}\",scope=\"repository:other:push\"");
                if let Some(service) = service {
                    bearer.push_str(&format!(",service=\"{service}\""));
                }
                let hits = Arc::new(AtomicUsize::new(0));
                let tokens = hits.clone();
                let router = Router::new()
                    .route(
                        "/v2/",
                        get(move |headers: HeaderMap| {
                            assert!(!headers.contains_key("authorization"));
                            let mut challenges = HeaderMap::new();
                            if joined {
                                challenges.insert(
                                    "www-authenticate",
                                    HeaderValue::from_str(&format!(
                                        "Basic realm=\"registry\", {bearer}"
                                    ))
                                    .unwrap(),
                                );
                            } else {
                                challenges.append(
                                    "www-authenticate",
                                    HeaderValue::from_static("Basic realm=\"registry\""),
                                );
                                challenges.append(
                                    "www-authenticate",
                                    HeaderValue::from_str(&bearer).unwrap(),
                                );
                            }
                            async move { (StatusCode::UNAUTHORIZED, challenges) }
                        }),
                    )
                    .route(
                        "/token",
                        get(move |headers: HeaderMap, uri: axum::http::Uri| {
                            tokens.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(
                                headers["authorization"],
                                format!("Basic {}", B64.encode("test-user:test-password"))
                            );
                            let url = reqwest::Url::parse(&format!("http://test{uri}")).unwrap();
                            let pairs: Vec<_> = url
                                .query_pairs()
                                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                .collect();
                            let mut expected = vec![
                                ("route".to_string(), "keep".to_string()),
                                ("scope".to_string(), "repository:team/app:pull".to_string()),
                            ];
                            if let Some(service) = service {
                                expected.push(("service".to_string(), service.to_string()));
                            }
                            assert_eq!(pairs, expected);
                            async { r#"{"access_token":"scoped-token"}"# }
                        }),
                    );
                let task = tokio::spawn(async move {
                    axum::serve(listener, router).await.unwrap();
                });
                let auth = exchange_registry_basic_auth(
                    None,
                    &format!("http://{addr}"),
                    "team/app",
                    Auth::Basic("test-user".into(), "test-password".into()),
                    &[addr.to_string()],
                    true,
                )
                .await
                .unwrap();
                assert!(matches!(auth, Auth::Bearer(token) if token == "scoped-token"));
                assert_eq!(hits.load(Ordering::SeqCst), 1);
                task.abort();
            }
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn opted_in_http_verification_paths_pass_preflight() {
        // Isolate environment changes from parallel tests in a subprocess.
        const CHILD: &str = "CAP_COSIGN_HTTP_PREFLIGHT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cosign::tests::opted_in_http_verification_paths_pass_preflight",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("COSIGN_ALLOW_HTTP_REGISTRY", "true")
                .env("SIGSTORE_TUF_ROOT_PATH", "")
                .env_remove("COSIGN_REGISTRY_USERNAME")
                .env_remove("COSIGN_REGISTRY_PASSWORD")
                .env_remove("COSIGN_REGISTRY_BEARER_TOKEN")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use crate::clients::AllowList;
            use enclava_common::outbound_http::BlockedNetworks;
            use std::sync::atomic::{AtomicUsize, Ordering};
            let hits = Arc::new(AtomicUsize::new(0));
            let requests = hits.clone();
            let (base, task) = auth_test_server(axum::Router::new().fallback(move || {
                requests.fetch_add(1, Ordering::SeqCst);
                async { axum::http::StatusCode::NOT_FOUND }
            }))
            .await;
            let registry = base.strip_prefix("http://").unwrap();
            // Explicit test-only unblocked loopback, not production policy.
            let blocked = Arc::new(BlockedNetworks::empty());
            let egress = EgressGuard {
                proxy: crate::egress_proxy::EgressProxy::new(blocked.clone()),
                blocked,
                allowlist: AllowList::from_env_or_default(Some("127.0.0.1".into())),
            };
            let digest = format!("sha256:{}", "a".repeat(64));
            let image = format!("{registry}/team/app@{digest}");
            let policy = VerificationPolicy::PublicKey {
                pem: "unused".into(),
            };
            let err = verify_image(&egress, &image, &digest, &policy)
                .await
                .unwrap_err();
            // Empty pinned-root path deterministically stops after preflight,
            // without contacting the public TUF service.
            assert!(matches!(err, CosignError::TrustRoot(_)), "{err}");
            let err = fetch_portable_verification_material(&egress, &image, &digest)
                .await
                .unwrap_err();
            assert!(
                !err.to_string().contains("registry destination rejected"),
                "{err}"
            );
            assert!(
                hits.load(Ordering::SeqCst) > 0,
                "portable path must reach the HTTP registry through the proxy"
            );
            task.abort();
        });
    }

    #[tokio::test]
    async fn challenge_free_or_basic_only_registry_never_releases_basic_to_oci() {
        use axum::{Router, http::StatusCode, routing::get};
        for challenge in [None, Some("Basic realm=\"registry\"")] {
            let router = Router::new().route(
                "/v2/",
                get(move || async move {
                    match challenge {
                        Some(value) => (StatusCode::UNAUTHORIZED, [("www-authenticate", value)]),
                        None => (StatusCode::OK, [("www-authenticate", "")]),
                    }
                }),
            );
            let (base, task) = auth_test_server(router).await;
            let err = exchange_registry_basic_auth(
                None,
                &base,
                "team/app",
                Auth::Basic("test-user".into(), "test-password".into()),
                &["*".into()],
                true,
            )
            .await
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("unsafe OCI Basic fallback is disabled")
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn token_exchange_blocks_unlisted_ports_http_and_redirects() {
        use axum::{Router, http::StatusCode, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let realm = format!("http://{addr}/token");
        let challenge = format!("Bearer realm=\"{realm}\"");
        let router = Router::new()
            .route(
                "/v2/",
                get(move || {
                    let challenge = challenge.clone();
                    async move { (StatusCode::UNAUTHORIZED, [("www-authenticate", challenge)]) }
                }),
            )
            .route(
                "/token",
                get(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/must-not-receive-auth")],
                    )
                }),
            )
            .route(
                "/must-not-receive-auth",
                get(|| async {
                    panic!("token redirects must not be followed");
                    #[allow(unreachable_code)]
                    ""
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        for (allowed, http, error) in [
            (vec![addr.to_string()], false, "realm rejected"),
            (vec!["127.0.0.1".into()], true, "realm rejected"),
            (vec![addr.to_string()], true, "status 307"),
        ] {
            let err = exchange_registry_basic_auth(
                None,
                &format!("http://{addr}"),
                "team/app",
                Auth::Basic("test-user".into(), "test-password".into()),
                &allowed,
                http,
            )
            .await
            .unwrap_err();
            assert!(err.to_string().contains(error), "{err}");
        }
        task.abort();
    }

    #[test]
    fn portable_hub_precheck_uses_the_distribution_endpoint() {
        for registry in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
            assert_eq!(
                cosign_registry_base_url(registry).unwrap(),
                "https://registry-1.docker.io"
            );
        }
        for reference in [
            "nginx:latest",
            "docker.io/library/nginx:latest",
            "index.docker.io/library/nginx:latest",
        ] {
            let image: OciReference = reference.parse().unwrap();
            let base = cosign_registry_base_url(image.resolve_registry()).unwrap();
            assert_eq!(
                reqwest::Url::parse(&base).unwrap().host_str(),
                Some("registry-1.docker.io")
            );
        }
    }

    /// Regression test for issue #125: a malicious registry must not be able
    /// to make the attestation fetch buffer an unbounded manifest body. Both
    /// the declared-content-length path and the streamed-chunk path (no
    /// content-length) must degrade to `None` once the body exceeds the
    /// limit, and a small valid manifest must still parse.
    #[tokio::test]
    async fn fetch_attestation_tag_caps_oversized_registry_bodies() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn spawn_registry(body: Vec<u8>, declare_content_length: bool) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("loopback bind");
            let addr = listener.local_addr().expect("loopback address");
            let body = Arc::new(body);
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut chunk = [0u8; 1024];
                let mut head = Vec::new();
                loop {
                    let read = stream.read(&mut chunk).await.expect("read head");
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&chunk[..read]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = if declare_content_length {
                    format!("Content-Length: {}\r\n", body.len())
                } else {
                    "Transfer-Encoding: chunked\r\n".to_string()
                };
                let head = format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n");
                stream.write_all(head.as_bytes()).await.expect("head");
                if declare_content_length {
                    stream.write_all(&body).await.expect("body");
                } else {
                    // chunked encoding: one chunk holding the whole body
                    stream
                        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                        .await
                        .expect("chunk head");
                    stream.write_all(&body).await.expect("chunk body");
                    stream.write_all(b"\r\n0\r\n\r\n").await.expect("chunk end");
                }
            });
            format!("http://{addr}")
        }

        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let client = reqwest::Client::builder().build().unwrap();

        // Small valid manifest still parses.
        let base = spawn_registry(b"{\"schemaVersion\":2}".to_vec(), true).await;
        let tag = fetch_attestation_tag(&client, &base, "team/app", digest, "att", 1024)
            .await
            .unwrap();
        assert!(tag.is_some(), "small manifest should parse");

        // Oversized declared body is rejected via the content-length check.
        let big: Vec<u8> = serde_json::json!({ "pad": "x".repeat(4096) })
            .to_string()
            .into_bytes();
        let base = spawn_registry(big.clone(), true).await;
        let tag = fetch_attestation_tag(&client, &base, "team/app", digest, "att", 1024)
            .await
            .unwrap();
        assert!(tag.is_none(), "oversized att must degrade to None");

        // Oversized streamed body (chunked, no content-length) is rejected
        // while streaming, before the whole body is buffered.
        let base = spawn_registry(big, false).await;
        let tag = fetch_attestation_tag(&client, &base, "team/app", digest, "att", 1024)
            .await
            .unwrap();
        assert!(tag.is_none(), "oversized streamed att must degrade to None");
    }
}
