use crate::acme::{AcmeConfig, AcmeRateLimitCache};
use crate::clients::RegistryClient;
use crate::dns::DnsConfig;
use crate::kbs::KbsPolicyConfig;
use crate::signing_service::SigningServiceClient;
use ed25519_dalek::SigningKey;
use enclava_engine::types::AttestationConfig;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

/// Ownership model for a running CAP instance.
///
/// A CAP process is either a standalone control plane that accepts public
/// management writes, or a PaaS-managed control plane that only accepts
/// management writes through authenticated `/internal/paas/*` routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapManagementMode {
    Standalone,
    PaasManaged,
}

impl CapManagementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::PaasManaged => "paas_managed",
        }
    }

    pub fn internal_paas_routes_enabled(self) -> bool {
        matches!(self, Self::PaasManaged)
    }
}

impl Default for CapManagementMode {
    fn default() -> Self {
        Self::Standalone
    }
}

impl FromStr for CapManagementMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "" | "standalone" | "self_service" => Ok(Self::Standalone),
            "paas_managed" | "paas-managed" | "paas" => Ok(Self::PaasManaged),
            other => Err(format!(
                "unsupported CAP_MANAGEMENT_MODE `{other}`; expected standalone or paas_managed"
            )),
        }
    }
}

/// Internal route authentication for PaaS -> CAP calls.
///
/// Tokens are stored as SHA-256 digests so they are not carried around in
/// state after startup. The SAN list is supplied by a trusted TLS-terminating
/// proxy after client certificate verification.
#[derive(Clone)]
pub struct InternalAuthConfig {
    token_sha256: Arc<[[u8; 32]]>,
    allowed_client_sans: Arc<[String]>,
    trusted_proxy_secret_sha256: Option<[u8; 32]>,
}

impl InternalAuthConfig {
    pub fn from_plaintext_tokens(tokens: &[&str], allowed_client_sans: &[&str]) -> Self {
        Self::from_plaintext_tokens_with_proxy_secret(tokens, allowed_client_sans, None)
    }

    pub fn from_plaintext_tokens_with_proxy_secret(
        tokens: &[&str],
        allowed_client_sans: &[&str],
        trusted_proxy_secret: Option<&str>,
    ) -> Self {
        let token_sha256 = tokens
            .iter()
            .map(|token| hash_token(token.as_bytes()))
            .collect::<Vec<_>>();
        let allowed_client_sans = allowed_client_sans
            .iter()
            .map(|san| san.trim().to_string())
            .filter(|san| !san.is_empty())
            .collect::<Vec<_>>();
        let trusted_proxy_secret_sha256 =
            trusted_proxy_secret.map(|secret| hash_token(secret.as_bytes()));
        Self {
            token_sha256: token_sha256.into(),
            allowed_client_sans: allowed_client_sans.into(),
            trusted_proxy_secret_sha256,
        }
    }

    pub fn from_plaintext_token_strings(
        tokens: Vec<String>,
        allowed_client_sans: Vec<String>,
        trusted_proxy_secret: Option<String>,
    ) -> Self {
        let token_refs = tokens.iter().map(String::as_str).collect::<Vec<_>>();
        let san_refs = allowed_client_sans
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        Self::from_plaintext_tokens_with_proxy_secret(
            &token_refs,
            &san_refs,
            trusted_proxy_secret.as_deref(),
        )
    }

    pub fn accepts_token(&self, token: &str) -> bool {
        let candidate = hash_token(token.as_bytes());
        self.token_sha256
            .iter()
            .any(|expected| expected.ct_eq(&candidate).into())
    }

    pub fn accepts_client_san(&self, client_san: &str) -> bool {
        self.allowed_client_sans.iter().any(|san| san == client_san)
    }

    pub fn requires_trusted_proxy(&self) -> bool {
        self.trusted_proxy_secret_sha256.is_some()
    }

    pub fn accepts_trusted_proxy_secret(&self, secret: &str) -> bool {
        let Some(expected) = self.trusted_proxy_secret_sha256.as_ref() else {
            return true;
        };
        let candidate = hash_token(secret.as_bytes());
        expected.ct_eq(&candidate).into()
    }

    pub fn is_usable(&self) -> bool {
        !self.token_sha256.is_empty() && !self.allowed_client_sans.is_empty()
    }
}

fn hash_token(token: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(token);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Shared application state accessible from all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Instance-level management ownership mode.
    pub management_mode: CapManagementMode,
    /// Ed25519 signing key for config JWTs.
    pub signing_key: Arc<SigningKey>,
    /// HMAC key for session JWT signing.
    pub hmac_key: Arc<[u8; 32]>,
    /// Base URL of this API server (for config metadata sync callbacks).
    pub api_url: String,
    /// Optional hosted console base URL used for browser approval.
    /// Self-hosted core deployments can leave this unset.
    pub dashboard_url: Option<String>,
    /// Platform domain suffix (e.g., "enclava.dev").
    pub platform_domain: String,
    /// TEE domain suffix (e.g., "tee.enclava.dev"). Per D1 the TEE-facing
    /// hostname is `<app>.<orgSlug>.<tee_domain_suffix>`.
    pub tee_domain_suffix: String,
    /// HTTP client for outbound requests.
    pub http_client: reqwest::Client,
    /// Outbound client for registry tag resolution, with registry allowlist.
    pub registry_client: RegistryClient,
    /// HTTP client for fixed internal Trustee/KBS calls.
    pub trustee_http_client: reqwest::Client,
    /// HTTP client for tenant TEE endpoints. Test environments may use staging
    /// ACME certificates that are not trusted by the public WebPKI roots.
    pub tee_http_client: reqwest::Client,
    /// Sidecar/runtime settings used when generating Kubernetes manifests.
    pub attestation: Option<AttestationConfig>,
    /// Cloudflare DNS settings for CAP-managed tenant host records.
    pub dns: Option<DnsConfig>,
    /// ACME settings for the workload-attested DNS-01 certificate broker.
    pub acme: Option<AcmeConfig>,
    /// Recent ACME rate-limit windows keyed by ACME directory and identifiers.
    pub acme_rate_limits: AcmeRateLimitCache,
    /// Trustee KBS policy settings for CAP-managed owner-resource bindings.
    pub kbs_policy: Option<KbsPolicyConfig>,
    /// Trustee callback used to validate workload attestation tokens before
    /// returning descriptor/keyring/policy artifacts to a pod.
    pub trustee_attestation_verify_url: Option<String>,
    /// Internal shared bearer token CAP presents to Trustee's attestation
    /// verification endpoint. This authenticates CAP as the verifier caller;
    /// the workload attestation token remains in the JSON request body.
    pub trustee_attestation_verify_bearer_token: Option<String>,
    /// Off-cluster policy signing service. When signed descriptor/keyring
    /// blobs are supplied on deploy, CAP forwards them here and persists the
    /// returned signed policy artifact.
    pub signing_service: Option<SigningServiceClient>,
    /// When true, CAP requires callers to submit signed descriptor/keyring
    /// blobs even if no platform signing-service URL is configured.
    pub require_customer_signed_policy_artifact: bool,
    /// Cluster-wide apply backpressure for this API instance. Applying a CAP
    /// deployment starts a Kata VM and attaches Longhorn volumes; bursts can
    /// overwhelm a single worker node before Kubernetes has useful feedback.
    pub deployment_apply_permits: Arc<Semaphore>,
    /// PaaS-only internal route authentication configuration. When unset or
    /// incomplete, `/internal/*` routes fail closed.
    pub internal_auth: Option<InternalAuthConfig>,
}

impl AppState {
    pub fn dashboard_url(&self) -> Option<&str> {
        self.dashboard_url.as_deref()
    }

    pub fn device_login_base_url(&self) -> &str {
        self.dashboard_url().unwrap_or(&self.api_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_auth_can_require_trusted_proxy_secret() {
        let config = InternalAuthConfig::from_plaintext_token_strings(
            vec!["token".to_string()],
            vec!["spiffe://local/enclava-paas".to_string()],
            Some("proxy-secret".to_string()),
        );

        assert!(config.requires_trusted_proxy());
        assert!(config.accepts_trusted_proxy_secret("proxy-secret"));
        assert!(!config.accepts_trusted_proxy_secret("wrong-secret"));
        assert!(config.is_usable());
    }
}
