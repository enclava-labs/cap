use crate::acme::AcmeConfig;
use crate::clients::RegistryClient;
use crate::dns::DnsConfig;
use crate::kbs::KbsPolicyConfig;
use crate::platform_release::PlatformReleaseEnvelope;
use crate::signing_service::SigningServiceClient;
use ed25519_dalek::SigningKey;
use enclava_engine::types::AttestationConfig;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

/// Ownership model for a running CAP instance.
///
/// A CAP process is either a standalone control plane that accepts public
/// management writes, or a PaaS-managed control plane that only accepts
/// management writes through authenticated `/internal/paas/*` routes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CapManagementMode {
    #[default]
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

const RESERVED_POOL_CONNECTIONS: usize = 2;
const MAX_CONCURRENT_SIDE_EFFECTS: usize = 8;

/// Bound all transactions that enter an advisory authority lane before they
/// acquire a database connection. Reserving pool headroom lets lease
/// heartbeats, ownership checks, and ordinary reads make progress even when
/// every admitted mutation is stalled on an external provider.
pub fn side_effect_admission_limit(pool: &PgPool) -> usize {
    let max_connections = pool.options().get_max_connections() as usize;
    max_connections
        .saturating_sub(RESERVED_POOL_CONNECTIONS)
        .clamp(1, MAX_CONCURRENT_SIDE_EFFECTS)
}

pub fn side_effect_admission_for_pool(pool: &PgPool) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(side_effect_admission_limit(pool)))
}

/// Maximum number of `namespace/app` failure signatures retained before the
/// oldest entries are evicted. The map only exists to rate-limit warn logs;
/// a bounded LRU-style cache keeps app churn (create, fail a probe, delete)
/// from growing process memory indefinitely, as flagged in cap#219 review.
pub const TEE_PROBE_FAILURE_CACHE_CAPACITY: usize = 1_024;

/// Bounded cache of TEE probe failure signatures, keyed by `namespace/app`.
///
/// `HashMap` + insertion-order `VecDeque` approximates an LRU: re-observed
/// keys are moved to the back (most recently used), and inserts past the
/// capacity evict from the front. Stale keys of deleted apps are therefore
/// evicted by churn rather than retained for the life of the process.
#[derive(Debug, Default)]
pub struct TeeProbeFailureCache {
    entries: std::collections::HashMap<String, String>,
    order: std::collections::VecDeque<String>,
}

impl TeeProbeFailureCache {
    /// Inserts or refreshes `key`, returning the previous signature if one
    /// existed. Evicts the least recently used entry when the cache is full.
    pub fn insert(&mut self, key: String, signature: String) -> Option<String> {
        let previous = self.entries.insert(key.clone(), signature);
        match &previous {
            // Refresh recency: move the existing key to the back.
            Some(_) => self.order.retain(|k| k != &key),
            None => {
                if self.entries.len() > TEE_PROBE_FAILURE_CACHE_CAPACITY {
                    // entries.len() is at most capacity + 1 here, so this
                    // loop runs at most once.
                    while self.entries.len() > TEE_PROBE_FAILURE_CACHE_CAPACITY {
                        if let Some(evicted) = self.order.pop_front() {
                            self.entries.remove(&evicted);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        self.order.push_back(key);
        previous
    }

    /// Returns the recorded signature for `key` without mutating recency:
    /// lookups stay O(1) so high-volume suppressed failures never scan the
    /// order queue under the mutex (#219 review). Recency advances only when
    /// a signature is (re-)recorded via `insert`.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.entries.get(key)
    }

    /// Removes `key` (e.g. after a successful probe for the app).
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.order.retain(|k| k != key);
        self.entries.remove(key)
    }
}

/// Shared application state accessible from all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Instance-level management ownership mode.
    pub management_mode: CapManagementMode,
    /// Immutable process-lifetime workload admission decision.
    pub deployment_dispatch_enabled: bool,
    /// False until startup provider reconciliation has completed.
    pub startup_ready: Arc<AtomicBool>,
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
    /// Cap (bytes) applied to outbound HTTP response bodies read into
    /// memory via `crate::clients::read_body_capped` (from
    /// `ClientConfig::body_limit_bytes`). Reads on `http_client` that use
    /// `.text()`/`.json()`/`.bytes()` directly are NOT capped — new call
    /// sites must read through `read_body_capped` (or a client wrapper
    /// carrying `body_limit`, like `RegistryClient`).
    pub outbound_body_limit: u64,
    /// Outbound client for registry tag resolution, with registry allowlist.
    pub registry_client: RegistryClient,
    /// HTTP client for fixed internal Trustee/KBS calls.
    pub trustee_http_client: reqwest::Client,
    /// HTTP client for tenant TEE endpoints. Test environments may use staging
    /// ACME certificates that are not trusted by the public WebPKI roots.
    pub tee_http_client: reqwest::Client,
    /// Rate-limit state for live TEE probe failure warns: the last failure
    /// signature per `namespace/app`, so a persistently failing probe logs on
    /// the first failure and on change of error class instead of per request.
    /// Bounded so keys of deleted apps cannot accumulate unboundedly (#219).
    /// Shared through the `AppState` clones handed to concurrent handlers.
    pub recent_tee_probe_failures: std::sync::Arc<std::sync::Mutex<TeeProbeFailureCache>>,
    /// Sidecar/runtime settings used when generating Kubernetes manifests.
    pub attestation: Option<AttestationConfig>,
    /// Signed public platform release envelope used to derive
    /// runtime-sensitive descriptor inputs for this API instance.
    pub platform_release_envelope: Option<PlatformReleaseEnvelope>,
    /// Cloudflare DNS settings for CAP-managed tenant host records.
    pub dns: Option<DnsConfig>,
    /// ACME settings for the workload-attested DNS-01 certificate broker.
    pub acme: Option<AcmeConfig>,
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
    /// Admission is acquired before opening any transaction that will enter
    /// an entitlement/signing/app advisory lane. Waiters therefore consume no
    /// PostgreSQL connection, preserving reserved headroom for heartbeats and
    /// ownership fencing.
    pub side_effect_admission: Arc<Semaphore>,
    /// PaaS-only internal route authentication configuration. When unset or
    /// incomplete, `/internal/*` routes fail closed.
    pub internal_auth: Option<InternalAuthConfig>,
}

impl AppState {
    pub fn startup_is_ready(&self) -> bool {
        self.startup_ready.load(Ordering::Acquire)
    }

    pub fn mark_startup_ready(&self) {
        self.startup_ready.store(true, Ordering::Release);
    }

    pub async fn admit_side_effect(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
        self.side_effect_admission.clone().acquire_owned().await
    }

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
    use sqlx::postgres::PgPoolOptions;

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

    #[tokio::test]
    async fn side_effect_admission_reserves_pool_headroom_before_lane_entry() {
        let pool = |max_connections| {
            PgPoolOptions::new()
                .max_connections(max_connections)
                .connect_lazy("postgresql://test:test@localhost:5432/test")
                .expect("lazy test pool")
        };
        assert_eq!(side_effect_admission_limit(&pool(2)), 1);
        assert_eq!(side_effect_admission_limit(&pool(3)), 1);
        assert_eq!(side_effect_admission_limit(&pool(4)), 2);
        assert_eq!(side_effect_admission_limit(&pool(20)), 8);
    }

    #[test]
    fn tee_probe_failure_cache_evicts_least_recently_used_key() {
        let mut cache = TeeProbeFailureCache::default();
        for i in 0..TEE_PROBE_FAILURE_CACHE_CAPACITY {
            cache.insert(format!("ns-{i}/app-{i}"), format!("failure-{i}"));
        }
        assert_eq!(cache.entries.len(), TEE_PROBE_FAILURE_CACHE_CAPACITY);

        // Recency advances on insert: re-recording an old key's signature
        // makes it the most recently used (get is O(1) and does not reorder).
        cache.insert("ns-0/app-0".to_string(), "failure-0".to_string());

        // Inserting one more key evicts ns-1/app-1, the least recently used,
        // but keeps the refreshed ns-0/app-0 entry.
        cache.insert("ns-new/app-new".to_string(), "failure-new".to_string());
        assert_eq!(cache.entries.len(), TEE_PROBE_FAILURE_CACHE_CAPACITY);
        assert!(cache.entries.contains_key("ns-0/app-0"));
        assert!(cache.entries.contains_key("ns-new/app-new"));
        assert!(!cache.entries.contains_key("ns-1/app-1"));
    }

    #[test]
    fn tee_probe_failure_cache_remove_drops_the_key_and_signature() {
        let mut cache = TeeProbeFailureCache::default();
        cache.insert("ns/app".to_string(), "failure".to_string());
        assert_eq!(cache.remove("ns/app").as_deref(), Some("failure"));
        assert!(cache.get("ns/app").is_none());
        assert!(cache.order.is_empty());
    }

    #[test]
    fn tee_probe_failure_cache_insert_replaces_signature_and_refreshes_recency() {
        let mut cache = TeeProbeFailureCache::default();
        assert_eq!(
            cache.insert("ns/app".to_string(), "first".to_string()),
            None
        );
        assert_eq!(
            cache.insert("ns/app".to_string(), "second".to_string()),
            Some("first".to_string())
        );
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.order.len(), 1);
        assert_eq!(cache.get("ns/app").map(String::as_str), Some("second"));
    }
}
