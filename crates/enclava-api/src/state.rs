use crate::acme::AcmeConfig;
use crate::clients::RegistryClient;
use crate::dns::DnsConfig;
use crate::kbs::KbsPolicyConfig;
use crate::signing_service::SigningServiceClient;
use ed25519_dalek::SigningKey;
use enclava_engine::types::AttestationConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Shared application state accessible from all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Ed25519 signing key for config JWTs.
    pub signing_key: Arc<SigningKey>,
    /// HMAC key for session JWT signing.
    pub hmac_key: Arc<[u8; 32]>,
    /// Base URL of this API server (for config metadata sync callbacks).
    pub api_url: String,
    /// BTCPay Server base URL.
    pub btcpay_url: String,
    /// BTCPay Server API key.
    pub btcpay_api_key: String,
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
    /// BTCPay webhook HMAC secret for signature verification.
    pub btcpay_webhook_secret: String,
    /// Sidecar/runtime settings used when generating Kubernetes manifests.
    pub attestation: Option<AttestationConfig>,
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
}
