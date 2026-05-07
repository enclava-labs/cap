//! Request and response types for the Platform API.
//! These mirror the API's JSON contract. They are CLI-local types,
//! not shared with the API crate (the CLI does not depend on enclava-api).

use serde::{Deserialize, Serialize};

// --- Auth ---

#[derive(Debug, Serialize)]
pub struct SignupRequest {
    pub provider: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub npub: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub provider: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub npub: Option<String>,
    /// NIP-98 signed event (JSON string)
    pub nostr_event: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: String,
    pub org_id: String,
    pub org_name: String,
}

// --- Apps ---

#[derive(Debug, Serialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub port: u16,
    pub image: Option<String>,
    pub unlock_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_pubkey_hash: Option<String>,
    pub storage_size: String,
    pub tls_storage_size: String,
    pub storage_paths: Vec<String>,
    pub cpu: String,
    pub memory: String,
    pub services: Vec<ServiceSpec>,
    pub health_path: Option<String>,
    pub health_interval: Option<u32>,
    pub health_timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity_issuer: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SetSignerRequest {
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmation_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub port: Option<u16>,
    pub storage_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub instance_id: String,
    #[serde(default)]
    pub service_account: Option<String>,
    #[serde(default)]
    pub bootstrap_owner_pubkey_hash: Option<String>,
    #[serde(default)]
    pub tenant_instance_identity_hash: Option<String>,
    pub domain: String,
    #[serde(default)]
    pub tee_domain: Option<String>,
    pub custom_domain: Option<String>,
    pub status: String,
    pub unlock_mode: String,
    #[serde(default)]
    pub signer_identity_subject: Option<String>,
    #[serde(default)]
    pub signer_identity_issuer: Option<String>,
    pub created_at: String,
}

// --- Deploy ---

#[derive(Debug, Serialize)]
pub struct DeployRequest {
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_descriptor_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_keyring_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_policy_artifact: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeployResponse {
    pub deployment_id: String,
    pub status: String,
    pub app_domain: String,
}

#[derive(Debug, Serialize)]
pub struct AgentPolicyRequest {
    pub descriptor: enclava_common::descriptor::DeploymentDescriptor,
}

#[derive(Debug, Deserialize)]
pub struct AgentPolicyResponse {
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
}

// --- Status ---

#[derive(Debug, Deserialize)]
pub struct AppStatus {
    pub app_name: String,
    pub status: String,
    pub pod_phase: Option<String>,
    pub tee_status: Option<String>,
    pub unlock_status: Option<String>,
    pub domain: String,
    pub last_deployed: Option<String>,
}

// --- Logs ---

#[derive(Debug, Deserialize)]
pub struct LogLine {
    pub timestamp: String,
    pub container: String,
    pub message: String,
}

// --- Config ---

#[derive(Debug, Deserialize)]
pub struct ConfigTokenResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockStatusResponse {
    pub unlock_mode: String,
    pub tee_url: String,
    pub ownership_state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUnlockModeRequest {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_receipt: Option<SignedReceiptResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_attestation: Option<TransitionReceiptAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_descriptor_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_keyring_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_policy_artifact: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUnlockModeResponse {
    pub app_name: String,
    pub unlock_mode: String,
    pub deployment_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceiptResponse {
    pub operation: String,
    pub payload: ReceiptPayloadView,
    pub receipt: ReceiptEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPayloadView {
    pub purpose: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_quote_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value_sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub pubkey: String,
    pub pubkey_sha256: String,
    pub payload_canonical_bytes: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionReceiptAttestation {
    pub tee_domain: String,
    pub nonce: String,
    pub leaf_spki_sha256: String,
    pub receipt_pubkey_sha256: String,
    pub attestation_evidence_sha256: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigKeysResponse {
    pub keys: Vec<ConfigKeyMeta>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigKeyMeta {
    pub key: String,
    pub updated_at: String,
}

// --- Domains ---

#[derive(Debug, Serialize)]
pub struct CreateChallengeRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub domain: String,
    pub txt_record_name: String,
    pub txt_record_value: String,
    pub expires_at: String,
    pub instructions: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyResponse {
    pub domain: String,
    pub verified_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DomainResponse {
    pub platform_domain: String,
    pub tee_domain: Option<String>,
    pub custom_domain: Option<String>,
}

// --- Rollback ---

#[derive(Debug, Serialize)]
pub struct RollbackRequest {
    pub deployment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RollbackResponse {
    pub deployment_id: String,
    pub rolled_back_to: String,
    pub status: String,
}

// --- Deployments ---

#[derive(Debug, Deserialize)]
pub struct DeploymentEntry {
    pub id: String,
    pub status: String,
    pub image_digest: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// --- Billing ---

#[derive(Debug, Deserialize)]
pub struct TierInfo {
    pub name: String,
    pub max_apps: u32,
    pub max_cpu: String,
    pub max_memory: String,
    pub max_storage: String,
    pub price_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct InvoiceResponse {
    pub invoice_id: String,
    pub payment_url: String,
    pub amount_sats: u64,
    pub lightning_invoice: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct BillingStatus {
    pub tier: String,
    pub status: String,
    pub period_end: Option<String>,
    #[serde(default)]
    pub grace_period_ends: Option<String>,
}

// --- Orgs ---

#[derive(Debug, Serialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct OrgResponse {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub display_name: Option<String>,
    pub tier: String,
    pub is_personal: bool,
}

#[derive(Debug, Serialize)]
pub struct InviteRequest {
    pub identifier: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterPublicKeyRequest {
    pub public_key: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPublicKeyResponse {
    pub id: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct PutOrgKeyringRequest {
    pub version: u64,
    pub keyring_payload: serde_json::Value,
    pub signature: String,
    pub signing_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct OrgKeyringResponse {
    pub org_id: String,
    pub version: u64,
    pub keyring_payload: serde_json::Value,
    pub signature: String,
    pub signing_pubkey: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct BootstrapSigningServiceRequest {
    pub owner_pubkey_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapSigningServiceResponse {
    pub org_id: String,
    pub state: String,
    pub owner_pubkey_fingerprint: String,
}

#[derive(Debug, Deserialize)]
pub struct MemberResponse {
    pub user_id: String,
    pub display_name: Option<String>,
    pub role: String,
}

// --- Unlock ---

#[derive(Debug, Deserialize)]
pub struct UnlockEndpointResponse {
    pub tee_url: String,
    pub unlock_endpoint: String,
    pub claim_endpoint: String,
}

// --- Errors ---

#[derive(Debug, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub detail: Option<String>,
}
