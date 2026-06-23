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

#[derive(Debug, Serialize)]
pub struct DeviceLoginStartRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Serialize)]
pub struct DeviceLoginPollRequest {
    pub device_code: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginPollResponse {
    pub status: String,
    pub interval: i64,
    pub expires_in: i64,
    pub error: Option<String>,
    pub auth: Option<AuthResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CurrentUserResponse {
    pub user_id: String,
    pub display_name: String,
    pub active_org: CurrentUserOrg,
    pub orgs: Vec<CurrentUserOrg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CurrentUserOrg {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_personal: bool,
    #[serde(default)]
    pub entitlement_class: Option<String>,
    #[serde(default)]
    pub deploy_allowed: Option<bool>,
    #[serde(default)]
    pub deploy_block_reason: Option<String>,
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
pub struct SignerRotationTokenRequest {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Deserialize)]
pub struct SignerRotationTokenResponse {
    pub token: String,
    pub expires_in_seconds: u64,
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

// --- Hosted Templates ---

#[derive(Debug, Clone, Deserialize)]
pub struct HostedTemplate {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub image: String,
    pub config_keys: Vec<HostedTemplateConfigKey>,
    #[serde(default)]
    pub persistence_path: Option<String>,
    #[serde(default)]
    pub security_notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostedTemplateConfigKey {
    pub key: String,
    pub label: String,
    pub description: String,
    pub input_type: String,
    pub required: bool,
    pub secret: bool,
    #[serde(default)]
    pub default_value: Option<String>,
    #[serde(default)]
    pub validation: Option<HostedTemplateConfigValidation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostedTemplateConfigValidation {
    #[serde(default)]
    pub max_bytes: Option<u32>,
    #[serde(default)]
    pub max_items: Option<u32>,
    #[serde(default)]
    pub allowed_algorithms: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateTemplateInstanceRequest {
    pub template_slug: String,
    pub instance_name: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct TemplateInstanceResponse {
    pub template: HostedTemplate,
    pub app: serde_json::Value,
    pub deployment: TemplateDeploymentResponse,
    pub config_token: Option<ConfigTokenResponse>,
    pub cap: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct TemplateDeploymentResponse {
    pub cap_deployment_id: Option<String>,
    pub status: String,
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

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentContextResponse {
    pub api_signing_pubkey: String,
    #[serde(default)]
    pub tls_certificate_broker_url: Option<String>,
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
    #[serde(default)]
    pub tee_url: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
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

#[derive(Debug)]
pub struct ConfigKeysResponse {
    pub keys: Vec<ConfigKeyMeta>,
}

impl<'de> Deserialize<'de> for ConfigKeysResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Wrapped { keys: Vec<ConfigKeyMeta> },
            Bare(Vec<ConfigKeyMeta>),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Wrapped { keys } | Wire::Bare(keys) => Ok(Self { keys }),
        }
    }
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
    #[serde(alias = "deployment_id")]
    pub id: String,
    pub status: String,
    pub image_digest: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
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
    pub entitlement_class: String,
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
    pub message: Option<String>,
    pub detail: Option<String>,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ConfigKeysResponse, ConfigTokenResponse};

    #[test]
    fn config_token_accepts_live_api_shape() {
        let parsed: ConfigTokenResponse = serde_json::from_value(serde_json::json!({
            "token": "jwt",
            "tee_url": "https://app.example/.well-known/confidential/config",
            "expires_in_seconds": 300,
        }))
        .expect("live config-token response should decode");

        assert_eq!(parsed.token, "jwt");
        assert_eq!(
            parsed.tee_url.as_deref(),
            Some("https://app.example/.well-known/confidential/config")
        );
        assert_eq!(parsed.expires_in_seconds, Some(300));
        assert_eq!(parsed.expires_at, None);
    }

    #[test]
    fn config_keys_accepts_live_api_array_shape() {
        let parsed: ConfigKeysResponse = serde_json::from_value(serde_json::json!([
            {
                "key": "DATABASE_URL",
                "updated_at": "2026-05-09T17:00:00Z"
            }
        ]))
        .expect("live config key list response should decode");

        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].key, "DATABASE_URL");
    }

    #[test]
    fn config_keys_accepts_wrapped_shape() {
        let parsed: ConfigKeysResponse = serde_json::from_value(serde_json::json!({
            "keys": [
                {
                    "key": "DATABASE_URL",
                    "updated_at": "2026-05-09T17:00:00Z"
                }
            ]
        }))
        .expect("wrapped config key list response should decode");

        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].key, "DATABASE_URL");
    }
}
