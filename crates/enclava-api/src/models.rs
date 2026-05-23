use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Enums ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "tier_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "provider_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Email,
    Nostr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "role_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "unlock_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UnlockMode {
    Auto,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "app_status_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    Creating,
    Running,
    Stopped,
    Failed,
    Deleting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "trigger_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    Api,
    Cli,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "deploy_status_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeployStatus {
    Pending,
    Applying,
    Watching,
    Healthy,
    Failed,
    #[serde(rename = "rolled_back")]
    #[sqlx(rename = "rolled_back")]
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "sub_status_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SubStatus {
    Active,
    Expired,
    #[serde(rename = "grace_period")]
    #[sqlx(rename = "grace_period")]
    GracePeriod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "payment_status_enum", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PaymentStatus {
    Pending,
    Confirmed,
    Expired,
}

// --- Row structs ---

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub tier: Tier,
    pub is_personal: bool,
    pub cust_slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: Provider,
    pub identifier: String,
    pub credential_hash: Option<String>,
    pub is_primary: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Membership {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct App {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub namespace: String,
    pub instance_id: String,
    pub tenant_id: String,
    pub service_account: String,
    pub bootstrap_owner_pubkey_hash: String,
    pub tenant_instance_identity_hash: String,
    pub unlock_mode: UnlockMode,
    pub domain: String,
    pub tee_domain: Option<String>,
    pub custom_domain: Option<String>,
    pub status: AppStatus,
    pub signer_identity_subject: Option<String>,
    pub signer_identity_issuer: Option<String>,
    pub signer_identity_set_at: Option<DateTime<Utc>>,
    pub source_provider: Option<String>,
    pub source_repository: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AppContainer {
    pub id: Uuid,
    pub app_id: Uuid,
    pub name: String,
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub port: Option<i32>,
    pub command: Option<String>,
    pub storage_paths: Option<Vec<String>>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AppResources {
    pub app_id: Uuid,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub app_data_size: String,
    pub tls_data_size: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Deployment {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub app_id: Uuid,
    pub trigger: Trigger,
    pub status: DeployStatus,
    pub spec_snapshot: serde_json::Value,
    pub manifest_hash: Option<String>,
    pub image_digest: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub cosign_verified: bool,
    pub provenance_attestation: Option<serde_json::Value>,
    pub sbom: Option<serde_json::Value>,
    pub external_id: Option<String>,
    pub source_provider: Option<String>,
    pub source_repository: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub org_id: Uuid,
    pub created_by: Uuid,
    pub key_hash: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Subscription {
    pub id: Uuid,
    pub org_id: Uuid,
    pub tier: Tier,
    pub status: SubStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Payment {
    pub id: Uuid,
    pub org_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub amount_sats: i64,
    pub btcpay_invoice_id: String,
    pub status: PaymentStatus,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ConfigMetadata {
    pub id: Uuid,
    pub app_id: Uuid,
    pub key_name: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
