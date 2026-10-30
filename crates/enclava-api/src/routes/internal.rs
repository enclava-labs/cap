use axum::{
    Extension, Json,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::middleware::{AuthContext, ManagementOrigin};
use crate::models::Role;
use crate::routes::deployments::public_deployment_error_message;
use crate::routes::platform::{DeploymentContextResponse, deployment_context_response};
use crate::routes::status::observe_app_status_fields_for_deployment;
use crate::state::AppState;

type InternalRouteError = (StatusCode, Json<serde_json::Value>);
type IdempotencyResponse = (StatusCode, serde_json::Value);

const IDEMPOTENCY_DEFAULT_LEASE_SECONDS: i64 = 60;
const IDEMPOTENCY_LEGACY_STALE_SECONDS: i64 = 30 * 60;
const IDEMPOTENCY_RETRY_DEFER_SECONDS: i64 = 5;

/// Upper bound for a stamped `retry_after` hint. The deferral lease windows
/// are seconds-to-minutes; the cap only exists so a corrupt or hand-edited
/// lease row cannot push callers into absurd waits. Raise it if a legitimate
/// deferral lease ever exceeds it (today: 5s defer, 60s reservation leases).
pub(crate) const IDEMPOTENCY_RETRY_HINT_MAX_SECONDS: i64 = 300;
const CONFIG_TOKEN_HARD_ATTEMPT_SECONDS: u64 = 30;
const CONFIG_TOKEN_CANCELLATION_SECONDS: u64 = 5;
const CONFIG_TOKEN_RECEIPT_LEASE_SECONDS: i64 = 60;
const CONFIG_TOKEN_SAFE_RETURN_SECONDS: i64 = CONFIG_TOKEN_HARD_ATTEMPT_SECONDS as i64;
const PROOF_BUNDLE_MEDIA_TYPE: &str = "application/vnd.enclava.proof-bundle.v1";
const MAX_PROOF_BUNDLE_BYTES: usize = 1_048_576;

#[derive(Debug, sqlx::FromRow)]
struct IdempotencyRow {
    method: String,
    path: String,
    request_hash: Vec<u8>,
    response_status: Option<i32>,
    response_body: Option<serde_json::Value>,
    reservation_token: Option<Uuid>,
    operation_id: Option<Uuid>,
    lease_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    recovery_kind: Option<String>,
    capability_receipt_version: Option<i16>,
    capability_resource_id: Option<Uuid>,
    capability_instance_id: Option<String>,
    known_not_applied: bool,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    database_now: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdempotencyRecovery {
    RetrySafe,
    DeterministicResource { legacy_identity_bound: bool },
    ExpiringCapability { recovery_after_seconds: i64 },
    DeterministicExpiringCapability,
    FailClosed,
}

impl IdempotencyRecovery {
    fn kind(self) -> &'static str {
        match self {
            Self::RetrySafe => "retry_safe",
            Self::DeterministicResource { .. } => "deterministic_resource",
            Self::ExpiringCapability { .. } => "expiring_capability",
            Self::DeterministicExpiringCapability => "deterministic_expiring_capability",
            Self::FailClosed => "fail_closed",
        }
    }

    fn lease_seconds(self) -> i64 {
        match self {
            Self::ExpiringCapability {
                recovery_after_seconds,
            } => recovery_after_seconds,
            Self::DeterministicExpiringCapability => CONFIG_TOKEN_RECEIPT_LEASE_SECONDS,
            _ => IDEMPOTENCY_DEFAULT_LEASE_SECONDS,
        }
    }

    fn refreshes_lease(self) -> bool {
        !matches!(self, Self::DeterministicExpiringCapability)
    }
}

enum IdempotencyBegin {
    Execute(IdempotencyLease),
    Replay(IdempotencyResponse),
}

struct IdempotencyLease {
    pool: sqlx::PgPool,
    key: String,
    token: Uuid,
    operation_id: Uuid,
    reclaimed: bool,
    regenerate: bool,
    committed_keyring_checkpoint: bool,
    config_token_receipt: Option<ConfigTokenReceipt>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

struct IdempotencyLeaseClaim {
    operation_id: Uuid,
    reclaimed: bool,
    regenerate: bool,
    committed_keyring_checkpoint: bool,
    config_token_receipt: Option<ConfigTokenReceipt>,
}

#[derive(Clone, Debug)]
struct ConfigTokenReceipt {
    operation_id: Uuid,
    receipt_version: i16,
    resource_id: Uuid,
    instance_id: String,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigTokenResourceBinding {
    resource_id: Uuid,
    instance_id: String,
}

impl ConfigTokenReceipt {
    fn new(
        operation_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
        receipt_version: i16,
        binding: ConfigTokenResourceBinding,
    ) -> Self {
        let issued_at = chrono::DateTime::from_timestamp(created_at.timestamp(), 0)
            .expect("PostgreSQL timestamptz has a representable whole-second value");
        Self {
            operation_id,
            receipt_version,
            resource_id: binding.resource_id,
            instance_id: binding.instance_id,
            issued_at,
            expires_at: issued_at
                + chrono::Duration::seconds(crate::auth::jwt::CONFIG_TOKEN_TTL_SECONDS),
        }
    }

    fn issuance(&self) -> crate::auth::jwt::ConfigTokenIssuance {
        crate::auth::jwt::ConfigTokenIssuance {
            receipt_version: self.receipt_version,
            issued_at: self.issued_at,
            jti: format!("cap-config-receipt-v1-{}", self.operation_id),
            resource_id: self.resource_id,
            instance_id: self.instance_id.clone(),
        }
    }
}

#[derive(Clone)]
struct IdempotencyCancellation {
    pool: sqlx::PgPool,
    key: String,
    token: Uuid,
}

impl IdempotencyLease {
    fn new(
        pool: sqlx::PgPool,
        key: String,
        token: Uuid,
        claim: IdempotencyLeaseClaim,
        recovery: IdempotencyRecovery,
    ) -> Self {
        let lease_seconds = recovery.lease_seconds();
        let heartbeat_pool = pool.clone();
        let heartbeat_key = key.clone();
        let heartbeat = recovery.refreshes_lease().then(|| {
            tokio::spawn(async move {
                let refresh_seconds = (lease_seconds / 3).max(1) as u64;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(refresh_seconds)).await;
                    match sqlx::query(
                        "UPDATE cap_internal_idempotency
                            SET lease_expires_at = clock_timestamp()
                                + ($3::bigint * interval '1 second'),
                                updated_at = clock_timestamp()
                          WHERE idempotency_key = $1
                            AND reservation_token = $2
                            AND completed_at IS NULL",
                    )
                    .bind(&heartbeat_key)
                    .bind(token)
                    .bind(lease_seconds)
                    .execute(&heartbeat_pool)
                    .await
                    {
                        Ok(result) if result.rows_affected() == 1 => {}
                        Ok(_) => return,
                        // A transient database failure must not spin. Retry on
                        // the next interval while the DB deadline is authority.
                        Err(_) => {}
                    }
                }
            })
        });
        Self {
            pool,
            key,
            token,
            operation_id: claim.operation_id,
            reclaimed: claim.reclaimed,
            regenerate: claim.regenerate,
            committed_keyring_checkpoint: claim.committed_keyring_checkpoint,
            config_token_receipt: claim.config_token_receipt,
            heartbeat,
        }
    }
    fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    fn reclaimed(&self) -> bool {
        self.reclaimed
    }

    fn config_token_receipt(&self) -> Option<&ConfigTokenReceipt> {
        self.config_token_receipt.as_ref()
    }

    fn cancellation(&self) -> IdempotencyCancellation {
        IdempotencyCancellation {
            pool: self.pool.clone(),
            key: self.key.clone(),
            token: self.token,
        }
    }

    fn stop_heartbeat(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
    }
}

impl Drop for IdempotencyLease {
    fn drop(&mut self) {
        self.stop_heartbeat();
    }
}

const STATUS_OBSERVATION_CONCURRENCY: usize = 16;

pub struct InternalAuth {
    pub client_san: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InternalAuthError {
    #[error("internal route authentication is not configured")]
    NotConfigured,
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid bearer token")]
    InvalidToken,
    #[error("missing client certificate identity")]
    MissingClientIdentity,
    #[error("client certificate identity is not allowed")]
    ClientIdentityNotAllowed,
    #[error("missing trusted internal proxy proof")]
    MissingTrustedProxy,
    #[error("invalid trusted internal proxy proof")]
    InvalidTrustedProxy,
}

impl IntoResponse for InternalAuthError {
    fn into_response(self) -> Response {
        let status = match self {
            InternalAuthError::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            InternalAuthError::MissingToken
            | InternalAuthError::InvalidToken
            | InternalAuthError::MissingClientIdentity
            | InternalAuthError::ClientIdentityNotAllowed
            | InternalAuthError::MissingTrustedProxy
            | InternalAuthError::InvalidTrustedProxy => StatusCode::UNAUTHORIZED,
        };
        (status, Json(serde_json::json!({"error": self.to_string()}))).into_response()
    }
}

impl FromRequestParts<AppState> for InternalAuth {
    type Rejection = InternalAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(config) = state
            .internal_auth
            .as_ref()
            .filter(|config| config.is_usable())
        else {
            return Err(InternalAuthError::NotConfigured);
        };

        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(InternalAuthError::MissingToken)?;
        if !config.accepts_token(token) {
            return Err(InternalAuthError::InvalidToken);
        }

        let proxy_secret = parts
            .headers
            .get("x-enclava-internal-proxy-secret")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(InternalAuthError::MissingTrustedProxy)?;
        if !config.accepts_trusted_proxy_secret(proxy_secret) {
            return Err(InternalAuthError::InvalidTrustedProxy);
        }

        let client_san = parts
            .headers
            .get("x-enclava-internal-client-san")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(InternalAuthError::MissingClientIdentity)?;
        if !config.accepts_client_san(client_san) {
            return Err(InternalAuthError::ClientIdentityNotAllowed);
        }

        Ok(Self {
            client_san: client_san.to_string(),
        })
    }
}

pub async fn paas_deployment_context(
    _auth: InternalAuth,
    State(state): State<AppState>,
) -> Json<DeploymentContextResponse> {
    Json(deployment_context_response(&state))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertPaaSOrgRequest {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default = "default_active_status")]
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncPaaSMemberRequest {
    pub display_name: String,
    pub role: String,
    pub active: bool,
    #[serde(default)]
    pub version: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncPaaSEntitlementRequest {
    pub version: i64,
    pub deploy_allowed: bool,
    #[serde(default)]
    pub block_reason: Option<String>,
    pub limits: crate::entitlements::EntitlementLimits,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalCreateAppRequest {
    pub name: String,
    // Preserve durable retry hashes; new requests with this legacy default are refused.
    #[serde(default = "default_unlock_mode")]
    pub unlock_mode: String,
    #[serde(default)]
    pub bootstrap_pubkey_hash: Option<String>,
    #[serde(default)]
    pub signer_identity_subject: Option<String>,
    #[serde(default)]
    pub signer_identity_issuer: Option<String>,
    #[serde(default)]
    pub egress_allowlist: Vec<crate::routes::apps::CreateEgressAllowRule>,
    #[serde(default = "crate::routes::apps::default_egress_mode")]
    pub egress_mode: String,
    /// Optional initial resource overrides (cpu/memory/storage/tls_storage).
    /// Absent fields keep the hosted defaults; values are still checked
    /// against the org's entitlement before the app is committed. Skipped in
    /// serialization so replayed pre-upgrade requests keep their persisted
    /// idempotency fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<crate::routes::deployments::DeployResources>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InternalAppDesiredState {
    Running,
    Stopped,
}

impl InternalAppDesiredState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InternalAppDesiredStateRequest {
    pub desired_state: InternalAppDesiredState,
    pub operation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalDeployRequest {
    pub image: String,
    #[serde(default)]
    pub container_name: Option<String>,
    #[serde(default)]
    pub resources: Option<crate::routes::deployments::DeployResources>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub customer_descriptor_blob: Option<String>,
    #[serde(default)]
    pub org_keyring_blob: Option<String>,
    #[serde(default)]
    pub signed_policy_artifact: Option<String>,
    #[serde(default)]
    pub workload_security_profile: Option<String>,
    #[serde(default)]
    pub log_encryption: Option<enclava_engine::types::LogEncryptionConfig>,
}

#[derive(Debug, Serialize)]
pub struct InternalListResponse {
    pub items: Vec<serde_json::Value>,
}

fn default_active_status() -> String {
    "active".to_string()
}

fn default_unlock_mode() -> String {
    "auto".to_string()
}

fn json_error(
    status: StatusCode,
    error: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": error.into()})))
}

/// Body for every `idempotency_request_in_progress` response: the request is
/// deferred under a live (or reapplied) lease and the caller must retry with
/// the same key. Every in-progress 409 routes through this body so
/// disposition-driven callers see one uniform contract -- live-lease retries
/// (`begin_idempotent_request_with_recovery`), the deterministic config-token
/// cutoff deferrals, the explicit `defer_idempotent_request`, and the
/// cancel-after-transient-conflict path all carry the same stamp. The explicit
/// `idempotency_disposition: "deferred"` field distinguishes a CAP-intentional
/// defer (retain intent, retry same key) from a missing field (conservative
/// fallback) without inferring it from the status code.
fn idempotency_in_progress_error() -> InternalRouteError {
    // Contract row 2: the lease is incomplete and a same-key retry re-executes
    // once it frees. Every such response is semantically "deferred"; stamp it
    // centrally so callers no longer lean on the legacy `disposition` field.
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "idempotency_request_in_progress",
            "retryable": true,
            "disposition": "retry_same_key",
            "idempotency_disposition": "deferred",
        })),
    )
}

/// The deferred-409 contract with a server-clock lease hint attached: whole
/// seconds until a same-key retry can re-execute. Only call this where the
/// lease window is actually known (the live-lease `!reclaimable` branch and
/// the explicit defer, which both know the expiry they just read/wrote);
/// sites without a known window return the bare contract and callers treat a
/// missing `retry_after` as "retry same key, unknown wait".
fn idempotency_in_progress_with_retry(seconds: i64) -> InternalRouteError {
    let (status, Json(mut body)) = idempotency_in_progress_error();
    body["retry_after"] = serde_json::json!(seconds.clamp(1, IDEMPOTENCY_RETRY_HINT_MAX_SECONDS));
    (status, Json(body))
}

fn idempotency_key_reused_error() -> InternalRouteError {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "idempotency_key_reused",
            "retryable": false,
            "disposition": "retry_with_new_key",
        })),
    )
}

fn idempotency_resource_conflict_error() -> InternalRouteError {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "idempotency_resource_conflict",
            "retryable": false,
            "disposition": "reconcile_then_retry_with_new_key",
        })),
    )
}

fn db_error() -> (StatusCode, Json<serde_json::Value>) {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn validate_external_id(
    value: &str,
    label: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if value.trim() != value || value.is_empty() || value.len() > 200 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("{label} must be non-empty, unpadded, and at most 200 characters"),
        ));
    }
    Ok(())
}

fn validate_org_name(name: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || !name.chars().next().unwrap().is_ascii_alphanumeric()
        || !name.chars().last().unwrap().is_ascii_alphanumeric()
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "name must be a DNS-safe lowercase organization name",
        ));
    }
    Ok(())
}

fn parse_status(status: &str) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    match status {
        "active" | "suspended" | "deleted" => Ok(status),
        _ => Err(json_error(
            StatusCode::BAD_REQUEST,
            "status must be active, suspended, or deleted",
        )),
    }
}

fn parse_role(role: &str) -> Result<Role, (StatusCode, Json<serde_json::Value>)> {
    match role {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        _ => Err(json_error(
            StatusCode::BAD_REQUEST,
            "role must be owner, admin, or member",
        )),
    }
}

fn role_as_str(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

const PAAS_USER_MAPPING_LANE_DOMAIN: i32 = 0x5055_5345;

fn paas_user_mapping_lane_key(paas_user_id: &str) -> i32 {
    let digest = Sha256::digest(paas_user_id.as_bytes());
    i32::from_be_bytes(digest[..4].try_into().expect("SHA-256 word"))
}

/// Serialize creation of the global PaaS-user mapping.
///
/// Lock order is organization entitlement -> organization signing -> PaaS
/// user mapping -> app. No path acquires an organization lane after this
/// mapping lane, so the same hosted user can be synced into multiple orgs
/// without a reverse-order deadlock or duplicate local user.
async fn lock_paas_user_mapping_lane(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    paas_user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(PAAS_USER_MAPPING_LANE_DOMAIN)
        .bind(paas_user_mapping_lane_key(paas_user_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn write_membership_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
    active: bool,
) -> Result<(), sqlx::Error> {
    let removed_at: Option<chrono::DateTime<chrono::Utc>> = (!active).then(chrono::Utc::now);
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, removed_at)
         VALUES ($1, $2, $3::role_enum, $4)
         ON CONFLICT (user_id, org_id) DO UPDATE
            SET role = EXCLUDED.role,
                removed_at = EXCLUDED.removed_at",
    )
    .bind(user_id)
    .bind(org_id)
    .bind(role)
    .bind(removed_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

struct MembershipAuthorityAudit<'a> {
    org_id: Uuid,
    user_id: Uuid,
    role: &'a str,
    active: bool,
    version: i64,
    client_san: &'a str,
    repair: bool,
}

async fn audit_membership_authority_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: MembershipAuthorityAudit<'_>,
) -> Result<(), sqlx::Error> {
    let mut detail = serde_json::json!({
        "role": audit.role,
        "active": audit.active,
        "version": audit.version,
        "client_san": audit.client_san,
    });
    if audit.repair {
        detail["repair"] = serde_json::Value::String("legacy_membership_projection".to_string());
    }
    sqlx::query(
        "INSERT INTO audit_log (org_id, user_id, action, detail)
         VALUES ($1, $2, 'org.member.sync', $3)",
    )
    .bind(audit.org_id)
    .bind(audit.user_id)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn request_hash<T: Serialize>(body: &T) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    let bytes = serde_json::to_vec(body).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize request body",
        )
    })?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "idempotency-key header is required",
            )
        })
}

async fn begin_idempotent_request(
    state: &AppState,
    key: &str,
    method: &str,
    path: &str,
    hash: &[u8],
) -> Result<IdempotencyBegin, InternalRouteError> {
    begin_idempotent_request_with_recovery(
        state,
        key,
        method,
        path,
        hash,
        IdempotencyRecovery::RetrySafe,
    )
    .await
}

fn idempotency_operation_id(key: &str, method: &str, path: &str, hash: &[u8]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"enclava-cap-internal-idempotency-operation-v1\0");
    for part in [key.as_bytes(), method.as_bytes(), path.as_bytes(), hash] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: deterministic application-defined payload.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn idempotency_deployment_external_id(operation_id: Uuid) -> String {
    format!("cap-internal-idempotency-{operation_id}")
}

async fn set_idempotency_completion_owner(
    connection: &mut sqlx::PgConnection,
    token: Uuid,
) -> Result<(), InternalRouteError> {
    sqlx::query_scalar::<_, String>(
        "SELECT set_config('enclava.idempotency_reservation_token', $1, true)",
    )
    .bind(token.to_string())
    .fetch_one(connection)
    .await
    .map_err(|_| db_error())?;
    Ok(())
}

fn idempotency_recovery_required_body() -> serde_json::Value {
    serde_json::json!({
        "error": "idempotency_recovery_required",
        "retryable": false,
        "disposition": "reconcile_then_retry_with_new_key",
        "idempotency_disposition": "completed",
    })
}

async fn complete_unrecoverable_idempotency_request(
    pool: &sqlx::PgPool,
    key: &str,
    previous_token: Option<Uuid>,
    token: Uuid,
    operation_id: Uuid,
    recovery_kind: &str,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let mut tx = pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, previous_token.unwrap_or(token)).await?;
    // The same body is cached and returned so a disposition-driven caller
    // always terminalizes the consumed key through the completed channel.
    let body = idempotency_recovery_required_body();
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET reservation_token = $2,
                operation_id = COALESCE(operation_id, $3),
                recovery_kind = COALESCE(recovery_kind, $4),
                response_status = $5,
                response_body = $6,
                completed_at = clock_timestamp(),
                updated_at = clock_timestamp(),
                attempt_count = attempt_count + 1
          WHERE idempotency_key = $1
            AND completed_at IS NULL
            AND reservation_token IS NOT DISTINCT FROM $7
            AND (
                ($7::uuid IS NULL AND updated_at <= clock_timestamp()
                    - ($8::bigint * interval '1 second'))
                OR ($7::uuid IS NOT NULL AND lease_expires_at <= clock_timestamp())
            )",
    )
    .bind(key)
    .bind(token)
    .bind(operation_id)
    .bind(recovery_kind)
    .bind(StatusCode::CONFLICT.as_u16() as i32)
    .bind(&body)
    .bind(previous_token)
    .bind(IDEMPOTENCY_LEGACY_STALE_SECONDS)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(idempotency_in_progress_error());
    }
    tx.commit().await.map_err(|_| db_error())?;
    Ok(IdempotencyBegin::Replay((StatusCode::CONFLICT, body)))
}

fn is_paas_config_token_idempotency_path(method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }
    let Some(rest) = path.strip_prefix("/internal/paas/orgs/") else {
        return false;
    };
    let segments = rest.split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        [org, "apps", app, "config-token"] => !org.is_empty() && !app.is_empty(),
        [org, "deployments", deployment_id, "config-token"] => {
            !org.is_empty() && Uuid::parse_str(deployment_id).is_ok()
        }
        _ => false,
    }
}

fn expired_config_token_body(
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    legacy: bool,
) -> serde_json::Value {
    if legacy {
        serde_json::json!({
            "error": "idempotency_capability_expired",
            "retryable": false,
            "disposition": "new_key_after_expiry",
            "proof_version": "legacy_expiring_capability_lease_v1",
            "recovery_after": expires_at,
        })
    } else {
        serde_json::json!({
            "error": "idempotency_capability_expired",
            "retryable": false,
            "disposition": "new_key_after_expiry",
            "proof_version": "deterministic_config_token_receipt_v1",
            "capability_issued_at": issued_at,
            "capability_expires_at": expires_at,
        })
    }
}

struct ExpiredConfigTokenReceipt<'a> {
    key: &'a str,
    previous_token: Option<Uuid>,
    operation_id: Uuid,
    stored_recovery_kind: &'a str,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    legacy: bool,
}

async fn terminalize_expired_config_token_receipt(
    pool: &sqlx::PgPool,
    receipt: ExpiredConfigTokenReceipt<'_>,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let terminal_token = receipt.previous_token.unwrap_or_else(Uuid::new_v4);
    let body = expired_config_token_body(receipt.issued_at, receipt.expires_at, receipt.legacy);
    let mut tx = pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, terminal_token).await?;
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET reservation_token = $2,
                operation_id = COALESCE(operation_id, $3),
                response_status = $4,
                response_body = $5,
                completed_at = COALESCE(completed_at, clock_timestamp()),
                lease_expires_at = CASE WHEN $9 THEN lease_expires_at ELSE NULL END,
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token IS NOT DISTINCT FROM $6
            AND recovery_kind = $7
            AND response_status IS NULL
            AND $8::timestamptz <= clock_timestamp()
            AND (
                NOT $9
                OR completed_at IS NOT NULL
                OR lease_expires_at IS NULL
                OR lease_expires_at <= clock_timestamp()
            )",
    )
    .bind(receipt.key)
    .bind(terminal_token)
    .bind(receipt.operation_id)
    .bind(StatusCode::CONFLICT.as_u16() as i32)
    .bind(&body)
    .bind(receipt.previous_token)
    .bind(receipt.stored_recovery_kind)
    .bind(receipt.expires_at)
    .bind(receipt.legacy)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() == 1 {
        tx.commit().await.map_err(|_| db_error())?;
        return Ok(IdempotencyBegin::Replay((StatusCode::CONFLICT, body)));
    }
    tx.rollback().await.map_err(|_| db_error())?;

    let replay: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT response_status, response_body
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND response_status IS NOT NULL",
    )
    .bind(receipt.key)
    .fetch_optional(pool)
    .await
    .map_err(|_| db_error())?;
    if let Some((status, body)) = replay {
        let status = StatusCode::from_u16(status as u16).map_err(|_| db_error())?;
        return Ok(IdempotencyBegin::Replay((status, body)));
    }
    Err(idempotency_in_progress_error())
}

async fn sanitize_legacy_completed_config_token_response(
    pool: &sqlx::PgPool,
    key: &str,
    previous_token: Option<Uuid>,
    operation_id: Uuid,
    issued_at: chrono::DateTime<chrono::Utc>,
    recovery_after: chrono::DateTime<chrono::Utc>,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let terminal_token = previous_token.unwrap_or_else(Uuid::new_v4);
    let body = expired_config_token_body(issued_at, recovery_after, true);
    let mut tx = pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, terminal_token).await?;
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET reservation_token = $2,
                operation_id = COALESCE(operation_id, $3),
                response_status = $4,
                response_body = $5,
                completed_at = COALESCE(completed_at, clock_timestamp()),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token IS NOT DISTINCT FROM $6
            AND response_status BETWEEN 200 AND 299",
    )
    .bind(key)
    .bind(terminal_token)
    .bind(operation_id)
    .bind(StatusCode::CONFLICT.as_u16() as i32)
    .bind(&body)
    .bind(previous_token)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(idempotency_in_progress_error());
    }
    tx.commit().await.map_err(|_| db_error())?;
    Ok(IdempotencyBegin::Replay((StatusCode::CONFLICT, body)))
}

async fn begin_idempotent_request_with_recovery(
    state: &AppState,
    key: &str,
    method: &str,
    path: &str,
    hash: &[u8],
    recovery: IdempotencyRecovery,
) -> Result<IdempotencyBegin, InternalRouteError> {
    begin_idempotent_request_with_recovery_and_binding(
        state,
        key,
        method,
        path,
        hash,
        recovery,
        ConfigTokenIdempotencyOptions::default(),
    )
    .await
}

#[derive(Default)]
struct ConfigTokenIdempotencyOptions<'a> {
    binding: Option<&'a ConfigTokenResourceBinding>,
    legacy_request_hash: Option<&'a [u8]>,
}

fn config_token_receipt_from_row(
    row: &IdempotencyRow,
    fallback_operation_id: Uuid,
) -> Result<ConfigTokenReceipt, InternalRouteError> {
    Ok(ConfigTokenReceipt::new(
        row.operation_id.unwrap_or(fallback_operation_id),
        row.created_at,
        row.capability_receipt_version.ok_or_else(db_error)?,
        ConfigTokenResourceBinding {
            resource_id: row.capability_resource_id.ok_or_else(db_error)?,
            instance_id: row.capability_instance_id.clone().ok_or_else(db_error)?,
        },
    ))
}

fn is_safe_migrated_legacy_config_token_terminal(row: &IdempotencyRow) -> bool {
    if !matches!(
        row.recovery_kind.as_deref(),
        None | Some("expiring_capability")
    ) || row.completed_at.is_none()
        || row.response_status != Some(StatusCode::CONFLICT.as_u16() as i32)
    {
        return false;
    }
    let Some(body) = row
        .response_body
        .as_ref()
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    if body.len() != 5
        || body.get("error").and_then(serde_json::Value::as_str)
            != Some("idempotency_capability_expired")
        || body.get("retryable").and_then(serde_json::Value::as_bool) != Some(false)
        || body.get("disposition").and_then(serde_json::Value::as_str)
            != Some("new_key_after_expiry")
        || body
            .get("proof_version")
            .and_then(serde_json::Value::as_str)
            != Some("legacy_expiring_capability_lease_v1")
    {
        return false;
    }
    let Some(recovery_after) = body
        .get("recovery_after")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
    else {
        return false;
    };
    let issued_at = chrono::DateTime::from_timestamp(row.created_at.timestamp(), 0)
        .expect("PostgreSQL timestamptz has a whole-second value");
    let minimum_recovery_after = issued_at + chrono::Duration::seconds(6 * 60);
    let expected_recovery_after = row
        .lease_expires_at
        .map(|lease| lease.max(minimum_recovery_after))
        .unwrap_or(minimum_recovery_after);
    recovery_after == expected_recovery_after
}

async fn begin_idempotent_request_with_recovery_and_binding(
    state: &AppState,
    key: &str,
    method: &str,
    path: &str,
    hash: &[u8],
    recovery: IdempotencyRecovery,
    options: ConfigTokenIdempotencyOptions<'_>,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let config_token_binding = options.binding;
    let legacy_request_hash = options.legacy_request_hash;
    if recovery == IdempotencyRecovery::DeterministicExpiringCapability
        && (!is_paas_config_token_idempotency_path(method, path) || config_token_binding.is_none())
    {
        return Err(db_error());
    }
    let operation_id = idempotency_operation_id(key, method, path, hash);
    let token = Uuid::new_v4();
    let inserted_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "INSERT INTO cap_internal_idempotency (
             idempotency_key, method, path, request_hash,
             reservation_token, operation_id, lease_expires_at,
             recovery_kind, attempt_count, capability_receipt_version,
             capability_resource_id, capability_instance_id
         )
         VALUES (
             $1, $2, $3, $4, $5, $6,
             clock_timestamp() + ($7::bigint * interval '1 second'),
             $8, 1, $9, $10, $11
         )
         ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING created_at",
    )
    .bind(key)
    .bind(method)
    .bind(path)
    .bind(hash)
    .bind(token)
    .bind(operation_id)
    .bind(recovery.lease_seconds())
    .bind(recovery.kind())
    .bind(config_token_binding.map(|_| crate::auth::jwt::CONFIG_TOKEN_RECEIPT_VERSION))
    .bind(config_token_binding.map(|binding| binding.resource_id))
    .bind(config_token_binding.map(|binding| binding.instance_id.as_str()))
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    if let Some(created_at) = inserted_at {
        let config_token_receipt =
            (recovery == IdempotencyRecovery::DeterministicExpiringCapability).then(|| {
                ConfigTokenReceipt::new(
                    operation_id,
                    created_at,
                    crate::auth::jwt::CONFIG_TOKEN_RECEIPT_VERSION,
                    config_token_binding
                        .expect("config-token recovery requires a binding")
                        .clone(),
                )
            });
        return Ok(IdempotencyBegin::Execute(IdempotencyLease::new(
            state.db.clone(),
            key.to_string(),
            token,
            IdempotencyLeaseClaim {
                operation_id,
                reclaimed: false,
                regenerate: false,
                committed_keyring_checkpoint: false,
                config_token_receipt,
            },
            recovery,
        )));
    }

    let row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                reservation_token, operation_id, lease_expires_at,
                recovery_kind, capability_receipt_version,
                capability_resource_id, capability_instance_id,
                known_not_applied,
                completed_at, created_at, updated_at,
                clock_timestamp() AS database_now
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;

    let exact_request = row.request_hash == hash;
    let legacy_recovery_shape = row.recovery_kind.as_deref() == Some("expiring_capability")
        || (row.recovery_kind.is_none() && is_safe_migrated_legacy_config_token_terminal(&row));
    let compatible_legacy_request = recovery
        == IdempotencyRecovery::DeterministicExpiringCapability
        && legacy_recovery_shape
        && legacy_request_hash.is_some_and(|legacy_hash| row.request_hash == legacy_hash);
    if row.method != method || row.path != path || (!exact_request && !compatible_legacy_request) {
        return Err(idempotency_key_reused_error());
    }
    if row.recovery_kind.as_deref() == Some(recovery.kind())
        && let Some(binding) = config_token_binding
        && (row.capability_receipt_version != Some(crate::auth::jwt::CONFIG_TOKEN_RECEIPT_VERSION)
            || row.capability_resource_id != Some(binding.resource_id)
            || row.capability_instance_id.as_deref() != Some(binding.instance_id.as_str()))
    {
        return Err(idempotency_key_reused_error());
    }

    if recovery == IdempotencyRecovery::DeterministicExpiringCapability
        && row
            .response_status
            .is_some_and(|status| (200..300).contains(&status))
    {
        let issued_at = chrono::DateTime::from_timestamp(row.created_at.timestamp(), 0)
            .expect("PostgreSQL timestamptz has a whole-second value");
        let minimum_recovery_after = issued_at + chrono::Duration::seconds(6 * 60);
        let recovery_after = row
            .lease_expires_at
            .map(|lease| lease.max(minimum_recovery_after))
            .unwrap_or(minimum_recovery_after);
        return sanitize_legacy_completed_config_token_response(
            &state.db,
            key,
            row.reservation_token,
            row.operation_id.unwrap_or(operation_id),
            issued_at,
            recovery_after,
        )
        .await;
    }

    if let Some(response) = completed_idempotency_response(&row) {
        return Ok(IdempotencyBegin::Replay(response));
    }

    let reclaimable = (row.known_not_applied
        && row
            .lease_expires_at
            .is_some_and(|lease_expires_at| lease_expires_at <= row.database_now))
        || match row.reservation_token {
            None => {
                row.updated_at
                    <= row.database_now
                        - chrono::Duration::seconds(IDEMPOTENCY_LEGACY_STALE_SECONDS)
            }
            Some(_) => row
                .lease_expires_at
                .is_some_and(|lease_expires_at| lease_expires_at <= row.database_now),
        };
    if !reclaimable && recovery != IdempotencyRecovery::DeterministicExpiringCapability {
        // The lease is live and not expired (every reclaimable arm requires
        // expiry or staleness), so the window to its freeing is a known,
        // positive quantity -- stamp it so callers stop scheduling into the
        // lease (the #194 self-inflicted 409 loop). Legacy rows without a
        // lease expiry fall back to the bare contract.
        return Err(match row.lease_expires_at {
            Some(lease_expires_at) => idempotency_in_progress_with_retry(
                (lease_expires_at - row.database_now).num_seconds(),
            ),
            None => idempotency_in_progress_error(),
        });
    }

    if recovery == IdempotencyRecovery::DeterministicExpiringCapability
        && row.recovery_kind.as_deref() == Some(recovery.kind())
    {
        let receipt = config_token_receipt_from_row(&row, operation_id)?;
        if receipt.expires_at <= row.database_now {
            if row.completed_at.is_none() && !reclaimable {
                return Err(idempotency_in_progress_error());
            }
            return terminalize_expired_config_token_receipt(
                &state.db,
                ExpiredConfigTokenReceipt {
                    key,
                    previous_token: row.reservation_token,
                    operation_id: receipt.operation_id,
                    stored_recovery_kind: recovery.kind(),
                    issued_at: receipt.issued_at,
                    expires_at: receipt.expires_at,
                    legacy: false,
                },
            )
            .await;
        }
        if row.completed_at.is_some() {
            return Ok(IdempotencyBegin::Execute(IdempotencyLease::new(
                state.db.clone(),
                key.to_string(),
                row.reservation_token.unwrap_or(token),
                IdempotencyLeaseClaim {
                    operation_id: receipt.operation_id,
                    reclaimed: false,
                    regenerate: true,
                    committed_keyring_checkpoint: false,
                    config_token_receipt: Some(receipt),
                },
                recovery,
            )));
        }
        if !reclaimable {
            return Err(idempotency_in_progress_error());
        }
    }

    if recovery == IdempotencyRecovery::DeterministicExpiringCapability
        && row.recovery_kind.as_deref() == Some("expiring_capability")
    {
        let issued_at = chrono::DateTime::from_timestamp(row.created_at.timestamp(), 0)
            .expect("PostgreSQL timestamptz has a whole-second value");
        let minimum_recovery_after = issued_at + chrono::Duration::seconds(6 * 60);
        let expires_at = row
            .lease_expires_at
            .map(|lease| lease.max(minimum_recovery_after))
            .unwrap_or(minimum_recovery_after);
        if expires_at > row.database_now || !reclaimable {
            return Err(idempotency_in_progress_error());
        }
        return terminalize_expired_config_token_receipt(
            &state.db,
            ExpiredConfigTokenReceipt {
                key,
                previous_token: row.reservation_token,
                operation_id: row.operation_id.unwrap_or(operation_id),
                stored_recovery_kind: "expiring_capability",
                issued_at,
                expires_at,
                legacy: true,
            },
        )
        .await;
    }

    if !reclaimable {
        return Err(idempotency_in_progress_error());
    }

    let legacy_unbound = row.operation_id.is_none();
    let policy_changed = row
        .recovery_kind
        .as_deref()
        .is_some_and(|stored| stored != recovery.kind());
    let deterministic_legacy_is_unsafe = matches!(
        recovery,
        IdempotencyRecovery::DeterministicResource {
            legacy_identity_bound: false
        }
    ) && legacy_unbound;
    // A deferred publication checkpoint (keyring or signer rotation) is the
    // one incomplete FailClosed shape a same-key retry may reclaim: the
    // mutation is known committed, so the retry only reconciles publication.
    let publication_checkpoint_pending = !legacy_unbound
        && row.response_status == Some(i32::from(StatusCode::SERVICE_UNAVAILABLE.as_u16()))
        && matches!(
            row.response_body
                .as_ref()
                .and_then(|body| body.get("code"))
                .and_then(serde_json::Value::as_str),
            Some(KEYRING_POLICY_RECONCILIATION_PENDING_CODE)
                | Some(crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE)
        );
    if !row.known_not_applied
        && (policy_changed
            || deterministic_legacy_is_unsafe
            || (recovery == IdempotencyRecovery::FailClosed && !publication_checkpoint_pending))
    {
        return complete_unrecoverable_idempotency_request(
            &state.db,
            key,
            row.reservation_token,
            token,
            operation_id,
            recovery.kind(),
        )
        .await;
    }

    if let IdempotencyRecovery::ExpiringCapability {
        recovery_after_seconds,
    } = recovery
    {
        let recovery_at = row
            .lease_expires_at
            .unwrap_or(row.updated_at + chrono::Duration::seconds(recovery_after_seconds));
        if recovery_at > row.database_now {
            return Err(idempotency_in_progress_error());
        }

        // Capability responses deliberately remain absent from the ledger:
        // bearer tokens and their endpoint metadata must never become
        // operator-readable replay state.  Once the capability's DB-authored
        // validity window has elapsed, close the key with a bounded
        // reconciliation disposition instead of issuing a second capability.
        return complete_unrecoverable_idempotency_request(
            &state.db,
            key,
            row.reservation_token,
            token,
            row.operation_id.unwrap_or(operation_id),
            recovery.kind(),
        )
        .await;
    }

    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET reservation_token = $2,
                operation_id = COALESCE(operation_id, $3),
                lease_expires_at = clock_timestamp()
                    + ($4::bigint * interval '1 second'),
                recovery_kind = CASE
                    WHEN $8 THEN $5
                    ELSE COALESCE(recovery_kind, $5)
                END,
                known_not_applied = false,
                updated_at = clock_timestamp(),
                attempt_count = attempt_count + 1
          WHERE idempotency_key = $1
            AND completed_at IS NULL
            AND reservation_token IS NOT DISTINCT FROM $6
            AND (
                ($8 AND known_not_applied
                    AND lease_expires_at <= clock_timestamp())
                OR (
                    NOT $8
                    AND (
                        ($6::uuid IS NULL AND updated_at <= clock_timestamp()
                            - ($7::bigint * interval '1 second'))
                        OR ($6::uuid IS NOT NULL
                            AND lease_expires_at <= clock_timestamp())
                    )
                )
            )",
    )
    .bind(key)
    .bind(token)
    .bind(operation_id)
    .bind(recovery.lease_seconds())
    .bind(recovery.kind())
    .bind(row.reservation_token)
    .bind(IDEMPOTENCY_LEGACY_STALE_SECONDS)
    .bind(row.known_not_applied)
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(idempotency_in_progress_error());
    }

    Ok(IdempotencyBegin::Execute(IdempotencyLease::new(
        state.db.clone(),
        key.to_string(),
        token,
        IdempotencyLeaseClaim {
            operation_id: row.operation_id.unwrap_or(operation_id),
            reclaimed: true,
            regenerate: false,
            committed_keyring_checkpoint: publication_checkpoint_pending
                && row
                    .response_body
                    .as_ref()
                    .and_then(|body| body.get("code"))
                    .and_then(serde_json::Value::as_str)
                    == Some(KEYRING_POLICY_RECONCILIATION_PENDING_CODE),
            config_token_receipt: (recovery
                == IdempotencyRecovery::DeterministicExpiringCapability)
                .then(|| {
                    ConfigTokenReceipt::new(
                        row.operation_id.unwrap_or(operation_id),
                        row.created_at,
                        row.capability_receipt_version
                            .expect("config-token receipt version was validated"),
                        ConfigTokenResourceBinding {
                            resource_id: row
                                .capability_resource_id
                                .expect("config-token resource was validated"),
                            instance_id: row
                                .capability_instance_id
                                .clone()
                                .expect("config-token instance was validated"),
                        },
                    )
                }),
        },
        recovery,
    )))
}

fn completed_idempotency_response(row: &IdempotencyRow) -> Option<IdempotencyResponse> {
    row.completed_at?;
    let status = row
        .response_status
        .and_then(|code| StatusCode::from_u16(code as u16).ok())?;
    let body = row
        .response_body
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    Some((status, body))
}

fn idempotency_replay(
    method: &str,
    path: &str,
    hash: &[u8],
    row: IdempotencyRow,
) -> Result<Option<IdempotencyResponse>, InternalRouteError> {
    if row.method != method || row.path != path || row.request_hash != hash {
        return Err(idempotency_key_reused_error());
    }
    completed_idempotency_response(&row)
        .map(Some)
        .ok_or_else(idempotency_in_progress_error)
}

/// Reserve and replay membership-sync idempotency inside the caller's
/// authority transaction. A concurrent insert of the same key blocks on the
/// primary-key constraint until the winning transaction commits or rolls
/// back, so it observes either a complete response or a clean retry slot.
async fn begin_membership_idempotent_request_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    method: &str,
    path: &str,
    hash: &[u8],
) -> Result<Option<IdempotencyResponse>, InternalRouteError> {
    let inserted = sqlx::query(
        "INSERT INTO cap_internal_idempotency (idempotency_key, method, path, request_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(key)
    .bind(method)
    .bind(path)
    .bind(hash)
    .execute(&mut **tx)
    .await
    .map_err(|_| db_error())?
    .rows_affected()
        == 1;

    if inserted {
        return Ok(None);
    }

    let row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                reservation_token, operation_id, lease_expires_at,
                recovery_kind, capability_receipt_version,
                capability_resource_id, capability_instance_id,
                known_not_applied,
                completed_at, created_at, updated_at,
                clock_timestamp() AS database_now
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| db_error())?;

    idempotency_replay(method, path, hash, row)
}

async fn finish_membership_idempotent_request_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<(), InternalRouteError> {
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET response_status = $2,
                response_body = $3,
                completed_at = now(),
                updated_at = now()
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .bind(status.as_u16() as i32)
    .bind(body)
    .execute(&mut **tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(db_error());
    }
    Ok(())
}

async fn finish_idempotent_request(
    mut lease: IdempotencyLease,
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    lease.stop_heartbeat();
    let mut tx = lease.pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, lease.token).await?;
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET response_status = $2,
                response_body = $3,
                completed_at = clock_timestamp(),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token = $4
            AND completed_at IS NULL",
    )
    .bind(&lease.key)
    .bind(status.as_u16() as i32)
    .bind(body)
    .bind(lease.token)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(db_error());
    }
    tx.commit().await.map_err(|_| db_error())?;
    Ok(())
}

/// Exact known-not-applied outcomes. Every other post-lease failure defaults
/// to either completed (non-5xx) or outcome-unknown (5xx); status text alone
/// never grants re-execution authority.
const TRANSIENT_RETRY_CONFLICT_MESSAGES: &[&str] = &[
    "app mutation already in progress",
    "deployment mutation is still in progress",
    "deployment mutation is still in progress; retry after its lease completes",
    "deployment mutation is still in progress; retry rollback",
    "current deployment generation is still in progress",
    "an earlier deployment is still completing setup; retry after setup is reconciled",
    "an earlier deployment rollout is still in progress; retry after it settles",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdempotencyErrorDisposition {
    KnownNotApplied,
    OutcomeUnknown,
    Completed,
}

fn idempotency_error_disposition(
    status: StatusCode,
    body: &serde_json::Value,
) -> IdempotencyErrorDisposition {
    if status == StatusCode::CONFLICT
        && body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| TRANSIENT_RETRY_CONFLICT_MESSAGES.contains(&message))
    {
        return IdempotencyErrorDisposition::KnownNotApplied;
    }
    if status.is_server_error() {
        return IdempotencyErrorDisposition::OutcomeUnknown;
    }
    IdempotencyErrorDisposition::Completed
}

/// Stamp a durably-cached error body as a completed idempotent result. PaaS
/// terminalizes the intent regardless of HTTP status when this field is present.
fn stamp_idempotency_completion(body: &mut serde_json::Value) {
    if let Some(map) = body.as_object_mut() {
        map.insert(
            "idempotency_disposition".to_string(),
            serde_json::json!("completed"),
        );
        map.insert("retryable".to_string(), serde_json::json!(false));
    }
}

/// Keep the request bound until retry. A checkpoint preserves a known committed
/// outcome across process loss without mislabeling it as not applied.
async fn defer_idempotent_request(
    mut lease: IdempotencyLease,
    checkpoint: Option<&IdempotencyResponse>,
) -> InternalRouteError {
    lease.stop_heartbeat();
    let update = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET lease_expires_at = clock_timestamp()
                + ($3::bigint * interval '1 second'),
                updated_at = clock_timestamp(),
                response_status = $4,
                response_body = $5
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(IDEMPOTENCY_RETRY_DEFER_SECONDS)
    .bind(checkpoint.map(|(status, _)| i32::from(status.as_u16())))
    .bind(checkpoint.map(|(_, body)| body));
    let updated = if checkpoint.is_some() {
        let mut tx = match lease.pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return db_error(),
        };
        if let Err(error) = set_idempotency_completion_owner(&mut tx, lease.token).await {
            return error;
        }
        let updated = update.execute(&mut *tx).await;
        if updated.is_ok() && tx.commit().await.is_err() {
            return db_error();
        }
        updated
    } else {
        update.execute(&lease.pool).await
    };
    // Both Ok arms return the same deferred body now that the central
    // in-progress helper carries the `deferred` stamp: a 1-row update means the
    // defer landed; a 0-row update means the lease was already completed or
    // reclaimed. Either way the client guidance is retry-same-key.
    match updated {
        // The defer just re-armed the lease for exactly
        // IDEMPOTENCY_RETRY_DEFER_SECONDS, so the retry hint is exact.
        Ok(_) => idempotency_in_progress_with_retry(IDEMPOTENCY_RETRY_DEFER_SECONDS),
        Err(_) => db_error(),
    }
}

async fn release_known_not_applied_idempotent_request(
    mut lease: IdempotencyLease,
) -> Result<(), InternalRouteError> {
    lease.stop_heartbeat();
    let released_token = Uuid::new_v4();
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET reservation_token = $3,
                known_not_applied = true,
                lease_expires_at = clock_timestamp(),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(released_token)
    .execute(&lease.pool)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() != 1 {
        return Err(idempotency_in_progress_error());
    }
    Ok(())
}

async fn complete_idempotent_result(
    lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    match result {
        Ok((status, body)) => {
            finish_idempotent_request(lease, status, &body).await?;
            Ok((status, body))
        }
        Err((status, Json(mut body))) => {
            match idempotency_error_disposition(status, &body) {
                IdempotencyErrorDisposition::KnownNotApplied => {
                    release_known_not_applied_idempotent_request(lease).await?;
                    return Err(idempotency_in_progress_error());
                }
                IdempotencyErrorDisposition::OutcomeUnknown => {
                    let terminal = idempotency_recovery_required_body();
                    finish_idempotent_request(lease, StatusCode::CONFLICT, &terminal).await?;
                    return Err((StatusCode::CONFLICT, Json(terminal)));
                }
                IdempotencyErrorDisposition::Completed => {}
            }
            stamp_idempotency_completion(&mut body);
            finish_idempotent_request(lease, status, &body).await?;
            Err((status, Json(body)))
        }
    }
}

/// Ordered app teardown is resumable even after partially applied provider work.
/// Keep this exception local to DELETE; generic RetrySafe operations fail closed.
/// A locked TEE (423 `app_delete_teardown_locked`) is recoverable — the owner
/// can unlock the workload — so it defers like a 5xx instead of being cached
/// as a terminal receipt that a same-key retry would replay forever. The
/// deferred body carries a fixed `cause` so PaaS callers can see why.
async fn complete_app_delete_result(
    lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    if let Err((status, body)) = &result {
        let teardown_locked = *status == StatusCode::LOCKED
            && body.get("error").and_then(serde_json::Value::as_str)
                == Some("app_delete_teardown_locked");
        // The budget 409 is a transient pre-mutation rejection: another app's
        // teardown pins currently occupy the shared signed-policy byte
        // budget, and the delete becomes admissible once they clear. It must
        // defer (row stays incomplete) rather than terminalize the receipt
        // with retryable:false — a same-key retry would otherwise replay the
        // conflict forever even after capacity frees (Codex review on
        // 3b168c73).
        let budget_conflict = *status == StatusCode::CONFLICT
            && body.get("error").and_then(serde_json::Value::as_str)
                == Some("app_delete_kbs_policy_budget_exceeded");
        if status.is_server_error() || teardown_locked || budget_conflict {
            let (deferred_status, Json(mut deferred_body)) =
                defer_idempotent_request(lease, None).await;
            if teardown_locked && deferred_status == StatusCode::CONFLICT {
                deferred_body["cause"] = serde_json::json!("app_delete_teardown_locked");
            }
            if budget_conflict && deferred_status == StatusCode::CONFLICT {
                deferred_body["cause"] = serde_json::json!("app_delete_kbs_policy_budget_exceeded");
            }
            // Surface the teardown disposition (restored vs kept deleting)
            // on the deferral too: hosted callers retry through the deferral
            // and would otherwise never see why the attempt failed — the
            // original failure body is dropped by the deferral shape. The
            // teardown branch attaches `reason` for every deferral-worthy
            // status (token 500, transport 502, locked 423); other delete
            // step failures carry none, so copy whatever is present.
            if let Some(reason) = body.get("reason") {
                deferred_body["reason"] = reason.clone();
            }
            return Err((deferred_status, Json(deferred_body)));
        }
    }
    complete_idempotent_result(lease, result).await
}

const KEYRING_POLICY_RECONCILIATION_PENDING_CODE: &str = "keyring_policy_reconciliation_pending";

/// A confirmed publication-pending checkpoint survives reclaim. An unrelated
/// 5xx on that reclaim is not rewritten as publication-pending: authority
/// mismatches and uncertain upstream writes must terminalize instead of
/// staying re-executable under a committed-publication cause.
async fn complete_keyring_result(
    lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    if lease.committed_keyring_checkpoint
        && let Err((status, body)) = &result
        && status.is_server_error()
        && !(*status == StatusCode::SERVICE_UNAVAILABLE
            && body.get("code").and_then(serde_json::Value::as_str)
                == Some(KEYRING_POLICY_RECONCILIATION_PENDING_CODE))
    {
        tracing::warn!(
            idempotency_key = %lease.key,
            %status,
            "reclaimed keyring publication checkpoint saw an unrelated server error; not relabeling it as publication-pending"
        );
    }
    if let Err((status, body)) = &result
        && *status == StatusCode::SERVICE_UNAVAILABLE
        && body.get("code").and_then(serde_json::Value::as_str)
            == Some(KEYRING_POLICY_RECONCILIATION_PENDING_CODE)
    {
        let checkpoint = (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"code": KEYRING_POLICY_RECONCILIATION_PENDING_CODE}),
        );
        let (deferred_status, Json(mut deferred_body)) =
            defer_idempotent_request(lease, Some(&checkpoint)).await;
        if deferred_status == StatusCode::CONFLICT {
            deferred_body["cause"] = serde_json::json!(KEYRING_POLICY_RECONCILIATION_PENDING_CODE);
        }
        return Err((deferred_status, Json(deferred_body)));
    }
    complete_idempotent_result(lease, result).await
}

const SIGNER_PUBLICATION_CHECKPOINT_RESPONSE_FIELD: &str = "committed_response";
const SIGNER_PUBLICATION_CHECKPOINT_GENERATION_FIELD: &str = "signer_rotation_generation";

/// Preflight failures are known not applied. A committed rotation instead
/// retains its result so retries can publish without consuming its token again.
async fn complete_signer_result(
    lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    match result {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(body)))
            if body.get("code").and_then(serde_json::Value::as_str)
                == Some("kbs_publication_not_configured") =>
        {
            release_known_not_applied_idempotent_request(lease).await?;
            let (status, Json(mut body)) = idempotency_in_progress_error();
            body["cause"] = serde_json::json!("kbs_publication_not_configured");
            Err((status, Json(body)))
        }
        Err((status, Json(body)))
            if status == StatusCode::SERVICE_UNAVAILABLE
                && body.get("code").and_then(serde_json::Value::as_str)
                    == Some(crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE) =>
        {
            let checkpoint = (status, body);
            let (status, Json(mut body)) = defer_idempotent_request(lease, Some(&checkpoint)).await;
            if status == StatusCode::CONFLICT {
                body["cause"] = serde_json::json!(
                    crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                );
            }
            Err((status, Json(body)))
        }
        other => complete_idempotent_result(lease, other).await,
    }
}

fn signer_publication_checkpoint_error(
    committed: serde_json::Value,
    rotation_generation: i64,
) -> InternalRouteError {
    let mut body = serde_json::json!({
        "code": crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE,
    });
    body[SIGNER_PUBLICATION_CHECKPOINT_RESPONSE_FIELD] = committed;
    body[SIGNER_PUBLICATION_CHECKPOINT_GENERATION_FIELD] = serde_json::json!(rotation_generation);
    (StatusCode::SERVICE_UNAVAILABLE, Json(body))
}

/// Only the reservation-token owner may resume publication. Malformed
/// checkpoints fail closed instead of re-executing the mutation: the parser
/// requires the rotation generation captured in the same transaction as the
/// committed response, and never invents one for a checkpoint written before
/// the field existed. The caller terminalizes that failure through the
/// completed channel with the bounded new-key disposition.
async fn signer_publication_checkpoint(
    pool: &sqlx::PgPool,
    lease: &IdempotencyLease,
) -> Result<Option<(Uuid, i64, serde_json::Value)>, InternalRouteError> {
    let row: Option<(Option<i32>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT response_status, response_body
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .fetch_optional(pool)
    .await
    .map_err(|_| db_error())?;
    let Some((status, body)) = row else {
        return Err(idempotency_in_progress_error());
    };
    if status.is_none() && body.is_none() {
        return Ok(None);
    }
    if status != Some(i32::from(StatusCode::SERVICE_UNAVAILABLE.as_u16())) {
        return Err(db_error());
    }
    let Some(mut body) = body else {
        return Err(db_error());
    };
    if body.get("code").and_then(serde_json::Value::as_str)
        != Some(crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE)
    {
        return Err(db_error());
    }
    let rotation_generation = body
        .get(SIGNER_PUBLICATION_CHECKPOINT_GENERATION_FIELD)
        .and_then(serde_json::Value::as_i64)
        .filter(|generation| *generation >= 0)
        .ok_or_else(db_error)?;
    // A new write never stores a count; a checkpoint carrying both fences is
    // contradictory and must not downgrade to a generation-only retry.
    if body.get("rotation_count").is_some() {
        return Err(db_error());
    }
    let Some(committed) = body
        .get_mut(SIGNER_PUBLICATION_CHECKPOINT_RESPONSE_FIELD)
        .map(serde_json::Value::take)
    else {
        return Err(db_error());
    };
    if committed.get("rotation_count").is_some()
        || committed
            .get(SIGNER_PUBLICATION_CHECKPOINT_GENERATION_FIELD)
            .is_some()
    {
        return Err(db_error());
    }
    let app_id = committed
        .get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(db_error)?;
    Ok(Some((app_id, rotation_generation, committed)))
}

/// Return an expiring capability exactly once without persisting it in CAP's
/// idempotency ledger.  The incomplete row and its DB-authored lease are the
/// replay marker: callers receive `idempotency_in_progress` while the
/// capability may still be valid and a bounded reconcile/new-key disposition
/// after expiry.  Error DTOs remain safe to persist and replay.
///
/// A handler 5xx is deferred in place: the heartbeat is stopped and the row
/// stays incomplete with its DB-authored lease preserved
/// (`lease_seconds()` = `recovery_after_seconds`, e.g. 11 min for signer
/// rotation).  That lease must not be shortened to the generic retry interval,
/// or reclaim would collapse to the bounded reconcile disposition seconds
/// after a transient failure instead of holding the capability window.
/// Non-5xx handler errors are persist-safe DTOs and delegate to
/// [`complete_idempotent_result`] (stamped + cached).  The only caller,
/// `issue_paas_signer_rotation_token`, claims no mutation or deployment lane,
/// so neither busy string can surface here.
async fn complete_expiring_capability_result(
    mut lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    match result {
        Ok(response) => {
            lease.stop_heartbeat();
            Ok(response)
        }
        Err((status, body)) => {
            // Defer a 5xx WITHOUT calling `defer_idempotent_request`: that
            // helper rewrites `lease_expires_at` to the ~5 s retry interval,
            // shortening the capability's heartbeat-maintained hold and
            // collapsing reclaim to `recovery_required` seconds after a
            // transient failure. Preserve the DB-authored lease instead.
            if status.is_server_error() {
                lease.stop_heartbeat();
                return Err(idempotency_in_progress_error());
            }
            complete_idempotent_result(lease, Err((status, body))).await
        }
    }
}

async fn cancel_incomplete_idempotency_reservation(
    cancellation: &IdempotencyCancellation,
) -> Result<(), InternalRouteError> {
    let deleted = sqlx::query(
        "DELETE FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&cancellation.key)
    .bind(cancellation.token)
    .execute(&cancellation.pool)
    .await
    .map_err(|_| db_error())?;
    if deleted.rows_affected() == 1 {
        return Ok(());
    }

    let completed: Option<bool> = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(&cancellation.key)
    .fetch_optional(&cancellation.pool)
    .await
    .map_err(|_| db_error())?;
    match completed {
        None | Some(true) => Ok(()),
        Some(false) => Err(idempotency_in_progress_error()),
    }
}

async fn cancel_incomplete_idempotency_reservation_bounded(
    cancellation: &IdempotencyCancellation,
    timeout: std::time::Duration,
) -> Result<(), InternalRouteError> {
    // A Tokio timeout alone can drop the client future while PostgreSQL is
    // still waiting on a row lock. Give the server a slightly shorter hard
    // statement/lock timeout so a canceled cleanup cannot wake later and
    // delete a receipt that has since become authoritative.
    let started = std::time::Instant::now();
    let mut tx = cancellation.pool.begin().await.map_err(|_| db_error())?;
    let remaining = timeout.saturating_sub(started.elapsed());
    // Reserve most of the outer budget for PostgreSQL cancellation and the
    // transaction rollback. A blocked DELETE is never allowed to outlive the
    // client-side cleanup future.
    let database_millis = (remaining.as_millis() / 3).clamp(1, 250);
    let timeout_setting = format!("{database_millis}ms");
    sqlx::query_scalar::<_, String>("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_setting)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    sqlx::query_scalar::<_, String>("SELECT set_config('lock_timeout', $1, true)")
        .bind(&timeout_setting)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    sqlx::query(
        "DELETE FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&cancellation.key)
    .bind(cancellation.token)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    tx.commit().await.map_err(|_| db_error())?;
    Ok(())
}

async fn cancel_idempotency_reservation(
    mut lease: IdempotencyLease,
) -> Result<(), InternalRouteError> {
    lease.stop_heartbeat();
    let cancellation = lease.cancellation();
    cancel_incomplete_idempotency_reservation(&cancellation).await
}

enum ConfigTokenReceiptCompletion {
    Completed,
    Deferred,
    Terminal(IdempotencyResponse),
}

async fn finish_config_token_receipt(
    lease: &mut IdempotencyLease,
) -> Result<ConfigTokenReceiptCompletion, InternalRouteError> {
    lease.stop_heartbeat();
    let receipt = lease.config_token_receipt.clone().ok_or_else(db_error)?;
    let mut tx = lease.pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, lease.token).await?;
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET completed_at = clock_timestamp(),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND recovery_kind = 'deterministic_expiring_capability'
            AND completed_at IS NULL
            AND response_status IS NULL
            AND response_body IS NULL
            AND operation_id = $3
            AND capability_receipt_version = $4
            AND capability_resource_id = $5
            AND capability_instance_id = $6
            AND date_trunc('second', created_at)
                + ($7::bigint * interval '1 second')
                > clock_timestamp() + ($8::bigint * interval '1 second')",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(receipt.operation_id)
    .bind(receipt.receipt_version)
    .bind(receipt.resource_id)
    .bind(&receipt.instance_id)
    .bind(crate::auth::jwt::CONFIG_TOKEN_TTL_SECONDS)
    .bind(CONFIG_TOKEN_SAFE_RETURN_SECONDS)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if updated.rows_affected() == 1 {
        tx.commit().await.map_err(|_| db_error())?;
        return Ok(ConfigTokenReceiptCompletion::Completed);
    }
    tx.rollback().await.map_err(|_| db_error())?;

    // Signing has already happened. If it completed inside the no-return
    // window, retain a durable completed receipt without returning or
    // deleting the bearer generation. Duplicates remain retryable under the
    // same key until absolute expiry terminalizes it.
    let mut tx = lease.pool.begin().await.map_err(|_| db_error())?;
    set_idempotency_completion_owner(&mut tx, lease.token).await?;
    let deferred = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET completed_at = clock_timestamp(),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND recovery_kind = 'deterministic_expiring_capability'
            AND completed_at IS NULL
            AND response_status IS NULL
            AND response_body IS NULL
            AND operation_id = $3
            AND capability_receipt_version = $4
            AND capability_resource_id = $5
            AND capability_instance_id = $6
            AND date_trunc('second', created_at)
                + ($7::bigint * interval '1 second') > clock_timestamp()",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(receipt.operation_id)
    .bind(receipt.receipt_version)
    .bind(receipt.resource_id)
    .bind(&receipt.instance_id)
    .bind(crate::auth::jwt::CONFIG_TOKEN_TTL_SECONDS)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if deferred.rows_affected() == 1 {
        tx.commit().await.map_err(|_| db_error())?;
        return Ok(ConfigTokenReceiptCompletion::Deferred);
    }
    tx.rollback().await.map_err(|_| db_error())?;

    if receipt.expires_at <= database_clock(&lease.pool).await? {
        let terminal = terminalize_expired_config_token_receipt(
            &lease.pool,
            ExpiredConfigTokenReceipt {
                key: &lease.key,
                previous_token: Some(lease.token),
                operation_id: receipt.operation_id,
                stored_recovery_kind: IdempotencyRecovery::DeterministicExpiringCapability.kind(),
                issued_at: receipt.issued_at,
                expires_at: receipt.expires_at,
                legacy: false,
            },
        )
        .await?;
        return match terminal {
            IdempotencyBegin::Replay(response) => {
                Ok(ConfigTokenReceiptCompletion::Terminal(response))
            }
            IdempotencyBegin::Execute(_) => Err(db_error()),
        };
    }
    Err(db_error())
}

async fn database_clock(
    pool: &sqlx::PgPool,
) -> Result<chrono::DateTime<chrono::Utc>, InternalRouteError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .map_err(|_| db_error())
}

async fn finalize_regenerated_config_token_response(
    lease: &IdempotencyLease,
    response: IdempotencyResponse,
) -> Result<IdempotencyResponse, InternalRouteError> {
    let receipt = lease.config_token_receipt.as_ref().ok_or_else(db_error)?;
    let mut tx = lease.pool.begin().await.map_err(|_| db_error())?;
    let row: Option<(Option<i32>, Option<serde_json::Value>, bool, bool)> = sqlx::query_as(
        "SELECT response_status, response_body,
                date_trunc('second', created_at)
                    + ($7::bigint * interval '1 second')
                    > clock_timestamp() + ($8::bigint * interval '1 second')
                    AS safe_to_return,
                date_trunc('second', created_at)
                    + ($7::bigint * interval '1 second') <= clock_timestamp()
                    AS expired
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND operation_id = $3
            AND recovery_kind = 'deterministic_expiring_capability'
            AND capability_receipt_version = $4
            AND capability_resource_id = $5
            AND capability_instance_id = $6
            AND completed_at IS NOT NULL
          FOR UPDATE",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(receipt.operation_id)
    .bind(receipt.receipt_version)
    .bind(receipt.resource_id)
    .bind(&receipt.instance_id)
    .bind(crate::auth::jwt::CONFIG_TOKEN_TTL_SECONDS)
    .bind(CONFIG_TOKEN_SAFE_RETURN_SECONDS)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    match row {
        Some((None, None, true, false)) => {
            tx.commit().await.map_err(|_| db_error())?;
            Ok(response)
        }
        Some((Some(status), Some(body), _, _)) => {
            tx.rollback().await.map_err(|_| db_error())?;
            let status = StatusCode::from_u16(status as u16).map_err(|_| db_error())?;
            Ok((status, body))
        }
        Some((None, None, false, true)) => {
            tx.rollback().await.map_err(|_| db_error())?;
            let terminal = terminalize_expired_config_token_receipt(
                &lease.pool,
                ExpiredConfigTokenReceipt {
                    key: &lease.key,
                    previous_token: Some(lease.token),
                    operation_id: receipt.operation_id,
                    stored_recovery_kind: IdempotencyRecovery::DeterministicExpiringCapability
                        .kind(),
                    issued_at: receipt.issued_at,
                    expires_at: receipt.expires_at,
                    legacy: false,
                },
            )
            .await?;
            match terminal {
                IdempotencyBegin::Replay(response) => Ok(response),
                IdempotencyBegin::Execute(_) => Err(db_error()),
            }
        }
        Some((None, None, false, false)) => {
            tx.rollback().await.map_err(|_| db_error())?;
            Err(idempotency_in_progress_error())
        }
        _ => Err(db_error()),
    }
}

async fn complete_deterministic_config_token_result_with_timeout<F>(
    lease: IdempotencyLease,
    result: F,
    hard_timeout: std::time::Duration,
    cancellation_timeout: std::time::Duration,
) -> Result<IdempotencyResponse, InternalRouteError>
where
    F: std::future::Future<Output = Result<IdempotencyResponse, InternalRouteError>>,
{
    let mut lease = lease;
    let regenerate = lease.regenerate;
    let cancellation = (!regenerate).then(|| lease.cancellation());
    let attempt = async move {
        match result.await {
            Ok(response) if regenerate => {
                finalize_regenerated_config_token_response(&lease, response).await
            }
            Ok(response) => {
                let finish_cancellation = lease.cancellation();
                match finish_config_token_receipt(&mut lease).await {
                    Ok(ConfigTokenReceiptCompletion::Completed) => {
                        finalize_regenerated_config_token_response(&lease, response).await
                    }
                    Ok(ConfigTokenReceiptCompletion::Deferred) => {
                        Err(idempotency_in_progress_error())
                    }
                    Ok(ConfigTokenReceiptCompletion::Terminal(terminal)) => Ok(terminal),
                    Err(error) => {
                        cancel_incomplete_idempotency_reservation(&finish_cancellation).await?;
                        Err(error)
                    }
                }
            }
            Err(error) if regenerate => Err(error),
            Err(error) => {
                cancel_idempotency_reservation(lease).await?;
                Err(error)
            }
        }
    };

    match tokio::time::timeout(hard_timeout, attempt).await {
        Ok(result) => result,
        Err(_) => {
            if let Some(cancellation) = cancellation.as_ref() {
                let _ = tokio::time::timeout(
                    cancellation_timeout,
                    cancel_incomplete_idempotency_reservation_bounded(
                        cancellation,
                        cancellation_timeout,
                    ),
                )
                .await;
            }
            Err(json_error(
                StatusCode::GATEWAY_TIMEOUT,
                "config token generation timed out",
            ))
        }
    }
}

async fn complete_deterministic_config_token_result<F>(
    lease: IdempotencyLease,
    result: F,
) -> Result<IdempotencyResponse, InternalRouteError>
where
    F: std::future::Future<Output = Result<IdempotencyResponse, InternalRouteError>>,
{
    complete_deterministic_config_token_result_with_timeout(
        lease,
        result,
        std::time::Duration::from_secs(CONFIG_TOKEN_HARD_ATTEMPT_SECONDS),
        std::time::Duration::from_secs(CONFIG_TOKEN_CANCELLATION_SECONDS),
    )
    .await
}

pub async fn upsert_paas_org(
    auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpsertPaaSOrgRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    validate_org_name(&body.name)?;
    let status = parse_status(&body.status)?;
    let key = idempotency_key(&headers)?;
    let path = format!("/internal/paas/orgs/{paas_org_id}");
    let hash = request_hash(&body)?;
    let idempotency = match begin_idempotent_request(&state, key, "PUT", &path, &hash).await? {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };

    let result: Result<IdempotencyResponse, InternalRouteError> = async {
    let existing_org_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'organization'
            AND paas_external_id = $1",
    )
    .bind(&paas_org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let cap_org_id = existing_org_id.unwrap_or_else(Uuid::new_v4);
    let response_status = if existing_org_id.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    if existing_org_id.is_some() {
        sqlx::query(
            "UPDATE organizations
                SET name = $2,
                    display_name = $3,
                    updated_at = now()
              WHERE id = $1",
        )
        .bind(cap_org_id)
        .bind(&body.name)
        .bind(body.display_name.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    } else {
        crate::db::orgs::insert_org_conn(
            &mut tx,
            cap_org_id,
            &body.name,
            body.display_name.as_deref(),
            false,
        )
        .await
        .map_err(|err| {
            if err.to_string().contains("duplicate key") || err.to_string().contains("unique") {
                json_error(StatusCode::CONFLICT, "organization name already exists")
            } else {
                db_error()
            }
        })?;
    }

    sqlx::query(
        "INSERT INTO organization_management
             (org_id, mode, paas_org_id, status, suspended_at, updated_at)
         VALUES ($1, 'paas_managed', $2, $3, CASE WHEN $3 = 'suspended' THEN now() ELSE NULL END, now())
         ON CONFLICT (org_id) DO UPDATE
            SET mode = 'paas_managed',
                paas_org_id = EXCLUDED.paas_org_id,
                status = EXCLUDED.status,
                suspended_at = EXCLUDED.suspended_at,
                updated_at = now()",
    )
    .bind(cap_org_id)
    .bind(&paas_org_id)
    .bind(status)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    sqlx::query(
        "INSERT INTO paas_external_mappings
             (resource_type, paas_external_id, cap_id, org_id, metadata, updated_at)
         VALUES ('organization', $1, $2, $2, $3, now())
         ON CONFLICT (resource_type, paas_external_id) DO UPDATE
            SET cap_id = EXCLUDED.cap_id,
                org_id = EXCLUDED.org_id,
                metadata = EXCLUDED.metadata,
                updated_at = now()",
    )
    .bind(&paas_org_id)
    .bind(cap_org_id)
    .bind(serde_json::json!({"client_san": auth.client_san}))
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    tx.commit().await.map_err(|_| db_error())?;

    let response = serde_json::json!({
        "cap_org_id": cap_org_id,
        "paas_org_id": paas_org_id,
        "name": body.name,
        "status": status,
    });
    Ok((response_status, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn sync_paas_member(
    auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, paas_user_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SyncPaaSMemberRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    validate_external_id(&paas_user_id, "paas_user_id")?;
    if body.version < 0 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "version must be non-negative",
        ));
    }
    let role = parse_role(&body.role)?;
    let key = idempotency_key(&headers)?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}");
    let hash = request_hash(&body)?;

    let cap_org_id: Uuid = sqlx::query_scalar(
        "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'organization'
            AND paas_external_id = $1",
    )
    .bind(&paas_org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "PaaS organization is not mapped"))?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    lock_paas_user_mapping_lane(&mut tx, &paas_user_id)
        .await
        .map_err(|_| db_error())?;
    if let Some((status, response)) =
        begin_membership_idempotent_request_in_tx(&mut tx, key, "PUT", &path, &hash).await?
    {
        tx.commit().await.map_err(|_| db_error())?;
        return Ok((status, Json(response)));
    }

    let mapped_user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'user'
            AND paas_external_id = $1",
    )
    .bind(&paas_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    let cap_user_id = mapped_user_id.unwrap_or_else(Uuid::new_v4);
    type MembershipAuthorityRow = (String, i64, String, bool);
    let existing: Option<MembershipAuthorityRow> = if mapped_user_id.is_some() {
        sqlx::query_as(
            "SELECT pms.paas_user_id,
                    pms.version,
                    pms.role,
                    pms.active
               FROM paas_membership_sync_state pms
              WHERE pms.org_id = $1
                AND pms.user_id = $2
              FOR UPDATE OF pms",
        )
        .bind(cap_org_id)
        .bind(cap_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?
    } else {
        None
    };

    let role_name = role_as_str(role);
    if existing
        .as_ref()
        .is_some_and(|(stored_paas_user_id, _, _, _)| stored_paas_user_id != &paas_user_id)
    {
        let mut error = json_error(
            StatusCode::CONFLICT,
            "membership user mapping is inconsistent",
        );
        stamp_idempotency_completion(&mut error.1.0);
        finish_membership_idempotent_request_in_tx(&mut tx, key, error.0, &error.1.0).await?;
        tx.commit().await.map_err(|_| db_error())?;
        return Err(error);
    }
    let membership: Option<(String, bool)> = if existing.is_some() {
        sqlx::query_as(
            "SELECT role::text, removed_at IS NULL
               FROM memberships
              WHERE org_id = $1 AND user_id = $2
              FOR UPDATE",
        )
        .bind(cap_org_id)
        .bind(cap_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?
    } else {
        None
    };

    // Before rejecting a stale or divergent delivery, repair an unambiguous
    // legacy projection split from the stored latest sync authority. The old
    // handler committed memberships before sync state, so a crash could leave
    // an already-removed user active and authorized.
    let repair_stored_projection =
        existing
            .as_ref()
            .is_some_and(|(_, version, stored_role, stored_active)| {
                body.version <= *version
                    && membership
                        .as_ref()
                        .is_none_or(|(membership_role, membership_active)| {
                            membership_role != stored_role || membership_active != stored_active
                        })
            });
    if repair_stored_projection {
        let (_, stored_version, stored_role, stored_active) = existing
            .as_ref()
            .expect("repair requires stored membership authority");
        write_membership_projection_in_tx(
            &mut tx,
            cap_org_id,
            cap_user_id,
            stored_role,
            *stored_active,
        )
        .await
        .map_err(|_| db_error())?;
        audit_membership_authority_in_tx(
            &mut tx,
            MembershipAuthorityAudit {
                org_id: cap_org_id,
                user_id: cap_user_id,
                role: stored_role,
                active: *stored_active,
                version: *stored_version,
                client_san: &auth.client_san,
                repair: true,
            },
        )
        .await
        .map_err(|_| db_error())?;
    }

    let write_authority = match existing {
        Some((_, version, _, _)) if body.version < version => {
            let mut error = json_error(StatusCode::CONFLICT, "membership version is stale");
            stamp_idempotency_completion(&mut error.1.0);
            finish_membership_idempotent_request_in_tx(&mut tx, key, error.0, &error.1.0).await?;
            tx.commit().await.map_err(|_| db_error())?;
            return Err(error);
        }
        Some((existing_paas_user_id, version, existing_role, active))
            if body.version == version =>
        {
            if existing_paas_user_id != paas_user_id
                || existing_role != role_name
                || active != body.active
            {
                let mut error = json_error(
                    StatusCode::CONFLICT,
                    "membership version already exists with different content",
                );
                stamp_idempotency_completion(&mut error.1.0);
                finish_membership_idempotent_request_in_tx(&mut tx, key, error.0, &error.1.0)
                    .await?;
                tx.commit().await.map_err(|_| db_error())?;
                return Err(error);
            }
            false
        }
        _ => true,
    };

    if write_authority {
        if mapped_user_id.is_some() {
            sqlx::query("UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1")
                .bind(cap_user_id)
                .bind(&body.display_name)
                .execute(&mut *tx)
                .await
                .map_err(|_| db_error())?;
        } else {
            sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, $2)")
                .bind(cap_user_id)
                .bind(&body.display_name)
                .execute(&mut *tx)
                .await
                .map_err(|_| db_error())?;
            sqlx::query(
                "INSERT INTO paas_external_mappings
                     (resource_type, paas_external_id, cap_id, metadata, updated_at)
                 VALUES ('user', $1, $2, $3, now())",
            )
            .bind(&paas_user_id)
            .bind(cap_user_id)
            .bind(serde_json::json!({"client_san": &auth.client_san}))
            .execute(&mut *tx)
            .await
            .map_err(|_| db_error())?;
        }
    }

    if write_authority {
        write_membership_projection_in_tx(&mut tx, cap_org_id, cap_user_id, role_name, body.active)
            .await
            .map_err(|_| db_error())?;
    }

    if write_authority {
        sqlx::query(
            "INSERT INTO paas_membership_sync_state
                 (org_id, user_id, paas_user_id, role, version, active, synced_at)
             VALUES ($1, $2, $3, $4, $5, $6, now())
             ON CONFLICT (org_id, user_id) DO UPDATE
                SET paas_user_id = EXCLUDED.paas_user_id,
                    role = EXCLUDED.role,
                    version = EXCLUDED.version,
                    active = EXCLUDED.active,
                    synced_at = now()",
        )
        .bind(cap_org_id)
        .bind(cap_user_id)
        .bind(&paas_user_id)
        .bind(role_name)
        .bind(body.version)
        .bind(body.active)
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    }

    if write_authority {
        audit_membership_authority_in_tx(
            &mut tx,
            MembershipAuthorityAudit {
                org_id: cap_org_id,
                user_id: cap_user_id,
                role: role_name,
                active: body.active,
                version: body.version,
                client_san: &auth.client_san,
                repair: false,
            },
        )
        .await
        .map_err(|_| db_error())?;
    }

    let response = serde_json::json!({
        "cap_org_id": cap_org_id,
        "cap_user_id": cap_user_id,
        "paas_org_id": paas_org_id,
        "paas_user_id": paas_user_id,
        "role": role_as_str(role),
        "active": body.active,
    });
    finish_membership_idempotent_request_in_tx(&mut tx, key, StatusCode::OK, &response).await?;
    tx.commit().await.map_err(|_| db_error())?;
    Ok((StatusCode::OK, Json(response)))
}

pub async fn sync_paas_entitlement(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SyncPaaSEntitlementRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    if body.version < 0 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "version must be non-negative",
        ));
    }
    if !body.deploy_allowed && body.block_reason.as_deref().unwrap_or("").is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "block_reason is required when deploy_allowed is false",
        ));
    }
    let key = idempotency_key(&headers)?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/entitlements");
    let hash = request_hash(&body)?;
    let idempotency = match begin_idempotent_request(&state, key, "PUT", &path, &hash).await? {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };

    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let cap_org_id: Uuid = sqlx::query_scalar(
            "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'organization'
            AND paas_external_id = $1",
        )
        .bind(&paas_org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "PaaS organization is not mapped"))?;

        let limits = serde_json::to_value(&body.limits).map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize entitlement limits",
            )
        })?;
        let mut tx = state.db.begin().await.map_err(|_| db_error())?;
        crate::entitlements::lock_org_entitlement_lane(&mut tx, cap_org_id)
            .await
            .map_err(|_| db_error())?;
        let existing: Option<(i64, bool, Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT version, deploy_allowed, block_reason, limits
           FROM organization_entitlements
          WHERE org_id = $1",
        )
        .bind(cap_org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?;
        let write_entitlement = match existing {
            Some((version, _, _, _)) if body.version < version => {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "entitlement version is stale",
                ));
            }
            Some((version, deploy_allowed, block_reason, existing_limits))
                if body.version == version =>
            {
                if deploy_allowed != body.deploy_allowed
                    || block_reason != body.block_reason
                    || existing_limits != limits
                {
                    return Err(json_error(
                        StatusCode::CONFLICT,
                        "entitlement version already exists with different content",
                    ));
                }
                false
            }
            _ => true,
        };
        if write_entitlement {
            sqlx::query(
                "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, block_reason, limits, source, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'paas', now())
             ON CONFLICT (org_id) DO UPDATE
                SET version = EXCLUDED.version,
                    deploy_allowed = EXCLUDED.deploy_allowed,
                    block_reason = EXCLUDED.block_reason,
                    limits = EXCLUDED.limits,
                    source = EXCLUDED.source,
                    updated_at = now()",
            )
            .bind(cap_org_id)
            .bind(body.version)
            .bind(body.deploy_allowed)
            .bind(body.block_reason.as_deref())
            .bind(&limits)
            .execute(&mut *tx)
            .await
            .map_err(|_| db_error())?;
        }
        tx.commit().await.map_err(|_| db_error())?;

        let response = serde_json::json!({
            "cap_org_id": cap_org_id,
            "paas_org_id": paas_org_id,
            "version": body.version,
            "deploy_allowed": body.deploy_allowed,
            "block_reason": body.block_reason,
            "limits": limits,
        });
        Ok((StatusCode::OK, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

async fn mapped_cap_org(
    state: &AppState,
    paas_org_id: &str,
) -> Result<(Uuid, String, String), (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_as(
        "SELECT o.id, o.name, o.cust_slug
           FROM paas_external_mappings m
           JOIN organizations o ON o.id = m.cap_id
          WHERE m.resource_type = 'organization'
            AND m.paas_external_id = $1",
    )
    .bind(paas_org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "PaaS organization is not mapped"))
}

fn actor_paas_user_id(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let value = headers
        .get("x-enclava-paas-user-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "x-enclava-paas-user-id is required",
            )
        })?;
    validate_external_id(value, "paas_user_id")?;
    Ok(value.to_string())
}

async fn internal_actor_context(
    state: &AppState,
    paas_org_id: &str,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, Json<serde_json::Value>)> {
    let paas_user_id = actor_paas_user_id(headers)?;
    let (cap_org_id, org_name, _org_slug) = mapped_cap_org(state, paas_org_id).await?;
    let cap_user_id: Uuid = sqlx::query_scalar(
        "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'user'
            AND paas_external_id = $1",
    )
    .bind(&paas_user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "PaaS user is not mapped"))?;
    let role: Option<(Role,)> = sqlx::query_as(
        "SELECT role as \"role: _\"
           FROM memberships
          WHERE org_id = $1
            AND user_id = $2
            AND removed_at IS NULL",
    )
    .bind(cap_org_id)
    .bind(cap_user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let role = role
        .map(|(role,)| role)
        .ok_or_else(|| json_error(StatusCode::FORBIDDEN, "PaaS user is not a CAP org member"))?;

    Ok(AuthContext {
        user_id: cap_user_id,
        org_id: cap_org_id,
        org_name,
        role,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    })
}

fn parse_internal_body<T: DeserializeOwned>(
    body: serde_json::Value,
) -> Result<T, (StatusCode, Json<serde_json::Value>)> {
    serde_json::from_value(body).map_err(|error| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("invalid request body: {error}"),
        )
    })
}

fn to_value<T: Serialize>(
    value: T,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    serde_json::to_value(value).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize response body",
        )
    })
}

async fn begin_actor_idempotent_request(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    auth: &AuthContext,
    body: &serde_json::Value,
    recovery: IdempotencyRecovery,
) -> Result<IdempotencyBegin, (StatusCode, Json<serde_json::Value>)> {
    let key = idempotency_key(headers)?;
    let hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))?;
    begin_idempotent_request_with_recovery(state, key, method, path, &hash, recovery).await
}

async fn begin_actor_deterministic_config_token_request(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    auth: &AuthContext,
    body: &serde_json::Value,
    binding: &ConfigTokenResourceBinding,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let key = idempotency_key(headers)?;
    let hash = deterministic_config_token_request_hash(auth, body, binding)?;
    let legacy_hash = legacy_config_token_request_hash(auth, body)?;
    begin_idempotent_request_with_recovery_and_binding(
        state,
        key,
        "POST",
        path,
        &hash,
        IdempotencyRecovery::DeterministicExpiringCapability,
        ConfigTokenIdempotencyOptions {
            binding: Some(binding),
            legacy_request_hash: Some(&legacy_hash),
        },
    )
    .await
}

fn deterministic_config_token_request_hash(
    auth: &AuthContext,
    body: &serde_json::Value,
    binding: &ConfigTokenResourceBinding,
) -> Result<Vec<u8>, InternalRouteError> {
    request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "capability_resource_id": binding.resource_id,
        "capability_instance_id": binding.instance_id,
        "body": body,
    }))
}

fn legacy_config_token_request_hash(
    auth: &AuthContext,
    body: &serde_json::Value,
) -> Result<Vec<u8>, InternalRouteError> {
    request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))
}

async fn preflight_existing_config_token_request(
    state: &AppState,
    key: &str,
    path: &str,
    auth: &AuthContext,
    body: &serde_json::Value,
) -> Result<Option<IdempotencyResponse>, InternalRouteError> {
    let row: Option<IdempotencyRow> = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                reservation_token, operation_id, lease_expires_at,
                recovery_kind, capability_receipt_version,
                capability_resource_id, capability_instance_id,
                known_not_applied,
                completed_at, created_at, updated_at,
                clock_timestamp() AS database_now
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.method != "POST" || row.path != path {
        return Err(idempotency_key_reused_error());
    }

    match row.recovery_kind.as_deref() {
        Some("deterministic_expiring_capability") => {
            let fallback_operation_id =
                idempotency_operation_id(key, "POST", path, &row.request_hash);
            let receipt = config_token_receipt_from_row(&row, fallback_operation_id)?;
            let stored_binding = ConfigTokenResourceBinding {
                resource_id: receipt.resource_id,
                instance_id: receipt.instance_id.clone(),
            };
            let expected_hash =
                deterministic_config_token_request_hash(auth, body, &stored_binding)?;
            if row.request_hash != expected_hash {
                return Err(idempotency_key_reused_error());
            }
            if let Some(response) = completed_idempotency_response(&row) {
                return Ok(Some(response));
            }
            if receipt.expires_at > row.database_now {
                return Ok(None);
            }
            let terminal = terminalize_expired_config_token_receipt(
                &state.db,
                ExpiredConfigTokenReceipt {
                    key,
                    previous_token: row.reservation_token,
                    operation_id: receipt.operation_id,
                    stored_recovery_kind: "deterministic_expiring_capability",
                    issued_at: receipt.issued_at,
                    expires_at: receipt.expires_at,
                    legacy: false,
                },
            )
            .await?;
            match terminal {
                IdempotencyBegin::Replay(response) => Ok(Some(response)),
                IdempotencyBegin::Execute(_) => Err(db_error()),
            }
        }
        Some("expiring_capability") => {
            let legacy_hash = legacy_config_token_request_hash(auth, body)?;
            if row.request_hash != legacy_hash {
                return Err(idempotency_key_reused_error());
            }
            let issued_at = chrono::DateTime::from_timestamp(row.created_at.timestamp(), 0)
                .expect("PostgreSQL timestamptz has a whole-second value");
            let minimum_recovery_after = issued_at + chrono::Duration::minutes(6);
            let recovery_after = row
                .lease_expires_at
                .map(|lease| lease.max(minimum_recovery_after))
                .unwrap_or(minimum_recovery_after);
            if row
                .response_status
                .is_some_and(|status| (200..300).contains(&status))
            {
                let sanitized = sanitize_legacy_completed_config_token_response(
                    &state.db,
                    key,
                    row.reservation_token,
                    row.operation_id.unwrap_or_else(|| {
                        idempotency_operation_id(key, "POST", path, &legacy_hash)
                    }),
                    issued_at,
                    recovery_after,
                )
                .await?;
                return match sanitized {
                    IdempotencyBegin::Replay(response) => Ok(Some(response)),
                    IdempotencyBegin::Execute(_) => Err(db_error()),
                };
            }
            if let Some(response) = completed_idempotency_response(&row) {
                return Ok(Some(response));
            }
            if recovery_after > row.database_now {
                return Err(idempotency_in_progress_error());
            }
            let terminal = terminalize_expired_config_token_receipt(
                &state.db,
                ExpiredConfigTokenReceipt {
                    key,
                    previous_token: row.reservation_token,
                    operation_id: row.operation_id.unwrap_or_else(|| {
                        idempotency_operation_id(key, "POST", path, &legacy_hash)
                    }),
                    stored_recovery_kind: "expiring_capability",
                    issued_at,
                    expires_at: recovery_after,
                    legacy: true,
                },
            )
            .await?;
            match terminal {
                IdempotencyBegin::Replay(response) => Ok(Some(response)),
                IdempotencyBegin::Execute(_) => Err(db_error()),
            }
        }
        None => {
            let legacy_hash = legacy_config_token_request_hash(auth, body)?;
            if row.request_hash != legacy_hash
                || !is_safe_migrated_legacy_config_token_terminal(&row)
            {
                return Err(idempotency_key_reused_error());
            }
            Ok(completed_idempotency_response(&row))
        }
        _ => Err(idempotency_key_reused_error()),
    }
}

async fn app_config_token_resource_binding(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
) -> Result<ConfigTokenResourceBinding, InternalRouteError> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, namespace, name
           FROM apps
          WHERE org_id = $1
            AND name = $2",
    )
    .bind(org_id)
    .bind(app_name)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let (resource_id, namespace, name) =
        row.ok_or_else(|| json_error(StatusCode::NOT_FOUND, "app not found"))?;
    Ok(ConfigTokenResourceBinding {
        resource_id,
        instance_id: format!("{namespace}-{name}"),
    })
}

async fn deployment_config_token_resource_binding(
    state: &AppState,
    org_id: Uuid,
    deployment_id: Uuid,
) -> Result<ConfigTokenResourceBinding, InternalRouteError> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT a.id, a.namespace, a.name
           FROM deployments d
           JOIN apps a ON a.id = d.app_id
          WHERE d.id = $1
            AND d.org_id = $2
            AND a.org_id = $2",
    )
    .bind(deployment_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let (resource_id, namespace, name) =
        row.ok_or_else(|| json_error(StatusCode::NOT_FOUND, "deployment not found"))?;
    Ok(ConfigTokenResourceBinding {
        resource_id,
        instance_id: format!("{namespace}-{name}"),
    })
}

struct ConfigTokenBindingResolution {
    binding: ConfigTokenResourceBinding,
    live_resource: bool,
}

async fn stored_deterministic_config_token_binding(
    state: &AppState,
    key: &str,
    path: &str,
) -> Result<Option<ConfigTokenResourceBinding>, InternalRouteError> {
    let row: Option<(Option<i16>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT capability_receipt_version,
                capability_resource_id,
                capability_instance_id
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1
            AND method = 'POST'
            AND path = $2
            AND recovery_kind = 'deterministic_expiring_capability'",
    )
    .bind(key)
    .bind(path)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some((receipt_version, resource_id, instance_id)) = row else {
        return Ok(None);
    };
    if receipt_version != Some(crate::auth::jwt::CONFIG_TOKEN_RECEIPT_VERSION) {
        return Err(db_error());
    }
    Ok(Some(ConfigTokenResourceBinding {
        resource_id: resource_id.ok_or_else(db_error)?,
        instance_id: instance_id
            .filter(|value| !value.is_empty())
            .ok_or_else(db_error)?,
    }))
}

async fn config_token_binding_with_receipt_fallback(
    state: &AppState,
    key: &str,
    path: &str,
    live_binding: Result<ConfigTokenResourceBinding, InternalRouteError>,
) -> Result<ConfigTokenBindingResolution, InternalRouteError> {
    let stored_binding = stored_deterministic_config_token_binding(state, key, path).await?;
    match (live_binding, stored_binding) {
        (Ok(binding), Some(stored)) if binding != stored => Err(idempotency_key_reused_error()),
        (Ok(binding), _) => Ok(ConfigTokenBindingResolution {
            binding,
            live_resource: true,
        }),
        (Err(not_found), Some(binding)) if not_found.0 == StatusCode::NOT_FOUND => {
            Ok(ConfigTokenBindingResolution {
                binding,
                live_resource: false,
            })
        }
        (Err(not_found), None) if not_found.0 == StatusCode::NOT_FOUND => Err(not_found),
        (Err(error), _) => Err(error),
    }
}

async fn require_deploy_entitlement(
    state: &AppState,
    cap_org_id: Uuid,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    let row: Option<(bool, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT deploy_allowed, block_reason, limits
           FROM organization_entitlements
          WHERE org_id = $1",
    )
    .bind(cap_org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some((deploy_allowed, block_reason, limits)) = row else {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "paas_managed_entitlement_missing",
        ));
    };
    if !deploy_allowed {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            block_reason.unwrap_or_else(|| "paas_managed_entitlement_blocked".to_string()),
        ));
    }
    Ok(limits)
}

struct InternalCreateAppIdentity<'a> {
    app_id: Uuid,
    org_id: Uuid,
    org_name: &'a str,
    body: &'a InternalCreateAppRequest,
    egress_allowlist: &'a [enclava_engine::types::EgressRule],
    egress_mode: &'a str,
    app_host: &'a str,
    tee_host: &'a str,
    resources: &'a crate::models::AppResources,
}

#[derive(sqlx::FromRow)]
struct InternalAppIdentityRow {
    org_id: Uuid,
    name: String,
    namespace: String,
    instance_id: String,
    tenant_id: String,
    service_account: String,
    bootstrap_owner_pubkey_hash: String,
    tenant_instance_identity_hash: String,
    unlock_mode: String,
    domain: String,
    tee_domain: Option<String>,
    signer_identity_subject: Option<String>,
    egress_allowlist: serde_json::Value,
    egress_mode: String,
    signer_identity_issuer: Option<String>,
    cpu_limit: Option<String>,
    memory_limit: Option<String>,
    app_data_size: Option<String>,
    tls_data_size: Option<String>,
}

async fn adopt_exact_internal_app(
    state: &AppState,
    expected: &InternalCreateAppIdentity<'_>,
) -> Result<Option<serde_json::Value>, InternalRouteError> {
    let row: Option<InternalAppIdentityRow> = sqlx::query_as(
        "SELECT a.org_id,
                a.name,
                a.namespace,
                a.instance_id,
                a.tenant_id,
                a.service_account,
                a.bootstrap_owner_pubkey_hash,
                a.tenant_instance_identity_hash,
                a.unlock_mode::text,
                a.domain,
                a.tee_domain,
                a.signer_identity_subject,
                a.egress_allowlist,
                a.egress_mode,
                a.signer_identity_issuer,
                r.cpu_limit,
                r.memory_limit,
                r.app_data_size,
                r.tls_data_size
           FROM apps a
           LEFT JOIN app_resources r ON r.app_id = a.id
          WHERE a.id = $1",
    )
    .bind(expected.app_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some(row) = row else {
        return Ok(None);
    };

    let expected_instance_id = format!(
        "{}-{}",
        expected.org_name,
        &expected.app_id.to_string()[..8]
    );
    let expected_namespace = format!("cap-{}-{}", expected.org_name, expected.body.name);
    let expected_service_account = format!("cap-{}-sa", expected.body.name);
    let expected_egress =
        serde_json::to_value(expected.egress_allowlist).map_err(|_| db_error())?;
    let identity_hash = enclava_common::crypto::compute_identity_hash(
        expected.org_name,
        &expected_instance_id,
        &row.bootstrap_owner_pubkey_hash,
    );
    let password_hash_matches = expected.body.unlock_mode != "password"
        || expected.body.bootstrap_pubkey_hash.as_deref()
            == Some(row.bootstrap_owner_pubkey_hash.as_str());
    let exact = row.org_id == expected.org_id
        && row.name == expected.body.name
        && row.namespace == expected_namespace
        && row.instance_id == expected_instance_id
        && row.tenant_id == expected.org_name
        && row.service_account == expected_service_account
        && password_hash_matches
        && row.tenant_instance_identity_hash == identity_hash
        && row.unlock_mode == expected.body.unlock_mode
        && row.domain == expected.app_host
        && row.tee_domain.as_deref() == Some(expected.tee_host)
        && row.signer_identity_subject == expected.body.signer_identity_subject
        && row.egress_allowlist == expected_egress
        && row.egress_mode == expected.egress_mode
        && row.signer_identity_issuer == expected.body.signer_identity_issuer
        && row.cpu_limit.as_deref() == Some(expected.resources.cpu_limit.as_str())
        && row.memory_limit.as_deref() == Some(expected.resources.memory_limit.as_str())
        && row.app_data_size.as_deref() == Some(expected.resources.app_data_size.as_str())
        && row.tls_data_size.as_deref() == Some(expected.resources.tls_data_size.as_str());
    if !exact {
        return Err(idempotency_resource_conflict_error());
    }

    Ok(Some(serde_json::json!({
        "cap_org_id": expected.org_id,
        "cap_app_id": expected.app_id,
        "name": expected.body.name,
        "namespace": row.namespace,
        "instance_id": row.instance_id,
        "service_account": row.service_account,
        "bootstrap_owner_pubkey_hash": row.bootstrap_owner_pubkey_hash,
        "tenant_instance_identity_hash": row.tenant_instance_identity_hash,
        "status": "creating",
        "domain": row.domain,
        "tee_domain": row.tee_domain,
        "signer_identity_subject": row.signer_identity_subject,
        "signer_identity_issuer": row.signer_identity_issuer,
    })))
}

pub async fn create_paas_app(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<InternalCreateAppRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    crate::routes::apps::validate_app_name(&body.name)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let key = idempotency_key(&headers)?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps");
    let hash = request_hash(&body)?;
    let idempotency = match begin_idempotent_request_with_recovery(
        &state,
        key,
        "POST",
        &path,
        &hash,
        IdempotencyRecovery::DeterministicResource {
            legacy_identity_bound: false,
        },
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };

    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let (cap_org_id, org_name, org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
        let limits = require_deploy_entitlement(&state, cap_org_id).await?;
        let max_apps = limits
            .get("max_apps")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid entitlement limits",
                )
            })?;
        let app_id = idempotency.operation_id();
        let app_host =
            enclava_common::hostnames::app_hostname(&body.name, &org_slug, &state.platform_domain)
                .map_err(|error| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        format!("invalid app hostname: {error}"),
                    )
                })?;
        let tee_host = enclava_common::hostnames::tee_hostname(
            &body.name,
            &org_slug,
            &state.tee_domain_suffix,
        )
        .map_err(|error| {
            json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid tee hostname: {error}"),
            )
        })?;
        let egress_allowlist =
            crate::routes::apps::validate_egress_allowlist(&body.egress_allowlist)
                .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
        let egress_mode = crate::routes::apps::validate_egress_mode(&body.egress_mode)
            .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;

        // Effective resource row: hosted defaults overlaid with any caller
        // overrides. Computed before adoption so replayed create requests compare
        // against what this call would actually persist.
        let resources = crate::routes::apps::hosted_app_resources(app_id, body.resources.as_ref());

        if idempotency.reclaimed() {
            let expected = InternalCreateAppIdentity {
                app_id,
                org_id: cap_org_id,
                org_name: &org_name,
                body: &body,
                egress_allowlist: &egress_allowlist,
                egress_mode: egress_mode.as_str(),
                app_host: &app_host,
                tee_host: &tee_host,
                resources: &resources,
            };
            if let Some(response) = adopt_exact_internal_app(&state, &expected).await? {
                return Ok((StatusCode::CREATED, response));
            }
        }

        let conflicting_name: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM apps WHERE org_id = $1 AND name = $2 AND id <> $3)",
        )
        .bind(cap_org_id)
        .bind(&body.name)
        .bind(app_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| db_error())?;
        if conflicting_name {
            return Err(idempotency_resource_conflict_error());
        }

        let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps WHERE org_id = $1")
            .bind(cap_org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| db_error())?;
        if app_count >= max_apps as i64 {
            return Err(json_error(StatusCode::FORBIDDEN, "entitlement_app_limit"));
        }

        // The hosted request carries no source-provider fields; the shared
        // candidate builder re-runs the request validations (same bodies) and
        // derives the row every create path persists.
        let create = crate::routes::apps::CreateAppRequest {
            name: body.name.clone(),
            unlock_mode: body.unlock_mode.clone(),
            bootstrap_pubkey_hash: body.bootstrap_pubkey_hash.clone(),
            signer_identity_subject: body.signer_identity_subject.clone(),
            signer_identity_issuer: body.signer_identity_issuer.clone(),
            source_provider: None,
            source_repository: None,
            egress_allowlist: body.egress_allowlist.clone(),
            egress_mode: body.egress_mode.clone(),
        };
        let app = crate::routes::apps::build_app_candidate(
            &state, app_id, cap_org_id, &org_name, &org_slug, &create,
        )
        .await?;

        let mut tx = state.db.begin().await.map_err(|_| db_error())?;
        crate::routes::apps::create_app_inner(
            &mut tx,
            crate::routes::apps::CreateAppActor::PaasInternal,
            crate::routes::apps::CreateAppInput {
                app: &app,
                resource_overrides: body.resources.as_ref(),
            },
        )
        .await
        .map_err(|error| match error {
            crate::routes::apps::CreateAppError::Response(response) => response,
            crate::routes::apps::CreateAppError::NameTaken => {
                json_error(StatusCode::CONFLICT, "app name already taken in this org")
            }
            crate::routes::apps::CreateAppError::StaleOwnerSeed => {
                json_error(StatusCode::CONFLICT, "stale_owner_seed")
            }
            crate::routes::apps::CreateAppError::Db => db_error(),
        })?;
        tx.commit().await.map_err(|_| db_error())?;

        let response = serde_json::json!({
            "cap_org_id": cap_org_id,
            "cap_app_id": app_id,
            "name": body.name,
            "namespace": app.namespace,
            "instance_id": app.instance_id,
            "service_account": app.service_account,
            "bootstrap_owner_pubkey_hash": app.bootstrap_owner_pubkey_hash,
            "tenant_instance_identity_hash": app.tenant_instance_identity_hash,
            "status": "creating",
            "domain": app_host,
            "tee_domain": tee_host,
            "signer_identity_subject": body.signer_identity_subject,
            "signer_identity_issuer": body.signer_identity_issuer,
        });
        Ok((StatusCode::CREATED, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn list_paas_apps(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let (cap_org_id, _org_name, _org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
    let rows = crate::db::paas::list_paas_org_apps_pool(&state.db, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "cap_app_id": row.id,
                    "name": row.name,
                    "status": row.status,
                    "domain": row.domain,
                    "tee_domain": row.tee_domain,
                })
            })
            .collect(),
    }))
}

/// Reopen only the legacy failed-delete receipt, before ordinary terminal replay.
/// operation_id identifies the request, not the app, so creation time is the
/// available incarnation boundary. The execution path enforces it again.
async fn begin_app_delete_request(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    auth: &AuthContext,
    body: &serde_json::Value,
    app_name: &str,
) -> Result<IdempotencyBegin, InternalRouteError> {
    let key = idempotency_key(headers)?;
    let hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))?;
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    let row: Option<IdempotencyRow> = sqlx::query_as(
        "SELECT cap_internal_idempotency.*, clock_timestamp() AS database_now
           FROM cap_internal_idempotency WHERE idempotency_key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if let Some(row) = row {
        if row.method != "DELETE" || row.path != path || row.request_hash != hash {
            return Err(idempotency_key_reused_error());
        }
        if row.recovery_kind.as_deref() == Some("retry_safe")
            && row.response_status == Some(409)
            && row.response_body.as_ref() == Some(&idempotency_recovery_required_body())
            && row.completed_at.is_some()
        {
            let app_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM apps
                  WHERE org_id = $1 AND name = $2
                    AND status = 'deleting'::app_status_enum AND created_at < $3",
            )
            .bind(auth.org_id)
            .bind(app_name)
            .bind(row.created_at)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| db_error())?;
            if let Some(app_id) = app_id {
                crate::deploy::lock_app_deployment_lane(&mut tx, app_id)
                    .await
                    .map_err(|_| db_error())?;
                let current: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM apps
                      WHERE id = $1 AND org_id = $2 AND name = $3
                        AND status = 'deleting'::app_status_enum AND created_at < $4
                      FOR UPDATE",
                )
                .bind(app_id)
                .bind(auth.org_id)
                .bind(app_name)
                .bind(row.created_at)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| db_error())?;
                if current.is_some() {
                    let token = Uuid::new_v4();
                    // The owner trigger compares against OLD.reservation_token.
                    set_idempotency_completion_owner(
                        &mut tx,
                        row.reservation_token.unwrap_or(token),
                    )
                    .await?;
                    let updated = sqlx::query(
                        "UPDATE cap_internal_idempotency
                            SET response_status = NULL, response_body = NULL,
                                completed_at = NULL, reservation_token = $2,
                                lease_expires_at = clock_timestamp()
                                    + ($3::bigint * interval '1 second'),
                                known_not_applied = false,
                                attempt_count = attempt_count + 1,
                                updated_at = clock_timestamp()
                          WHERE idempotency_key = $1
                            AND reservation_token IS NOT DISTINCT FROM $4
                            AND method = 'DELETE' AND path = $5 AND request_hash = $6
                            AND recovery_kind = 'retry_safe' AND response_status = 409
                            AND response_body = $7 AND completed_at IS NOT NULL",
                    )
                    .bind(key)
                    .bind(token)
                    .bind(IDEMPOTENCY_DEFAULT_LEASE_SECONDS)
                    .bind(row.reservation_token)
                    .bind(path)
                    .bind(&hash)
                    .bind(idempotency_recovery_required_body())
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| db_error())?;
                    if updated.rows_affected() != 1 {
                        return Err(idempotency_in_progress_error());
                    }
                    let operation_id = row.operation_id.ok_or_else(db_error)?;
                    tx.commit().await.map_err(|_| db_error())?;
                    return Ok(IdempotencyBegin::Execute(IdempotencyLease::new(
                        state.db.clone(),
                        key.to_string(),
                        token,
                        IdempotencyLeaseClaim {
                            operation_id,
                            reclaimed: true,
                            regenerate: false,
                            committed_keyring_checkpoint: false,
                            config_token_receipt: None,
                        },
                        IdempotencyRecovery::RetrySafe,
                    )));
                }
            }
        }
        if let Some(response) = completed_idempotency_response(&row) {
            tx.commit().await.map_err(|_| db_error())?;
            return Ok(IdempotencyBegin::Replay(response));
        }
    }
    tx.rollback().await.map_err(|_| db_error())?;
    begin_idempotent_request(state, key, "DELETE", path, &hash).await
}

pub async fn delete_paas_app(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    crate::routes::apps::validate_app_name_for_existing(&app_name)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}");
    let idempotency =
        match begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name).await? {
            IdempotencyBegin::Execute(lease) => lease,
            IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
        };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let reclaimed = idempotency.reclaimed();
        let created_before = sqlx::query_scalar(
            "SELECT created_at FROM cap_internal_idempotency
              WHERE idempotency_key = $1 AND reservation_token = $2",
        )
        .bind(&idempotency.key)
        .bind(idempotency.token)
        .fetch_one(&state.db)
        .await
        .map_err(|_| db_error())?;
        let abandon_teardown = match body.get("abandon_teardown") {
            None | Some(serde_json::Value::Bool(false)) => false,
            Some(serde_json::Value::Bool(true)) => true,
            Some(_) => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_abandon_teardown",
                ));
            }
        };
        let status = match crate::routes::apps::delete_app_before(
            auth,
            State(state.clone()),
            Path(app_name),
            Some(created_before),
            abandon_teardown,
        )
        .await
        {
            Ok(status) => status,
            Err((StatusCode::NOT_FOUND, _)) if reclaimed => StatusCode::NO_CONTENT,
            Err(error) => return Err(error),
        };
        let response = serde_json::json!({"status": "deleted"});
        Ok((status, response))
    }
    .await;
    let (status, response) = complete_app_delete_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn put_paas_app_desired_state(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    Extension(engine): Extension<Arc<enclava_engine::apply::engine::ApplyEngine>>,
    Json(body): Json<InternalAppDesiredStateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    validate_external_id(&body.operation_id, "operation_id")?;
    crate::routes::apps::validate_app_name_for_existing(&app_name)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/desired-state");
    let hash = request_hash(&body)?;
    let idempotency =
        match begin_idempotent_request(&state, &body.operation_id, "PUT", &path, &hash).await? {
            IdempotencyBegin::Execute(lease) => lease,
            IdempotencyBegin::Replay((status, response)) => {
                return Ok((status, Json(response)));
            }
        };
    let operation_id = idempotency.operation_id();

    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let (cap_org_id, _, _) = mapped_cap_org(&state, &paas_org_id).await?;
        let desired_state = body.desired_state.as_str();
        crate::deploy::set_app_desired_state(
            &state,
            &engine,
            cap_org_id,
            &app_name,
            desired_state,
            operation_id,
        )
        .await?;
        Ok((
            StatusCode::OK,
            serde_json::json!({
                "operation_id": body.operation_id,
                "desired_state": desired_state,
                "runtime_state": desired_state,
            }),
        ))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn get_paas_app_logs(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<crate::routes::logs::RawLogQuery>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    validate_org_name(&app_name)?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    if auth.role == Role::Member {
        return Err(json_error(StatusCode::FORBIDDEN, "scope_not_allowed"));
    }
    crate::routes::logs::paas_app_logs(auth, state, app_name, query).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalProofBundleQuery {
    nonce: String,
    origin: String,
}

pub async fn get_paas_proof_bundle(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    Query(query): Query<InternalProofBundleQuery>,
) -> Result<Response, InternalRouteError> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    crate::routes::apps::validate_app_name_for_existing(&app_name)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let nonce: [u8; 32] = general_purpose::URL_SAFE_NO_PAD
        .decode(&query.nonce)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "invalid_nonce"))?;
    let canonical_nonce = general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    if canonical_nonce != query.nonce {
        return Err(json_error(StatusCode::BAD_REQUEST, "invalid_nonce"));
    }

    let (cap_org_id, _, _) = mapped_cap_org(&state, &paas_org_id).await?;
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT a.id, COALESCE(job.artifact_deployment_id, d.id)
           FROM apps a
           JOIN LATERAL (
               SELECT id FROM deployments
                WHERE app_id = a.id AND status = 'healthy'
                ORDER BY completed_at DESC NULLS LAST, created_at DESC
                LIMIT 1
           ) d ON true
           LEFT JOIN LATERAL (
               SELECT artifact_deployment_id
                 FROM deployment_apply_jobs
                WHERE app_id = a.id AND deployment_id = d.id
                ORDER BY generation DESC
                LIMIT 1
           ) job ON true
          WHERE a.org_id = $1 AND a.name = $2",
    )
    .bind(cap_org_id)
    .bind(&app_name)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let (app_id, deployment_id) =
        row.ok_or_else(|| json_error(StatusCode::NOT_FOUND, "app_or_deployment_not_found"))?;
    let artifacts = crate::signing_service::load_workload_artifacts_for_deployment(
        &state.db,
        app_id,
        deployment_id,
    )
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| json_error(StatusCode::CONFLICT, "workload_artifacts_not_found"))?;
    let mut allowed_domains = vec![
        artifacts.descriptor.app_domain.as_str(),
        artifacts.descriptor.tee_domain.as_str(),
    ];
    allowed_domains.extend(
        artifacts
            .descriptor
            .custom_domains
            .iter()
            .map(String::as_str),
    );
    let origin = validated_proof_origin(&query.origin, &allowed_domains)
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "origin_not_allowed"))?;
    let domain = reqwest::Url::parse(&origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "origin_not_allowed"))?;
    let client = crate::routes::logs::resolved_tenant_tee_client(
        app_id,
        &app_name,
        &artifacts.descriptor.namespace,
        &domain,
    )
    .await
    .unwrap_or_else(|| state.tee_http_client.clone());
    let url = format!("{origin}/.well-known/confidential/proof-bundle?nonce={canonical_nonce}");
    let upstream = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client
            .get(url)
            .header(header::ACCEPT, PROOF_BUNDLE_MEDIA_TYPE)
            .timeout(std::time::Duration::from_secs(20))
            .send(),
    )
    .await
    .map_err(|_| json_error(StatusCode::GATEWAY_TIMEOUT, "proof_bundle_timeout"))?
    .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "proof_bundle_unavailable"))?;
    if !upstream.status().is_success() {
        let status = if upstream.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_GATEWAY
        };
        return Err(json_error(status, "proof_bundle_unavailable"));
    }
    if upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(PROOF_BUNDLE_MEDIA_TYPE)
        || upstream.content_length().unwrap_or(0) > MAX_PROOF_BUNDLE_BYTES as u64
    {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            "invalid_proof_bundle_response",
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| json_error(StatusCode::BAD_GATEWAY, "proof_bundle_unavailable"))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_PROOF_BUNDLE_BYTES {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                "proof_bundle_too_large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, PROOF_BUNDLE_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}

fn validated_proof_origin(value: &str, allowed_domains: &[&str]) -> Option<String> {
    let origin = reqwest::Url::parse(value).ok()?;
    if origin.scheme() != "https"
        || origin.username() != ""
        || origin.password().is_some()
        || origin.port_or_known_default() != Some(443)
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return None;
    }
    let host = origin.host_str()?;
    allowed_domains
        .contains(&host)
        .then(|| format!("https://{host}"))
}

pub async fn list_paas_members(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let (cap_org_id, _org_name, _org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
    let rows = crate::db::paas::list_paas_org_members_pool(&state.db, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "cap_user_id": row.user_id,
                    "display_name": row.display_name,
                    "role": row.role,
                    "active": row.active,
                })
            })
            .collect(),
    }))
}

pub async fn list_paas_deployments(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let (cap_org_id, _org_name, _org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
    let rows = crate::db::paas::list_paas_org_deployments_pool(&state.db, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(|row| {
                let image = row
                    .spec_snapshot
                    .get("image")
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
                serde_json::json!({
                    "cap_deployment_id": row.deployment_id,
                    "cap_app_id": row.app_id,
                    "app_name": row.app_name,
                    "status": row.status,
                    "image": image,
                    "spec": row.spec_snapshot,
                    "image_digest": row.image_digest,
                    "error_message": public_deployment_error_message(row.error_message.as_deref()),
                })
            })
            .collect(),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn observed_internal_status_item(
    state: &AppState,
    cap_app_id: Uuid,
    app_name: String,
    namespace: String,
    recorded_app_status: String,
    domain: String,
    tee_domain: Option<String>,
    cap_deployment_id: Option<Uuid>,
    recorded_deployment_status: Option<String>,
    image_digest: Option<String>,
    recorded_error_message: Option<String>,
) -> serde_json::Value {
    let observed = observe_app_status_fields_for_deployment(
        state,
        cap_app_id,
        &namespace,
        &app_name,
        &domain,
        tee_domain.as_deref(),
        cap_deployment_id,
    )
    .await;
    let app_status = observed.effective_status(&recorded_app_status);
    let runtime_failure_applies = cap_deployment_id
        .is_some_and(|deployment_id| observed.runtime_failure_applies_to_latest(deployment_id));
    let deployment_status = if runtime_failure_applies {
        Some("failed".to_string())
    } else {
        recorded_deployment_status.clone()
    };
    let live_error_message = runtime_failure_applies
        .then(|| observed.runtime_failure_public_message())
        .flatten();
    let error_message =
        project_internal_deployment_error(live_error_message, recorded_error_message.as_deref());
    let latest_deployment = cap_deployment_id.map(|id| {
        serde_json::json!({
            "cap_deployment_id": id,
            "status": deployment_status,
            "recorded_status": recorded_deployment_status,
            "image_digest": image_digest,
            "error_message": error_message,
            "observation": &observed.observation,
        })
    });
    serde_json::json!({
        "cap_app_id": cap_app_id,
        "app_name": app_name,
        "status": app_status,
        "recorded_status": recorded_app_status,
        "domain": domain,
        "tee_domain": tee_domain,
        "latest_deployment": latest_deployment,
        "observation": observed.observation,
    })
}

fn project_internal_deployment_error(
    live_error_message: Option<String>,
    recorded_error_message: Option<&str>,
) -> Option<String> {
    live_error_message.or_else(|| public_deployment_error_message(recorded_error_message))
}

pub async fn list_paas_status(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let (cap_org_id, _org_name, _org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
    let rows = crate::db::paas::list_paas_org_status_pool(&state.db, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    let items = stream::iter(rows.into_iter().map(|row| {
        let state = state.clone();
        async move {
            observed_internal_status_item(
                &state,
                row.app_id,
                row.app_name,
                row.namespace,
                row.app_status,
                row.domain,
                row.tee_domain,
                row.deployment_id,
                row.deployment_status,
                row.image_digest,
                row.error_message,
            )
            .await
        }
    }))
    .buffered(STATUS_OBSERVATION_CONCURRENCY)
    .collect()
    .await;
    Ok(Json(InternalListResponse { items }))
}

pub async fn list_paas_cluster_status(
    _auth: InternalAuth,
    State(state): State<AppState>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    let rows = crate::db::paas::list_paas_cluster_status_pool(&state.db)
        .await
        .map_err(|_| db_error())?;

    let items = stream::iter(rows.into_iter().map(|row| {
        let state = state.clone();
        async move {
            let mut item = observed_internal_status_item(
                &state,
                row.app_id,
                row.app_name,
                row.namespace,
                row.app_status,
                row.domain,
                row.tee_domain,
                row.deployment_id,
                row.deployment_status,
                row.image_digest,
                row.error_message,
            )
            .await;
            let object = item
                .as_object_mut()
                .expect("internal status item is always an object");
            object.insert(
                "paas_org_id".to_string(),
                serde_json::json!(row.paas_org_id),
            );
            object.insert("cap_org_id".to_string(), serde_json::json!(row.cap_org_id));
            object.insert(
                "cap_org_name".to_string(),
                serde_json::json!(row.cap_org_name),
            );
            object.insert(
                "cap_org_display_name".to_string(),
                serde_json::json!(row.cap_org_display_name),
            );
            item
        }
    }))
    .buffered(STATUS_OBSERVATION_CONCURRENCY)
    .collect()
    .await;
    Ok(Json(InternalListResponse { items }))
}

enum InternalDeploymentAdoption {
    Missing,
    SetupIncomplete,
    Response(serde_json::Value),
}

async fn adopt_exact_internal_deployment(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
    external_id: &str,
    body: &InternalDeployRequest,
) -> Result<InternalDeploymentAdoption, InternalRouteError> {
    type DeploymentAdoptionRow = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        Option<String>,
        bool,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        serde_json::Value,
        String,
    );
    let row: Option<DeploymentAdoptionRow> = sqlx::query_as(
        "SELECT d.id,
                d.app_id,
                COALESCE(a.custom_domain, a.domain),
                d.trigger::text,
                d.status::text,
                d.image_digest,
                d.cosign_verified,
                d.error_message,
                d.created_at,
                d.completed_at,
                d.spec_snapshot,
                a.name
           FROM deployments d
           JOIN apps a ON a.id = d.app_id
          WHERE d.org_id = $1 AND d.external_id = $2",
    )
    .bind(org_id)
    .bind(external_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some(row) = row else {
        return Ok(InternalDeploymentAdoption::Missing);
    };

    if matches!(
        row.10
            .get("setup_state")
            .and_then(serde_json::Value::as_str),
        Some("dns_pending" | "cleanup_pending")
    ) {
        return Ok(InternalDeploymentAdoption::SetupIncomplete);
    }

    let expected_resources = serde_json::to_value(&body.resources).map_err(|_| db_error())?;
    let expected_log_encryption =
        serde_json::to_value(&body.log_encryption).map_err(|_| db_error())?;
    let expected_profile = body
        .workload_security_profile
        .as_deref()
        .unwrap_or("restricted");
    let exact = row.11 == app_name
        && row.10.get("app_name").and_then(serde_json::Value::as_str) == Some(app_name)
        && row.10.get("image").and_then(serde_json::Value::as_str) == Some(body.image.as_str())
        && row
            .10
            .get("container_name")
            .and_then(serde_json::Value::as_str)
            == Some(body.container_name.as_deref().unwrap_or("web"))
        && row
            .10
            .get("external_id")
            .and_then(serde_json::Value::as_str)
            == Some(external_id)
        && row.10.get("resources") == Some(&expected_resources)
        && row
            .10
            .get("workload_security_profile")
            .and_then(serde_json::Value::as_str)
            == Some(expected_profile)
        && row.10.get("log_encryption") == Some(&expected_log_encryption);
    if !exact {
        return Err(idempotency_resource_conflict_error());
    }

    Ok(InternalDeploymentAdoption::Response(serde_json::json!({
        "deployment_id": row.0,
        "app_id": row.1,
        "app_domain": row.2,
        "trigger": row.3,
        "status": row.4,
        "image_digest": row.5,
        "cosign_verified": row.6,
        "error_message": public_deployment_error_message(row.7.as_deref()),
        "created_at": row.8,
        "completed_at": row.9,
    })))
}

pub async fn deploy_paas_app(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<InternalDeployRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/deploy");
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    require_deploy_entitlement(&state, auth.org_id).await?;
    let raw_body = to_value(&body)?;
    let legacy_identity_bound = body
        .external_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &raw_body,
        IdempotencyRecovery::DeterministicResource {
            legacy_identity_bound,
        },
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let external_id = body
        .external_id
        .clone()
        .unwrap_or_else(|| idempotency_deployment_external_id(idempotency.operation_id()));
    if idempotency.reclaimed() {
        match adopt_exact_internal_deployment(&state, auth.org_id, &app_name, &external_id, &body)
            .await
        {
            Ok(InternalDeploymentAdoption::Missing) => {}
            Ok(InternalDeploymentAdoption::SetupIncomplete) => {
                return Err(defer_idempotent_request(idempotency, None).await);
            }
            Ok(InternalDeploymentAdoption::Response(response)) => {
                let (status, response) =
                    complete_idempotent_result(idempotency, Ok((StatusCode::CREATED, response)))
                        .await?;
                return Ok((status, Json(response)));
            }
            Err(error) => {
                let _ = complete_idempotent_result(idempotency, Err(error)).await?;
                unreachable!("an error result cannot complete as success");
            }
        }
    }
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let deploy_request = crate::routes::deployments::DeployRequest {
            image: body.image,
            container_name: body.container_name,
            resources: body.resources,
            external_id: Some(external_id),
            source_provider: None,
            source_repository: None,
            customer_descriptor_blob: body.customer_descriptor_blob,
            org_keyring_blob: body.org_keyring_blob,
            signed_policy_artifact: body.signed_policy_artifact,
            workload_security_profile: body.workload_security_profile,
            log_encryption: body.log_encryption,
            customer_config_roll_hold_seconds: None,
        };
        let (status, Json(response)) = crate::routes::deployments::deploy(
            auth,
            State(state.clone()),
            Path(app_name),
            Json(deploy_request),
        )
        .await?;
        let response = to_value(response)?;
        Ok((status, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn generate_paas_agent_policy(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<crate::routes::deployments::AgentPolicyRequest>,
) -> Result<
    Json<crate::routes::deployments::AgentPolicyResponse>,
    (StatusCode, Json<serde_json::Value>),
> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    require_deploy_entitlement(&state, auth.org_id).await?;
    crate::routes::deployments::generate_agent_policy(
        auth,
        State(state),
        Path(app_name),
        Json(body),
    )
    .await
}

pub async fn register_paas_public_key(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/users/me/public-keys");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let (status, Json(response)) =
            crate::routes::users::register_public_key(auth, State(state.clone()), Json(parsed))
                .await?;
        let response = to_value(response)?;
        Ok((status, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn get_paas_keyring(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let org_name = auth.org_name.clone();
    let Json(response) =
        crate::routes::orgs::get_keyring(auth, State(state), Path(org_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn get_paas_signing_readiness(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let org_name = auth.org_name.clone();
    let Json(response) =
        crate::routes::orgs::get_signing_readiness(auth, State(state), Path(org_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn put_paas_keyring(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/keyring");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "PUT",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let org_name = auth.org_name.clone();
        let parsed = parse_internal_body(body)?;
        let (status, Json(response)) = crate::routes::orgs::put_keyring(
            auth,
            State(state.clone()),
            Path(org_name),
            Json(parsed),
        )
        .await?;
        let response = to_value(response)?;
        Ok((status, response))
    }
    .await;
    let (status, response) = complete_keyring_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn bootstrap_paas_keyring_signing_service(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/keyring/bootstrap-signing-service");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let org_name = auth.org_name.clone();
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::orgs::bootstrap_signing_service_owner(
            auth,
            State(state.clone()),
            Path(org_name),
            Json(parsed),
        )
        .await?;
        let response = to_value(response)?;
        Ok((StatusCode::OK, response))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn rotate_paas_keyring_owner(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/keyring/rotate-owner");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let org_name = auth.org_name.clone();
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::orgs::rotate_org_owner(
            auth,
            State(state.clone()),
            Path(org_name),
            Json(parsed),
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    }
    .await;
    let (status, response) = complete_keyring_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn issue_paas_signer_rotation_token(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer/rotation-token");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::ExpiringCapability {
            recovery_after_seconds: 11 * 60,
        },
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::apps::issue_signer_rotation_token_route(
            auth,
            State(state.clone()),
            Path(app_name),
            Json(parsed),
        )
        .await?;
        let response = to_value(response)?;
        Ok((StatusCode::OK, response))
    }
    .await;
    let (status, response) = complete_expiring_capability_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn rotate_paas_signer(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "PATCH",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, mut body)) => {
            // Older completed receipts may contain private fencing metadata.
            if let Some(map) = body.as_object_mut() {
                map.remove("rotation_count");
                map.remove(SIGNER_PUBLICATION_CHECKPOINT_GENERATION_FIELD);
            }
            return Ok((status, Json(body)));
        }
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        // The checkpoint lookup runs inside the result scope on purpose: any
        // failure there — including a malformed or unverifiable checkpoint
        // such as one written before the generation field existed — must
        // flow through complete_signer_result, which terminalizes
        // outcome-unknown failures to the bounded new-key disposition on
        // the completed channel. Surfacing it with `?` outside would leave
        // the row incomplete and re-run on every lease expiry forever.
        let (app_id, rotation_generation, committed) =
            match signer_publication_checkpoint(&state.db, &idempotency).await? {
                Some((app_id, rotation_generation, committed)) => {
                    (app_id, rotation_generation, committed)
                }
                None => {
                    let parsed = parse_internal_body(body)?;
                    let (committed, rotation_generation) =
                        crate::routes::apps::rotate_signer_commit(auth, &state, &app_name, parsed)
                            .await?;
                    (committed.id, rotation_generation, to_value(&committed)?)
                }
            };
        let (Some(expected_subject), Some(expected_issuer)) = (
            committed
                .get("signer_identity_subject")
                .and_then(serde_json::Value::as_str),
            committed
                .get("signer_identity_issuer")
                .and_then(serde_json::Value::as_str),
        ) else {
            return Err(db_error());
        };
        // The generation captured with the committed response (in the same
        // transaction) is compared against the live generation before and
        // after publication, so any interleaved authority event — including
        // a rotate-back that restores the same subject/issuer — turns this
        // retry into a terminal superseded result instead of a false success.
        match crate::routes::apps::reconcile_signer_publication(
            &state,
            app_id,
            expected_subject,
            expected_issuer,
            rotation_generation,
        )
        .await
        {
            Ok(()) => Ok((StatusCode::OK, committed)),
            Err((StatusCode::CONFLICT, Json(body)))
                if body.get("code").and_then(serde_json::Value::as_str)
                    == Some(crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE) =>
            {
                Err((StatusCode::CONFLICT, Json(body)))
            }
            Err(_) => Err(signer_publication_checkpoint_error(
                committed,
                rotation_generation,
            )),
        }
    }
    .await;
    let (status, response) = complete_signer_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn get_paas_app_domain(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::domains::get_domain(auth, State(state), Path(app_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn create_paas_domain_challenge(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::domains::create_challenge(
            auth,
            State(state.clone()),
            Path(app_name),
            Json(parsed),
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn verify_paas_domain_challenge(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name, domain)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}/verify");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let Json(response) = crate::routes::domains::verify_challenge(
            auth,
            State(state.clone()),
            Path((app_name, domain)),
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn remove_paas_custom_domain(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name, domain)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "DELETE",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::RetrySafe,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let status = crate::routes::domains::remove_custom_domain(
            auth,
            State(state.clone()),
            Path((app_name, domain)),
        )
        .await?;
        Ok((status, serde_json::json!({"status": "deleted"})))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn list_paas_config_keys(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::config::list_config_keys(auth, State(state), Path(app_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn issue_paas_config_token(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token");
    let key = idempotency_key(&headers)?;
    if let Some((status, response)) =
        preflight_existing_config_token_request(&state, key, &path, &auth, &body).await?
    {
        return Ok((status, Json(response)));
    }
    let binding = config_token_binding_with_receipt_fallback(
        &state,
        key,
        &path,
        app_config_token_resource_binding(&state, auth.org_id, &app_name).await,
    )
    .await?;
    if !binding.live_resource {
        return Err(idempotency_in_progress_error());
    }
    let idempotency = match begin_actor_deterministic_config_token_request(
        &state,
        &headers,
        &path,
        &auth,
        &body,
        &binding.binding,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let issuance = idempotency
        .config_token_receipt()
        .ok_or_else(db_error)?
        .issuance();
    let result = async {
        let Json(response) = crate::routes::config::issue_config_token_route_for_issuance(
            auth,
            state.clone(),
            app_name,
            issuance,
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    };
    let (status, response) =
        complete_deterministic_config_token_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn sync_paas_config_metadata(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/sync");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::RetrySafe,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        crate::auth::scopes::require_config_metadata_write(&auth)?;
        let status = crate::routes::config::sync_config_metadata_for_org(
            &state,
            auth.org_id,
            &app_name,
            &parsed,
        )
        .await?;
        Ok((status, serde_json::json!({"status": "synced"})))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn delete_paas_config_metadata(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name, key_name)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/{key_name}/meta");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "DELETE",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::RetrySafe,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        crate::auth::scopes::require_config_metadata_write(&auth)?;
        let status = crate::routes::config::delete_config_metadata_for_org(
            &state,
            auth.org_id,
            &app_name,
            &key_name,
        )
        .await?;
        Ok((status, serde_json::json!({"status": "deleted"})))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn rollback_paas_app(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    require_deploy_entitlement(&state, auth.org_id).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/rollback");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let (status, Json(response)) = crate::routes::deployments::rollback(
            auth,
            State(state.clone()),
            Path(app_name),
            Json(parsed),
        )
        .await?;
        Ok((status, to_value(response)?))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn create_paas_generic_deployment(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    require_deploy_entitlement(&state, auth.org_id).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/deployments");
    let legacy_identity_bound = body
        .get("external_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "POST",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::DeterministicResource {
            legacy_identity_bound,
        },
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        // The cached response stores a time-relative
        // `customer_config_hold_remaining_ms` measured when the first
        // request committed. Replaying it verbatim would anchor the stale
        // duration at the retry's receipt and grant a fresh window after
        // CAP's real deadline, so recompute the remainder from the stored
        // hold before replaying — and refuse the replay when the hold's
        // durable state cannot be established or ended terminally.
        IdempotencyBegin::Replay((status, body)) => {
            let (status, body) = refresh_replayed_hold_remainder(&state, status, body).await?;
            return Ok((status, Json(body)));
        }
    };
    let reclaimed = idempotency.reclaimed();
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let mut parsed: crate::routes::deployments::GenericDeploymentRequest =
            parse_internal_body(body)?;
        if parsed.external_id.is_none() {
            parsed.external_id = Some(idempotency_deployment_external_id(
                idempotency.operation_id(),
            ));
        }
        let (status, Json(response)) = crate::routes::deployments::create_generic_deployment_inner(
            auth,
            state.clone(),
            parsed,
            true,
        )
        .await?;
        Ok((status, to_value(response)?))
    }
    .await;
    if reclaimed
        && matches!(
            &result,
            Err((StatusCode::CONFLICT, Json(response)))
                if response.get("error").and_then(serde_json::Value::as_str)
                    == Some("external_id belongs to a deployment whose setup did not complete")
        )
    {
        return Err(defer_idempotent_request(idempotency, None).await);
    }
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

/// Recompute a cached idempotent response's `customer_config_hold_remaining_ms`
/// from the stored hold before replay. The field is a duration measured at
/// commit time; replaying the cached value verbatim would anchor that stale
/// remainder at the retry's receipt and let the CLI spend a fresh window
/// after CAP's real expiry.
///
/// Terminal outcomes fail closed rather than being replayed as-is:
///
/// * An *unreleased terminal* hold (expired, swept, or superseded) means the
///   deployment failed without ever rolling. Replaying the cached success
///   body with `customer_config_hold: false` would let a retried CLI treat
///   that failed deployment as an ordinary unheld deploy and write the old
///   request's values into whichever TEE is serving, so the replay is
///   answered with the durable terminal failure instead.
/// * A database failure while reloading the hold is served as a retryable
///   503, never as an authoritative-looking hold without its deadline. The
///   CLI's only fallback for `hold: true` with no deadline anchors at the
///   retry's own request time, which can grant a fresh window after CAP
///   already expired the hold.
async fn refresh_replayed_hold_remainder(
    state: &AppState,
    status: StatusCode,
    mut body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), (StatusCode, Json<serde_json::Value>)> {
    let Some(deployment_id) = body
        .get("deployment_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return Ok((status, body));
    };
    let replay_state =
        crate::deployment_jobs::customer_config_hold_replay_state(&state.db, deployment_id)
            .await
            .map_err(|_| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the customer-config hold state could not be re-read for replay; retry with the same idempotency key",
                )
            })?;
    let Some(object) = body.as_object_mut() else {
        return Ok((status, body));
    };
    match replay_state {
        crate::deployment_jobs::CustomerConfigHoldReplay::Open(hold) => {
            object.insert(
                "customer_config_hold".to_string(),
                serde_json::Value::Bool(true),
            );
            object.insert(
                "customer_config_hold_until".to_string(),
                serde_json::Value::String(hold.until.to_rfc3339()),
            );
            object.insert(
                "customer_config_hold_remaining_ms".to_string(),
                serde_json::Value::from(hold.remaining_ms),
            );
        }
        crate::deployment_jobs::CustomerConfigHoldReplay::Released => {
            // The hold released since the first response: the roll resumed.
            // Do not keep reporting a live window, and let the replayed
            // response describe the deployment's then-current state.
            object.insert(
                "customer_config_hold".to_string(),
                serde_json::Value::Bool(false),
            );
            object.insert(
                "customer_config_hold_until".to_string(),
                serde_json::Value::Null,
            );
            object.insert(
                "customer_config_hold_remaining_ms".to_string(),
                serde_json::Value::Null,
            );
        }
        crate::deployment_jobs::CustomerConfigHoldReplay::EndedUnreleased => {
            // The hold expired or was superseded without a release: the
            // deployment is terminally failed and its roll never happened.
            // Replay the durable failure instead of letting the cached
            // success body masquerade as an ordinary unheld deploy.
            *object = ended_unreleased_hold_replay_body(object);
            return Ok((StatusCode::GONE, body));
        }
        crate::deployment_jobs::CustomerConfigHoldReplay::NotHeld => {
            // No held apply job exists. A cached body that never reported a
            // hold replays verbatim; a cached *held* response whose job row
            // is gone (e.g. the app was deleted) must not masquerade as a
            // live hold, so it fails closed the same way.
            if object
                .get("customer_config_hold")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                *object = ended_unreleased_hold_replay_body(object);
                return Ok((StatusCode::GONE, body));
            }
            return Ok((status, body));
        }
    }
    Ok((status, body))
}

/// Replace a cached held-create response body with the terminal-failure
/// body an unreleased ended hold must replay.
fn ended_unreleased_hold_replay_body(
    object: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut replacement = serde_json::json!({
        "error": "the customer-config roll hold ended without a release and the deployment failed without rolling; start a new deploy instead of retrying this one",
    });
    let replacement_object = replacement
        .as_object_mut()
        .expect("replacement error object");
    if let Some(instance) = object.get("app_name") {
        replacement_object.insert("app_name".to_string(), instance.clone());
    }
    std::mem::take(replacement_object)
}

pub async fn get_paas_generic_deployment(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, deployment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::deployments::get_generic_deployment(auth, State(state), Path(deployment_id))
            .await?;
    Ok(Json(to_value(response)?))
}

pub async fn release_paas_customer_config_roll(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, deployment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    crate::auth::scopes::require_app_write(&auth)?;
    match crate::deployment_jobs::release_customer_config_hold(
        &state.db,
        auth.org_id,
        deployment_id,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        crate::deployment_jobs::CustomerConfigHoldRelease::Released => {
            Ok(Json(serde_json::json!({"status": "released"})))
        }
        crate::deployment_jobs::CustomerConfigHoldRelease::AlreadyReleased => {
            Ok(Json(serde_json::json!({"status": "already_released"})))
        }
        crate::deployment_jobs::CustomerConfigHoldRelease::NotHeld => {
            Ok(Json(serde_json::json!({"status": "not_held"})))
        }
        crate::deployment_jobs::CustomerConfigHoldRelease::NotFound => {
            Err(json_error(StatusCode::NOT_FOUND, "deployment not found"))
        }
        crate::deployment_jobs::CustomerConfigHoldRelease::Unavailable(message) => {
            Err(json_error(StatusCode::CONFLICT, message))
        }
    }
}

pub async fn issue_paas_generic_config_token(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, deployment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path =
        format!("/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/config-token");
    let key = idempotency_key(&headers)?;
    if let Some((status, response)) =
        preflight_existing_config_token_request(&state, key, &path, &auth, &body).await?
    {
        return Ok((status, Json(response)));
    }
    let binding = config_token_binding_with_receipt_fallback(
        &state,
        key,
        &path,
        deployment_config_token_resource_binding(&state, auth.org_id, deployment_id).await,
    )
    .await?;
    if !binding.live_resource {
        return Err(idempotency_in_progress_error());
    }
    let idempotency = match begin_actor_deterministic_config_token_request(
        &state,
        &headers,
        &path,
        &auth,
        &body,
        &binding.binding,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let issuance = idempotency
        .config_token_receipt()
        .ok_or_else(db_error)?
        .issuance();
    let result = async {
        let Json(response) = crate::routes::deployments::generic_config_token_for_issuance(
            auth,
            state.clone(),
            deployment_id,
            issuance,
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    };
    let (status, response) =
        complete_deterministic_config_token_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

pub async fn get_paas_unlock_status(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::unlock::unlock_status(auth, State(state), Path(app_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn get_paas_unlock_endpoint(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::unlock::unlock_endpoint(auth, State(state), Path(app_name)).await?;
    Ok(Json(to_value(response)?))
}

pub async fn update_paas_unlock_mode(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    require_deploy_entitlement(&state, auth.org_id).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/mode");
    let idempotency = match begin_actor_idempotent_request(
        &state,
        &headers,
        "PUT",
        &path,
        &auth,
        &body,
        IdempotencyRecovery::FailClosed,
    )
    .await?
    {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::unlock::update_unlock_mode(
            auth,
            State(state.clone()),
            Path(app_name),
            Json(parsed),
        )
        .await?;
        Ok((StatusCode::OK, to_value(response)?))
    }
    .await;
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
}

#[cfg(test)]
#[path = "internal/tests/mod.rs"]
mod tests;
