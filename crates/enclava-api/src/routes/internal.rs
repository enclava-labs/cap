use axum::{
    Json,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
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
const CONFIG_TOKEN_HARD_ATTEMPT_SECONDS: u64 = 30;
const CONFIG_TOKEN_CANCELLATION_SECONDS: u64 = 5;
const CONFIG_TOKEN_RECEIPT_LEASE_SECONDS: i64 = 60;
const CONFIG_TOKEN_SAFE_RETURN_SECONDS: i64 = CONFIG_TOKEN_HARD_ATTEMPT_SECONDS as i64;

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
    config_token_receipt: Option<ConfigTokenReceipt>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

struct IdempotencyLeaseClaim {
    operation_id: Uuid,
    reclaimed: bool,
    regenerate: bool,
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

#[derive(Clone, Debug)]
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

        if config.requires_trusted_proxy() {
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
    #[serde(default = "default_auto_unlock_mode")]
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

fn default_auto_unlock_mode() -> String {
    "auto".to_string()
}

fn json_error(
    status: StatusCode,
    error: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": error.into()})))
}

fn idempotency_in_progress_error() -> InternalRouteError {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "idempotency_request_in_progress",
            "retryable": true,
            "disposition": "retry_same_key",
        })),
    )
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
    let body = serde_json::json!({
        "error": "idempotency_recovery_required",
        "retryable": false,
        "disposition": "reconcile_then_retry_with_new_key",
    });
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
                lease_expires_at = NULL,
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token IS NOT DISTINCT FROM $6
            AND recovery_kind = $7
            AND response_status IS NULL
            AND $8::timestamptz <= clock_timestamp()
            AND (
                completed_at IS NOT NULL
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
                lease_expires_at = NULL,
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

    let reclaimable = match row.reservation_token {
        None => {
            row.updated_at
                <= row.database_now - chrono::Duration::seconds(IDEMPOTENCY_LEGACY_STALE_SECONDS)
        }
        Some(_) => row
            .lease_expires_at
            .is_some_and(|lease_expires_at| lease_expires_at <= row.database_now),
    };
    if !reclaimable && recovery != IdempotencyRecovery::DeterministicExpiringCapability {
        return Err(idempotency_in_progress_error());
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
    if policy_changed
        || deterministic_legacy_is_unsafe
        || recovery == IdempotencyRecovery::FailClosed
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
                recovery_kind = COALESCE(recovery_kind, $5),
                updated_at = clock_timestamp(),
                attempt_count = attempt_count + 1
          WHERE idempotency_key = $1
            AND completed_at IS NULL
            AND reservation_token IS NOT DISTINCT FROM $6
            AND (
                ($6::uuid IS NULL AND updated_at <= clock_timestamp()
                    - ($7::bigint * interval '1 second'))
                OR ($6::uuid IS NOT NULL AND lease_expires_at <= clock_timestamp())
            )",
    )
    .bind(key)
    .bind(token)
    .bind(operation_id)
    .bind(recovery.lease_seconds())
    .bind(recovery.kind())
    .bind(row.reservation_token)
    .bind(IDEMPOTENCY_LEGACY_STALE_SECONDS)
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

async fn defer_idempotent_request(mut lease: IdempotencyLease) -> Result<(), InternalRouteError> {
    lease.stop_heartbeat();
    let updated = sqlx::query(
        "UPDATE cap_internal_idempotency
            SET lease_expires_at = clock_timestamp()
                + ($3::bigint * interval '1 second'),
                updated_at = clock_timestamp()
          WHERE idempotency_key = $1
            AND reservation_token = $2
            AND completed_at IS NULL",
    )
    .bind(&lease.key)
    .bind(lease.token)
    .bind(IDEMPOTENCY_RETRY_DEFER_SECONDS)
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
        Err((status, Json(body))) => {
            finish_idempotent_request(lease, status, &body).await?;
            Err((status, Json(body)))
        }
    }
}

/// Return an expiring capability exactly once without persisting it in CAP's
/// idempotency ledger.  The incomplete row and its DB-authored lease are the
/// replay marker: callers receive `idempotency_in_progress` while the
/// capability may still be valid and a bounded reconcile/new-key disposition
/// after expiry.  Error DTOs remain safe to persist and replay.
async fn complete_expiring_capability_result(
    mut lease: IdempotencyLease,
    result: Result<IdempotencyResponse, InternalRouteError>,
) -> Result<IdempotencyResponse, InternalRouteError> {
    match result {
        Ok(response) => {
            lease.stop_heartbeat();
            Ok(response)
        }
        Err(error) => complete_idempotent_result(lease, Err(error)).await,
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
        let error = json_error(
            StatusCode::CONFLICT,
            "membership user mapping is inconsistent",
        );
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
            let error = json_error(StatusCode::CONFLICT, "membership version is stale");
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
                let error = json_error(
                    StatusCode::CONFLICT,
                    "membership version already exists with different content",
                );
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
    let hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "capability_resource_id": binding.resource_id,
        "capability_instance_id": binding.instance_id,
        "body": body,
    }))?;
    let legacy_hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))?;
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

async fn replay_safe_migrated_legacy_config_token_terminal(
    state: &AppState,
    key: &str,
    path: &str,
    auth: &AuthContext,
    body: &serde_json::Value,
) -> Result<Option<IdempotencyResponse>, InternalRouteError> {
    let legacy_hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))?;
    let row: Option<IdempotencyRow> = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                reservation_token, operation_id, lease_expires_at,
                recovery_kind, capability_receipt_version,
                capability_resource_id, capability_instance_id,
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
    if row.method != "POST"
        || row.path != path
        || row.request_hash != legacy_hash
        || !is_safe_migrated_legacy_config_token_terminal(&row)
    {
        return Ok(None);
    }
    Ok(completed_idempotency_response(&row))
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
    match live_binding {
        Ok(binding) => Ok(ConfigTokenBindingResolution {
            binding,
            live_resource: true,
        }),
        Err(not_found) if not_found.0 == StatusCode::NOT_FOUND => {
            let Some(binding) = stored_deterministic_config_token_binding(state, key, path).await?
            else {
                return Err(not_found);
            };
            Ok(ConfigTokenBindingResolution {
                binding,
                live_resource: false,
            })
        }
        Err(error) => Err(error),
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
        && row.cpu_limit.as_deref() == Some("1")
        && row.memory_limit.as_deref() == Some("1Gi")
        && row.app_data_size.as_deref() == Some("5Gi")
        && row.tls_data_size.as_deref() == Some("2Gi");
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
    let tee_host =
        enclava_common::hostnames::tee_hostname(&body.name, &org_slug, &state.tee_domain_suffix)
            .map_err(|error| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid tee hostname: {error}"),
                )
            })?;
    let signer_set_at =
        if body.signer_identity_subject.is_some() || body.signer_identity_issuer.is_some() {
            Some(chrono::Utc::now())
        } else {
            None
        };
    let egress_allowlist = crate::routes::apps::validate_egress_allowlist(&body.egress_allowlist)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let egress_mode = crate::routes::apps::validate_egress_mode(&body.egress_mode)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;

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

    let (tenant_id, instance_id, namespace, service_account, pubkey_hash, identity_hash) =
        crate::routes::apps::derive_identity(
            &org_name,
            app_id,
            &body.name,
            &body.unlock_mode,
            body.bootstrap_pubkey_hash.as_deref(),
        )
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;

    let resources = crate::models::AppResources {
        app_id,
        cpu_limit: "1".to_string(),
        memory_limit: "1Gi".to_string(),
        app_data_size: "5Gi".to_string(),
        tls_data_size: "2Gi".to_string(),
    };
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, cap_org_id)
        .await
        .map_err(|_| db_error())?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app_id)
        .await
        .map_err(|_| db_error())?;
    crate::routes::deployments::enforce_authoritative_entitlement(
        &mut tx, cap_org_id, &resources, true,
    )
    .await?;

    sqlx::query(
        "INSERT INTO apps (
            id, org_id, name, namespace, instance_id, tenant_id, service_account,
            bootstrap_owner_pubkey_hash, tenant_instance_identity_hash,
            unlock_mode, domain, tee_domain,
            signer_identity_subject, signer_identity_issuer, signer_identity_set_at,
            egress_allowlist, egress_mode
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11, $12, $13, $14, $15, $16, $17)",
    )
    .bind(app_id)
    .bind(cap_org_id)
    .bind(&body.name)
    .bind(&namespace)
    .bind(&instance_id)
    .bind(&tenant_id)
    .bind(&service_account)
    .bind(&pubkey_hash)
    .bind(&identity_hash)
    .bind(&body.unlock_mode)
    .bind(&app_host)
    .bind(&tee_host)
    .bind(body.signer_identity_subject.as_deref())
    .bind(body.signer_identity_issuer.as_deref())
    .bind(signer_set_at)
    .bind(sqlx::types::Json(egress_allowlist.clone()))
    .bind(egress_mode.as_str())
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if error.to_string().contains("duplicate key") || error.to_string().contains("unique") {
            json_error(StatusCode::CONFLICT, "app name already taken in this org")
        } else {
            db_error()
        }
    })?;
    sqlx::query(
        "INSERT INTO app_resources (
             app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(resources.app_id)
    .bind(&resources.cpu_limit)
    .bind(&resources.memory_limit)
    .bind(&resources.app_data_size)
    .bind(&resources.tls_data_size)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    tx.commit().await.map_err(|_| db_error())?;

    let response = serde_json::json!({
        "cap_org_id": cap_org_id,
        "cap_app_id": app_id,
        "name": body.name,
        "namespace": namespace,
        "instance_id": instance_id,
        "service_account": service_account,
        "bootstrap_owner_pubkey_hash": pubkey_hash,
        "tenant_instance_identity_hash": identity_hash,
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
    let rows: Vec<(Uuid, String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT id,
               name,
               status::text,
               domain,
               tee_domain
          FROM apps
         WHERE org_id = $1
         ORDER BY created_at DESC, id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(|(id, name, status, domain, tee_domain)| {
                serde_json::json!({
                    "cap_app_id": id,
                    "name": name,
                    "status": status,
                    "domain": domain,
                    "tee_domain": tee_domain,
                })
            })
            .collect(),
    }))
}

pub async fn delete_paas_app(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    crate::routes::apps::validate_app_name(&app_name)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}");
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
        let reclaimed = idempotency.reclaimed();
        let status =
            match crate::routes::apps::delete_app(auth, State(state.clone()), Path(app_name)).await
            {
                Ok(status) => status,
                Err((StatusCode::NOT_FOUND, _)) if reclaimed => StatusCode::NO_CONTENT,
                Err(error) => return Err(error),
            };
        let response = serde_json::json!({"status": "deleted"});
        Ok((status, response))
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

pub async fn list_paas_members(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path(paas_org_id): Path<String>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let (cap_org_id, _org_name, _org_slug) = mapped_cap_org(&state, &paas_org_id).await?;
    let rows: Vec<(Uuid, String, String, bool)> = sqlx::query_as(
        r#"
        SELECT u.id,
               u.display_name,
               m.role::text,
               m.removed_at IS NULL AS active
          FROM memberships m
          JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1
         ORDER BY u.display_name, u.id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(|(cap_user_id, display_name, role, active)| {
                serde_json::json!({
                    "cap_user_id": cap_user_id,
                    "display_name": display_name,
                    "role": role,
                    "active": active,
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
    type PaasDeploymentRow = (
        Uuid,
        Uuid,
        String,
        String,
        serde_json::Value,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<PaasDeploymentRow> = sqlx::query_as(
        r#"
        SELECT d.id,
               d.app_id,
               a.name,
               d.status::text,
               d.spec_snapshot,
               d.image_digest,
               d.error_message
          FROM deployments d
          JOIN apps a ON a.id = d.app_id
         WHERE d.org_id = $1
         ORDER BY d.created_at DESC, d.id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(
                |(
                    cap_deployment_id,
                    cap_app_id,
                    app_name,
                    status,
                    spec,
                    image_digest,
                    error_message,
                )| {
                    let image = spec
                        .get("image")
                        .and_then(|value| value.as_str())
                        .map(str::to_string);
                    serde_json::json!({
                        "cap_deployment_id": cap_deployment_id,
                        "cap_app_id": cap_app_id,
                        "app_name": app_name,
                        "status": status,
                        "image": image,
                        "spec": spec,
                        "image_digest": image_digest,
                        "error_message": public_deployment_error_message(error_message.as_deref()),
                    })
                },
            )
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
    type PaasStatusRow = (
        Uuid,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<PaasStatusRow> = sqlx::query_as(
        r#"
        SELECT a.id,
               a.name,
               a.namespace,
               a.status::text,
               a.domain,
               a.tee_domain,
               latest.id,
               latest.status,
               latest.image_digest,
               latest.error_message
          FROM apps a
          LEFT JOIN LATERAL (
              SELECT d.id,
                     d.status::text AS status,
                     d.image_digest,
                     d.error_message
                FROM deployments d
                LEFT JOIN deployment_apply_jobs apply_job
                  ON apply_job.deployment_id = d.id
               WHERE d.app_id = a.id
               ORDER BY (apply_job.generation IS NOT NULL) DESC,
                        apply_job.generation DESC NULLS LAST,
                        d.created_at DESC,
                        d.id DESC
               LIMIT 1
          ) latest ON TRUE
         WHERE a.org_id = $1
         ORDER BY a.created_at DESC, a.id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;
    let items = stream::iter(rows.into_iter().map(
        |(
            cap_app_id,
            app_name,
            namespace,
            app_status,
            domain,
            tee_domain,
            cap_deployment_id,
            deployment_status,
            image_digest,
            error_message,
        )| {
            let state = state.clone();
            async move {
                observed_internal_status_item(
                    &state,
                    cap_app_id,
                    app_name,
                    namespace,
                    app_status,
                    domain,
                    tee_domain,
                    cap_deployment_id,
                    deployment_status,
                    image_digest,
                    error_message,
                )
                .await
            }
        },
    ))
    .buffered(STATUS_OBSERVATION_CONCURRENCY)
    .collect()
    .await;
    Ok(Json(InternalListResponse { items }))
}

pub async fn list_paas_cluster_status(
    _auth: InternalAuth,
    State(state): State<AppState>,
) -> Result<Json<InternalListResponse>, (StatusCode, Json<serde_json::Value>)> {
    type PaasClusterStatusRow = (
        String,
        Uuid,
        String,
        Option<String>,
        Uuid,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<PaasClusterStatusRow> = sqlx::query_as(
        r#"
        SELECT m.paas_external_id,
               o.id,
               o.name,
               o.display_name,
               a.id,
               a.name,
               a.namespace,
               a.status::text,
               a.domain,
               a.tee_domain,
               latest.id,
               latest.status,
               latest.image_digest,
               latest.error_message
          FROM apps a
          JOIN organizations o ON o.id = a.org_id
          JOIN paas_external_mappings m
            ON m.org_id = o.id
           AND m.resource_type = 'organization'
          LEFT JOIN LATERAL (
              SELECT d.id,
                     d.status::text AS status,
                     d.image_digest,
                     d.error_message
                FROM deployments d
                LEFT JOIN deployment_apply_jobs apply_job
                  ON apply_job.deployment_id = d.id
               WHERE d.app_id = a.id
               ORDER BY (apply_job.generation IS NOT NULL) DESC,
                        apply_job.generation DESC NULLS LAST,
                        d.created_at DESC,
                        d.id DESC
               LIMIT 1
          ) latest ON TRUE
         ORDER BY a.created_at DESC, a.id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;

    let items = stream::iter(rows.into_iter().map(
        |(
            paas_org_id,
            cap_org_id,
            cap_org_name,
            cap_org_display_name,
            cap_app_id,
            app_name,
            namespace,
            app_status,
            domain,
            tee_domain,
            cap_deployment_id,
            deployment_status,
            image_digest,
            error_message,
        )| {
            let state = state.clone();
            async move {
                let mut item = observed_internal_status_item(
                    &state,
                    cap_app_id,
                    app_name,
                    namespace,
                    app_status,
                    domain,
                    tee_domain,
                    cap_deployment_id,
                    deployment_status,
                    image_digest,
                    error_message,
                )
                .await;
                let object = item
                    .as_object_mut()
                    .expect("internal status item is always an object");
                object.insert("paas_org_id".to_string(), serde_json::json!(paas_org_id));
                object.insert("cap_org_id".to_string(), serde_json::json!(cap_org_id));
                object.insert("cap_org_name".to_string(), serde_json::json!(cap_org_name));
                object.insert(
                    "cap_org_display_name".to_string(),
                    serde_json::json!(cap_org_display_name),
                );
                item
            }
        },
    ))
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
                defer_idempotent_request(idempotency).await?;
                return Err(idempotency_in_progress_error());
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
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
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
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
    };
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        let parsed = parse_internal_body(body)?;
        let Json(response) = crate::routes::apps::rotate_signer(
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
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
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
        replay_safe_migrated_legacy_config_token_terminal(&state, key, &path, &auth, &body).await?
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
        IdempotencyBegin::Execute(lease) if !binding.live_resource => {
            drop(lease);
            return Err(idempotency_in_progress_error());
        }
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
        IdempotencyBegin::Replay((status, body)) => return Ok((status, Json(body))),
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
        let (status, Json(response)) = crate::routes::deployments::create_generic_deployment(
            auth,
            State(state.clone()),
            Json(parsed),
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
        defer_idempotent_request(idempotency).await?;
        return Err(idempotency_in_progress_error());
    }
    let (status, response) = complete_idempotent_result(idempotency, result).await?;
    Ok((status, Json(response)))
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
        replay_safe_migrated_legacy_config_token_terminal(&state, key, &path, &auth, &body).await?
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
        IdempotencyBegin::Execute(lease) if !binding.live_resource => {
            drop(lease);
            return Err(idempotency_in_progress_error());
        }
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
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use sqlx::Connection;

    async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect membership sync regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate membership sync regression database");
        pool
    }

    async fn named_database_test_pool(application_name: &str) -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse membership sync regression database URL")
            .application_name(application_name);
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect named membership sync pool")
    }

    async fn wait_for_named_lock_waiters(
        pool: &sqlx::PgPool,
        application_name: &str,
        expected: i64,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT count(*)
                       FROM pg_stat_activity
                      WHERE datname = current_database()
                        AND application_name = $1
                        AND wait_event_type = 'Lock'",
                )
                .bind(application_name)
                .fetch_one(pool)
                .await
                .expect("inspect named membership sync lock state");
                if waiting >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("membership sync writers did not reach the mapping lane");
    }

    fn idempotency_headers(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(key).expect("valid idempotency key"),
        );
        headers
    }

    async fn sync_member(
        state: &AppState,
        paas_org_id: &str,
        paas_user_id: &str,
        idempotency_key: &str,
        body: SyncPaaSMemberRequest,
    ) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
        sync_paas_member(
            InternalAuth {
                client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
            },
            State(state.clone()),
            Path((paas_org_id.to_string(), paas_user_id.to_string())),
            idempotency_headers(idempotency_key),
            Json(body),
        )
        .await
    }

    fn member_request(
        display_name: &str,
        role: &str,
        active: bool,
        version: i64,
    ) -> SyncPaaSMemberRequest {
        SyncPaaSMemberRequest {
            display_name: display_name.to_string(),
            role: role.to_string(),
            active,
            version,
        }
    }

    async fn insert_mapped_org(
        pool: &sqlx::PgPool,
        org_id: Uuid,
        org_name: &str,
        paas_org_id: &str,
    ) {
        crate::db::orgs::insert_org_pool(pool, org_id, org_name, None, false)
            .await
            .expect("insert membership sync organization");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id, org_id)
             VALUES ('organization', $1, $2, $2)",
        )
        .bind(paas_org_id)
        .bind(org_id)
        .execute(pool)
        .await
        .expect("map membership sync organization");
    }

    fn idempotency_test_state(pool: sqlx::PgPool) -> AppState {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool;
        state
    }

    fn expect_idempotency_execution(begin: IdempotencyBegin) -> IdempotencyLease {
        match begin {
            IdempotencyBegin::Execute(lease) => lease,
            IdempotencyBegin::Replay((status, body)) => {
                panic!("expected execution, got replay {status}: {body}")
            }
        }
    }

    fn expect_idempotency_replay(begin: IdempotencyBegin) -> IdempotencyResponse {
        match begin {
            IdempotencyBegin::Replay(response) => response,
            IdempotencyBegin::Execute(_) => panic!("expected replay, got execution"),
        }
    }

    fn test_config_token_binding() -> ConfigTokenResourceBinding {
        ConfigTokenResourceBinding {
            resource_id: Uuid::new_v4(),
            instance_id: format!("test-instance-{}", Uuid::new_v4().simple()),
        }
    }

    async fn begin_test_config_token_receipt(
        state: &AppState,
        key: &str,
        path: &str,
        hash: &[u8],
        binding: &ConfigTokenResourceBinding,
    ) -> Result<IdempotencyBegin, InternalRouteError> {
        begin_idempotent_request_with_recovery_and_binding(
            state,
            key,
            "POST",
            path,
            hash,
            IdempotencyRecovery::DeterministicExpiringCapability,
            ConfigTokenIdempotencyOptions {
                binding: Some(binding),
                legacy_request_hash: None,
            },
        )
        .await
    }

    async fn insert_config_token_test_actor(
        pool: &sqlx::PgPool,
        org_id: Uuid,
        org_name: &str,
        paas_org_id: &str,
        user_id: Uuid,
        paas_user_id: &str,
    ) {
        insert_mapped_org(pool, org_id, org_name, paas_org_id).await;
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Config Token Test')")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("insert config-token actor");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
        )
        .bind(paas_user_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("map config-token actor");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner')",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(pool)
        .await
        .expect("authorize config-token actor");
    }

    async fn insert_config_token_test_app(
        pool: &sqlx::PgPool,
        org_id: Uuid,
        org_name: &str,
        app_id: Uuid,
        app_name: &str,
        identity_suffix: &str,
    ) {
        let namespace = format!("cap-{org_name}-{app_name}-{identity_suffix}");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain,
                 signer_identity_subject, signer_identity_issuer,
                 egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 $12, $13, '[]'::jsonb, 'restricted'
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(app_name)
        .bind(&namespace)
        .bind(format!("{org_name}-{identity_suffix}"))
        .bind(org_name)
        .bind(format!("cap-{app_name}-{identity_suffix}-sa"))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!(
            "{app_name}-{identity_suffix}.{org_name}.enclava.test"
        ))
        .bind(format!(
            "{app_name}-{identity_suffix}.{org_name}.tee.enclava.test"
        ))
        .bind("https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main")
        .bind("https://token.actions.githubusercontent.com")
        .execute(pool)
        .await
        .expect("insert config-token app");
    }

    fn config_token_actor_headers(key: &str, paas_user_id: &str) -> HeaderMap {
        let mut headers = idempotency_headers(key);
        headers.insert(
            "x-enclava-paas-user-id",
            HeaderValue::from_str(paas_user_id).expect("valid PaaS actor header"),
        );
        headers
    }

    fn internal_test_auth() -> InternalAuth {
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        }
    }

    async fn expire_idempotency_lease(pool: &sqlx::PgPool, key: &str) {
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET lease_expires_at = clock_timestamp() - interval '1 minute',
                    updated_at = clock_timestamp() - interval '1 minute'
              WHERE idempotency_key = $1",
        )
        .bind(key)
        .execute(pool)
        .await
        .expect("expire idempotency lease with the database clock");
    }

    #[tokio::test]
    async fn migration_terminalizes_only_stale_legacy_reservations_without_data_leakage() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let mut connection = sqlx::PgConnection::connect(&database_url)
            .await
            .expect("connect isolated idempotency migration database");
        let schema = format!("idempotency_migration_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut connection)
            .await
            .expect("create isolated idempotency migration schema");
        sqlx::query(&format!("SET search_path TO {schema}, public"))
            .execute(&mut connection)
            .await
            .expect("select isolated idempotency migration schema");

        let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut migrations: Vec<std::path::PathBuf> = std::fs::read_dir(&migration_dir)
            .expect("read API migrations")
            .map(|entry| entry.expect("read migration entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
            .collect();
        migrations.sort();
        let lease_migration = migrations
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("0040_"))
            })
            .cloned()
            .expect("find idempotency lease migration");
        for migration in migrations.iter().filter(|path| *path < &lease_migration) {
            let sql = std::fs::read_to_string(migration).expect("read prerequisite migration");
            sqlx::raw_sql(&sql)
                .execute(&mut connection)
                .await
                .unwrap_or_else(|error| panic!("apply {}: {error}", migration.display()));
        }

        let stale_key = "migration-stale-legacy";
        let recent_key = "migration-recent-legacy";
        let completed_key = "migration-completed-legacy";
        let path = "/internal/test/migration-terminalization";
        let stale_hash = Sha256::digest(b"stale secret request payload").to_vec();
        let recent_hash = Sha256::digest(b"recent secret request payload").to_vec();
        let completed_hash = Sha256::digest(b"completed secret request payload").to_vec();
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash, updated_at
             ) VALUES
                 ($1, 'POST', $4, $5, clock_timestamp() - interval '31 minutes'),
                 ($2, 'POST', $4, $6, clock_timestamp() - interval '29 minutes'),
                 ($3, 'POST', $4, $7, clock_timestamp() - interval '1 day')",
        )
        .bind(stale_key)
        .bind(recent_key)
        .bind(completed_key)
        .bind(path)
        .bind(&stale_hash)
        .bind(&recent_hash)
        .bind(&completed_hash)
        .execute(&mut connection)
        .await
        .expect("seed pre-lease idempotency rows");
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET response_status = 201,
                    response_body = '{\"status\":\"already-complete\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
        )
        .bind(completed_key)
        .execute(&mut connection)
        .await
        .expect("complete control legacy row before lease migration");

        let migration_sql =
            std::fs::read_to_string(&lease_migration).expect("read idempotency lease migration");
        sqlx::raw_sql(&migration_sql)
            .execute(&mut connection)
            .await
            .expect("apply idempotency lease migration");

        type MigrationLedgerMetadata = (
            Option<Uuid>,
            Option<Uuid>,
            Option<String>,
            Option<i32>,
            Option<serde_json::Value>,
            bool,
            i32,
        );
        let stale_metadata: MigrationLedgerMetadata = sqlx::query_as(
            "SELECT reservation_token, operation_id, recovery_kind,
                    response_status, response_body,
                    completed_at IS NOT NULL, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(stale_key)
        .fetch_one(&mut connection)
        .await
        .expect("load migration-terminalized legacy row");
        assert!(stale_metadata.0.is_some());
        assert_eq!(stale_metadata.1, stale_metadata.0);
        assert_eq!(stale_metadata.2.as_deref(), Some("fail_closed"));
        assert_eq!(stale_metadata.3, Some(409));
        assert_eq!(
            stale_metadata.4,
            Some(serde_json::json!({
                "error": "idempotency_recovery_required",
                "retryable": false,
                "disposition": "reconcile_then_retry_with_new_key",
            }))
        );
        assert!(stale_metadata.5);
        assert_eq!(stale_metadata.6, 1);
        assert_eq!(
            stale_metadata
                .4
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(3),
            "terminal response must not expose the key, path, hash, or request payload"
        );

        let pre_upgrade_completion = sqlx::query(
            "UPDATE cap_internal_idempotency
                SET response_status = 200,
                    response_body = '{\"status\":\"late-old-handler\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
        )
        .bind(stale_key)
        .execute(&mut connection)
        .await
        .expect_err("migration fence must reject pre-upgrade key-only completion");
        assert_eq!(
            pre_upgrade_completion
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("42501")
        );

        let stale_row: IdempotencyRow = sqlx::query_as(
            "SELECT method, path, request_hash, response_status, response_body,
                    reservation_token, operation_id, lease_expires_at,
                    recovery_kind,
                    NULL::smallint AS capability_receipt_version,
                    NULL::uuid AS capability_resource_id,
                    NULL::text AS capability_instance_id,
                    completed_at, created_at, updated_at,
                    clock_timestamp() AS database_now
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(stale_key)
        .fetch_one(&mut connection)
        .await
        .expect("load migration-terminalized row for replay");
        assert_eq!(
            idempotency_replay("POST", path, &stale_hash, stale_row)
                .expect("terminal migration row is replayable")
                .expect("terminal migration row has a response"),
            (
                StatusCode::CONFLICT,
                serde_json::json!({
                    "error": "idempotency_recovery_required",
                    "retryable": false,
                    "disposition": "reconcile_then_retry_with_new_key",
                })
            )
        );

        let recent_metadata: MigrationLedgerMetadata = sqlx::query_as(
            "SELECT reservation_token, operation_id, recovery_kind,
                    response_status, response_body,
                    completed_at IS NOT NULL, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(recent_key)
        .fetch_one(&mut connection)
        .await
        .expect("load recent legacy row after migration");
        assert_eq!(recent_metadata, (None, None, None, None, None, false, 0));
        let recent_row: IdempotencyRow = sqlx::query_as(
            "SELECT method, path, request_hash, response_status, response_body,
                    reservation_token, operation_id, lease_expires_at,
                    recovery_kind,
                    NULL::smallint AS capability_receipt_version,
                    NULL::uuid AS capability_resource_id,
                    NULL::text AS capability_instance_id,
                    completed_at, created_at, updated_at,
                    clock_timestamp() AS database_now
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(recent_key)
        .fetch_one(&mut connection)
        .await
        .expect("load recent row for in-progress replay check");
        let recent_error = idempotency_replay("POST", path, &recent_hash, recent_row)
            .expect_err("recent legacy reservation remains in progress");
        assert_eq!(recent_error.0, StatusCode::CONFLICT);
        assert_eq!(
            recent_error.1.0,
            serde_json::json!({
                "error": "idempotency_request_in_progress",
                "retryable": true,
                "disposition": "retry_same_key",
            })
        );

        let completed_control: (Option<i32>, Option<serde_json::Value>, bool) = sqlx::query_as(
            "SELECT response_status, response_body, completed_at IS NOT NULL
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(completed_key)
        .fetch_one(&mut connection)
        .await
        .expect("load completed migration control row");
        assert_eq!(
            completed_control,
            (
                Some(201),
                Some(serde_json::json!({"status": "already-complete"})),
                true,
            )
        );

        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&mut connection)
            .await
            .expect("drop isolated idempotency migration schema");
    }

    #[tokio::test]
    async fn deterministic_config_token_migration_scrubs_legacy_and_enforces_confidentiality() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let mut connection = sqlx::PgConnection::connect(&database_url)
            .await
            .expect("connect isolated config-token migration database");
        let schema = format!("config_token_migration_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut connection)
            .await
            .expect("create isolated config-token migration schema");
        sqlx::query(&format!("SET search_path TO {schema}, public"))
            .execute(&mut connection)
            .await
            .expect("select isolated config-token migration schema");

        let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut migrations: Vec<std::path::PathBuf> = std::fs::read_dir(&migration_dir)
            .expect("read API migrations")
            .map(|entry| entry.expect("read migration entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
            .collect();
        migrations.sort();
        let receipt_migration = migrations
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("0043_"))
            })
            .cloned()
            .expect("find deterministic config-token receipt migration");
        for migration in migrations.iter().filter(|path| *path < &receipt_migration) {
            let sql = std::fs::read_to_string(migration).expect("read prerequisite migration");
            sqlx::raw_sql(&sql)
                .execute(&mut connection)
                .await
                .unwrap_or_else(|error| panic!("apply {}: {error}", migration.display()));
        }

        let app_key = format!("legacy-app-{}", Uuid::new_v4().simple());
        let deployment_key = format!("legacy-deployment-{}", Uuid::new_v4().simple());
        let signer_key = format!("legacy-signer-{}", Uuid::new_v4().simple());
        let null_kind_key = format!("legacy-null-kind-{}", Uuid::new_v4().simple());
        let incomplete_null_key = format!("legacy-null-incomplete-{}", Uuid::new_v4().simple());
        let deployment_id = Uuid::new_v4();
        let app_secret = format!("legacy-app-bearer-{}", Uuid::new_v4());
        let deployment_secret = format!("legacy-deployment-bearer-{}", Uuid::new_v4());
        let signer_secret = format!("legacy-signer-bearer-{}", Uuid::new_v4());
        let null_kind_secret = format!("legacy-null-bearer-{}", Uuid::new_v4());
        let app_path = "/internal/paas/orgs/legacy/apps/example/config-token";
        let deployment_path =
            format!("/internal/paas/orgs/legacy/deployments/{deployment_id}/config-token");
        let signer_path = "/internal/paas/orgs/legacy/apps/example/signer/rotation-token";
        let null_kind_path = format!(
            "/internal/paas/orgs/legacy/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let incomplete_null_path = format!(
            "/internal/paas/orgs/legacy/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let legacy_auth = AuthContext {
            user_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            org_name: "legacy-migration-org".to_string(),
            role: Role::Owner,
            api_key: None,
            management_origin: ManagementOrigin::PaasInternal,
        };
        let legacy_body = serde_json::json!({"migration": "direct-replay"});
        let null_kind_hash = request_hash(&serde_json::json!({
            "cap_user_id": legacy_auth.user_id,
            "cap_org_id": legacy_auth.org_id,
            "body": &legacy_body,
        }))
        .expect("hash pre-0043 null-kind request");
        for (key, path, status, body) in [
            (
                app_key.as_str(),
                app_path,
                200_i32,
                serde_json::json!({
                    "token": app_secret,
                    "tee_url": "https://legacy-secret.example.test/config"
                }),
            ),
            (
                deployment_key.as_str(),
                deployment_path.as_str(),
                409_i32,
                serde_json::json!({
                    "error": "idempotency_recovery_required",
                    "retryable": false,
                    "disposition": "reconcile_then_retry_with_new_key",
                    "discarded_marker": deployment_secret,
                }),
            ),
            (
                signer_key.as_str(),
                signer_path,
                200_i32,
                serde_json::json!({"token": signer_secret}),
            ),
        ] {
            let token = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO cap_internal_idempotency (
                     idempotency_key, method, path, request_hash,
                     response_status, response_body, completed_at,
                     reservation_token, operation_id, lease_expires_at,
                     recovery_kind, attempt_count, created_at, updated_at
                 ) VALUES (
                     $1, 'POST', $2, $3, $4, $5,
                     clock_timestamp() - interval '1 minute',
                     $6, $6,
                     date_trunc('second', clock_timestamp()) - interval '1 minute',
                     'expiring_capability', 1,
                     date_trunc('second', clock_timestamp()) - interval '7 minutes',
                     clock_timestamp() - interval '1 minute'
                 )",
            )
            .bind(key)
            .bind(path)
            .bind(Sha256::digest(key.as_bytes()).to_vec())
            .bind(status)
            .bind(body)
            .bind(token)
            .execute(&mut connection)
            .await
            .expect("seed pre-0043 capability row");
        }
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 recovery_kind, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, 200,
                 jsonb_build_object('token', $4::text),
                 clock_timestamp() - interval '1 minute', NULL,
                 date_trunc('second', clock_timestamp()) - interval '7 minutes',
                 clock_timestamp() - interval '1 minute'
             )",
        )
        .bind(&null_kind_key)
        .bind(&null_kind_path)
        .bind(&null_kind_hash)
        .bind(&null_kind_secret)
        .execute(&mut connection)
        .await
        .expect("seed pre-0043 completed null-kind config-token row");
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 recovery_kind, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, NULL,
                 date_trunc('second', clock_timestamp()) - interval '1 day',
                 clock_timestamp() - interval '1 day'
             )",
        )
        .bind(&incomplete_null_key)
        .bind(&incomplete_null_path)
        .bind(&null_kind_hash)
        .execute(&mut connection)
        .await
        .expect("seed pre-0043 incomplete null-kind config-token row");

        let migration_sql =
            std::fs::read_to_string(&receipt_migration).expect("read receipt migration");
        sqlx::raw_sql(&migration_sql)
            .execute(&mut connection)
            .await
            .expect("apply deterministic config-token receipt migration");

        for (key, secret) in [
            (app_key.as_str(), app_secret.as_str()),
            (deployment_key.as_str(), deployment_secret.as_str()),
        ] {
            let (status, body, ledger_text): (i32, serde_json::Value, String) = sqlx::query_as(
                "SELECT response_status, response_body,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
            )
            .bind(key)
            .fetch_one(&mut connection)
            .await
            .expect("inspect migrated legacy config-token row");
            assert_eq!(status, 409);
            assert_eq!(body["error"], "idempotency_capability_expired");
            assert_eq!(body["retryable"], false);
            assert_eq!(body["disposition"], "new_key_after_expiry");
            assert_eq!(body["proof_version"], "legacy_expiring_capability_lease_v1");
            assert!(body.get("recovery_after").is_some());
            assert!(body.get("capability_expires_at").is_none());
            assert!(!ledger_text.contains(secret));
            assert!(!ledger_text.contains("legacy-secret.example.test"));
        }
        let signer_control: (i32, serde_json::Value) = sqlx::query_as(
            "SELECT response_status, response_body
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&signer_key)
        .fetch_one(&mut connection)
        .await
        .expect("inspect signer-rotation control row");
        assert_eq!(signer_control.0, 200);
        assert_eq!(signer_control.1["token"], signer_secret);

        let null_kind_terminal: (i32, serde_json::Value, Option<String>, String) = sqlx::query_as(
            "SELECT response_status, response_body, recovery_kind,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(&null_kind_key)
        .fetch_one(&mut connection)
        .await
        .expect("inspect migrated null-kind config-token row");
        assert_eq!(null_kind_terminal.0, StatusCode::CONFLICT.as_u16() as i32);
        assert_eq!(
            null_kind_terminal.1["error"],
            "idempotency_capability_expired"
        );
        assert_eq!(
            null_kind_terminal.1["proof_version"],
            "legacy_expiring_capability_lease_v1"
        );
        assert_eq!(null_kind_terminal.2, None);
        assert!(!null_kind_terminal.3.contains(&null_kind_secret));

        let replay_options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse isolated config-token migration database URL")
            .options([("search_path", format!("{schema},public"))]);
        let replay_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(replay_options)
            .await
            .expect("connect isolated config-token migration replay pool");
        let replay_state = idempotency_test_state(replay_pool.clone());
        let replay_headers = idempotency_headers(&null_kind_key);
        let binding = test_config_token_binding();
        let (replay_status, replay_body) = expect_idempotency_replay(
            begin_actor_deterministic_config_token_request(
                &replay_state,
                &replay_headers,
                &null_kind_path,
                &legacy_auth,
                &legacy_body,
                &binding,
            )
            .await
            .expect("replay migrated null-kind config-token terminal"),
        );
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay_body, null_kind_terminal.1);

        let incomplete_headers = idempotency_headers(&incomplete_null_key);
        let incomplete = begin_actor_deterministic_config_token_request(
            &replay_state,
            &incomplete_headers,
            &incomplete_null_path,
            &legacy_auth,
            &legacy_body,
            &binding,
        )
        .await
        .err()
        .expect("incomplete null-kind row must not gain legacy compatibility");
        assert_eq!(incomplete.0, StatusCode::CONFLICT);
        assert_eq!(incomplete.1.0["error"], "idempotency_key_reused");
        replay_pool.close().await;

        let constraint_path = format!(
            "/internal/paas/orgs/constraint/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let missing_binding = sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $4,
                 clock_timestamp() + interval '1 minute',
                 'deterministic_expiring_capability', 1
             )",
        )
        .bind(format!("missing-binding-{}", Uuid::new_v4()))
        .bind(&constraint_path)
        .bind(vec![1_u8; 32])
        .bind(Uuid::new_v4())
        .execute(&mut connection)
        .await
        .expect_err("deterministic receipt requires its complete binding");
        assert_eq!(
            missing_binding
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("23514")
        );

        let invalid_binding = sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count,
                 capability_receipt_version, capability_resource_id,
                 capability_instance_id
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $4,
                 clock_timestamp() + interval '1 minute',
                 'deterministic_expiring_capability', 1, 2, $5, ''
             )",
        )
        .bind(format!("invalid-binding-{}", Uuid::new_v4()))
        .bind(&constraint_path)
        .bind(vec![2_u8; 32])
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut connection)
        .await
        .expect_err("deterministic receipt rejects unknown version and empty instance");
        assert_eq!(
            invalid_binding
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("23514")
        );

        let malicious_body = sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 reservation_token, operation_id, recovery_kind, attempt_count,
                 capability_receipt_version, capability_resource_id,
                 capability_instance_id, created_at
             ) VALUES (
                 $1, 'POST', $2, $3, 409,
                 jsonb_build_object(
                     'error', 'idempotency_capability_expired',
                     'retryable', false,
                     'disposition', 'new_key_after_expiry',
                     'proof_version', 'deterministic_config_token_receipt_v1',
                     'capability_issued_at', 'eyJhbGciOiJFZERTQSJ9.bearer',
                     'capability_expires_at', 'eyJhbGciOiJFZERTQSJ9.bearer',
                     'token', 'extra-bearer-sink'
                 ),
                 clock_timestamp(), $4, $4,
                 'deterministic_expiring_capability', 1, 1, $5,
                 'safe-instance', date_trunc('second', clock_timestamp())
             )",
        )
        .bind(format!("malicious-body-{}", Uuid::new_v4()))
        .bind(&constraint_path)
        .bind(vec![3_u8; 32])
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut connection)
        .await
        .expect_err("terminal timestamp fields and extra keys cannot carry bearers");
        assert_eq!(
            malicious_body
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("23514")
        );

        let stale_writer_success = sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 reservation_token, operation_id, recovery_kind, attempt_count
             ) VALUES (
                 $1, 'POST', $2, $3, 200,
                 '{\"token\":\"stale-old-writer-bearer\"}'::jsonb,
                 clock_timestamp(), $4, $4, 'expiring_capability', 1
             )",
        )
        .bind(format!("stale-writer-{}", Uuid::new_v4()))
        .bind(&constraint_path)
        .bind(vec![4_u8; 32])
        .bind(Uuid::new_v4())
        .execute(&mut connection)
        .await
        .expect_err("all config-token route families reject stored 2xx responses");
        assert_eq!(
            stale_writer_success
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("23514")
        );

        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&mut connection)
            .await
            .expect("drop isolated config-token migration schema");
    }

    #[test]
    fn deterministic_operation_identity_is_stable_and_request_bound() {
        let hash_a = Sha256::digest(b"request-a").to_vec();
        let hash_b = Sha256::digest(b"request-b").to_vec();
        let operation = idempotency_operation_id("key-a", "POST", "/internal/test", &hash_a);

        assert_eq!(
            operation,
            idempotency_operation_id("key-a", "POST", "/internal/test", &hash_a)
        );
        assert_ne!(
            operation,
            idempotency_operation_id("key-b", "POST", "/internal/test", &hash_a)
        );
        assert_ne!(
            operation,
            idempotency_operation_id("key-a", "PUT", "/internal/test", &hash_a)
        );
        assert_ne!(
            operation,
            idempotency_operation_id("key-a", "POST", "/internal/test", &hash_b)
        );
        assert_eq!(operation.get_version_num(), 8);
        assert_eq!(
            idempotency_deployment_external_id(operation),
            format!("cap-internal-idempotency-{operation}")
        );
    }

    #[tokio::test]
    async fn abandoned_lease_reclaims_once_and_replays_the_committed_response() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("lease-reclaim-{suffix}");
        let path = format!("/internal/test/lease-reclaim/{suffix}");
        let hash = Sha256::digest(b"same-request").to_vec();

        let first = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::RetrySafe,
            )
            .await
            .expect("reserve first attempt"),
        );
        let operation_id = first.operation_id();
        let first_token = first.token;
        drop(first);
        expire_idempotency_lease(&pool, &key).await;

        let second = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::RetrySafe,
            )
            .await
            .expect("reclaim abandoned attempt"),
        );
        assert!(second.reclaimed());
        assert_eq!(second.operation_id(), operation_id);
        assert_ne!(second.token, first_token);
        let response = serde_json::json!({"result": "committed", "operation_id": operation_id});
        finish_idempotent_request(second, StatusCode::CREATED, &response)
            .await
            .expect("complete reclaimed attempt");

        let replay = expect_idempotency_replay(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::RetrySafe,
            )
            .await
            .expect("replay reclaimed response"),
        );
        assert_eq!(replay, (StatusCode::CREATED, response));
        let attempts: i32 = sqlx::query_scalar(
            "SELECT attempt_count FROM cap_internal_idempotency WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("read reclaimed attempt count");
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn live_lease_does_not_starve_a_single_connection_pool() {
        let migration_pool = database_test_pool().await;
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse single-connection idempotency database URL")
            .application_name(&format!("idempotency-pool-one-{}", Uuid::new_v4()));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("connect single-connection idempotency pool");
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("pool-one-{suffix}");
        let path = format!("/internal/test/pool-one/{suffix}");
        let hash = Sha256::digest(b"pool-one-request").to_vec();

        let lease = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "PUT", &path, &hash)
                .await
                .expect("reserve with a one-connection pool"),
        );
        let available: i32 = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sqlx::query_scalar("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("reservation must not hold the only pool connection")
        .expect("query through the available connection");
        assert_eq!(available, 1);

        let in_progress = begin_idempotent_request(&state, &key, "PUT", &path, &hash)
            .await
            .err()
            .expect("a live exact reservation remains in progress");
        assert_eq!(in_progress.0, StatusCode::CONFLICT);
        assert_eq!(in_progress.1.0["error"], "idempotency_request_in_progress");

        let response = serde_json::json!({"status": "done"});
        finish_idempotent_request(lease, StatusCode::OK, &response)
            .await
            .expect("complete through one-connection pool");
        assert_eq!(
            expect_idempotency_replay(
                begin_idempotent_request(&state, &key, "PUT", &path, &hash)
                    .await
                    .expect("replay through one-connection pool")
            ),
            (StatusCode::OK, response)
        );
        drop(migration_pool);
    }

    #[tokio::test]
    async fn stale_owner_and_pre_upgrade_completion_are_fenced_after_reclaim() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("owner-fence-{suffix}");
        let path = format!("/internal/test/owner-fence/{suffix}");
        let hash = Sha256::digest(b"owner-fence-request").to_vec();

        let first = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("reserve old owner"),
        );
        let stale_token = first.token;
        let operation_id = first.operation_id();
        drop(first);
        expire_idempotency_lease(&pool, &key).await;
        let current = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("reclaim with current owner"),
        );
        assert_ne!(current.token, stale_token);

        let blind_write = sqlx::query(
            "UPDATE cap_internal_idempotency
                SET response_status = 200,
                    response_body = '{\"owner\":\"pre-upgrade\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .execute(&pool)
        .await
        .expect_err("pre-upgrade key-only completion must be fenced");
        assert_eq!(
            blind_write
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("42501")
        );

        let stale_lease = IdempotencyLease {
            pool: pool.clone(),
            key: key.clone(),
            token: stale_token,
            operation_id,
            reclaimed: false,
            regenerate: false,
            config_token_receipt: None,
            heartbeat: None,
        };
        let stale_completion = finish_idempotent_request(
            stale_lease,
            StatusCode::OK,
            &serde_json::json!({"owner": "stale"}),
        )
        .await
        .expect_err("stale token cannot complete a reclaimed row");
        assert_eq!(stale_completion.0, StatusCode::INTERNAL_SERVER_ERROR);

        let response = serde_json::json!({"owner": "current"});
        finish_idempotent_request(current, StatusCode::OK, &response)
            .await
            .expect("current owner completes the row");
        assert_eq!(
            expect_idempotency_replay(
                begin_idempotent_request(&state, &key, "POST", &path, &hash)
                    .await
                    .expect("replay current owner response")
            ),
            (StatusCode::OK, response)
        );
    }

    #[tokio::test]
    async fn recovery_deadlines_are_decided_by_the_database_clock() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let legacy_key = format!("database-clock-legacy-{suffix}");
        let legacy_path = format!("/internal/test/database-clock-legacy/{suffix}");
        let legacy_hash = Sha256::digest(b"database-clock-legacy").to_vec();
        sqlx::query(
            "INSERT INTO cap_internal_idempotency
                 (idempotency_key, method, path, request_hash, updated_at)
             VALUES ($1, 'POST', $2, $3, clock_timestamp() + interval '1 day')",
        )
        .bind(&legacy_key)
        .bind(&legacy_path)
        .bind(&legacy_hash)
        .execute(&pool)
        .await
        .expect("seed forward-skewed legacy reservation");

        let future = begin_idempotent_request_with_recovery(
            &state,
            &legacy_key,
            "POST",
            &legacy_path,
            &legacy_hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .err()
        .expect("database-future row must remain live");
        assert_eq!(future.1.0["error"], "idempotency_request_in_progress");
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET updated_at = clock_timestamp() - interval '1 day'
              WHERE idempotency_key = $1",
        )
        .bind(&legacy_key)
        .execute(&pool)
        .await
        .expect("move legacy reservation behind database clock");
        let reclaimed_legacy = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(
                &state,
                &legacy_key,
                "POST",
                &legacy_path,
                &legacy_hash,
                IdempotencyRecovery::RetrySafe,
            )
            .await
            .expect("database-past legacy row is reclaimable"),
        );
        assert!(reclaimed_legacy.reclaimed());
        finish_idempotent_request(
            reclaimed_legacy,
            StatusCode::OK,
            &serde_json::json!({"legacy": "recovered"}),
        )
        .await
        .expect("complete legacy recovery");

        let capability_key = format!("database-clock-capability-{suffix}");
        let capability_path = format!("/internal/test/database-clock-capability/{suffix}");
        let capability_hash = Sha256::digest(b"database-clock-capability").to_vec();
        let capability_recovery = IdempotencyRecovery::ExpiringCapability {
            recovery_after_seconds: 360,
        };
        let capability = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(
                &state,
                &capability_key,
                "POST",
                &capability_path,
                &capability_hash,
                capability_recovery,
            )
            .await
            .expect("reserve expiring capability"),
        );
        drop(capability);
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET lease_expires_at = clock_timestamp() + interval '1 day'
              WHERE idempotency_key = $1",
        )
        .bind(&capability_key)
        .execute(&pool)
        .await
        .expect("move capability deadline ahead of database clock");
        let live_capability = begin_idempotent_request_with_recovery(
            &state,
            &capability_key,
            "POST",
            &capability_path,
            &capability_hash,
            capability_recovery,
        )
        .await
        .err()
        .expect("database-future capability remains live");
        assert_eq!(
            live_capability.1.0["error"],
            "idempotency_request_in_progress"
        );
        expire_idempotency_lease(&pool, &capability_key).await;
        let (status, body) = expect_idempotency_replay(
            begin_idempotent_request_with_recovery(
                &state,
                &capability_key,
                "POST",
                &capability_path,
                &capability_hash,
                capability_recovery,
            )
            .await
            .expect("database-past capability is closed for reconciliation"),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "idempotency_recovery_required");
        assert_eq!(body["retryable"], false);
        assert_eq!(body["disposition"], "reconcile_then_retry_with_new_key");
    }

    #[tokio::test]
    async fn expiring_capability_plaintext_never_enters_idempotency_ledger() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("capability-confidentiality-{suffix}");
        let path = "/internal/paas/orgs/org/apps/app/signer/rotation-token".to_string();
        let hash = Sha256::digest(format!("capability-{suffix}")).to_vec();
        let recovery = IdempotencyRecovery::ExpiringCapability {
            recovery_after_seconds: 360,
        };
        let lease = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
                .await
                .expect("reserve capability request"),
        );
        let secret_token = format!("jwt-secret-marker-{suffix}");
        let secret_url = format!("https://secret-{suffix}.example.test");
        let secret_ip = "192.0.2.77";
        let response = serde_json::json!({
            "token": secret_token,
            "tee_url": secret_url,
            "resolve_ip": secret_ip,
        });
        let (status, returned) =
            complete_expiring_capability_result(lease, Ok((StatusCode::OK, response.clone())))
                .await
                .expect("return capability once");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(returned, response);

        let stored: (Option<i32>, Option<serde_json::Value>, bool) = sqlx::query_as(
            "SELECT response_status, response_body, completed_at IS NOT NULL
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("read capability ledger marker");
        assert_eq!(stored, (None, None, false));

        let duplicate =
            begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
                .await
                .err()
                .expect("live capability cannot be replayed or reissued");
        assert_eq!(duplicate.1.0["error"], "idempotency_request_in_progress");

        expire_idempotency_lease(&pool, &key).await;
        let (status, tombstone) = expect_idempotency_replay(
            begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
                .await
                .expect("expired capability closes with tombstone"),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(tombstone["retryable"], false);
        let ledger_text: String = sqlx::query_scalar(
            "SELECT response_body::text FROM cap_internal_idempotency WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("read capability tombstone");
        for marker in [secret_token.as_str(), secret_url.as_str(), secret_ip] {
            assert!(!ledger_text.contains(marker));
        }
    }

    #[tokio::test]
    async fn deterministic_config_token_receipt_regenerates_exact_bearer_without_plaintext() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let deployment_id = Uuid::new_v4();
        let key = format!("deterministic-config-token-{suffix}");
        let path =
            format!("/internal/paas/orgs/org-{suffix}/deployments/{deployment_id}/config-token");
        let hash = Sha256::digest(format!("deterministic-config-token-{suffix}")).to_vec();
        let binding = test_config_token_binding();
        let first = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("reserve deterministic config-token receipt"),
        );
        let first_receipt = first.config_token_receipt().unwrap().clone();
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let issued = crate::auth::jwt::issue_config_token_for_issuance(
            &state.signing_key,
            user_id,
            org_id,
            binding.resource_id,
            &binding.instance_id,
            vec!["config:write".to_string()],
            &first_receipt.issuance(),
        )
        .expect("issue deterministic config bearer");
        let secret_url = format!("https://tee-{suffix}.example.test/config");
        let secret_ip = "192.0.2.77";
        let first_response = serde_json::json!({
            "token": issued.token,
            "tee_url": secret_url,
            "tee_resolve_ip": secret_ip,
            "issued_at": issued.issued_at,
            "expires_at": issued.expires_at,
            "expires_in_seconds": 299,
        });
        let first_returned = complete_deterministic_config_token_result_with_timeout(
            first,
            async { Ok((StatusCode::OK, first_response.clone())) },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("complete non-secret issuance receipt");
        assert_eq!(first_returned, (StatusCode::OK, first_response.clone()));

        let ledger: (bool, Option<i32>, Option<serde_json::Value>, String) = sqlx::query_as(
            "SELECT completed_at IS NOT NULL, response_status, response_body,
                    to_jsonb(cap_internal_idempotency)::text
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect deterministic capability receipt");
        assert!(ledger.0);
        assert_eq!(ledger.1, None);
        assert_eq!(ledger.2, None);
        for marker in [
            first_response["token"].as_str().unwrap(),
            first_response["tee_url"].as_str().unwrap(),
            secret_ip,
        ] {
            assert!(!ledger.3.contains(marker));
        }

        let duplicate = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("regenerate completed config-token receipt"),
        );
        assert!(duplicate.regenerate);
        let duplicate_receipt = duplicate.config_token_receipt().unwrap().clone();
        assert_eq!(duplicate_receipt.issued_at, first_receipt.issued_at);
        assert_eq!(duplicate_receipt.expires_at, first_receipt.expires_at);
        let regenerated = crate::auth::jwt::issue_config_token_for_issuance(
            &state.signing_key,
            user_id,
            org_id,
            binding.resource_id,
            &binding.instance_id,
            vec!["config:write".to_string()],
            &duplicate_receipt.issuance(),
        )
        .expect("regenerate exact config bearer");
        assert_eq!(regenerated.token, first_response["token"]);
        assert_eq!(regenerated.issued_at, issued.issued_at);
        assert_eq!(regenerated.expires_at, issued.expires_at);
        let duplicate_response = serde_json::json!({
            "token": regenerated.token,
            "tee_url": first_response["tee_url"],
            "tee_resolve_ip": "192.0.2.88",
            "issued_at": regenerated.issued_at,
            "expires_at": regenerated.expires_at,
            "expires_in_seconds": 298,
        });
        let duplicate_returned = complete_deterministic_config_token_result_with_timeout(
            duplicate,
            async { Ok((StatusCode::OK, duplicate_response.clone())) },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("return regenerated config bearer");
        assert_eq!(duplicate_returned, (StatusCode::OK, duplicate_response));
    }

    #[tokio::test]
    async fn deterministic_config_token_errors_cancel_and_live_then_stale_lease_reclaims() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let deployment_id = Uuid::new_v4();
        let path =
            format!("/internal/paas/orgs/org-{suffix}/deployments/{deployment_id}/config-token");
        let hash = Sha256::digest(format!("config-token-errors-{suffix}")).to_vec();
        let binding = test_config_token_binding();
        let error_key = format!("config-token-error-{suffix}");
        let first = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &error_key, &path, &hash, &binding)
                .await
                .expect("reserve failing config-token attempt"),
        );
        let failure = complete_deterministic_config_token_result_with_timeout(
            first,
            async {
                Err(json_error(
                    StatusCode::BAD_GATEWAY,
                    "bounded config token failure",
                ))
            },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("explicit handler failure is returned");
        assert_eq!(failure.0, StatusCode::BAD_GATEWAY);
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cap_internal_idempotency WHERE idempotency_key = $1",
        )
        .bind(&error_key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0, "explicit failure must release the exact key");
        let retry = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &error_key, &path, &hash, &binding)
                .await
                .expect("retry released key"),
        );
        cancel_idempotency_reservation(retry).await.unwrap();

        let stale_key = format!("config-token-stale-{suffix}");
        let live = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
                .await
                .expect("reserve live config-token attempt"),
        );
        let in_progress =
            begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
                .await
                .err()
                .expect("live receipt remains exclusive");
        assert_eq!(in_progress.1.0["error"], "idempotency_request_in_progress");
        let issued_at = live.config_token_receipt().unwrap().issued_at;
        drop(live);
        expire_idempotency_lease(&pool, &stale_key).await;
        let reclaimed = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
                .await
                .expect("stale config-token lease is reclaimable"),
        );
        assert!(reclaimed.reclaimed());
        assert_eq!(
            reclaimed.config_token_receipt().unwrap().issued_at,
            issued_at
        );
        cancel_idempotency_reservation(reclaimed).await.unwrap();
    }

    #[tokio::test]
    async fn deterministic_config_token_policy_cannot_reclaim_generic_deploy_mutation() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("generic-deploy-not-config-{suffix}");
        let path = format!("/internal/paas/orgs/org-{suffix}/deployments");
        let hash = Sha256::digest(format!("generic-deploy-not-config-{suffix}")).to_vec();
        let original = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::DeterministicResource {
                    legacy_identity_bound: true,
                },
            )
            .await
            .expect("reserve generic deploy mutation"),
        );
        let original_token = original.token;
        drop(original);
        expire_idempotency_lease(&pool, &key).await;

        let rejected = begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::DeterministicExpiringCapability,
        )
        .await
        .err()
        .expect("config-token recovery is path scoped");
        assert_eq!(rejected.0, StatusCode::INTERNAL_SERVER_ERROR);
        let unchanged: (Uuid, i32) = sqlx::query_as(
            "SELECT reservation_token, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, (original_token, 1));
    }

    #[tokio::test]
    async fn config_token_finalizers_enforce_safe_return_cutoff_and_terminal_authority() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let path = format!(
            "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let hash = Sha256::digest(format!("safe-return-{suffix}")).to_vec();
        let binding = test_config_token_binding();

        // Initial completion is also fenced. Even if its route future
        // succeeds, CAP must not hand a bearer across the final 30 seconds.
        let initial_key = format!("safe-return-initial-{suffix}");
        let initial = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &initial_key, &path, &hash, &binding)
                .await
                .expect("reserve initial safe-return receipt"),
        );
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '271 seconds'
              WHERE idempotency_key = $1",
        )
        .bind(&initial_key)
        .execute(&pool)
        .await
        .expect("move initial receipt inside safe-return cutoff");
        let initial_error = complete_deterministic_config_token_result_with_timeout(
            initial,
            async {
                Ok((
                    StatusCode::OK,
                    serde_json::json!({"token": "must-not-cross-cutoff"}),
                ))
            },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("initial completion inside cutoff is deferred");
        assert_eq!(initial_error.0, StatusCode::CONFLICT);
        assert_eq!(
            initial_error.1.0["error"],
            "idempotency_request_in_progress"
        );
        let initial_stored: (bool, Option<i32>, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT completed_at IS NOT NULL, response_status, response_body
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&initial_key)
        .fetch_one(&pool)
        .await
        .expect("inspect cutoff-fenced initial receipt");
        assert_eq!(initial_stored, (true, None, None));

        // A paused regeneration that crosses absolute expiry must observe the
        // concurrently committed terminal proof, never return its bearer.
        let replay_key = format!("safe-return-replay-{suffix}");
        let first = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
                .await
                .expect("reserve replay cutoff receipt"),
        );
        complete_deterministic_config_token_result_with_timeout(
            first,
            async { Ok((StatusCode::OK, serde_json::json!({"token": "first"}))) },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("complete replay cutoff receipt");
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '299 seconds'
              WHERE idempotency_key = $1",
        )
        .bind(&replay_key)
        .execute(&pool)
        .await
        .expect("move replay receipt next to expiry");
        let replay = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
                .await
                .expect("begin near-expiry regeneration"),
        );
        let expires_at = replay.config_token_receipt().unwrap().expires_at;
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let paused = tokio::spawn(async move {
            complete_deterministic_config_token_result_with_timeout(
                replay,
                async move {
                    let _ = release_rx.await;
                    Ok((
                        StatusCode::OK,
                        serde_json::json!({"token": "must-not-cross-expiry"}),
                    ))
                },
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(1),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if database_clock(&pool).await.expect("read DB clock") >= expires_at {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("receipt reaches DB-authored expiry");
        let terminal = expect_idempotency_replay(
            begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
                .await
                .expect("terminalize expired receipt"),
        );
        assert_eq!(terminal.0, StatusCode::CONFLICT);
        assert_eq!(terminal.1["error"], "idempotency_capability_expired");
        release_tx.send(()).expect("release paused regeneration");
        let paused_result = paused
            .await
            .expect("join paused regeneration")
            .expect("terminal proof is returned as an idempotency response");
        assert_eq!(paused_result, terminal);
        assert!(paused_result.1.get("token").is_none());
    }

    #[tokio::test]
    async fn config_token_timeout_is_bounded_and_completion_cancellation_is_cas_safe() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("bounded-cancellation-{suffix}");
        let path = format!(
            "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let hash = Sha256::digest(format!("bounded-cancellation-{suffix}")).to_vec();
        let binding = test_config_token_binding();
        let lease = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("reserve bounded cancellation receipt"),
        );
        let stale_cancellation = lease.cancellation();
        let mut blocker = pool.begin().await.expect("begin cancellation blocker");
        sqlx::query(
            "SELECT 1 FROM cap_internal_idempotency
              WHERE idempotency_key = $1 FOR UPDATE",
        )
        .bind(&key)
        .fetch_one(&mut *blocker)
        .await
        .expect("lock cancellation receipt");
        let started = std::time::Instant::now();
        let timed_out = complete_deterministic_config_token_result_with_timeout(
            lease,
            async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Ok((StatusCode::OK, serde_json::json!({"token": "late"})))
            },
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(30),
        )
        .await
        .expect_err("blocked cancellation remains bounded");
        assert_eq!(timed_out.0, StatusCode::GATEWAY_TIMEOUT);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        blocker
            .rollback()
            .await
            .expect("release cancellation blocker");
        let still_incomplete: Option<bool> = sqlx::query_scalar(
            "SELECT completed_at IS NULL FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_optional(&pool)
        .await
        .expect("bounded cancellation leaves locked receipt for lease recovery");
        if still_incomplete == Some(true) {
            expire_idempotency_lease(&pool, &key).await;
        }
        let current = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("retry absent receipt or reclaim after fixed receipt lease"),
        );
        assert_eq!(current.reclaimed(), still_incomplete == Some(true));
        let mut current = current;
        assert!(matches!(
            finish_config_token_receipt(&mut current).await.unwrap(),
            ConfigTokenReceiptCompletion::Completed
        ));
        cancel_incomplete_idempotency_reservation(&stale_cancellation)
            .await
            .expect("late old cancellation must not delete current completed receipt");
        let completed: bool = sqlx::query_scalar(
            "SELECT completed_at IS NOT NULL FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("completed receipt survives stale cancellation");
        assert!(completed);
    }

    #[tokio::test]
    async fn config_token_finish_error_releases_exact_reservation_for_retry() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("finish-error-{suffix}");
        let path = format!(
            "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let hash = Sha256::digest(format!("finish-error-{suffix}")).to_vec();
        let binding = test_config_token_binding();
        let lease = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("reserve finish-error receipt"),
        );
        let function_name = format!("fail_config_finish_{suffix}");
        let trigger_name = format!("fail_config_finish_trigger_{suffix}");
        let ddl = format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'forced config receipt finish failure'; END $$;
             CREATE TRIGGER {trigger_name}
             BEFORE UPDATE OF completed_at ON cap_internal_idempotency
             FOR EACH ROW WHEN (OLD.idempotency_key = '{key}')
             EXECUTE FUNCTION {function_name}();"
        );
        sqlx::raw_sql(&ddl)
            .execute(&pool)
            .await
            .expect("install scoped finish failure trigger");
        let error = complete_deterministic_config_token_result_with_timeout(
            lease,
            async { Ok((StatusCode::OK, serde_json::json!({"token": "not-returned"}))) },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("finish failure is returned");
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cap_internal_idempotency WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect failed receipt cleanup");
        assert_eq!(remaining, 0);
        let cleanup = format!(
            "DROP TRIGGER {trigger_name} ON cap_internal_idempotency;
             DROP FUNCTION {function_name}();"
        );
        sqlx::raw_sql(&cleanup)
            .execute(&pool)
            .await
            .expect("remove scoped finish failure trigger");
        let retry = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("retry key released by finish failure"),
        );
        cancel_idempotency_reservation(retry).await.unwrap();
    }

    #[tokio::test]
    async fn config_token_binding_mismatch_rejects_same_key() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("binding-mismatch-{suffix}");
        let path = format!(
            "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let hash = Sha256::digest(format!("binding-mismatch-{suffix}")).to_vec();
        let binding = test_config_token_binding();
        let first = expect_idempotency_execution(
            begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
                .await
                .expect("reserve bound receipt"),
        );
        complete_deterministic_config_token_result_with_timeout(
            first,
            async { Ok((StatusCode::OK, serde_json::json!({"token": "first"}))) },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("complete bound receipt");
        let mutated = ConfigTokenResourceBinding {
            resource_id: binding.resource_id,
            instance_id: format!("{}-mutated", binding.instance_id),
        };
        let reused = begin_test_config_token_receipt(&state, &key, &path, &hash, &mutated)
            .await
            .err()
            .expect("mutated instance binding must not regenerate");
        assert_eq!(reused.0, StatusCode::CONFLICT);
        assert_eq!(reused.1.0["error"], "idempotency_key_reused");
    }

    #[tokio::test]
    async fn app_config_token_route_replays_exactly_and_rejects_name_recreation() {
        let pool = database_test_pool().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let app_a = Uuid::new_v4();
        let app_b = Uuid::new_v4();
        let org_name = format!("tokenorg{}", &suffix[..8]);
        let paas_org_id = format!("paas-token-org-{suffix}");
        let paas_user_id = format!("paas-token-user-{suffix}");
        let app_name = format!("tokenapp{}", &suffix[..8]);
        insert_config_token_test_actor(
            &pool,
            org_id,
            &org_name,
            &paas_org_id,
            user_id,
            &paas_user_id,
        )
        .await;
        insert_config_token_test_app(&pool, org_id, &org_name, app_a, &app_name, "a").await;
        let state = idempotency_test_state(pool.clone());
        let key = format!("app-config-route-{suffix}");
        let headers = config_token_actor_headers(&key, &paas_user_id);
        let call = |state: AppState, headers: HeaderMap| {
            issue_paas_config_token(
                internal_test_auth(),
                State(state),
                Path((paas_org_id.clone(), app_name.clone())),
                headers,
                Json(serde_json::json!({})),
            )
        };
        let (first_status, Json(first)) = call(state.clone(), headers.clone())
            .await
            .expect("issue first app config token");
        assert_eq!(first_status, StatusCode::OK);
        let (duplicate_status, Json(duplicate)) = call(state.clone(), headers.clone())
            .await
            .expect("regenerate exact app config token");
        assert_eq!(duplicate_status, StatusCode::OK);
        assert_eq!(duplicate["token"], first["token"]);
        assert_eq!(duplicate["issued_at"], first["issued_at"]);
        assert_eq!(duplicate["expires_at"], first["expires_at"]);
        let issued_at = chrono::DateTime::parse_from_rfc3339(
            first["issued_at"].as_str().expect("issued_at string"),
        )
        .unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            first["expires_at"].as_str().expect("expires_at string"),
        )
        .unwrap();
        assert_eq!((expires_at - issued_at).num_seconds(), 300);

        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_a)
            .execute(&pool)
            .await
            .expect("delete original app identity");

        let missing = call(
            state.clone(),
            config_token_actor_headers(&format!("app-config-missing-{suffix}"), &paas_user_id),
        )
        .await
        .expect_err("a new key still observes the missing app");
        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(missing.1.0["error"], "app not found");

        let live_receipt = call(state.clone(), headers.clone())
            .await
            .expect_err("a deleted app cannot regenerate a live receipt");
        assert_eq!(live_receipt.0, StatusCode::CONFLICT);
        assert_eq!(live_receipt.1.0["error"], "idempotency_request_in_progress");

        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '301 seconds'
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .execute(&pool)
        .await
        .expect("expire deleted-app config-token receipt");
        let (expired_status, Json(expired)) = call(state.clone(), headers.clone())
            .await
            .expect("terminalize deleted-app config-token receipt");
        assert_eq!(expired_status, StatusCode::CONFLICT);
        assert_eq!(expired["error"], "idempotency_capability_expired");
        assert_eq!(expired["retryable"], false);
        assert_eq!(expired["disposition"], "new_key_after_expiry");
        assert_eq!(
            expired["proof_version"],
            "deterministic_config_token_receipt_v1"
        );
        assert!(expired.get("capability_issued_at").is_some());
        assert!(expired.get("capability_expires_at").is_some());
        assert!(expired.get("token").is_none());

        let legacy_hash = request_hash(&serde_json::json!({
            "cap_user_id": user_id,
            "cap_org_id": org_id,
            "body": serde_json::json!({}),
        }))
        .expect("hash deleted-app legacy request");
        let legacy_created_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT date_trunc('second', clock_timestamp()) - interval '7 minutes'",
        )
        .fetch_one(&pool)
        .await
        .expect("select deleted-app legacy receipt time");
        let legacy_proof = expired_config_token_body(
            legacy_created_at,
            legacy_created_at + chrono::Duration::minutes(6),
            true,
        );
        for (legacy_variant, recovery_kind) in
            [("null", None), ("expiring", Some("expiring_capability"))]
        {
            let legacy_key = format!("legacy-deleted-app-{legacy_variant}-{suffix}");
            sqlx::query(
                "INSERT INTO cap_internal_idempotency (
                     idempotency_key, method, path, request_hash,
                     response_status, response_body, completed_at,
                     recovery_kind, created_at, updated_at
                 ) VALUES (
                     $1, 'POST', $2, $3, 409, $4, clock_timestamp(),
                     $5, $6, clock_timestamp()
                 )",
            )
            .bind(&legacy_key)
            .bind(format!(
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token"
            ))
            .bind(&legacy_hash)
            .bind(&legacy_proof)
            .bind(recovery_kind)
            .bind(legacy_created_at)
            .execute(&pool)
            .await
            .expect("seed migrated legacy receipt for deleted app");
            let (legacy_status, Json(legacy_replay)) = call(
                state.clone(),
                config_token_actor_headers(&legacy_key, &paas_user_id),
            )
            .await
            .expect("replay safe migrated legacy terminal after app deletion");
            assert_eq!(legacy_status, StatusCode::CONFLICT);
            assert_eq!(legacy_replay, legacy_proof);
        }

        insert_config_token_test_app(&pool, org_id, &org_name, app_b, &app_name, "b").await;
        let recreated = call(state, headers)
            .await
            .expect_err("same app name with a new UUID cannot reuse receipt");
        assert_eq!(recreated.0, StatusCode::CONFLICT);
        assert_eq!(recreated.1.0["error"], "idempotency_key_reused");
        let ledger: (Uuid, String, Option<i32>, Option<serde_json::Value>, String) =
            sqlx::query_as(
                "SELECT capability_resource_id, capability_instance_id,
                        response_status, response_body,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
            )
            .bind(&key)
            .fetch_one(&pool)
            .await
            .expect("inspect app config-token receipt");
        assert_eq!(ledger.0, app_a);
        assert!(ledger.1.ends_with(&format!("-{app_name}")));
        assert_eq!(ledger.2, Some(StatusCode::CONFLICT.as_u16() as i32));
        assert_eq!(ledger.3, Some(expired));
        assert!(!ledger.4.contains(first["token"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn generic_deployment_config_token_route_replays_and_rejects_app_rebind() {
        let pool = database_test_pool().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let app_a = Uuid::new_v4();
        let app_b = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let org_name = format!("genericorg{}", &suffix[..8]);
        let paas_org_id = format!("paas-generic-org-{suffix}");
        let paas_user_id = format!("paas-generic-user-{suffix}");
        let app_name_a = format!("genericapp{}", &suffix[..8]);
        let app_name_b = format!("reboundapp{}", &suffix[..8]);
        insert_config_token_test_actor(
            &pool,
            org_id,
            &org_name,
            &paas_org_id,
            user_id,
            &paas_user_id,
        )
        .await;
        insert_config_token_test_app(&pool, org_id, &org_name, app_a, &app_name_a, "a").await;
        sqlx::query(
            "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_a)
        .execute(&pool)
        .await
        .expect("insert generic config-token deployment");
        let state = idempotency_test_state(pool.clone());
        let key = format!("generic-config-route-{suffix}");
        let headers = config_token_actor_headers(&key, &paas_user_id);
        let call = |state: AppState, headers: HeaderMap| {
            issue_paas_generic_config_token(
                internal_test_auth(),
                State(state),
                Path((paas_org_id.clone(), deployment_id)),
                headers,
                Json(serde_json::json!({})),
            )
        };
        let (first_status, Json(first)) = call(state.clone(), headers.clone())
            .await
            .expect("issue first generic config token");
        let (duplicate_status, Json(duplicate)) = call(state.clone(), headers.clone())
            .await
            .expect("regenerate exact generic config token");
        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(duplicate_status, StatusCode::OK);
        assert_eq!(first["deployment_id"], deployment_id.to_string());
        assert_eq!(duplicate["token"], first["token"]);
        assert_eq!(duplicate["issued_at"], first["issued_at"]);
        assert_eq!(duplicate["expires_at"], first["expires_at"]);

        insert_config_token_test_app(&pool, org_id, &org_name, app_b, &app_name_b, "b").await;
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("remove deployment before identity rebind");

        let missing = call(
            state.clone(),
            config_token_actor_headers(&format!("generic-config-missing-{suffix}"), &paas_user_id),
        )
        .await
        .expect_err("a new key still observes the missing deployment");
        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(missing.1.0["error"], "deployment not found");

        let live_receipt = call(state.clone(), headers.clone())
            .await
            .expect_err("a deleted deployment cannot regenerate a live receipt");
        assert_eq!(live_receipt.0, StatusCode::CONFLICT);
        assert_eq!(live_receipt.1.0["error"], "idempotency_request_in_progress");

        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '301 seconds'
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .execute(&pool)
        .await
        .expect("expire deleted-deployment config-token receipt");
        let (expired_status, Json(expired)) = call(state.clone(), headers.clone())
            .await
            .expect("terminalize deleted-deployment config-token receipt");
        assert_eq!(expired_status, StatusCode::CONFLICT);
        assert_eq!(expired["error"], "idempotency_capability_expired");
        assert_eq!(expired["retryable"], false);
        assert_eq!(expired["disposition"], "new_key_after_expiry");
        assert_eq!(
            expired["proof_version"],
            "deterministic_config_token_receipt_v1"
        );
        assert!(expired.get("capability_issued_at").is_some());
        assert!(expired.get("capability_expires_at").is_some());
        assert!(expired.get("token").is_none());

        sqlx::query(
            "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_b)
        .execute(&pool)
        .await
        .expect("recreate deployment ID against a different app identity");
        let rebound = call(state, headers)
            .await
            .expect_err("deployment app rebind cannot reuse receipt");
        assert_eq!(rebound.0, StatusCode::CONFLICT);
        assert_eq!(rebound.1.0["error"], "idempotency_key_reused");
        let ledger: (Option<i32>, Option<serde_json::Value>, String) = sqlx::query_as(
            "SELECT response_status, response_body,
                    to_jsonb(cap_internal_idempotency)::text
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect generic config-token receipt");
        assert_eq!(ledger.0, Some(StatusCode::CONFLICT.as_u16() as i32));
        assert_eq!(ledger.1, Some(expired));
        assert!(!ledger.2.contains(first["token"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn legacy_config_token_receipt_uses_conservative_lease_proof() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("legacy-config-receipt-{suffix}");
        let path = format!(
            "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
            Uuid::new_v4()
        );
        let auth = AuthContext {
            user_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            org_name: format!("org-{suffix}"),
            role: Role::Owner,
            api_key: None,
            management_origin: ManagementOrigin::PaasInternal,
        };
        let body = serde_json::json!({});
        let legacy_hash = request_hash(&serde_json::json!({
            "cap_user_id": auth.user_id,
            "cap_org_id": auth.org_id,
            "body": body,
        }))
        .unwrap();
        let operation_id = idempotency_operation_id(&key, "POST", &path, &legacy_hash);
        let token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $5,
                 date_trunc('second', clock_timestamp()) - interval '1 minute',
                 'expiring_capability', 1,
                 date_trunc('second', clock_timestamp()) - interval '7 minutes',
                 clock_timestamp() - interval '1 minute'
             )",
        )
        .bind(&key)
        .bind(&path)
        .bind(&legacy_hash)
        .bind(token)
        .bind(operation_id)
        .execute(&pool)
        .await
        .expect("seed legacy config-token lease");
        let binding = test_config_token_binding();
        let headers = idempotency_headers(&key);
        let (status, proof) = expect_idempotency_replay(
            begin_actor_deterministic_config_token_request(
                &state, &headers, &path, &auth, &body, &binding,
            )
            .await
            .expect("terminalize legacy config-token lease"),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(proof["error"], "idempotency_capability_expired");
        assert_eq!(proof["retryable"], false);
        assert_eq!(proof["disposition"], "new_key_after_expiry");
        assert_eq!(
            proof["proof_version"],
            "legacy_expiring_capability_lease_v1"
        );
        assert!(proof.get("recovery_after").is_some());
        assert!(proof.get("capability_expires_at").is_none());
        assert!(proof.get("token").is_none());
    }

    #[tokio::test]
    async fn ordinary_handler_error_is_completed_and_replayed_without_side_effect_retry() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("error-replay-{suffix}");
        let path = format!("/internal/test/error-replay/{suffix}");
        let hash = Sha256::digest(b"error-replay-request").to_vec();
        let side_effects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let lease = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("reserve failing handler"),
        );
        let attempt_side_effects = side_effects.clone();
        let result: Result<IdempotencyResponse, InternalRouteError> = async move {
            attempt_side_effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "bounded_handler_failure",
            ))
        }
        .await;
        let failure = complete_idempotent_result(lease, result)
            .await
            .expect_err("first handler returns its completed error");
        assert_eq!(failure.0, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = expect_idempotency_replay(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("exact retry replays the completed error"),
        );
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "bounded_handler_failure");
        assert_eq!(
            side_effects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "replay must not invoke the handler side effect again"
        );
        let completed: bool = sqlx::query_scalar(
            "SELECT completed_at IS NOT NULL
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect completed handler error");
        assert!(completed);
    }

    #[tokio::test]
    async fn unsafe_legacy_recovery_terminalizes_with_nonretryable_disposition() {
        let pool = database_test_pool().await;
        let state = idempotency_test_state(pool.clone());
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("fail-closed-{suffix}");
        let path = format!("/internal/test/fail-closed/{suffix}");
        let hash = Sha256::digest(b"fail-closed-request").to_vec();
        sqlx::query(
            "INSERT INTO cap_internal_idempotency
                 (idempotency_key, method, path, request_hash, updated_at)
             VALUES ($1, 'POST', $2, $3, clock_timestamp() - interval '1 day')",
        )
        .bind(&key)
        .bind(&path)
        .bind(&hash)
        .execute(&pool)
        .await
        .expect("seed abandoned unsafe legacy reservation");

        let first = expect_idempotency_replay(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::FailClosed,
            )
            .await
            .expect("terminalize unsafe legacy reservation"),
        );
        assert_eq!(first.0, StatusCode::CONFLICT);
        assert_eq!(first.1["error"], "idempotency_recovery_required");
        assert_eq!(first.1["retryable"], false);
        assert_eq!(first.1["disposition"], "reconcile_then_retry_with_new_key");
        assert_eq!(
            expect_idempotency_replay(
                begin_idempotent_request_with_recovery(
                    &state,
                    &key,
                    "POST",
                    &path,
                    &hash,
                    IdempotencyRecovery::FailClosed,
                )
                .await
                .expect("replay terminal legacy disposition")
            ),
            first
        );

        let persisted: (bool, i32, String) = sqlx::query_as(
            "SELECT completed_at IS NOT NULL, attempt_count, recovery_kind
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect terminal legacy disposition");
        assert_eq!(persisted, (true, 1, "fail_closed".to_string()));
    }

    #[tokio::test]
    async fn create_app_adopts_only_the_exact_operation_after_response_loss() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("idemapp{}", &suffix[..8]);
        let paas_org_id = format!("paas-app-recovery-{suffix}");
        insert_mapped_org(&pool, org_id, &org_name, &paas_org_id).await;
        sqlx::query(
            "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
        )
        .bind(org_id)
        .bind(&paas_org_id)
        .execute(&pool)
        .await
        .expect("mark app recovery org PaaS-managed");
        sqlx::query(
            "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
        )
        .bind(org_id)
        .bind(serde_json::json!({
            "name": "app-recovery-test",
            "max_apps": 10,
            "max_cpu": "10",
            "max_memory": "10Gi",
            "max_storage": "100Gi"
        }))
        .execute(&pool)
        .await
        .expect("insert app recovery entitlement");

        let state = idempotency_test_state(pool.clone());
        let key = format!("create-app-recovery-{suffix}");
        let body = InternalCreateAppRequest {
            name: format!("recover{}", &suffix[..8]),
            unlock_mode: "password".to_string(),
            bootstrap_pubkey_hash: Some("a".repeat(64)),
            signer_identity_subject: None,
            signer_identity_issuer: None,
            egress_allowlist: Vec::new(),
            egress_mode: "restricted".to_string(),
        };
        let first = create_paas_app(
            InternalAuth {
                client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
            },
            State(state.clone()),
            Path(paas_org_id.clone()),
            idempotency_headers(&key),
            Json(body),
        )
        .await
        .expect("create app before simulated response loss");
        assert_eq!(first.0, StatusCode::CREATED);
        let first_response = first.1.0;
        let app_id = first_response["cap_app_id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("created app ID");

        let token: Uuid = sqlx::query_scalar(
            "SELECT reservation_token
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("load completed app reservation token");
        let mut tx = pool
            .begin()
            .await
            .expect("begin simulated response-loss update");
        set_idempotency_completion_owner(&mut tx, token)
            .await
            .expect("prove simulated response-loss owner");
        sqlx::query(
            "UPDATE cap_internal_idempotency
                SET response_status = NULL,
                    response_body = NULL,
                    completed_at = NULL,
                    lease_expires_at = clock_timestamp() - interval '1 minute',
                    updated_at = clock_timestamp() - interval '1 minute'
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .execute(&mut *tx)
        .await
        .expect("simulate committed app with lost response");
        tx.commit().await.expect("commit simulated response loss");

        let retry_body = InternalCreateAppRequest {
            name: format!("recover{}", &suffix[..8]),
            unlock_mode: "password".to_string(),
            bootstrap_pubkey_hash: Some("a".repeat(64)),
            signer_identity_subject: None,
            signer_identity_issuer: None,
            egress_allowlist: Vec::new(),
            egress_mode: "restricted".to_string(),
        };
        let retried = create_paas_app(
            InternalAuth {
                client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
            },
            State(state),
            Path(paas_org_id),
            idempotency_headers(&key),
            Json(retry_body),
        )
        .await
        .expect("adopt exact app after response loss");
        assert_eq!(retried.0, StatusCode::CREATED);
        assert_eq!(retried.1.0, first_response);

        let authority: (i64, i64, i32) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM apps WHERE id = $1),
                 (SELECT count(*) FROM apps WHERE org_id = $2 AND name = $3),
                 (SELECT attempt_count FROM cap_internal_idempotency
                   WHERE idempotency_key = $4)",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("recover{}", &suffix[..8]))
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect exact app adoption authority");
        assert_eq!(authority, (1, 1, 2));
    }

    #[tokio::test]
    async fn generic_deployment_setup_pending_stays_retriable_then_adopts_exactly() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("idemdeploy{}", &suffix[..8]);
        let paas_org_id = format!("paas-deploy-recovery-{suffix}");
        let paas_user_id = format!("paas-deploy-user-{suffix}");
        let app_name = format!("recover{}", &suffix[..8]);
        let repository = "acme/confidential-app";
        let image = "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let signer_subject =
            "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main";
        let signer_issuer = "https://token.actions.githubusercontent.com";
        insert_mapped_org(&pool, org_id, &org_name, &paas_org_id).await;
        sqlx::query(
            "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
        )
        .bind(org_id)
        .bind(&paas_org_id)
        .execute(&pool)
        .await
        .expect("mark deployment recovery org PaaS-managed");
        sqlx::query(
            "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
        )
        .bind(org_id)
        .bind(serde_json::json!({
            "name": "deployment-recovery-test",
            "max_apps": 10,
            "max_cpu": "10",
            "max_memory": "10Gi",
            "max_storage": "100Gi"
        }))
        .execute(&pool)
        .await
        .expect("insert deployment recovery entitlement");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Deploy Recovery User')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert deployment recovery user");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
        )
        .bind(&paas_user_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("map deployment recovery user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner')",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("authorize deployment recovery user");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain,
                 signer_identity_subject, signer_identity_issuer,
                 source_provider, source_repository, egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 $12, $13, 'github', $14, '[]'::jsonb, 'restricted'
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(&app_name)
        .bind(format!("cap-{org_name}-{app_name}"))
        .bind(format!("{org_name}-{}", &app_id.simple().to_string()[..8]))
        .bind(&org_name)
        .bind(format!("cap-{app_name}-sa"))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("{app_name}.{org_name}.enclava.test"))
        .bind(format!("{app_name}.{org_name}.tee.enclava.test"))
        .bind(signer_subject)
        .bind(signer_issuer)
        .bind(repository)
        .execute(&pool)
        .await
        .expect("insert exact generic deployment app");

        let mut state = idempotency_test_state(pool.clone());
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        let key = format!("generic-deploy-recovery-{suffix}");
        let path = format!("/internal/paas/orgs/{paas_org_id}/deployments");
        let body = serde_json::json!({
            "app": {
                "name": app_name,
                "create_if_missing": false,
                "unlock_mode": "password",
                "egress_allowlist": [],
                "egress_mode": "restricted"
            },
            "source": {
                "provider": "github",
                "repository": repository
            },
            "workload": {
                "image": image,
                "container_name": null,
                "resources": null
            },
            "signing": {
                "subject": signer_subject,
                "issuer": signer_issuer
            },
            "security": {
                "workload_security_profile": null,
                "log_encryption": null
            }
        });
        let mut headers = idempotency_headers(&key);
        headers.insert(
            "x-enclava-paas-user-id",
            HeaderValue::from_str(&paas_user_id).expect("valid deployment actor header"),
        );
        let auth = internal_actor_context(&state, &paas_org_id, &headers)
            .await
            .expect("resolve deployment recovery actor");
        let first = expect_idempotency_execution(
            begin_actor_idempotent_request(
                &state,
                &headers,
                "POST",
                &path,
                &auth,
                &body,
                IdempotencyRecovery::DeterministicResource {
                    legacy_identity_bound: false,
                },
            )
            .await
            .expect("reserve generic deployment before response loss"),
        );
        let external_id = idempotency_deployment_external_id(first.operation_id());
        drop(first);
        let mut deployment_tx = pool
            .begin()
            .await
            .expect("begin durable pending deployment seed");
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, status, spec_snapshot,
                 image_digest, cosign_verified, external_id,
                 source_provider, source_repository
             ) VALUES (
                 $1, $2, $3, 'api', 'pending', $4, $5, true, $6,
                 'github', $7
             )",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(serde_json::json!({
            "app_name": app_name,
            "image": image,
            "container_name": "web",
            "resources": null,
            "external_id": external_id,
            "workload_security_profile": "restricted",
            "log_encryption": null,
            "setup_state": "dns_pending"
        }))
        .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind(&external_id)
        .bind(repository)
        .execute(&mut *deployment_tx)
        .await
        .expect("seed committed deployment with setup pending");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 log_encryption, state
             ) VALUES (
                 $1, $2, $3, $1, 1, $4, $5,
                 false, false, NULL, 'setup_pending'
             )",
        )
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .bind(serde_json::json!({"version": 1, "log_encryption": null}))
        .bind(vec![0_u8; 32])
        .execute(&mut *deployment_tx)
        .await
        .expect("seed durable pending deployment apply job");
        deployment_tx
            .commit()
            .await
            .expect("commit durable pending deployment seed");
        expire_idempotency_lease(&pool, &key).await;

        let pending = create_paas_generic_deployment(
            InternalAuth {
                client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
            },
            State(state.clone()),
            Path(paas_org_id.clone()),
            headers.clone(),
            Json(body.clone()),
        )
        .await
        .expect_err("setup-pending exact deployment remains retriable");
        assert_eq!(pending.0, StatusCode::CONFLICT);
        assert_eq!(pending.1.0["error"], "idempotency_request_in_progress");
        assert_eq!(pending.1.0["retryable"], true);
        assert_eq!(pending.1.0["disposition"], "retry_same_key");
        let pending_authority: (bool, i64, i32) = sqlx::query_as(
            "SELECT completed_at IS NULL,
                    (SELECT count(*) FROM deployments WHERE external_id = $2),
                    attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .bind(&external_id)
        .fetch_one(&pool)
        .await
        .expect("inspect deferred generic deployment recovery");
        assert_eq!(pending_authority, (true, 1, 2));

        sqlx::query(
            "UPDATE deployments
                SET spec_snapshot = jsonb_set(
                    spec_snapshot,
                    '{setup_state}',
                    to_jsonb($2::text)
                )
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind("accepted")
        .execute(&pool)
        .await
        .expect("accept durable deployment setup");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'pending', updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("advance durable deployment job after setup acceptance");
        expire_idempotency_lease(&pool, &key).await;
        let adopted = create_paas_generic_deployment(
            InternalAuth {
                client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
            },
            State(state),
            Path(paas_org_id),
            headers,
            Json(body),
        )
        .await
        .expect("adopt exact deployment after durable setup accepts");
        assert_eq!(adopted.0, StatusCode::OK);
        assert_eq!(adopted.1.0["deployment_id"], deployment_id.to_string());
        assert_eq!(adopted.1.0["app_id"], app_id.to_string());

        let completed_authority: (bool, i64, i32) = sqlx::query_as(
            "SELECT completed_at IS NOT NULL,
                    (SELECT count(*) FROM deployments WHERE external_id = $2),
                    attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
        )
        .bind(&key)
        .bind(&external_id)
        .fetch_one(&pool)
        .await
        .expect("inspect completed exact deployment adoption");
        assert_eq!(completed_authority, (true, 1, 3));
    }

    #[tokio::test]
    async fn membership_idempotency_key_cannot_replay_across_tenants() {
        let pool = database_test_pool().await;
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let suffix = org_a.simple().to_string();
        let paas_org_a = format!("paas-idem-a-{suffix}");
        let paas_org_b = format!("paas-idem-b-{suffix}");
        let paas_user_a = format!("paas-idem-user-a-{suffix}");
        let paas_user_b = format!("paas-idem-user-b-{suffix}");
        insert_mapped_org(
            &pool,
            org_a,
            &format!("member-idem-a-{suffix}"),
            &paas_org_a,
        )
        .await;
        insert_mapped_org(
            &pool,
            org_b,
            &format!("member-idem-b-{suffix}"),
            &paas_org_b,
        )
        .await;

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let key = format!("membership-cross-tenant-{suffix}");
        let (_, Json(first_response)) = sync_member(
            &state,
            &paas_org_a,
            &paas_user_a,
            &key,
            member_request("Shared Display", "member", true, 1),
        )
        .await
        .expect("apply first tenant membership sync");
        assert_eq!(first_response["cap_org_id"], org_a.to_string());

        let reused = sync_member(
            &state,
            &paas_org_b,
            &paas_user_b,
            &key,
            member_request("Shared Display", "member", true, 1),
        )
        .await
        .expect_err("same key on another tenant path must not replay");
        assert_eq!(reused.0, StatusCode::CONFLICT);
        assert_eq!(reused.1.0["error"], "idempotency_key_reused");

        let second_tenant_rows: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM paas_external_mappings
                   WHERE resource_type = 'user' AND paas_external_id = $1),
                 (SELECT count(*) FROM memberships WHERE org_id = $2),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $2 AND action = 'org.member.sync')",
        )
        .bind(&paas_user_b)
        .bind(org_b)
        .fetch_one(&pool)
        .await
        .expect("inspect rejected cross-tenant replay");
        assert_eq!(second_tenant_rows, (0, 0, 0));
    }

    #[tokio::test]
    async fn membership_transaction_rollback_does_not_strand_idempotency_reservation() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let missing_user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let paas_org_id = format!("paas-rollback-org-{suffix}");
        let paas_user_id = format!("paas-rollback-user-{suffix}");
        insert_mapped_org(
            &pool,
            org_id,
            &format!("member-rollback-{suffix}"),
            &paas_org_id,
        )
        .await;
        // User mappings intentionally have no user FK. Seed a legacy corrupt
        // mapping so the membership FK fails after the transaction reserves
        // the idempotency key.
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
        )
        .bind(&paas_user_id)
        .bind(missing_user_id)
        .execute(&pool)
        .await
        .expect("seed missing-user mapping");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let key = format!("membership-rollback-{suffix}");
        let failed = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &key,
            member_request("Missing User", "member", true, 1),
        )
        .await
        .expect_err("membership FK failure must roll back the request");
        assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR);

        let rolled_back: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM cap_internal_idempotency
                   WHERE idempotency_key = $1),
                 (SELECT count(*) FROM paas_membership_sync_state
                   WHERE org_id = $2),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $2 AND action = 'org.member.sync')",
        )
        .bind(&key)
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("inspect rolled-back membership request");
        assert_eq!(rolled_back, (0, 0, 0));
    }

    #[tokio::test]
    async fn concurrent_same_key_membership_sync_has_one_mutation_and_audit() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let paas_org_id = format!("paas-same-key-org-{suffix}");
        let paas_user_id = format!("paas-same-key-user-{suffix}");
        insert_mapped_org(
            &pool,
            org_id,
            &format!("member-same-key-{suffix}"),
            &paas_org_id,
        )
        .await;

        let application_name = format!("member-same-key-{suffix}");
        let mut state = crate::test_support::lazy_state();
        state.db = named_database_test_pool(&application_name).await;
        let mut blocker = pool.begin().await.expect("begin same-key mapping blocker");
        lock_paas_user_mapping_lane(&mut blocker, &paas_user_id)
            .await
            .expect("block same-key mapping lane");

        let key = format!("membership-same-key-{suffix}");
        let spawn_writer = |state: AppState| {
            let paas_org_id = paas_org_id.clone();
            let paas_user_id = paas_user_id.clone();
            let key = key.clone();
            tokio::spawn(async move {
                sync_member(
                    &state,
                    &paas_org_id,
                    &paas_user_id,
                    &key,
                    member_request("One Member", "admin", true, 1),
                )
                .await
            })
        };
        let writer_a = spawn_writer(state.clone());
        let writer_b = spawn_writer(state);
        wait_for_named_lock_waiters(&pool, &application_name, 2).await;
        blocker
            .commit()
            .await
            .expect("release same-key mapping lane");

        let (status_a, Json(response_a)) = writer_a
            .await
            .expect("join first same-key writer")
            .expect("first same-key writer succeeds");
        let (status_b, Json(response_b)) = writer_b
            .await
            .expect("join second same-key writer")
            .expect("second same-key writer replays");
        assert_eq!(status_a, StatusCode::OK);
        assert_eq!(status_b, StatusCode::OK);
        assert_eq!(response_a, response_b);

        let committed: (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM cap_internal_idempotency
                   WHERE idempotency_key = $1 AND completed_at IS NOT NULL),
                 (SELECT count(*) FROM paas_external_mappings
                   WHERE resource_type = 'user' AND paas_external_id = $2),
                 (SELECT count(*) FROM memberships WHERE org_id = $3),
                 (SELECT count(*) FROM paas_membership_sync_state WHERE org_id = $3),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $3 AND action = 'org.member.sync')",
        )
        .bind(&key)
        .bind(&paas_user_id)
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("inspect concurrent same-key authority");
        assert_eq!(committed, (1, 1, 1, 1, 1));
    }

    #[tokio::test]
    async fn exact_membership_replay_repairs_legacy_projection_before_success() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let paas_org_id = format!("paas-repair-org-{suffix}");
        let paas_user_id = format!("paas-repair-user-{suffix}");
        insert_mapped_org(
            &pool,
            org_id,
            &format!("member-repair-{suffix}"),
            &paas_org_id,
        )
        .await;
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Removed Member')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert legacy split-brain user");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
        )
        .bind(&paas_user_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("map legacy split-brain user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role, removed_at)
             VALUES ($1, $2, 'owner', NULL)",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("seed stale active owner projection");
        sqlx::query(
            "INSERT INTO paas_membership_sync_state
                 (org_id, user_id, paas_user_id, role, version, active)
             VALUES ($1, $2, $3, 'member', 2, false)",
        )
        .bind(org_id)
        .bind(user_id)
        .bind(&paas_user_id)
        .execute(&pool)
        .await
        .expect("seed latest inactive membership authority");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let (status, _) = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &format!("membership-repair-{suffix}"),
            member_request("Removed Member", "member", false, 2),
        )
        .await
        .expect("exact latest replay repairs stale membership projection");
        assert_eq!(status, StatusCode::OK);

        let repaired: (String, bool, i64, String, bool, serde_json::Value) = sqlx::query_as(
            "SELECT m.role::text,
                    m.removed_at IS NULL,
                    pms.version,
                    pms.role,
                    pms.active,
                    audit.detail
               FROM memberships m
               JOIN paas_membership_sync_state pms
                 ON pms.org_id = m.org_id AND pms.user_id = m.user_id
               JOIN LATERAL (
                    SELECT detail FROM audit_log
                     WHERE org_id = m.org_id
                       AND user_id = m.user_id
                       AND action = 'org.member.sync'
                     ORDER BY id DESC LIMIT 1
               ) audit ON TRUE
              WHERE m.org_id = $1 AND m.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("load repaired membership projection");
        assert_eq!(
            repaired,
            (
                "member".to_string(),
                false,
                2,
                "member".to_string(),
                false,
                serde_json::json!({
                    "role": "member",
                    "active": false,
                    "version": 2,
                    "client_san": "spiffe://paas.example.test/enclava-paas",
                    "repair": "legacy_membership_projection",
                }),
            )
        );

        let mut actor_headers = HeaderMap::new();
        actor_headers.insert(
            "x-enclava-paas-user-id",
            HeaderValue::from_str(&paas_user_id).expect("valid actor header"),
        );
        let rejected = internal_actor_context(&state, &paas_org_id, &actor_headers)
            .await
            .expect_err("repaired removed member cannot remain authorized");
        assert_eq!(rejected.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn membership_sync_rejects_stale_or_divergent_authority_and_replays_exactly() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("member-authority-{suffix}");
        let paas_org_id = format!("paas-org-{suffix}");
        let paas_user_id = format!("paas-user-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert membership authority org");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id, org_id)
             VALUES ('organization', $1, $2, $2)",
        )
        .bind(&paas_org_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("map membership authority org");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let _ = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &format!("member-v1-{suffix}"),
            member_request("Initial Owner", "owner", true, 1),
        )
        .await
        .expect("apply initial membership authority");
        let _ = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &format!("member-v2-{suffix}"),
            member_request("Removed Member", "member", false, 2),
        )
        .await
        .expect("apply membership removal and demotion");

        sqlx::query(
            "UPDATE memberships
                SET role = 'owner', removed_at = NULL
              WHERE org_id = $1",
        )
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("seed stale active-owner projection before stale delivery");

        let stale_key = format!("member-stale-{suffix}");
        let stale = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &stale_key,
            member_request("Stale Re-Escalation", "owner", true, 1),
        )
        .await
        .expect_err("stale membership reactivation must fail");
        assert_eq!(stale.0, StatusCode::CONFLICT);
        assert_eq!(stale.1.0["error"], "membership version is stale");
        let (stale_retry_status, Json(stale_retry_body)) = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &stale_key,
            member_request("Stale Re-Escalation", "owner", true, 1),
        )
        .await
        .expect("stale membership error replay is completed");
        assert_eq!(stale_retry_status, StatusCode::CONFLICT);
        assert_eq!(stale_retry_body["error"], "membership version is stale");

        let _ = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &format!("member-v2-replay-{suffix}"),
            member_request("Removed Member", "member", false, 2),
        )
        .await
        .expect("exact same-version membership replay is idempotent");

        let divergent_key = format!("member-v2-divergent-{suffix}");
        let divergent = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &divergent_key,
            member_request("Removed Member", "owner", true, 2),
        )
        .await
        .expect_err("same-version divergent membership authority must fail");
        assert_eq!(divergent.0, StatusCode::CONFLICT);
        assert_eq!(
            divergent.1.0["error"],
            "membership version already exists with different content"
        );
        let (divergent_retry_status, Json(divergent_retry_body)) = sync_member(
            &state,
            &paas_org_id,
            &paas_user_id,
            &divergent_key,
            member_request("Removed Member", "owner", true, 2),
        )
        .await
        .expect("divergent membership error replay is completed");
        assert_eq!(divergent_retry_status, StatusCode::CONFLICT);
        assert_eq!(
            divergent_retry_body["error"],
            "membership version already exists with different content"
        );

        let authority: (String, bool, i64, String, bool, String) = sqlx::query_as(
            "SELECT m.role::text,
                    m.removed_at IS NULL,
                    pms.version,
                    pms.role,
                    pms.active,
                    u.display_name
               FROM paas_membership_sync_state pms
               JOIN memberships m
                 ON m.org_id = pms.org_id AND m.user_id = pms.user_id
               JOIN users u ON u.id = pms.user_id
              WHERE pms.org_id = $1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load final membership authority");
        assert_eq!(
            authority,
            (
                "member".to_string(),
                false,
                2,
                "member".to_string(),
                false,
                "Removed Member".to_string(),
            ),
            "stale and divergent deliveries must not reactivate, re-escalate, or rename the member"
        );

        let audits: Vec<(i64, String, bool, serde_json::Value)> = sqlx::query_as(
            "SELECT (detail->>'version')::bigint,
                    detail->>'role',
                    (detail->>'active')::boolean,
                    detail
               FROM audit_log
              WHERE org_id = $1 AND action = 'org.member.sync'
              ORDER BY id",
        )
        .bind(org_id)
        .fetch_all(&pool)
        .await
        .expect("load membership authority audit");
        assert_eq!(
            audits,
            vec![
                (
                    1,
                    "owner".to_string(),
                    true,
                    serde_json::json!({
                        "role": "owner",
                        "active": true,
                        "version": 1,
                        "client_san": "spiffe://paas.example.test/enclava-paas",
                    }),
                ),
                (
                    2,
                    "member".to_string(),
                    false,
                    serde_json::json!({
                        "role": "member",
                        "active": false,
                        "version": 2,
                        "client_san": "spiffe://paas.example.test/enclava-paas",
                    }),
                ),
                (
                    2,
                    "member".to_string(),
                    false,
                    serde_json::json!({
                        "role": "member",
                        "active": false,
                        "version": 2,
                        "client_san": "spiffe://paas.example.test/enclava-paas",
                        "repair": "legacy_membership_projection",
                    }),
                ),
            ],
            "only committed authority generations and repairs receive minimal audit rows without user plaintext"
        );
    }

    #[tokio::test]
    async fn exact_org_replay_does_not_overwrite_global_display_from_another_org() {
        let pool = database_test_pool().await;
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let suffix = org_a.simple().to_string();
        let paas_org_a = format!("paas-display-a-{suffix}");
        let paas_org_b = format!("paas-display-b-{suffix}");
        let paas_user_id = format!("paas-display-user-{suffix}");
        insert_mapped_org(
            &pool,
            org_a,
            &format!("member-display-a-{suffix}"),
            &paas_org_a,
        )
        .await;
        insert_mapped_org(
            &pool,
            org_b,
            &format!("member-display-b-{suffix}"),
            &paas_org_b,
        )
        .await;

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let _ = sync_member(
            &state,
            &paas_org_a,
            &paas_user_id,
            &format!("display-a-v1-{suffix}"),
            member_request("Display A", "member", true, 1),
        )
        .await
        .expect("sync user through first org");
        let _ = sync_member(
            &state,
            &paas_org_b,
            &paas_user_id,
            &format!("display-b-v1-{suffix}"),
            member_request("Display B", "member", true, 1),
        )
        .await
        .expect("sync newer global display through second org");
        let _ = sync_member(
            &state,
            &paas_org_a,
            &paas_user_id,
            &format!("display-a-replay-{suffix}"),
            member_request("Display A", "member", true, 1),
        )
        .await
        .expect("exact first-org authority replay remains idempotent");

        let state_after_replay: (String, i64) = sqlx::query_as(
            "SELECT u.display_name,
                    (SELECT count(*) FROM audit_log
                      WHERE org_id IN ($1, $2) AND action = 'org.member.sync')
               FROM users u
               JOIN paas_external_mappings m
                 ON m.resource_type = 'user' AND m.cap_id = u.id
              WHERE m.paas_external_id = $3",
        )
        .bind(org_a)
        .bind(org_b)
        .bind(&paas_user_id)
        .fetch_one(&pool)
        .await
        .expect("load global display after exact org replay");
        assert_eq!(state_after_replay, ("Display B".to_string(), 2));
    }

    #[tokio::test]
    async fn concurrent_same_user_syncs_across_orgs_share_one_atomic_mapping() {
        let pool = database_test_pool().await;
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let suffix = org_a.simple().to_string();
        let paas_org_a = format!("paas-org-a-{suffix}");
        let paas_org_b = format!("paas-org-b-{suffix}");
        let paas_user_id = format!("paas-shared-user-{suffix}");
        let display_name = format!("Shared User {suffix}");
        for (org_id, org_name, paas_org_id) in [
            (org_a, format!("member-map-a-{suffix}"), &paas_org_a),
            (org_b, format!("member-map-b-{suffix}"), &paas_org_b),
        ] {
            crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
                .await
                .expect("insert concurrent mapping org");
            sqlx::query(
                "INSERT INTO paas_external_mappings
                     (resource_type, paas_external_id, cap_id, org_id)
                 VALUES ('organization', $1, $2, $2)",
            )
            .bind(paas_org_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("map concurrent membership org");
        }

        let application_name = format!("member-map-{suffix}");
        let writer_pool = named_database_test_pool(&application_name).await;
        let mut state = crate::test_support::lazy_state();
        state.db = writer_pool;

        let mut blocker = pool.begin().await.expect("begin user mapping blocker");
        lock_paas_user_mapping_lane(&mut blocker, &paas_user_id)
            .await
            .expect("block shared user mapping lane");

        let writer_a_state = state.clone();
        let writer_a_org = paas_org_a.clone();
        let writer_a_user = paas_user_id.clone();
        let writer_a_name = display_name.clone();
        let writer_a_key = format!("member-map-a-{suffix}");
        let writer_a = tokio::spawn(async move {
            sync_member(
                &writer_a_state,
                &writer_a_org,
                &writer_a_user,
                &writer_a_key,
                member_request(&writer_a_name, "owner", true, 1),
            )
            .await
        });
        let writer_b_state = state;
        let writer_b_org = paas_org_b.clone();
        let writer_b_user = paas_user_id.clone();
        let writer_b_name = display_name.clone();
        let writer_b_key = format!("member-map-b-{suffix}");
        let writer_b = tokio::spawn(async move {
            sync_member(
                &writer_b_state,
                &writer_b_org,
                &writer_b_user,
                &writer_b_key,
                member_request(&writer_b_name, "owner", true, 1),
            )
            .await
        });

        wait_for_named_lock_waiters(&pool, &application_name, 2).await;
        blocker.commit().await.expect("release user mapping lane");
        let _ = writer_a
            .await
            .expect("join first shared user sync")
            .expect("sync shared user into first org");
        let _ = writer_b
            .await
            .expect("join second shared user sync")
            .expect("sync shared user into second org");

        let mapping_count: i64 = sqlx::query_scalar(
            "SELECT count(*)
               FROM paas_external_mappings
              WHERE resource_type = 'user' AND paas_external_id = $1",
        )
        .bind(&paas_user_id)
        .fetch_one(&pool)
        .await
        .expect("count shared user mappings");
        assert_eq!(mapping_count, 1);
        let local_user_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM users WHERE display_name = $1")
                .bind(&display_name)
                .fetch_one(&pool)
                .await
                .expect("count shared local users");
        assert_eq!(local_user_count, 1, "no orphan duplicate user may survive");
        let authority: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*),
                    count(DISTINCT user_id),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id IN ($1, $2) AND action = 'org.member.sync')
               FROM paas_membership_sync_state
              WHERE org_id IN ($1, $2)",
        )
        .bind(org_a)
        .bind(org_b)
        .fetch_one(&pool)
        .await
        .expect("load shared membership authority");
        assert_eq!(authority, (2, 1, 2));
    }
}

#[cfg(test)]
mod confidentiality_tests {
    use super::project_internal_deployment_error;

    #[test]
    fn stored_internal_deployment_errors_are_projected_without_plaintext() {
        const STORED_SECRET: &str =
            "pod 'tenant-pod' container 'tenant-app' is CrashLoopBackOff: secret=private-key";
        let response = serde_json::json!({
            "latest_deployment": {
                "status": "failed",
                "error_message": project_internal_deployment_error(None, Some(STORED_SECRET)),
            }
        });
        let serialized = serde_json::to_string(&response).expect("serialize internal response");

        assert_eq!(
            response["latest_deployment"]["error_message"],
            "deployment_error"
        );
        assert!(!serialized.contains(STORED_SECRET));
        assert!(!serialized.contains("private-key"));
        assert!(serialized.len() < 128);
    }

    #[test]
    fn internal_deployment_projection_preserves_safe_supersession_code() {
        let projected = project_internal_deployment_error(
            None,
            Some(crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR),
        );

        assert_eq!(
            projected.as_deref(),
            Some(crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR)
        );
    }

    #[test]
    fn bounded_live_runtime_error_takes_precedence_over_recorded_error() {
        let live = "container_runtime_failure status=waiting code=crash_loop_back_off";
        let projected = project_internal_deployment_error(
            Some(live.to_string()),
            Some("stored-secret=tenant-token"),
        );

        assert_eq!(projected.as_deref(), Some(live));
    }
}
