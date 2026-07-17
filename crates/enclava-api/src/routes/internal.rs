use axum::{
    Json,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::{AuthContext, ManagementOrigin};
use crate::models::Role;
use crate::routes::platform::{DeploymentContextResponse, deployment_context_response};
use crate::routes::status::live_pod_failure_message;
use crate::state::AppState;

type InternalRouteError = (StatusCode, Json<serde_json::Value>);
type IdempotencyResponse = (StatusCode, serde_json::Value);
type IdempotencyRow = (
    String,
    String,
    Vec<u8>,
    Option<i32>,
    Option<serde_json::Value>,
);

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
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?
    .rows_affected()
        == 1;

    if inserted {
        return Ok(None);
    }

    let row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;

    idempotency_replay(method, path, hash, row)
}

fn idempotency_replay(
    method: &str,
    path: &str,
    hash: &[u8],
    row: IdempotencyRow,
) -> Result<Option<IdempotencyResponse>, InternalRouteError> {
    if row.0 != method || row.1 != path || row.2 != hash {
        return Err(json_error(StatusCode::CONFLICT, "idempotency_key_reused"));
    }

    let Some(status) = row
        .3
        .and_then(|code| StatusCode::from_u16(code as u16).ok())
    else {
        return Err(json_error(
            StatusCode::CONFLICT,
            "idempotency_request_in_progress",
        ));
    };
    let body = row.4.unwrap_or_else(|| serde_json::json!({}));
    Ok(Some((status, body)))
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
        "SELECT method, path, request_hash, response_status, response_body
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
    state: &AppState,
    key: &str,
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    sqlx::query(
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
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;
    Ok(())
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
    if let Some((status, body)) = begin_idempotent_request(&state, key, "PUT", &path, &hash).await?
    {
        return Ok((status, Json(body)));
    }

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
    finish_idempotent_request(&state, key, response_status, &response).await?;
    Ok((response_status, Json(response)))
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
    if let Some((status, body)) = begin_idempotent_request(&state, key, "PUT", &path, &hash).await?
    {
        return Ok((status, Json(body)));
    }

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
    finish_idempotent_request(&state, key, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
) -> Result<Option<(StatusCode, Json<serde_json::Value>)>, (StatusCode, Json<serde_json::Value>)> {
    let key = idempotency_key(headers)?;
    let hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))?;
    Ok(begin_idempotent_request(state, key, method, path, &hash)
        .await?
        .map(|(status, body)| (status, Json(body))))
}

async fn finish_actor_idempotent_request(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let key = idempotency_key(headers)?;
    finish_idempotent_request(state, key, status, body).await
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
    if let Some((status, body)) =
        begin_idempotent_request(&state, key, "POST", &path, &hash).await?
    {
        return Ok((status, Json(body)));
    }

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
    let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps WHERE org_id = $1")
        .bind(cap_org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| db_error())?;
    if app_count >= max_apps as i64 {
        return Err(json_error(StatusCode::FORBIDDEN, "entitlement_app_limit"));
    }

    let app_id = Uuid::new_v4();
    let (tenant_id, instance_id, namespace, service_account, pubkey_hash, identity_hash) =
        crate::routes::apps::derive_identity(
            &org_name,
            app_id,
            &body.name,
            &body.unlock_mode,
            body.bootstrap_pubkey_hash.as_deref(),
        )
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))?;
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
    finish_idempotent_request(&state, key, StatusCode::CREATED, &response).await?;
    Ok((StatusCode::CREATED, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "DELETE", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let status =
        crate::routes::apps::delete_app(auth, State(state.clone()), Path(app_name)).await?;
    let response = serde_json::json!({"status": "deleted"});
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
                        "error_message": error_message,
                    })
                },
            )
            .collect(),
    }))
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
               WHERE d.app_id = a.id
               ORDER BY d.created_at DESC, d.id DESC
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
    let mut items = Vec::with_capacity(rows.len());
    for (
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
    ) in rows
    {
        let runtime_failure = live_pod_failure_message(&namespace, &app_name).await;
        let app_status = if runtime_failure.is_some() {
            "failed".to_string()
        } else {
            app_status
        };
        let deployment_status = if runtime_failure.is_some() && cap_deployment_id.is_some() {
            Some("failed".to_string())
        } else {
            deployment_status
        };
        let error_message = runtime_failure.or(error_message);
        let latest_deployment = cap_deployment_id.map(|id| {
            serde_json::json!({
                "cap_deployment_id": id,
                "status": deployment_status,
                "image_digest": image_digest,
                "error_message": error_message,
            })
        });
        items.push(serde_json::json!({
            "cap_app_id": cap_app_id,
            "app_name": app_name,
            "status": app_status,
            "domain": domain,
            "tee_domain": tee_domain,
            "latest_deployment": latest_deployment,
        }));
    }
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
               WHERE d.app_id = a.id
               ORDER BY d.created_at DESC, d.id DESC
               LIMIT 1
          ) latest ON TRUE
         ORDER BY a.created_at DESC, a.id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;

    let mut items = Vec::with_capacity(rows.len());
    for (
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
    ) in rows
    {
        let runtime_failure = live_pod_failure_message(&namespace, &app_name).await;
        let app_status = if runtime_failure.is_some() {
            "failed".to_string()
        } else {
            app_status
        };
        let deployment_status = if runtime_failure.is_some() && cap_deployment_id.is_some() {
            Some("failed".to_string())
        } else {
            deployment_status
        };
        let error_message = runtime_failure.or(error_message);
        let latest_deployment = cap_deployment_id.map(|id| {
            serde_json::json!({
                "cap_deployment_id": id,
                "status": deployment_status,
                "image_digest": image_digest,
                "error_message": error_message,
            })
        });
        items.push(serde_json::json!({
            "paas_org_id": paas_org_id,
            "cap_org_id": cap_org_id,
            "cap_org_name": cap_org_name,
            "cap_org_display_name": cap_org_display_name,
            "cap_app_id": cap_app_id,
            "app_name": app_name,
            "status": app_status,
            "domain": domain,
            "tee_domain": tee_domain,
            "latest_deployment": latest_deployment,
        }));
    }
    Ok(Json(InternalListResponse { items }))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &raw_body).await?
    {
        return Ok(response);
    }

    let deploy_request = crate::routes::deployments::DeployRequest {
        image: body.image,
        container_name: body.container_name,
        resources: body.resources,
        external_id: body.external_id,
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
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let (status, Json(response)) =
        crate::routes::users::register_public_key(auth, State(state.clone()), Json(parsed)).await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "PUT", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let org_name = auth.org_name.clone();
    let parsed = parse_internal_body(body)?;
    let (status, Json(response)) =
        crate::routes::orgs::put_keyring(auth, State(state.clone()), Path(org_name), Json(parsed))
            .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
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
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let Json(response) = crate::routes::apps::issue_signer_rotation_token_route(
        auth,
        State(state.clone()),
        Path(app_name),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "PATCH", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let Json(response) = crate::routes::apps::rotate_signer(
        auth,
        State(state.clone()),
        Path(app_name),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let Json(response) = crate::routes::domains::create_challenge(
        auth,
        State(state.clone()),
        Path(app_name),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let Json(response) = crate::routes::domains::verify_challenge(
        auth,
        State(state.clone()),
        Path((app_name, domain)),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "DELETE", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let status = crate::routes::domains::remove_custom_domain(
        auth,
        State(state.clone()),
        Path((app_name, domain)),
    )
    .await?;
    let response = serde_json::json!({"status": "deleted"});
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let Json(response) =
        crate::routes::config::issue_config_token_route(auth, State(state.clone()), Path(app_name))
            .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    crate::auth::scopes::require_config_metadata_write(&auth)?;
    let status = crate::routes::config::sync_config_metadata_for_org(
        &state,
        auth.org_id,
        &app_name,
        &parsed,
    )
    .await?;
    let response = serde_json::json!({"status": "synced"});
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "DELETE", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    crate::auth::scopes::require_config_metadata_write(&auth)?;
    let status = crate::routes::config::delete_config_metadata_for_org(
        &state,
        auth.org_id,
        &app_name,
        &key_name,
    )
    .await?;
    let response = serde_json::json!({"status": "deleted"});
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let (status, Json(response)) = crate::routes::deployments::rollback(
        auth,
        State(state.clone()),
        Path(app_name),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let (status, Json(response)) = crate::routes::deployments::create_generic_deployment(
        auth,
        State(state.clone()),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, status, &response).await?;
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let Json(response) = crate::routes::deployments::generic_config_token(
        auth,
        State(state.clone()),
        Path(deployment_id),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
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
    if let Some(response) =
        begin_actor_idempotent_request(&state, &headers, "PUT", &path, &auth, &body).await?
    {
        return Ok(response);
    }
    let parsed = parse_internal_body(body)?;
    let Json(response) = crate::routes::unlock::update_unlock_mode(
        auth,
        State(state.clone()),
        Path(app_name),
        Json(parsed),
    )
    .await?;
    let response = to_value(response)?;
    finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response).await?;
    Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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
