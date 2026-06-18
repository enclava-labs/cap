use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::{AuthContext, ManagementOrigin};
use crate::models::Role;
use crate::state::AppState;

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
    pub egress_allowlist: Vec<crate::routes::apps::EgressAllowRule>,
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
) -> Result<Option<(StatusCode, serde_json::Value)>, (StatusCode, Json<serde_json::Value>)> {
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

    let row: (Vec<u8>, Option<i32>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT request_hash, response_status, response_body
           FROM cap_internal_idempotency
          WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;

    if row.0 != hash {
        return Err(json_error(StatusCode::CONFLICT, "idempotency_key_reused"));
    }

    let Some(status) = row
        .1
        .and_then(|code| StatusCode::from_u16(code as u16).ok())
    else {
        return Err(json_error(
            StatusCode::CONFLICT,
            "idempotency_request_in_progress",
        ));
    };
    let body = row.2.unwrap_or_else(|| serde_json::json!({}));
    Ok(Some((status, body)))
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

    let (cap_org_id, response_status) = if let Some(org_id) = existing_org_id {
        sqlx::query(
            "UPDATE organizations
                SET name = $2,
                    display_name = $3,
                    updated_at = now()
              WHERE id = $1",
        )
        .bind(org_id)
        .bind(&body.name)
        .bind(body.display_name.as_deref())
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;
        (org_id, StatusCode::OK)
    } else {
        let org_id = Uuid::new_v4();
        crate::db::orgs::insert_org_pool(
            &state.db,
            org_id,
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
        (org_id, StatusCode::CREATED)
    };

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
    .execute(&state.db)
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
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

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
    let role = parse_role(&body.role)?;
    let key = idempotency_key(&headers)?;
    let path = format!("/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}");
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

    let cap_user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT cap_id
           FROM paas_external_mappings
          WHERE resource_type = 'user'
            AND paas_external_id = $1",
    )
    .bind(&paas_user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let cap_user_id = if let Some(user_id) = cap_user_id {
        sqlx::query("UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1")
            .bind(user_id)
            .bind(&body.display_name)
            .execute(&state.db)
            .await
            .map_err(|_| db_error())?;
        user_id
    } else {
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, $2)")
            .bind(user_id)
            .bind(&body.display_name)
            .execute(&state.db)
            .await
            .map_err(|_| db_error())?;
        sqlx::query(
            "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id, metadata, updated_at)
             VALUES ('user', $1, $2, $3, now())",
        )
        .bind(&paas_user_id)
        .bind(user_id)
        .bind(serde_json::json!({"client_san": auth.client_san}))
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;
        user_id
    };

    let removed_at: Option<chrono::DateTime<chrono::Utc>> = if body.active {
        None
    } else {
        Some(chrono::Utc::now())
    };
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, removed_at)
         VALUES ($1, $2, $3::role_enum, $4)
         ON CONFLICT (user_id, org_id) DO UPDATE
            SET role = EXCLUDED.role,
                removed_at = EXCLUDED.removed_at",
    )
    .bind(cap_user_id)
    .bind(cap_org_id)
    .bind(role_as_str(role))
    .bind(removed_at)
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

    sqlx::query(
        "INSERT INTO paas_membership_sync_state
             (org_id, user_id, paas_user_id, role, version, active, synced_at)
         VALUES ($1, $2, $3, $4, $5, $6, now())
         ON CONFLICT (org_id, user_id) DO UPDATE
            SET paas_user_id = EXCLUDED.paas_user_id,
                role = EXCLUDED.role,
                version = GREATEST(paas_membership_sync_state.version, EXCLUDED.version),
                active = EXCLUDED.active,
                synced_at = now()",
    )
    .bind(cap_org_id)
    .bind(cap_user_id)
    .bind(&paas_user_id)
    .bind(role_as_str(role))
    .bind(body.version)
    .bind(body.active)
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

    let response = serde_json::json!({
        "cap_org_id": cap_org_id,
        "cap_user_id": cap_user_id,
        "paas_org_id": paas_org_id,
        "paas_user_id": paas_user_id,
        "role": role_as_str(role),
        "active": body.active,
    });
    finish_idempotent_request(&state, key, StatusCode::OK, &response).await?;
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
                updated_at = now()
          WHERE organization_entitlements.version <= EXCLUDED.version",
    )
    .bind(cap_org_id)
    .bind(body.version)
    .bind(body.deploy_allowed)
    .bind(body.block_reason.as_deref())
    .bind(&limits)
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

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

fn is_idempotency_request_in_progress(error: &(StatusCode, Json<serde_json::Value>)) -> bool {
    error.0 == StatusCode::CONFLICT
        && error.1.0.get("error").and_then(serde_json::Value::as_str)
            == Some("idempotency_request_in_progress")
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
    crate::routes::apps::validate_egress_allowlist(&body.egress_allowlist)
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

    let egress_allowlist = crate::routes::apps::egress_allowlist_to_json(&body.egress_allowlist);
    sqlx::query(
        "INSERT INTO apps (
            id, org_id, name, namespace, instance_id, tenant_id, service_account,
            bootstrap_owner_pubkey_hash, tenant_instance_identity_hash,
            unlock_mode, domain, tee_domain,
            signer_identity_subject, signer_identity_issuer, signer_identity_set_at,
            egress_allowlist
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11, $12, $13, $14, $15, $16)",
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
    .bind(&egress_allowlist)
    .execute(&state.db)
    .await
    .map_err(|error| {
        if error.to_string().contains("duplicate key") || error.to_string().contains("unique") {
            json_error(StatusCode::CONFLICT, "app name already taken in this org")
        } else {
            db_error()
        }
    })?;
    sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
        .bind(app_id)
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;

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
        "egress_allowlist": egress_allowlist,
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
    let rows: Vec<(
        Uuid,
        Uuid,
        String,
        String,
        serde_json::Value,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT d.id,
               d.app_id,
               a.name,
               d.status::text,
               d.spec_snapshot,
               d.image_digest
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
                |(cap_deployment_id, cap_app_id, app_name, status, spec, image_digest)| {
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
    let rows: Vec<(
        Uuid,
        String,
        String,
        String,
        Option<String>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT a.id,
               a.name,
               a.status::text,
               a.domain,
               a.tee_domain,
               latest.id,
               latest.status,
               latest.image_digest
          FROM apps a
          LEFT JOIN LATERAL (
              SELECT d.id,
                     d.status::text AS status,
                     d.image_digest
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
    Ok(Json(InternalListResponse {
        items: rows
            .into_iter()
            .map(
                |(
                    cap_app_id,
                    app_name,
                    app_status,
                    domain,
                    tee_domain,
                    cap_deployment_id,
                    deployment_status,
                    image_digest,
                )| {
                    let latest_deployment = cap_deployment_id.map(|id| {
                        serde_json::json!({
                            "cap_deployment_id": id,
                            "status": deployment_status,
                            "image_digest": image_digest,
                        })
                    });
                    serde_json::json!({
                        "cap_app_id": cap_app_id,
                        "app_name": app_name,
                        "status": app_status,
                        "domain": domain,
                        "tee_domain": tee_domain,
                        "latest_deployment": latest_deployment,
                    })
                },
            )
            .collect(),
    }))
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

pub async fn recover_paas_app_runtime(
    _auth: InternalAuth,
    State(state): State<AppState>,
    Path((paas_org_id, app_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_external_id(&paas_org_id, "paas_org_id")?;
    let auth = internal_actor_context(&state, &paas_org_id, &headers).await?;
    let Json(response) =
        crate::routes::status::recover_runtime(auth, State(state), Path(app_name)).await?;
    Ok(Json(to_value(response)?))
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
    match begin_actor_idempotent_request(&state, &headers, "POST", &path, &auth, &body).await {
        Ok(Some(response)) => return Ok(response),
        Ok(None) => {}
        Err(error) if is_idempotency_request_in_progress(&error) => {
            let parsed = parse_internal_body(body)?;
            if let Some(response) =
                crate::routes::deployments::recover_generic_deployment_by_external_id(
                    &state, &auth, &parsed,
                )
                .await?
            {
                let response = to_value(response)?;
                finish_actor_idempotent_request(&state, &headers, StatusCode::OK, &response)
                    .await?;
                return Ok((StatusCode::OK, Json(response)));
            }
            return Err(error);
        }
        Err(error) => return Err(error),
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
