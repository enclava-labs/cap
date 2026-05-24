//! Auth extraction middleware for axum.
//!
//! Extracts the authenticated user from either:
//! - Authorization: Bearer <session-jwt>
//! - Authorization: Bearer <api-key>  (starts with "enclava_" or "enc_")
//! - X-API-Key: <api-key>
//!
//! Resolves the active org from:
//! - X-Enclava-Org header
//! - ?org= query parameter
//! - Falls back to user's personal org

use axum::{
    extract::{FromRequestParts, Query},
    http::{StatusCode, header, request::Parts},
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::api_key::{ValidatedApiKey, is_api_key_candidate, validate_api_key};
use crate::auth::jwt::verify_session_token;
use crate::state::AppState;

/// The authenticated request context, available to all handlers.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    pub role: crate::models::Role,
    /// If authenticated via API key, contains the key metadata.
    pub api_key: Option<ValidatedApiKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing or invalid authorization header")]
    MissingAuth,
    #[error("invalid session token: {0}")]
    InvalidToken(String),
    #[error("user not found")]
    UserNotFound,
    #[error("not a member of organization: {0}")]
    NotOrgMember(String),
    #[error("no organization context")]
    NoOrgContext,
    #[error("database error")]
    Db,
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AuthError::MissingAuth | AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::NotOrgMember(_) => StatusCode::FORBIDDEN,
            AuthError::UserNotFound | AuthError::NoOrgContext => StatusCode::UNAUTHORIZED,
            AuthError::Db => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}

/// Extract the bearer token from the Authorization header.
fn extract_bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

/// Extract API key from X-API-Key header.
fn extract_api_key_header(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("X-API-Key")?
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

/// Extract org name from X-Enclava-Org header or ?org= query param.
fn extract_org_hint(parts: &Parts) -> Option<String> {
    if let Some(org) = parts
        .headers
        .get("X-Enclava-Org")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        return Some(org);
    }

    #[derive(Deserialize)]
    struct OrgQuery {
        org: Option<String>,
    }
    let query: Query<OrgQuery> = Query::try_from_uri(&parts.uri).ok()?;
    query.org.clone()
}

/// Resolve the user_id from either a session JWT or an API key.
async fn resolve_auth(
    pool: &PgPool,
    hmac_key: &[u8; 32],
    parts: &Parts,
) -> Result<(Uuid, Option<ValidatedApiKey>), AuthError> {
    // Try X-API-Key header first
    if let Some(key) = extract_api_key_header(parts)
        && is_api_key_candidate(&key)
    {
        let validated = validate_api_key(pool, &key)
            .await
            .map_err(|_| AuthError::MissingAuth)?;
        return Ok((validated.created_by, Some(validated)));
    }

    // Try Authorization: Bearer
    let token = extract_bearer(parts).ok_or(AuthError::MissingAuth)?;

    // API key in bearer
    if is_api_key_candidate(&token) {
        let validated = validate_api_key(pool, &token)
            .await
            .map_err(|_| AuthError::MissingAuth)?;
        return Ok((validated.created_by, Some(validated)));
    }

    // Session JWT
    let claims = verify_session_token(hmac_key, &token)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken("invalid sub".into()))?;
    Ok((user_id, None))
}

/// Resolve the org context for the request.
async fn resolve_org(
    pool: &PgPool,
    user_id: Uuid,
    api_key: &Option<ValidatedApiKey>,
    org_hint: Option<String>,
) -> Result<(Uuid, String, crate::models::Role), AuthError> {
    // If API key, use the key's org
    if let Some(key) = api_key {
        let row: Option<(String, crate::models::Role)> = sqlx::query_as(
            "SELECT o.name, m.role as \"role: _\"
             FROM organizations o
             JOIN memberships m ON m.org_id = o.id
             WHERE o.id = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
        )
        .bind(key.org_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AuthError::Db)?;

        let (name, role) = row.ok_or_else(|| AuthError::NotOrgMember(key.org_id.to_string()))?;
        return Ok((key.org_id, name, role));
    }

    // Org hint from header/query
    if let Some(org_name) = org_hint {
        let row: Option<(Uuid, String, crate::models::Role)> = sqlx::query_as(
            "SELECT o.id, o.name, m.role as \"role: _\"
             FROM organizations o
             JOIN memberships m ON m.org_id = o.id
             WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
        )
        .bind(&org_name)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AuthError::Db)?;

        if let Some((org_id, name, role)) = row {
            return Ok((org_id, name, role));
        } else {
            return Err(AuthError::NotOrgMember(org_name));
        }
    }

    // Default: personal org
    let row: Option<(Uuid, String, crate::models::Role)> = sqlx::query_as(
        "SELECT o.id, o.name, m.role as \"role: _\"
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1 AND o.is_personal = true AND m.removed_at IS NULL
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthError::Db)?;

    row.ok_or(AuthError::NoOrgContext)
}

/// axum extractor: extracts AuthContext from the request.
/// Use as a handler parameter: `async fn handler(auth: AuthContext) -> ...`
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let (user_id, api_key) = resolve_auth(&state.db, &state.hmac_key, parts).await?;
        let org_hint = extract_org_hint(parts);
        let (org_id, org_name, role) = resolve_org(&state.db, user_id, &api_key, org_hint).await?;

        Ok(AuthContext {
            user_id,
            org_id,
            org_name,
            role,
            api_key,
        })
    }
}
