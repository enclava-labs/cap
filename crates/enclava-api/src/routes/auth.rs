use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::api_key;
use crate::auth::email;
use crate::auth::jwt::issue_session_token;
use crate::auth::middleware::AuthContext;
use crate::auth::nostr;
use crate::auth::scopes;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub provider: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub nostr_event: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    pub token: String,
}

const DEVICE_LOGIN_TTL_MINUTES: i64 = 10;
const DEVICE_LOGIN_POLL_INTERVAL_SECONDS: i64 = 5;
type DeviceLoginPollRow = (
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<Uuid>,
    Option<Uuid>,
);

async fn fetch_org_name(
    db: &sqlx::PgPool,
    org_id: Uuid,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_scalar::<_, String>("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_one(db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })
}

/// POST /auth/signup
pub async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<serde_json::Value>)> {
    match body.provider.as_str() {
        "email" => {
            let email_addr = body.email.as_deref().unwrap_or("");
            let password = body.password.as_deref().unwrap_or("");
            let (user_id, org_id) = email::signup(
                &state.db,
                email_addr,
                password,
                body.display_name.as_deref(),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let token = issue_session_token(&state.hmac_key, user_id).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let org_name = fetch_org_name(&state.db, org_id).await?;

            Ok((
                StatusCode::CREATED,
                Json(AuthResponse {
                    user_id,
                    org_id,
                    org_name,
                    token,
                }),
            ))
        }
        "nostr" => {
            let event_json = body.nostr_event.as_deref().ok_or((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "nostr_event is required"})),
            ))?;

            let url = format!("{}/auth/signup", state.api_url);
            let identity = nostr::verify_nip98_event(event_json, &url, "POST").map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let (user_id, org_id, _is_new) = nostr::signup_or_login(&state.db, &identity)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                })?;

            let token = issue_session_token(&state.hmac_key, user_id).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let org_name = fetch_org_name(&state.db, org_id).await?;

            Ok((
                StatusCode::CREATED,
                Json(AuthResponse {
                    user_id,
                    org_id,
                    org_name,
                    token,
                }),
            ))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("unsupported provider: {}", body.provider)})),
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginStartRequest {
    #[serde(default)]
    pub org: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceLoginStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginPollRequest {
    pub device_code: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceLoginPollResponse {
    pub status: String,
    pub interval: i64,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthResponse>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceLoginApproveRequest {
    pub user_code: String,
    #[serde(default)]
    pub org_id: Option<Uuid>,
    #[serde(default)]
    pub org_name: Option<String>,
    #[serde(default = "default_approve")]
    pub approve: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceLoginApproveResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

fn default_approve() -> bool {
    true
}

fn random_device_code() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = OsRng;
    let mut chars = [0u8; 8];
    for ch in &mut chars {
        let idx = rng.gen_range(0..ALPHABET.len());
        *ch = ALPHABET[idx];
    }
    format!(
        "{}{}{}{}-{}{}{}{}",
        chars[0] as char,
        chars[1] as char,
        chars[2] as char,
        chars[3] as char,
        chars[4] as char,
        chars[5] as char,
        chars[6] as char,
        chars[7] as char
    )
}

fn normalize_user_code(code: &str) -> String {
    code.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn code_hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

fn seconds_until(expires_at: DateTime<Utc>) -> i64 {
    (expires_at - Utc::now()).num_seconds().max(0)
}

/// POST /auth/device/start
pub async fn start_device_login(
    State(state): State<AppState>,
    Json(body): Json<DeviceLoginStartRequest>,
) -> Result<Json<DeviceLoginStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    let device_code = random_device_code();
    let user_code = random_user_code();
    let normalized_user_code = normalize_user_code(&user_code);
    let verification_uri = format!(
        "{}/cli/login",
        state.device_login_base_url().trim_end_matches('/')
    );
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    let expires_at = Utc::now() + Duration::minutes(DEVICE_LOGIN_TTL_MINUTES);
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO device_login_sessions (
             id, device_code_hash, user_code_hash, verification_uri,
             verification_uri_complete, requested_org_name, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(code_hash(&device_code))
    .bind(code_hash(&normalized_user_code))
    .bind(&verification_uri)
    .bind(&verification_uri_complete)
    .bind(body.org.as_deref())
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok(Json(DeviceLoginStartResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_LOGIN_TTL_MINUTES * 60,
        interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
    }))
}

/// POST /auth/device/poll
pub async fn poll_device_login(
    State(state): State<AppState>,
    Json(body): Json<DeviceLoginPollRequest>,
) -> Result<Json<DeviceLoginPollResponse>, (StatusCode, Json<serde_json::Value>)> {
    let hash = code_hash(&body.device_code);
    let row: Option<DeviceLoginPollRow> = sqlx::query_as(
        "SELECT status, expires_at, last_polled_at, approved_user_id, approved_org_id
         FROM device_login_sessions
         WHERE device_code_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let Some((status, expires_at, last_polled_at, approved_user_id, approved_org_id)) = row else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid device_code"})),
        ));
    };

    if Utc::now() >= expires_at && (status == "pending" || status == "approved") {
        let _ = sqlx::query(
            "UPDATE device_login_sessions
             SET status = 'expired'
             WHERE device_code_hash = $1 AND status IN ('pending', 'approved')",
        )
        .bind(&hash)
        .execute(&state.db)
        .await;
        return Ok(Json(DeviceLoginPollResponse {
            status: "expired".to_string(),
            interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
            expires_in: 0,
            error: Some("device login expired".to_string()),
            auth: None,
        }));
    }

    if status == "pending" {
        if let Some(last_polled_at) = last_polled_at {
            let next_allowed =
                last_polled_at + Duration::seconds(DEVICE_LOGIN_POLL_INTERVAL_SECONDS);
            if Utc::now() < next_allowed {
                return Ok(Json(DeviceLoginPollResponse {
                    status: "slow_down".to_string(),
                    interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
                    expires_in: seconds_until(expires_at),
                    error: Some("poll interval has not elapsed".to_string()),
                    auth: None,
                }));
            }
        }
        let _ = sqlx::query(
            "UPDATE device_login_sessions
             SET last_polled_at = now()
             WHERE device_code_hash = $1",
        )
        .bind(&hash)
        .execute(&state.db)
        .await;
        return Ok(Json(DeviceLoginPollResponse {
            status,
            interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
            expires_in: seconds_until(expires_at),
            error: None,
            auth: None,
        }));
    }

    if status == "approved" {
        let redeemed = sqlx::query(
            "UPDATE device_login_sessions
             SET status = 'expired',
                 last_polled_at = now()
             WHERE device_code_hash = $1
               AND status = 'approved'
               AND expires_at > now()",
        )
        .bind(&hash)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
        if redeemed.rows_affected() == 0 {
            return Ok(Json(DeviceLoginPollResponse {
                status: "expired".to_string(),
                interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
                expires_in: 0,
                error: Some("device login expired".to_string()),
                auth: None,
            }));
        }

        let user_id = approved_user_id.ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "approved device login is missing user"})),
        ))?;
        let org_id = approved_org_id.ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "approved device login is missing organization"})),
        ))?;
        let token = issue_session_token(&state.hmac_key, user_id).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
        let org_name = fetch_org_name(&state.db, org_id).await?;
        return Ok(Json(DeviceLoginPollResponse {
            status,
            interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
            expires_in: seconds_until(expires_at),
            error: None,
            auth: Some(AuthResponse {
                user_id,
                org_id,
                org_name,
                token,
            }),
        }));
    }

    Ok(Json(DeviceLoginPollResponse {
        status: status.clone(),
        interval: DEVICE_LOGIN_POLL_INTERVAL_SECONDS,
        expires_in: seconds_until(expires_at),
        error: Some(match status.as_str() {
            "denied" => "device login denied".to_string(),
            "expired" => "device login expired".to_string(),
            _ => "device login is not pending".to_string(),
        }),
        auth: None,
    }))
}

async fn resolve_approval_org(
    state: &AppState,
    user_id: Uuid,
    org_id: Option<Uuid>,
    org_name: Option<&str>,
) -> Result<(Uuid, String), (StatusCode, Json<serde_json::Value>)> {
    if let Some(org_id) = org_id {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT o.id, o.name
             FROM organizations o
             JOIN memberships m ON m.org_id = o.id
             WHERE o.id = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
        return row.ok_or((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "not a member of organization"})),
        ));
    }

    if let Some(org_name) = org_name.filter(|name| !name.trim().is_empty()) {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT o.id, o.name
             FROM organizations o
             JOIN memberships m ON m.org_id = o.id
             WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
        )
        .bind(org_name)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
        return row.ok_or((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "not a member of organization"})),
        ));
    }

    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT o.id, o.name
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1 AND o.is_personal = true AND m.removed_at IS NULL
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;
    row.ok_or((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": "user has no personal organization"})),
    ))
}

/// POST /auth/device/approve
pub async fn approve_device_login(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<DeviceLoginApproveRequest>,
) -> Result<Json<DeviceLoginApproveResponse>, (StatusCode, Json<serde_json::Value>)> {
    let normalized_user_code = normalize_user_code(&body.user_code);
    if normalized_user_code.len() != 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "user_code must contain 8 letters/digits"})),
        ));
    }
    let hash = code_hash(&normalized_user_code);

    let row: Option<(String, DateTime<Utc>, Option<String>)> = sqlx::query_as(
        "SELECT status, expires_at, requested_org_name
         FROM device_login_sessions
         WHERE user_code_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let Some((status, expires_at, requested_org_name)) = row else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_code"})),
        ));
    };
    if status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("device login is already {status}")})),
        ));
    }
    if Utc::now() >= expires_at {
        let _ = sqlx::query(
            "UPDATE device_login_sessions
             SET status = 'expired'
             WHERE user_code_hash = $1 AND status = 'pending'",
        )
        .bind(&hash)
        .execute(&state.db)
        .await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "device login expired"})),
        ));
    }

    if !body.approve {
        sqlx::query(
            "UPDATE device_login_sessions
             SET status = 'denied', denied_at = now()
             WHERE user_code_hash = $1 AND status = 'pending'",
        )
        .bind(&hash)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
        return Ok(Json(DeviceLoginApproveResponse {
            status: "denied".to_string(),
            org_id: None,
            org_name: None,
        }));
    }

    let (org_id, org_name) = resolve_approval_org(
        &state,
        auth.user_id,
        body.org_id,
        body.org_name.as_deref().or(requested_org_name.as_deref()),
    )
    .await?;

    sqlx::query(
        "UPDATE device_login_sessions
         SET status = 'approved',
             approved_user_id = $2,
             approved_org_id = $3,
             approved_at = now()
         WHERE user_code_hash = $1 AND status = 'pending'",
    )
    .bind(&hash)
    .bind(auth.user_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok(Json(DeviceLoginApproveResponse {
        status: "approved".to_string(),
        org_id: Some(org_id),
        org_name: Some(org_name),
    }))
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub provider: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub nostr_event: Option<String>,
}

/// POST /auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    match body.provider.as_str() {
        "email" => {
            let email_addr = body.email.as_deref().unwrap_or("");
            let password = body.password.as_deref().unwrap_or("");
            let identity = email::login(&state.db, email_addr, password)
                .await
                .map_err(|e| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                })?;

            let user_id: Uuid = sqlx::query_scalar(
                "SELECT user_id FROM user_identities WHERE provider = 'email' AND identifier = $1",
            )
            .bind(&identity.identifier)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;

            let org_id: Uuid = sqlx::query_scalar(
                "SELECT o.id FROM organizations o
                 JOIN memberships m ON m.org_id = o.id
                 WHERE m.user_id = $1 AND o.is_personal = true LIMIT 1",
            )
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;

            let token = issue_session_token(&state.hmac_key, user_id).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let org_name = fetch_org_name(&state.db, org_id).await?;

            Ok(Json(AuthResponse {
                user_id,
                org_id,
                org_name,
                token,
            }))
        }
        "nostr" => {
            let event_json = body.nostr_event.as_deref().ok_or((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "nostr_event is required"})),
            ))?;

            let url = format!("{}/auth/login", state.api_url);
            let identity = nostr::verify_nip98_event(event_json, &url, "POST").map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let (user_id, org_id, _) =
                nostr::signup_or_login(&state.db, &identity)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": e.to_string()})),
                        )
                    })?;

            let token = issue_session_token(&state.hmac_key, user_id).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?;

            let org_name = fetch_org_name(&state.db, org_id).await?;

            Ok(Json(AuthResponse {
                user_id,
                org_id,
                org_name,
                token,
            }))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("unsupported provider: {}", body.provider)})),
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub raw_key: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// POST /auth/api-keys
pub async fn create_api_key_route(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_requested_api_key_scopes(&auth, &body.scopes)?;

    let created = api_key::create_api_key(
        &state.db,
        auth.org_id,
        auth.user_id,
        &body.name,
        &body.scopes,
        body.expires_at,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyResponse {
            id: created.id,
            raw_key: created.raw_key,
            name: created.name,
            scopes: created.scopes,
        }),
    ))
}

/// DELETE /auth/api-keys/{id}
pub async fn revoke_api_key_route(
    auth: AuthContext,
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_requested_api_key_scopes(&auth, &[])?;

    let revoked = api_key::revoke_api_key(&state.db, key_id, auth.org_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "API key not found"})),
        ))
    }
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use crate::models::Role;
    use axum::extract::State;

    #[tokio::test]
    async fn create_api_key_rejects_member_before_database_access() {
        let err = create_api_key_route(
            crate::test_support::auth_context(Role::Member, &[]),
            State(crate::test_support::lazy_state()),
            Json(CreateApiKeyRequest {
                name: "deploy".to_string(),
                scopes: vec!["apps:write".to_string()],
                expires_at: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_api_key_rejects_scope_escalation_before_database_access() {
        let err = create_api_key_route(
            crate::test_support::auth_context(Role::Admin, &["org:admin", "apps:read"]),
            State(crate::test_support::lazy_state()),
            Json(CreateApiKeyRequest {
                name: "deploy".to_string(),
                scopes: vec!["apps:write".to_string()],
                expires_at: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
