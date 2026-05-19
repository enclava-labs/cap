use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
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

            // Get user_id from identity
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
