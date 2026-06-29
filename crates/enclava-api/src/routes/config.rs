//! Config management routes.
//!
//! The API never sees config values. It issues auth tokens and tracks key names.
//! Values go CLI -> TEE direct.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::auth::jwt::issue_config_token;
use crate::auth::middleware::AuthContext;
use crate::auth::scopes;
use crate::models::App;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ConfigTokenResponse {
    pub token: String,
    pub tee_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_resolve_ip: Option<IpAddr>,
    pub expires_in_seconds: u64,
}

fn config_token_instance_id(app: &App) -> String {
    format!("{}-{}", app.namespace, app.name)
}

fn config_token_tee_url(app: &App) -> Option<String> {
    let domain = app.tee_domain.as_deref()?;
    Some(format!("https://{domain}/.well-known/confidential/config"))
}

/// POST /apps/{name}/config-token -- issue a short-lived JWT for config writes.
pub async fn issue_config_token_route(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<ConfigTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_admin(&auth)?;
    scopes::require_scope(&auth, "config:write")?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let token = issue_config_token(
        &state.signing_key,
        auth.user_id,
        auth.org_id,
        app.id,
        &config_token_instance_id(&app),
        vec!["config:write".to_string()],
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let tee_url = config_token_tee_url(&app).ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "tee domain not configured"})),
        )
    })?;
    let tee_resolve_ip = match crate::edge::resolve_gateway_address(&app.name, &app.namespace).await
    {
        Ok(resolve_ip) => resolve_ip,
        Err(error) => {
            tracing::warn!(
                app = %app.name,
                namespace = %app.namespace,
                error = %error,
                "could not resolve tenant Gateway address for config-token response"
            );
            None
        }
    };

    Ok(Json(ConfigTokenResponse {
        token,
        tee_url,
        tee_resolve_ip,
        expires_in_seconds: 300,
    }))
}

#[derive(Debug, Serialize)]
pub struct ConfigKeyResponse {
    pub key: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// GET /apps/{name}/config -- list key names from metadata sync (no values).
pub async fn list_config_keys(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<Vec<ConfigKeyResponse>>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let keys: Vec<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT key_name, updated_at FROM config_metadata WHERE app_id = $1 ORDER BY key_name",
    )
    .bind(app.id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok(Json(
        keys.into_iter()
            .map(|(key, updated_at)| ConfigKeyResponse { key, updated_at })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ConfigSyncRequest {
    pub key_name: String,
    #[serde(default)]
    pub deleted: bool,
}

pub(crate) async fn sync_config_metadata_for_org(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
    body: &ConfigSyncRequest,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let app: Option<App> = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(org_id)
        .bind(app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    let app = app.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "app not found"})),
    ))?;

    if body.deleted {
        sqlx::query("DELETE FROM config_metadata WHERE app_id = $1 AND key_name = $2")
            .bind(app.id)
            .bind(body.key_name.as_str())
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    } else {
        sqlx::query(
            "INSERT INTO config_metadata (id, app_id, key_name)
             VALUES ($1, $2, $3)
             ON CONFLICT (app_id, key_name) DO UPDATE SET updated_at = now()",
        )
        .bind(Uuid::new_v4())
        .bind(app.id)
        .bind(body.key_name.as_str())
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    }

    Ok(StatusCode::OK)
}

pub(crate) async fn delete_config_metadata_for_org(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
    key_name: &str,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(org_id)
        .bind(app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    sqlx::query("DELETE FROM config_metadata WHERE app_id = $1 AND key_name = $2")
        .bind(app.id)
        .bind(key_name)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /apps/{name}/config/sync -- authenticated metadata sync callback.
pub async fn config_sync(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<ConfigSyncRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_config_metadata_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;
    sync_config_metadata_for_org(&state, auth.org_id, &app_name, &body).await
}

/// DELETE /apps/{name}/config/{key}/meta -- remove key metadata.
pub async fn delete_config_meta(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((app_name, key_name)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_config_metadata_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;
    delete_config_metadata_for_org(&state, auth.org_id, &app_name, &key_name).await
}

#[cfg(test)]
mod tests {
    use super::{ConfigSyncRequest, config_sync, config_token_instance_id, config_token_tee_url};
    use crate::models::{App, AppStatus, Role, UnlockMode};
    use axum::Json;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use uuid::Uuid;

    #[test]
    fn config_token_instance_id_matches_attestation_proxy_owner_instance_id() {
        let app = App {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            name: "demo".to_string(),
            namespace: "cap-a826eb13-demo".to_string(),
            instance_id: "demo".to_string(),
            tenant_id: "a826eb13".to_string(),
            service_account: "cap-demo-sa".to_string(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: "11".repeat(32),
            unlock_mode: UnlockMode::Password,
            domain: "demo.a826eb13.enclava.dev".to_string(),
            tee_domain: Some("demo.a826eb13.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: AppStatus::Running,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        assert_eq!(config_token_instance_id(&app), "cap-a826eb13-demo-demo");
    }

    #[test]
    fn config_token_url_targets_attested_tee_domain_not_app_or_custom_domain() {
        let app = App {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            name: "demo".to_string(),
            namespace: "cap-a826eb13-demo".to_string(),
            instance_id: "demo".to_string(),
            tenant_id: "a826eb13".to_string(),
            service_account: "cap-demo-sa".to_string(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: "11".repeat(32),
            unlock_mode: UnlockMode::Password,
            domain: "demo.a826eb13.enclava.dev".to_string(),
            tee_domain: Some("demo.a826eb13.tee.enclava.dev".to_string()),
            custom_domain: Some("demo.example.com".to_string()),
            status: AppStatus::Running,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        assert_eq!(
            config_token_tee_url(&app),
            Some(
                "https://demo.a826eb13.tee.enclava.dev/.well-known/confidential/config".to_string()
            )
        );
    }

    #[test]
    fn config_token_url_requires_tee_domain() {
        let app = App {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            name: "demo".to_string(),
            namespace: "cap-a826eb13-demo".to_string(),
            instance_id: "demo".to_string(),
            tenant_id: "a826eb13".to_string(),
            service_account: "cap-demo-sa".to_string(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: "11".repeat(32),
            unlock_mode: UnlockMode::Password,
            domain: "demo.a826eb13.enclava.dev".to_string(),
            tee_domain: None,
            custom_domain: Some("demo.example.com".to_string()),
            status: AppStatus::Running,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        assert_eq!(config_token_tee_url(&app), None);
    }

    #[tokio::test]
    async fn config_sync_rejects_unscoped_api_key_before_database_access() {
        let result = config_sync(
            crate::test_support::auth_context(Role::Admin, &["apps:write"]),
            State(crate::test_support::lazy_state()),
            Path("demo".to_string()),
            Json(ConfigSyncRequest {
                key_name: "SECRET".to_string(),
                deleted: false,
            }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("unscoped config sync unexpectedly passed authorization"),
            Err(err) => err,
        };

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
