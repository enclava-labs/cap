//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::App;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AppStatusResponse {
    pub app_name: String,
    pub status: String,
    pub domain: String,
    pub unlock_mode: String,
    pub pod_phase: Option<String>,
    pub pod_status: Option<String>,
    pub tee_status: Option<String>,
    pub storage_status: Option<String>,
}

/// GET /apps/{name}/status -- live status (pod, TEE, unlock).
pub async fn app_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<AppStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    let tee_status_url = format!("https://{}/.well-known/confidential/status", domain);

    let (pod_status, tee_status, storage_status, live_state) =
        match state.tee_http_client.get(&tee_status_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let live_state = body.get("state").and_then(|v| v.as_str()).map(String::from);
                    (
                        body.get("pod_status")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| Some("Running".to_string())),
                        body.get("tee_status")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| live_state.clone()),
                        body.get("storage_status")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| live_state.clone()),
                        live_state,
                    )
                } else {
                    (None, None, None, None)
                }
            }
            _ => (None, None, None, None),
        };

    let db_status = format!("{:?}", app.status).to_lowercase();
    let effective_status = match live_state.as_deref() {
        Some("unlocked") => "running".to_string(),
        Some("locked") => "locked".to_string(),
        Some("unclaimed") if db_status == "failed" => "creating".to_string(),
        _ => db_status,
    };

    Ok(Json(AppStatusResponse {
        app_name: app.name,
        status: effective_status,
        domain: domain.to_string(),
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        pod_phase: pod_status.clone(),
        pod_status,
        tee_status,
        storage_status,
    }))
}

#[derive(Debug, Serialize)]
pub struct LogLine {
    pub timestamp: String,
    pub container: String,
    pub message: String,
}

/// GET /apps/{name}/logs -- proxied container logs.
pub async fn app_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<Vec<LogLine>>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let _app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
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

    // TODO: proxy via kube-rs pod log API (Plan 3 integration)
    Ok(Json(vec![]))
}
