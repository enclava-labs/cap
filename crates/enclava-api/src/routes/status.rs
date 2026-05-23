//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
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
    let tee_status_url = confidential_status_url(domain, app.tee_domain.as_deref());

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
    let effective_status = effective_app_status(&db_status, live_state.as_deref());

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

fn effective_app_status(db_status: &str, live_state: Option<&str>) -> String {
    match live_state {
        Some("unlocked") if db_status == "running" => "running".to_string(),
        Some("locked") => "locked".to_string(),
        Some("unclaimed") if db_status == "failed" => "creating".to_string(),
        _ => db_status.to_string(),
    }
}

fn confidential_status_url(domain: &str, tee_domain: Option<&str>) -> String {
    let confidential_domain = tee_domain.unwrap_or(domain);
    format!("https://{confidential_domain}/.well-known/confidential/status")
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

    Ok(Json(vec![LogLine {
        timestamp: Utc::now().to_rfc3339(),
        container: "cap".to_string(),
        message: format!(
            "Live log streaming is not connected yet for {}; current app status is {}.",
            app.name,
            format!("{:?}", app.status).to_lowercase()
        ),
    }]))
}

#[cfg(test)]
mod tests {
    use super::{confidential_status_url, effective_app_status};

    #[test]
    fn unlocked_tee_does_not_mark_creating_app_running() {
        assert_eq!(
            effective_app_status("creating", Some("unlocked")),
            "creating"
        );
    }

    #[test]
    fn unlocked_tee_keeps_running_app_running() {
        assert_eq!(effective_app_status("running", Some("unlocked")), "running");
    }

    #[test]
    fn confidential_status_probe_uses_tee_domain() {
        assert_eq!(
            confidential_status_url("app.example.test", Some("app.tee.example.test")),
            "https://app.tee.example.test/.well-known/confidential/status"
        );
    }
}
