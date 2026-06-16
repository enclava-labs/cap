//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::jiff::Timestamp;
use kube::Api;
use kube::api::ListParams;
use serde::Serialize;
use serde_json::json;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::{App, UnlockMode};
use crate::state::AppState;
use enclava_engine::apply::watch::{
    force_delete_stale_terminating_pods, kata_start_error_needs_pod_recreate,
    plan_stale_terminating_pod_force_deletes, plan_unready_running_pod_recreates,
    pod_label_selector, recreate_kata_start_error_pods, recreate_unready_running_pods,
};

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
    pub runtime_recovery: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeRecoveryPodResponse {
    pub pod_name: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct RuntimeRecoveryResponse {
    pub app_name: String,
    pub status: String,
    pub recovered_pods: Vec<RuntimeRecoveryPodResponse>,
    pub unlock_may_be_required: bool,
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
        match fetch_confidential_status(&state, &tee_status_url).await {
            Some(body) => {
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
            }
            None => (None, None, None, None),
        };

    let db_status = format!("{:?}", app.status).to_lowercase();
    let runtime_recovery =
        live_runtime_recovery_reason(&app.namespace, &app.name, live_state.as_deref()).await;
    let effective_status = effective_app_status(
        &db_status,
        live_state.as_deref(),
        runtime_recovery.as_deref(),
    );

    Ok(Json(AppStatusResponse {
        app_name: app.name,
        status: effective_status,
        domain: domain.to_string(),
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        pod_phase: pod_status.clone(),
        pod_status,
        tee_status,
        storage_status,
        runtime_recovery,
    }))
}

async fn live_runtime_recovery_reason(
    namespace: &str,
    app_name: &str,
    live_state: Option<&str>,
) -> Option<String> {
    let client = kube::Client::try_default().await.ok()?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let list = pods
        .list(&ListParams::default().labels(&pod_label_selector(app_name)))
        .await
        .ok()?;

    runtime_recovery_reason_from_pods(&list.items, Timestamp::now(), live_state)
}

fn runtime_recovery_reason_from_pods(
    pods: &[Pod],
    now: Timestamp,
    live_state: Option<&str>,
) -> Option<String> {
    for pod in pods {
        if let Some(reason) = kata_start_error_needs_pod_recreate(&pod) {
            let pod_name = pod.metadata.name.as_deref().unwrap_or("<unknown>");
            return Some(format!("{pod_name}: {reason}"));
        }
    }

    plan_stale_terminating_pod_force_deletes(pods, now)
        .into_iter()
        .next()
        .map(|action| format!("{}: {}", action.pod_name, action.reason))
        .or_else(|| {
            if live_state != Some("unlocked") {
                return None;
            }
            plan_unready_running_pod_recreates(pods, now)
                .into_iter()
                .next()
                .map(|action| format!("{}: {}", action.pod_name, action.reason))
        })
}

/// POST /apps/{name}/runtime/recover -- repair known runtime-level pod failures.
pub async fn recover_runtime(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<RuntimeRecoveryResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

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

    let client = kube::Client::try_default().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "kubernetes client unavailable"})),
        )
    })?;
    let mut recovered = recreate_kata_start_error_pods(client.clone(), &app.namespace, &app.name)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "runtime recovery failed",
                    "message": err.to_string(),
                })),
            )
        })?;
    let stale_terminating_recovered =
        force_delete_stale_terminating_pods(client.clone(), &app.namespace, &app.name)
            .await
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "runtime recovery failed",
                        "message": err.to_string(),
                    })),
                )
            })?;
    recovered.extend(stale_terminating_recovered);
    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    let tee_status_url = confidential_status_url(domain, app.tee_domain.as_deref());
    let live_state = fetch_confidential_status(&state, &tee_status_url)
        .await
        .and_then(|body| {
            body.get("state")
                .and_then(|value| value.as_str())
                .map(String::from)
        });
    if live_state.as_deref() == Some("unlocked") {
        let unready_recovered = recreate_unready_running_pods(client, &app.namespace, &app.name)
            .await
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "runtime recovery failed",
                        "message": err.to_string(),
                    })),
                )
            })?;
        recovered.extend(unready_recovered);
    }
    let status = if recovered.is_empty() {
        "not_needed"
    } else {
        "restarted"
    };

    Ok(Json(RuntimeRecoveryResponse {
        app_name: app.name,
        status: status.to_string(),
        recovered_pods: recovered
            .into_iter()
            .map(|pod| RuntimeRecoveryPodResponse {
                pod_name: pod.pod_name,
                reason: pod.reason,
            })
            .collect(),
        unlock_may_be_required: app.unlock_mode == UnlockMode::Password,
    }))
}

fn effective_app_status(
    db_status: &str,
    live_state: Option<&str>,
    runtime_recovery: Option<&str>,
) -> String {
    if runtime_recovery.is_some() {
        return "runtime_restart_required".to_string();
    }

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

async fn fetch_confidential_status(state: &AppState, url: &str) -> Option<serde_json::Value> {
    let resp = state.tee_http_client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

/// GET /apps/{name}/logs -- proxied container logs.
pub async fn app_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
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

    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "logs_unavailable",
            "message": format!(
                "Live log streaming is not connected yet for {}; use `enclava status` for current state.",
                app.name
            ),
            "status": format!("{:?}", app.status).to_lowercase(),
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::{confidential_status_url, effective_app_status, runtime_recovery_reason_from_pods};
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateRunning, ContainerStatus, Pod, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
    use k8s_openapi::jiff::Timestamp;

    #[test]
    fn unlocked_tee_does_not_mark_creating_app_running() {
        assert_eq!(
            effective_app_status("creating", Some("unlocked"), None),
            "creating"
        );
    }

    #[test]
    fn unlocked_tee_keeps_running_app_running() {
        assert_eq!(
            effective_app_status("running", Some("unlocked"), None),
            "running"
        );
    }

    #[test]
    fn runtime_recovery_overrides_unlocked_tee_status() {
        assert_eq!(
            effective_app_status("running", Some("unlocked"), Some("runtime StartError")),
            "runtime_restart_required"
        );
    }

    #[test]
    fn stale_terminating_pod_requires_runtime_recovery() {
        let deleted_at = Time(
            "2026-06-15T08:00:00Z"
                .parse::<Timestamp>()
                .expect("timestamp parses"),
        );
        let now = "2026-06-15T08:01:00Z"
            .parse::<Timestamp>()
            .expect("timestamp parses");
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("routstr-core-prod-0".to_string()),
                deletion_timestamp: Some(deleted_at),
                deletion_grace_period_seconds: Some(30),
                ..Default::default()
            },
            ..Default::default()
        };

        let reason = runtime_recovery_reason_from_pods(&[pod], now, None)
            .expect("stale terminating pod should require recovery");

        assert!(reason.contains("routstr-core-prod-0"));
        assert!(reason.contains("stale terminating"));
    }

    #[test]
    fn unlocked_unready_web_pod_requires_runtime_recovery() {
        let started_at = Time(
            "2026-06-16T12:23:29Z"
                .parse::<Timestamp>()
                .expect("timestamp parses"),
        );
        let now = "2026-06-16T12:40:00Z"
            .parse::<Timestamp>()
            .expect("timestamp parses");
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("routstr-core-prod-0".to_string()),
                ..Default::default()
            },
            status: Some(PodStatus {
                phase: Some("Running".to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "web".to_string(),
                    ready: false,
                    restart_count: 0,
                    state: Some(ContainerState {
                        running: Some(ContainerStateRunning {
                            started_at: Some(started_at),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let reason = runtime_recovery_reason_from_pods(&[pod], now, Some("unlocked"))
            .expect("unlocked unready pod should require runtime recovery");

        assert!(reason.contains("routstr-core-prod-0"));
        assert!(reason.contains("unready"));
    }

    #[test]
    fn locked_unready_web_pod_does_not_require_runtime_recovery() {
        let started_at = Time(
            "2026-06-16T12:23:29Z"
                .parse::<Timestamp>()
                .expect("timestamp parses"),
        );
        let now = "2026-06-16T12:40:00Z"
            .parse::<Timestamp>()
            .expect("timestamp parses");
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("routstr-core-prod-0".to_string()),
                ..Default::default()
            },
            status: Some(PodStatus {
                phase: Some("Running".to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "web".to_string(),
                    ready: false,
                    restart_count: 0,
                    state: Some(ContainerState {
                        running: Some(ContainerStateRunning {
                            started_at: Some(started_at),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(runtime_recovery_reason_from_pods(&[pod], now, Some("locked")).is_none());
    }

    #[test]
    fn confidential_status_probe_uses_tee_domain() {
        assert_eq!(
            confidential_status_url("app.example.test", Some("app.tee.example.test")),
            "https://app.tee.example.test/.well-known/confidential/status"
        );
    }
}
