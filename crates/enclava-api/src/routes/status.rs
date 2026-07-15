//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use enclava_engine::apply::watch::{pod_label_selector, pod_runtime_failure_message};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::ListParams;
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::App;
use crate::state::AppState;

const DEPLOYMENT_ID_LABEL: &str = "enclava.dev/deployment-id";
const TEE_STATUS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveObservationState {
    Fresh,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveObservationReason {
    NotObserved,
    KubernetesUnavailable,
    PodNotFound,
    PodEvidenceIncomplete,
    TeeUnavailable,
    TeeMalformed,
    TeeEvidenceIncomplete,
    EvidenceMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveObservation {
    pub state: LiveObservationState,
    pub observed_at: DateTime<Utc>,
    pub deployment_id: Option<Uuid>,
    pub reason: Option<LiveObservationReason>,
}

impl LiveObservation {
    pub(crate) fn not_observed() -> Self {
        Self {
            state: LiveObservationState::Partial,
            observed_at: Utc::now(),
            deployment_id: None,
            reason: Some(LiveObservationReason::NotObserved),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AppStatusResponse {
    pub app_name: String,
    /// Effective current status. A cached database `running` value is never
    /// returned when the live observation is partial or unavailable.
    pub status: String,
    /// CAP's persisted lifecycle value, kept separate from live health.
    pub recorded_status: String,
    pub domain: String,
    pub unlock_mode: String,
    pub pod_phase: Option<String>,
    pub pod_status: Option<String>,
    pub tee_status: Option<String>,
    pub storage_status: Option<String>,
    pub observation: LiveObservation,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PodEvidence {
    found: bool,
    phase: Option<String>,
    deployment_id: Option<Uuid>,
    deployment_id_malformed: bool,
    runtime_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KubernetesEvidence {
    Available(PodEvidence),
    Unavailable,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TeeEvidenceFields {
    pod_status: Option<String>,
    tee_status: Option<String>,
    storage_status: Option<String>,
    live_state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TeeEvidence {
    Available(TeeEvidenceFields),
    Unavailable,
    Malformed,
}

#[derive(Clone, Debug)]
pub(crate) struct ObservedAppStatus {
    pub observation: LiveObservation,
    pod_phase: Option<String>,
    pod_status: Option<String>,
    tee_status: Option<String>,
    storage_status: Option<String>,
    live_state: Option<String>,
    runtime_failure: bool,
}

impl ObservedAppStatus {
    pub(crate) fn effective_status(&self, recorded_status: &str) -> String {
        effective_app_status(
            recorded_status,
            self.observation.state,
            self.live_state.as_deref(),
            self.runtime_failure,
        )
    }

    pub(crate) fn runtime_failed(&self) -> bool {
        self.runtime_failure
    }
}

/// GET /apps/{name}/status -- live status (pod, TEE, unlock).
pub async fn app_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<AppStatusResponse>, (StatusCode, Json<Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "app not found"})),
        ))?;

    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    let recorded_status = format!("{:?}", app.status).to_lowercase();
    let observed = observe_app_status(&state, &app).await;
    let status = observed.effective_status(&recorded_status);

    Ok(Json(AppStatusResponse {
        app_name: app.name,
        status,
        recorded_status,
        domain: domain.to_string(),
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        pod_phase: observed.pod_phase,
        pod_status: observed.pod_status,
        tee_status: observed.tee_status,
        storage_status: observed.storage_status,
        observation: observed.observation,
    }))
}

pub(crate) async fn observe_app_status(state: &AppState, app: &App) -> ObservedAppStatus {
    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    observe_app_status_fields(
        state,
        &app.namespace,
        &app.name,
        domain,
        app.tee_domain.as_deref(),
    )
    .await
}

pub(crate) async fn observe_app_status_fields(
    state: &AppState,
    namespace: &str,
    app_name: &str,
    domain: &str,
    tee_domain: Option<&str>,
) -> ObservedAppStatus {
    let tee_status_url = confidential_status_url(domain, tee_domain);
    let (kubernetes, tee) = tokio::join!(
        probe_kubernetes(namespace, app_name),
        probe_tee(state, &tee_status_url)
    );
    classify_live_observation(kubernetes, tee, Utc::now())
}

async fn probe_kubernetes(namespace: &str, app_name: &str) -> KubernetesEvidence {
    let Ok(client) = kube::Client::try_default().await else {
        return KubernetesEvidence::Unavailable;
    };
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let Ok(list) = pods
        .list(&ListParams::default().labels(&pod_label_selector(app_name)))
        .await
    else {
        return KubernetesEvidence::Unavailable;
    };
    let active = list
        .items
        .iter()
        .filter(|pod| pod.metadata.deletion_timestamp.is_none())
        .collect::<Vec<_>>();
    let runtime_failure = active
        .iter()
        .any(|pod| pod_runtime_failure_message(pod).is_some());
    if active.len() != 1 {
        return KubernetesEvidence::Available(PodEvidence {
            found: !active.is_empty(),
            runtime_failure,
            ..PodEvidence::default()
        });
    }
    let pod = active[0];
    let phase = pod.status.as_ref().and_then(|status| status.phase.clone());
    let deployment_id_label = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(DEPLOYMENT_ID_LABEL));
    let (deployment_id, deployment_id_malformed) = match deployment_id_label {
        Some(value) => match Uuid::parse_str(value) {
            Ok(deployment_id) => (Some(deployment_id), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };
    KubernetesEvidence::Available(PodEvidence {
        found: true,
        phase,
        deployment_id,
        deployment_id_malformed,
        runtime_failure,
    })
}

/// Compatibility helper for the existing operator inventory. Errors remain
/// unavailable to callers; live status uses `probe_kubernetes` so it can
/// distinguish an unavailable API from an observed absence.
pub async fn live_pod_failure_message(namespace: &str, app_name: &str) -> Option<String> {
    let client = kube::Client::try_default().await.ok()?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let list = pods
        .list(&ListParams::default().labels(&pod_label_selector(app_name)))
        .await
        .ok()?;
    list.items.iter().find_map(pod_runtime_failure_message)
}

async fn probe_tee(state: &AppState, tee_status_url: &str) -> TeeEvidence {
    let Ok(response) = state
        .tee_http_client
        .get(tee_status_url)
        .timeout(TEE_STATUS_PROBE_TIMEOUT)
        .send()
        .await
    else {
        return TeeEvidence::Unavailable;
    };
    if !response.status().is_success() {
        return TeeEvidence::Unavailable;
    }
    match response.json::<Value>().await {
        Ok(body) if body.is_object() => TeeEvidence::Available(tee_evidence_fields(&body)),
        Ok(_) | Err(_) => TeeEvidence::Malformed,
    }
}

fn tee_evidence_fields(body: &Value) -> TeeEvidenceFields {
    TeeEvidenceFields {
        pod_status: body
            .get("pod_status")
            .and_then(Value::as_str)
            .map(str::to_string),
        tee_status: body
            .get("tee_status")
            .and_then(Value::as_str)
            .map(str::to_string),
        storage_status: body
            .get("storage_status")
            .and_then(Value::as_str)
            .map(str::to_string),
        live_state: body
            .get("unlock_state")
            .or_else(|| body.get("state"))
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn classify_live_observation(
    kubernetes: KubernetesEvidence,
    tee: TeeEvidence,
    observed_at: DateTime<Utc>,
) -> ObservedAppStatus {
    let KubernetesEvidence::Available(pod) = kubernetes else {
        return incomplete_observation(
            LiveObservationState::Unavailable,
            LiveObservationReason::KubernetesUnavailable,
            observed_at,
            None,
            None,
            None,
            None,
            None,
            false,
        );
    };
    if !pod.found {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::PodNotFound,
            observed_at,
            None,
            None,
            None,
            None,
            None,
            false,
        );
    }
    if pod.phase.is_none() {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::PodEvidenceIncomplete,
            observed_at,
            pod.deployment_id,
            pod.phase,
            None,
            None,
            None,
            pod.runtime_failure,
        );
    }
    if !pod
        .phase
        .as_deref()
        .is_some_and(|phase| phase.eq_ignore_ascii_case("running"))
    {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::PodEvidenceIncomplete,
            observed_at,
            pod.deployment_id,
            pod.phase,
            None,
            None,
            None,
            pod.runtime_failure,
        );
    }
    let fields = match tee {
        TeeEvidence::Unavailable => {
            return incomplete_observation(
                LiveObservationState::Partial,
                LiveObservationReason::TeeUnavailable,
                observed_at,
                pod.deployment_id,
                pod.phase,
                None,
                None,
                None,
                pod.runtime_failure,
            );
        }
        TeeEvidence::Malformed => {
            return incomplete_observation(
                LiveObservationState::Partial,
                LiveObservationReason::TeeMalformed,
                observed_at,
                pod.deployment_id,
                pod.phase,
                None,
                None,
                None,
                pod.runtime_failure,
            );
        }
        TeeEvidence::Available(fields) => fields,
    };
    if fields.live_state.is_none() {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::TeeEvidenceIncomplete,
            observed_at,
            pod.deployment_id,
            pod.phase,
            fields.pod_status,
            fields.tee_status,
            fields.storage_status,
            pod.runtime_failure,
        );
    }
    if fields.pod_status.as_deref().is_some_and(|status| {
        !pod.phase
            .as_deref()
            .is_some_and(|phase| status.eq_ignore_ascii_case(phase))
    }) {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::EvidenceMismatch,
            observed_at,
            pod.deployment_id,
            pod.phase,
            fields.pod_status,
            fields.tee_status,
            fields.storage_status,
            pod.runtime_failure,
        );
    }
    if pod.deployment_id_malformed {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::PodEvidenceIncomplete,
            observed_at,
            None,
            pod.phase,
            fields.pod_status,
            fields.tee_status,
            fields.storage_status,
            pod.runtime_failure,
        );
    }
    if pod.deployment_id.is_none() {
        // Pods created before deployment identity was added to the pod
        // template can still provide current, complete TEE health. Preserve
        // that live health while explicitly marking identity evidence as
        // partial; consumers that require exact deployment identity continue
        // to fail closed until the workload is rolled forward.
        return ObservedAppStatus {
            observation: LiveObservation {
                state: LiveObservationState::Partial,
                observed_at,
                deployment_id: None,
                reason: Some(LiveObservationReason::PodEvidenceIncomplete),
            },
            pod_phase: pod.phase,
            pod_status: fields.pod_status,
            tee_status: fields.tee_status,
            storage_status: fields.storage_status,
            live_state: fields.live_state,
            runtime_failure: pod.runtime_failure,
        };
    }
    ObservedAppStatus {
        observation: LiveObservation {
            state: LiveObservationState::Fresh,
            observed_at,
            deployment_id: pod.deployment_id,
            reason: None,
        },
        pod_phase: pod.phase,
        pod_status: fields.pod_status,
        tee_status: fields.tee_status,
        storage_status: fields.storage_status,
        live_state: fields.live_state,
        runtime_failure: pod.runtime_failure,
    }
}

#[allow(clippy::too_many_arguments)]
fn incomplete_observation(
    state: LiveObservationState,
    reason: LiveObservationReason,
    observed_at: DateTime<Utc>,
    deployment_id: Option<Uuid>,
    pod_phase: Option<String>,
    pod_status: Option<String>,
    tee_status: Option<String>,
    storage_status: Option<String>,
    runtime_failure: bool,
) -> ObservedAppStatus {
    ObservedAppStatus {
        observation: LiveObservation {
            state,
            observed_at,
            deployment_id,
            reason: Some(reason),
        },
        pod_phase,
        pod_status,
        tee_status,
        storage_status,
        live_state: None,
        runtime_failure,
    }
}

fn effective_app_status(
    recorded_status: &str,
    observation_state: LiveObservationState,
    live_state: Option<&str>,
    runtime_failure: bool,
) -> String {
    if runtime_failure {
        return "failed".to_string();
    }
    if !matches!(recorded_status, "running" | "healthy") {
        return recorded_status.to_string();
    }
    match observation_state {
        LiveObservationState::Unavailable => "unavailable".to_string(),
        LiveObservationState::Partial if recorded_status == "running" => match live_state {
            Some("unlocked") => "running".to_string(),
            Some("locked") => "locked".to_string(),
            _ => "partial".to_string(),
        },
        LiveObservationState::Partial => "partial".to_string(),
        LiveObservationState::Fresh if recorded_status == "running" => match live_state {
            Some("unlocked") => "running".to_string(),
            Some("locked") => "locked".to_string(),
            _ => recorded_status.to_string(),
        },
        LiveObservationState::Fresh => recorded_status.to_string(),
    }
}

fn confidential_status_url(domain: &str, tee_domain: Option<&str>) -> String {
    let confidential_domain = tee_domain.unwrap_or(domain);
    format!("https://{confidential_domain}/.well-known/confidential/status")
}

/// GET /apps/{name}/logs -- proxied container logs.
pub async fn app_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "app not found"})),
        ))?;

    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "code": "encrypted_logs_required",
            "error": "encrypted_logs_required",
            "message": format!(
                "Tenant-controlled encrypted log streaming is required before workload logs can leave the confidential boundary for {}; use `enclava status` for current state.",
                app.name
            ),
            "status": format!("{:?}", app.status).to_lowercase(),
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        KubernetesEvidence, LiveObservationReason, LiveObservationState, PodEvidence, TeeEvidence,
        classify_live_observation, confidential_status_url, effective_app_status,
        tee_evidence_fields,
    };

    fn observed_at() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0)
            .single()
            .expect("timestamp")
    }

    fn complete_pod(deployment_id: Uuid) -> KubernetesEvidence {
        KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            deployment_id: Some(deployment_id),
            deployment_id_malformed: false,
            runtime_failure: false,
        })
    }

    fn complete_tee() -> TeeEvidence {
        TeeEvidence::Available(tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "ready",
            "storage_status": "unlocked",
            "state": "unlocked"
        })))
    }

    #[test]
    fn complete_live_evidence_is_fresh_and_identifies_exact_deployment() {
        let deployment_id = Uuid::new_v4();
        let observed =
            classify_live_observation(complete_pod(deployment_id), complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Fresh);
        assert_eq!(observed.observation.deployment_id, Some(deployment_id));
        assert_eq!(observed.observation.observed_at, observed_at());
        assert_eq!(observed.observation.reason, None);
    }

    #[test]
    fn kubernetes_failure_is_unavailable_without_raw_error_detail() {
        let observed = classify_live_observation(
            KubernetesEvidence::Unavailable,
            complete_tee(),
            observed_at(),
        );

        assert_eq!(
            observed.observation.state,
            LiveObservationState::Unavailable
        );
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::KubernetesUnavailable)
        );
        let json = serde_json::to_value(&observed.observation).expect("serialize observation");
        assert_eq!(json["reason"], "kubernetes_unavailable");
        assert!(json.to_string().len() < 256);
    }

    #[test]
    fn malformed_tee_json_is_partial() {
        let observed = classify_live_observation(
            complete_pod(Uuid::new_v4()),
            TeeEvidence::Malformed,
            observed_at(),
        );

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::TeeMalformed)
        );
    }

    #[test]
    fn missing_tee_pod_status_is_not_synthesized_as_running() {
        let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
            "tee_status": "ready",
            "storage_status": "unlocked",
            "state": "unlocked"
        })));
        let observed = classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Fresh);
        assert_eq!(observed.pod_status, None);
        assert_eq!(observed.observation.reason, None);
    }

    #[test]
    fn unavailable_observation_never_falls_back_to_recorded_running() {
        assert_eq!(
            effective_app_status("running", LiveObservationState::Unavailable, None, false),
            "unavailable"
        );
        assert_eq!(
            effective_app_status("running", LiveObservationState::Partial, None, false),
            "partial"
        );
    }

    #[test]
    fn fresh_unlocked_observation_keeps_running_app_running() {
        assert_eq!(
            effective_app_status(
                "running",
                LiveObservationState::Fresh,
                Some("unlocked"),
                false
            ),
            "running"
        );
    }

    #[test]
    fn complete_legacy_pod_health_stays_live_without_claiming_identity() {
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            deployment_id: None,
            deployment_id_malformed: false,
            runtime_failure: false,
        });
        let observed = classify_live_observation(pod, complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::PodEvidenceIncomplete)
        );
        assert_eq!(observed.observation.deployment_id, None);
        assert_eq!(observed.effective_status("running"), "running");
    }

    #[test]
    fn incomplete_evidence_preserves_in_progress_lifecycle_state() {
        assert_eq!(
            effective_app_status("pending", LiveObservationState::Unavailable, None, false),
            "pending"
        );
        assert_eq!(
            effective_app_status("applying", LiveObservationState::Partial, None, false),
            "applying"
        );
        assert_eq!(
            effective_app_status("watching", LiveObservationState::Unavailable, None, false),
            "watching"
        );
    }

    #[test]
    fn current_unlock_state_field_is_live_tee_evidence() {
        let fields = tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "ready",
            "storage_status": "unlocked",
            "unlock_state": "unlocked"
        }));
        assert_eq!(fields.live_state.as_deref(), Some("unlocked"));
    }

    #[test]
    fn non_running_pod_cannot_be_fresh_from_unlocked_tee_evidence() {
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Pending".to_string()),
            deployment_id: Some(Uuid::new_v4()),
            deployment_id_malformed: false,
            runtime_failure: false,
        });
        let observed = classify_live_observation(pod, complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::PodEvidenceIncomplete)
        );
        assert_eq!(observed.effective_status("running"), "partial");
    }

    #[test]
    fn malformed_deployment_identity_cannot_use_legacy_compatibility() {
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            deployment_id: None,
            deployment_id_malformed: true,
            runtime_failure: false,
        });
        let observed = classify_live_observation(pod, complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(observed.effective_status("running"), "partial");
    }

    #[test]
    fn healthy_deployment_fails_closed_without_fresh_evidence() {
        assert_eq!(
            effective_app_status("healthy", LiveObservationState::Unavailable, None, false),
            "unavailable"
        );
        assert_eq!(
            effective_app_status("healthy", LiveObservationState::Partial, None, false),
            "partial"
        );
        assert_eq!(
            effective_app_status(
                "healthy",
                LiveObservationState::Fresh,
                Some("unlocked"),
                false
            ),
            "healthy"
        );
    }

    #[test]
    fn ambiguous_pods_with_runtime_failure_fail_closed() {
        let observed = classify_live_observation(
            KubernetesEvidence::Available(PodEvidence {
                found: true,
                phase: None,
                deployment_id: None,
                deployment_id_malformed: false,
                runtime_failure: true,
            }),
            complete_tee(),
            observed_at(),
        );

        assert_eq!(observed.effective_status("running"), "failed");
    }

    #[test]
    fn recorded_failure_remains_safe_when_live_evidence_is_unavailable() {
        assert_eq!(
            effective_app_status("failed", LiveObservationState::Unavailable, None, false),
            "failed"
        );
    }

    #[test]
    fn confidential_status_probe_uses_tee_domain() {
        assert_eq!(
            confidential_status_url("app.example.test", Some("app.tee.example.test")),
            "https://app.tee.example.test/.well-known/confidential/status"
        );
    }
}
