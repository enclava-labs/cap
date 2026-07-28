//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use enclava_engine::apply::watch::{PodRuntimeFailure, pod_label_selector, pod_runtime_failure};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::ListParams;
use serde::Serialize;
use serde_json::{Value, json};
use std::{future::Future, time::Duration};
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::App;
use crate::state::AppState;

const DEPLOYMENT_ID_LABEL: &str = "enclava.dev/deployment-id";
const KUBERNETES_STATUS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
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
    TeeKbsTokenUnavailable,
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
    ready: bool,
    deployment_id: Option<Uuid>,
    deployment_id_malformed: bool,
    runtime_failure: Option<RuntimeFailureEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeFailureEvidence {
    failure: PodRuntimeFailure,
    deployment_id: Option<Uuid>,
    deployment_id_malformed: bool,
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
    kbs_token_unavailable: bool,
    supplemental_fields_malformed: bool,
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
    runtime_failure: Option<RuntimeFailureEvidence>,
}

impl ObservedAppStatus {
    pub(crate) fn effective_status(&self, recorded_status: &str) -> String {
        effective_app_status(
            recorded_status,
            self.observation.state,
            self.live_state.as_deref(),
            self.runtime_failure.is_some(),
        )
    }

    pub(crate) fn is_fresh_locked_for_deployment(&self, deployment_id: Uuid) -> bool {
        self.observation.state == LiveObservationState::Fresh
            && self.observation.deployment_id == Some(deployment_id)
            && self
                .pod_phase
                .as_deref()
                .is_some_and(|phase| phase.eq_ignore_ascii_case("running"))
            && self
                .live_state
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("locked"))
            && self.runtime_failure.is_none()
    }

    pub(crate) fn runtime_failure_public_message(&self) -> Option<String> {
        self.runtime_failure
            .as_ref()
            .map(|failure| failure.failure.public_message())
    }

    pub(crate) fn runtime_failure_matches_deployment(&self, expected_deployment_id: Uuid) -> bool {
        self.runtime_failure.as_ref().is_some_and(|failure| {
            !failure.deployment_id_malformed
                && failure.deployment_id == Some(expected_deployment_id)
        })
    }

    pub(crate) fn runtime_failure_applies_to_latest(&self, expected_deployment_id: Uuid) -> bool {
        self.runtime_failure.as_ref().is_some_and(|failure| {
            !failure.deployment_id_malformed
                && failure
                    .deployment_id
                    .is_none_or(|deployment_id| deployment_id == expected_deployment_id)
        })
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
    observe_app_status_for_deployment(state, app, None).await
}

pub(crate) async fn observe_app_status_for_deployment(
    state: &AppState,
    app: &App,
    expected_deployment_id: Option<Uuid>,
) -> ObservedAppStatus {
    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    observe_app_status_fields_for_deployment(
        state,
        &app.namespace,
        &app.name,
        domain,
        app.tee_domain.as_deref(),
        expected_deployment_id,
    )
    .await
}

pub(crate) async fn observe_app_status_fields_for_deployment(
    state: &AppState,
    namespace: &str,
    app_name: &str,
    domain: &str,
    tee_domain: Option<&str>,
    expected_deployment_id: Option<Uuid>,
) -> ObservedAppStatus {
    let tee_status_url = confidential_status_url(domain, tee_domain);
    let (kubernetes, tee) = tokio::join!(
        probe_kubernetes(namespace, app_name, expected_deployment_id),
        probe_tee(state, &tee_status_url)
    );
    classify_live_observation_for_deployment(kubernetes, tee, Utc::now(), expected_deployment_id)
}

async fn probe_kubernetes(
    namespace: &str,
    app_name: &str,
    expected_deployment_id: Option<Uuid>,
) -> KubernetesEvidence {
    bounded_kubernetes_probe(
        probe_kubernetes_unbounded(namespace, app_name, expected_deployment_id),
        KUBERNETES_STATUS_PROBE_TIMEOUT,
    )
    .await
}

async fn bounded_kubernetes_probe<F>(probe: F, deadline: Duration) -> KubernetesEvidence
where
    F: Future<Output = KubernetesEvidence>,
{
    tokio::time::timeout(deadline, probe)
        .await
        .unwrap_or(KubernetesEvidence::Unavailable)
}

async fn probe_kubernetes_unbounded(
    namespace: &str,
    app_name: &str,
    expected_deployment_id: Option<Uuid>,
) -> KubernetesEvidence {
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
    let legacy_failure_eligible = active.iter().all(|pod| {
        let (deployment_id, deployment_id_malformed) = pod_deployment_identity(pod);
        deployment_id.is_none() && !deployment_id_malformed
    });
    let runtime_failure = select_runtime_failure(
        active
            .iter()
            .filter_map(|pod| runtime_failure_evidence(pod))
            .collect(),
        expected_deployment_id,
        legacy_failure_eligible,
    );
    if active.len() != 1 {
        return KubernetesEvidence::Available(PodEvidence {
            found: !active.is_empty(),
            deployment_id: runtime_failure
                .as_ref()
                .and_then(|failure| failure.deployment_id),
            deployment_id_malformed: runtime_failure
                .as_ref()
                .is_some_and(|failure| failure.deployment_id_malformed),
            runtime_failure,
            ..PodEvidence::default()
        });
    }
    let pod = active[0];
    let phase = pod.status.as_ref().and_then(|status| status.phase.clone());
    let ready = pod_is_ready(pod);
    let (deployment_id, deployment_id_malformed) = pod_deployment_identity(pod);
    KubernetesEvidence::Available(PodEvidence {
        found: true,
        phase,
        ready,
        deployment_id,
        deployment_id_malformed,
        runtime_failure,
    })
}

fn pod_is_ready(pod: &Pod) -> bool {
    let Some(status) = pod.status.as_ref() else {
        return false;
    };
    let pod_ready = status.conditions.as_ref().is_some_and(|conditions| {
        conditions
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True")
    });
    let containers_ready = status
        .container_statuses
        .as_ref()
        .is_some_and(|containers| {
            !containers.is_empty() && containers.iter().all(|container| container.ready)
        });
    pod_ready && containers_ready
}

fn pod_deployment_identity(pod: &Pod) -> (Option<Uuid>, bool) {
    let deployment_id_label = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(DEPLOYMENT_ID_LABEL));
    match deployment_id_label {
        Some(value) => match Uuid::parse_str(value) {
            Ok(deployment_id) => (Some(deployment_id), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    }
}

fn runtime_failure_evidence(pod: &Pod) -> Option<RuntimeFailureEvidence> {
    let failure = pod_runtime_failure(pod)?;
    let (deployment_id, deployment_id_malformed) = pod_deployment_identity(pod);
    Some(RuntimeFailureEvidence {
        failure,
        deployment_id,
        deployment_id_malformed,
    })
}

fn select_runtime_failure(
    failures: Vec<RuntimeFailureEvidence>,
    expected_deployment_id: Option<Uuid>,
    legacy_failure_eligible: bool,
) -> Option<RuntimeFailureEvidence> {
    let Some(expected_deployment_id) = expected_deployment_id else {
        return failures.into_iter().next();
    };
    let selected = failures
        .iter()
        .position(|failure| failure.deployment_id == Some(expected_deployment_id))
        .or_else(|| {
            if legacy_failure_eligible {
                failures.iter().position(|failure| {
                    failure.deployment_id.is_none() && !failure.deployment_id_malformed
                })
            } else {
                None
            }
        });
    selected.and_then(|index| failures.into_iter().nth(index))
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
    let supplemental_fields_malformed =
        ["pod_status", "tee_status", "storage_status", "claims_error"]
            .into_iter()
            .any(|field| {
                body.get(field)
                    .is_some_and(|value| !value.is_null() && !value.is_string())
            });
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
            .map(str::to_ascii_lowercase),
        kbs_token_unavailable: body
            .get("claims_error")
            .and_then(Value::as_str)
            .is_some_and(|error| !error.trim().is_empty()),
        supplemental_fields_malformed,
    }
}

#[cfg(test)]
fn classify_live_observation(
    kubernetes: KubernetesEvidence,
    tee: TeeEvidence,
    observed_at: DateTime<Utc>,
) -> ObservedAppStatus {
    classify_live_observation_for_deployment(kubernetes, tee, observed_at, None)
}

fn classify_live_observation_for_deployment(
    kubernetes: KubernetesEvidence,
    tee: TeeEvidence,
    observed_at: DateTime<Utc>,
    expected_deployment_id: Option<Uuid>,
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
            None,
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
            None,
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
    if expected_deployment_id.is_some()
        && pod.deployment_id.is_some()
        && pod.deployment_id != expected_deployment_id
    {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::EvidenceMismatch,
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
    if fields.kbs_token_unavailable {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::TeeKbsTokenUnavailable,
            observed_at,
            pod.deployment_id,
            pod.phase,
            fields.pod_status,
            fields.tee_status,
            fields.storage_status,
            pod.runtime_failure,
        );
    }
    if !fields.live_state.as_deref().is_some_and(|state| {
        state.eq_ignore_ascii_case("locked") || state.eq_ignore_ascii_case("unlocked")
    }) {
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
    let tee_is_ready = fields
        .tee_status
        .as_deref()
        .is_none_or(|status| status.eq_ignore_ascii_case("ready"));
    let storage_matches_live_state = fields.storage_status.as_deref().is_none_or(|status| {
        fields
            .live_state
            .as_deref()
            .is_some_and(|state| status.eq_ignore_ascii_case(state))
    });
    if fields.supplemental_fields_malformed || !tee_is_ready || !storage_matches_live_state {
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
    if fields
        .live_state
        .as_deref()
        .is_some_and(|state| state.eq_ignore_ascii_case("unlocked"))
        && !pod.ready
    {
        return incomplete_observation(
            LiveObservationState::Partial,
            LiveObservationReason::PodEvidenceIncomplete,
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
    runtime_failure: Option<RuntimeFailureEvidence>,
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
    if recorded_status != "running" {
        return recorded_status.to_string();
    }
    match observation_state {
        LiveObservationState::Unavailable => "unavailable".to_string(),
        LiveObservationState::Partial => match live_state {
            Some("unlocked") => "running".to_string(),
            Some("locked") => "locked".to_string(),
            _ => "partial".to_string(),
        },
        LiveObservationState::Fresh => match live_state {
            Some("unlocked") => "running".to_string(),
            Some("locked") => "locked".to_string(),
            _ => recorded_status.to_string(),
        },
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
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, Pod,
        PodCondition, PodStatus,
    };
    use kube::api::ObjectMeta;
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        KubernetesEvidence, LiveObservationReason, LiveObservationState, PodEvidence,
        RuntimeFailureEvidence, TeeEvidence, bounded_kubernetes_probe, classify_live_observation,
        classify_live_observation_for_deployment, confidential_status_url, effective_app_status,
        pod_is_ready, runtime_failure_evidence, select_runtime_failure, tee_evidence_fields,
    };

    const WAITING_SECRET: &str = "waiting-message-secret=tenant-api-key";
    const TERMINATED_SECRET: &str = "terminated-message-secret=tenant-private-key";

    fn observed_at() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0)
            .single()
            .expect("timestamp")
    }

    fn complete_pod(deployment_id: Uuid) -> KubernetesEvidence {
        KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            ready: true,
            deployment_id: Some(deployment_id),
            deployment_id_malformed: false,
            runtime_failure: None,
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

    fn runtime_failure(
        deployment_id: Option<Uuid>,
        deployment_id_malformed: bool,
    ) -> RuntimeFailureEvidence {
        let labels = deployment_id
            .map(|deployment_id| deployment_id.to_string())
            .or_else(|| deployment_id_malformed.then(|| "not-a-uuid".to_string()))
            .map(|deployment_id| {
                BTreeMap::from([("enclava.dev/deployment-id".to_string(), deployment_id)])
            });
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("tenant-secret-pod-name".to_string()),
                labels,
                ..Default::default()
            },
            status: Some(PodStatus {
                phase: Some("Running".to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "tenant-secret-container-name".to_string(),
                    image: "example.test/workload@sha256:abc".to_string(),
                    image_id: "example.test/workload@sha256:abc".to_string(),
                    ready: false,
                    restart_count: 3,
                    state: Some(ContainerState {
                        waiting: Some(ContainerStateWaiting {
                            reason: Some("CrashLoopBackOff".to_string()),
                            message: Some(WAITING_SECRET.to_string()),
                        }),
                        ..Default::default()
                    }),
                    last_state: Some(ContainerState {
                        terminated: Some(ContainerStateTerminated {
                            reason: Some("StartError".to_string()),
                            exit_code: 128,
                            message: Some(TERMINATED_SECRET.to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        runtime_failure_evidence(&pod).expect("fatal runtime failure")
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
    fn guest_kbs_token_failure_is_explicit_and_discards_raw_error() {
        let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "ready",
            "storage_status": "unlocked",
            "state": "unlocked",
            "claims_error": "aa_token_fetch_failed:sensitive upstream diagnostics"
        })));
        let observed = classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::TeeKbsTokenUnavailable)
        );
        let serialized =
            serde_json::to_string(&observed.observation).expect("serialize safe observation");
        assert!(serialized.contains("tee_kbs_token_unavailable"));
        assert!(!serialized.contains("sensitive"));
        assert!(!serialized.contains("aa_token_fetch_failed"));
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
            ready: true,
            deployment_id: None,
            deployment_id_malformed: false,
            runtime_failure: None,
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
    fn mixed_case_locked_state_is_canonical_and_cannot_look_running() {
        let deployment_id = Uuid::new_v4();
        let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "ready",
            "storage_status": "locked",
            "unlock_state": "LoCkEd"
        })));
        let observed = classify_live_observation_for_deployment(
            complete_pod(deployment_id),
            tee,
            observed_at(),
            Some(deployment_id),
        );

        assert_eq!(observed.observation.state, LiveObservationState::Fresh);
        assert_eq!(observed.effective_status("running"), "locked");
        assert!(observed.is_fresh_locked_for_deployment(deployment_id));
    }

    #[tokio::test]
    async fn kubernetes_probe_timeout_is_unavailable() {
        let result = bounded_kubernetes_probe(
            std::future::pending::<KubernetesEvidence>(),
            std::time::Duration::from_millis(1),
        )
        .await;

        assert_eq!(result, KubernetesEvidence::Unavailable);
    }

    #[test]
    fn tee_error_state_cannot_produce_fresh_readiness() {
        let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "error",
            "storage_status": "error",
            "unlock_state": "error"
        })));
        let observed = classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::TeeEvidenceIncomplete)
        );
        assert_eq!(observed.effective_status("running"), "partial");
    }

    #[test]
    fn unhealthy_tee_or_storage_field_cannot_produce_fresh_readiness() {
        for (tee_status, storage_status) in [
            ("error", "unlocked"),
            ("ready", "error"),
            ("ready", "locked"),
        ] {
            let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
                "pod_status": "Running",
                "tee_status": tee_status,
                "storage_status": storage_status,
                "unlock_state": "unlocked"
            })));
            let observed =
                classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

            assert_eq!(observed.observation.state, LiveObservationState::Partial);
            assert_eq!(
                observed.observation.reason,
                Some(LiveObservationReason::TeeEvidenceIncomplete)
            );
            assert_eq!(observed.effective_status("running"), "partial");
        }
    }

    #[test]
    fn malformed_tee_supplemental_field_cannot_be_treated_as_omitted() {
        for body in [
            json!({
                "pod_status": "Running",
                "tee_status": 1,
                "storage_status": "unlocked",
                "unlock_state": "unlocked"
            }),
            json!({
                "pod_status": "Running",
                "tee_status": "ready",
                "storage_status": {"state": "unlocked"},
                "unlock_state": "unlocked"
            }),
            json!({
                "pod_status": ["Running"],
                "tee_status": "ready",
                "storage_status": "unlocked",
                "unlock_state": "unlocked"
            }),
        ] {
            let tee = TeeEvidence::Available(tee_evidence_fields(&body));
            let observed =
                classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

            assert_eq!(observed.observation.state, LiveObservationState::Partial);
            assert_eq!(
                observed.observation.reason,
                Some(LiveObservationReason::TeeEvidenceIncomplete)
            );
        }
    }

    #[test]
    fn omitted_or_null_supplemental_health_fields_remain_compatible() {
        for body in [
            json!({"state": "unlocked"}),
            json!({
                "pod_status": null,
                "tee_status": null,
                "storage_status": null,
                "state": "unlocked"
            }),
        ] {
            let tee = TeeEvidence::Available(tee_evidence_fields(&body));
            let observed =
                classify_live_observation(complete_pod(Uuid::new_v4()), tee, observed_at());

            assert_eq!(observed.observation.state, LiveObservationState::Fresh);
            assert_eq!(observed.effective_status("running"), "running");
        }
    }

    #[test]
    fn non_running_pod_cannot_be_fresh_from_unlocked_tee_evidence() {
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Pending".to_string()),
            ready: false,
            deployment_id: Some(Uuid::new_v4()),
            deployment_id_malformed: false,
            runtime_failure: None,
        });
        let observed = classify_live_observation(pod, complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::PodEvidenceIncomplete)
        );
        assert_eq!(observed.effective_status("running"), "partial");
        assert!(!observed.is_fresh_locked_for_deployment(Uuid::new_v4()));
    }

    #[test]
    fn unlocked_running_but_unready_pod_cannot_be_fresh() {
        let deployment_id = Uuid::new_v4();
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            ready: false,
            deployment_id: Some(deployment_id),
            deployment_id_malformed: false,
            runtime_failure: None,
        });
        let observed = classify_live_observation_for_deployment(
            pod,
            complete_tee(),
            observed_at(),
            Some(deployment_id),
        );

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::PodEvidenceIncomplete)
        );
        assert_eq!(observed.effective_status("running"), "partial");
        assert!(!observed.is_fresh_locked_for_deployment(deployment_id));
    }

    #[test]
    fn locked_running_pod_can_be_fresh_before_readiness() {
        let deployment_id = Uuid::new_v4();
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            ready: false,
            deployment_id: Some(deployment_id),
            deployment_id_malformed: false,
            runtime_failure: None,
        });
        let tee = TeeEvidence::Available(tee_evidence_fields(&json!({
            "pod_status": "Running",
            "tee_status": "ready",
            "storage_status": "locked",
            "unlock_state": "locked"
        })));
        let observed =
            classify_live_observation_for_deployment(pod, tee, observed_at(), Some(deployment_id));

        assert_eq!(observed.observation.state, LiveObservationState::Fresh);
        assert_eq!(observed.effective_status("running"), "locked");
    }

    #[test]
    fn pod_readiness_requires_ready_condition_and_all_containers() {
        let ready_status = || PodStatus {
            phase: Some("Running".to_string()),
            conditions: Some(vec![PodCondition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                ..Default::default()
            }]),
            container_statuses: Some(vec![ContainerStatus {
                name: "app".to_string(),
                image: "example.test/app@sha256:abc".to_string(),
                image_id: "example.test/app@sha256:abc".to_string(),
                ready: true,
                restart_count: 0,
                ..Default::default()
            }]),
            ..Default::default()
        };
        let mut pod = Pod {
            status: Some(ready_status()),
            ..Default::default()
        };

        assert!(pod_is_ready(&pod));
        pod.status
            .as_mut()
            .and_then(|status| status.container_statuses.as_mut())
            .expect("container status")[0]
            .ready = false;
        assert!(!pod_is_ready(&pod));
    }

    #[test]
    fn malformed_deployment_identity_cannot_use_legacy_compatibility() {
        let pod = KubernetesEvidence::Available(PodEvidence {
            found: true,
            phase: Some("Running".to_string()),
            ready: true,
            deployment_id: None,
            deployment_id_malformed: true,
            runtime_failure: None,
        });
        let observed = classify_live_observation(pod, complete_tee(), observed_at());

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(observed.effective_status("running"), "partial");
    }

    #[test]
    fn deployment_identity_mismatch_is_not_fresh() {
        let observed = classify_live_observation_for_deployment(
            complete_pod(Uuid::new_v4()),
            complete_tee(),
            observed_at(),
            Some(Uuid::new_v4()),
        );

        assert_eq!(observed.observation.state, LiveObservationState::Partial);
        assert_eq!(
            observed.observation.reason,
            Some(LiveObservationReason::EvidenceMismatch)
        );
        assert!(observed.observation.deployment_id.is_some());
        assert_eq!(observed.effective_status("running"), "partial");
    }

    #[test]
    fn ambiguous_pods_with_runtime_failure_fail_closed() {
        let deployment_id = Uuid::new_v4();
        let observed = classify_live_observation(
            KubernetesEvidence::Available(PodEvidence {
                found: true,
                phase: None,
                ready: false,
                deployment_id: Some(deployment_id),
                deployment_id_malformed: false,
                runtime_failure: Some(runtime_failure(Some(deployment_id), false)),
            }),
            complete_tee(),
            observed_at(),
        );

        assert_eq!(observed.effective_status("running"), "failed");
        assert!(observed.runtime_failure_matches_deployment(deployment_id));
    }

    #[test]
    fn serialized_internal_and_generic_live_failures_exclude_kubernetes_messages() {
        let deployment_id = Uuid::new_v4();
        let observed = classify_live_observation_for_deployment(
            KubernetesEvidence::Available(PodEvidence {
                found: true,
                phase: Some("Running".to_string()),
                ready: true,
                deployment_id: Some(deployment_id),
                deployment_id_malformed: false,
                runtime_failure: Some(runtime_failure(Some(deployment_id), false)),
            }),
            complete_tee(),
            observed_at(),
            Some(deployment_id),
        );
        let public_message = observed
            .runtime_failure_public_message()
            .expect("public runtime failure");
        assert_eq!(
            public_message,
            "container_runtime_failure status=waiting code=crash_loop_back_off; \
             previous_container_runtime_failure status=terminated code=start_error exit_code=128"
        );

        let responses = [
            json!({
                "latest_deployment": {
                    "status": "failed",
                    "error_message": &public_message,
                    "observation": &observed.observation,
                },
                "observation": &observed.observation,
            }),
            json!({
                "status": "failed",
                "app_status": "failed",
                "error_message": &public_message,
                "observation": &observed.observation,
            }),
        ];

        for response in responses {
            let serialized = serde_json::to_string(&response).expect("serialize response");
            assert!(!serialized.contains(WAITING_SECRET));
            assert!(!serialized.contains(TERMINATED_SECRET));
            assert!(!serialized.contains("tenant-secret-pod-name"));
            assert!(!serialized.contains("tenant-secret-container-name"));
            assert!(serialized.contains("crash_loop_back_off"));
            assert!(serialized.contains("start_error"));
            assert!(serialized.len() < 512);
        }
    }

    #[test]
    fn overlapping_pod_failure_prefers_the_expected_deployment_identity() {
        let previous_deployment_id = Uuid::new_v4();
        let expected_deployment_id = Uuid::new_v4();
        let selected = select_runtime_failure(
            vec![
                runtime_failure(Some(previous_deployment_id), false),
                runtime_failure(Some(expected_deployment_id), false),
            ],
            Some(expected_deployment_id),
            false,
        )
        .expect("runtime failure");

        assert_eq!(selected.deployment_id, Some(expected_deployment_id));
    }

    #[test]
    fn stale_labelled_failure_is_not_attributed_to_expected_deployment() {
        let previous_deployment_id = Uuid::new_v4();
        let expected_deployment_id = Uuid::new_v4();
        let selected = select_runtime_failure(
            vec![runtime_failure(Some(previous_deployment_id), false)],
            Some(expected_deployment_id),
            false,
        );

        assert_eq!(selected, None);
    }

    #[test]
    fn labelled_rollout_does_not_attribute_unlabelled_failure_to_latest() {
        let expected_deployment_id = Uuid::new_v4();
        let selected = select_runtime_failure(
            vec![runtime_failure(None, false)],
            Some(expected_deployment_id),
            false,
        );

        assert_eq!(selected, None);
    }

    #[test]
    fn pure_legacy_fleet_keeps_unlabelled_failure_compatibility() {
        let expected_deployment_id = Uuid::new_v4();
        let selected = select_runtime_failure(
            vec![runtime_failure(None, false)],
            Some(expected_deployment_id),
            true,
        )
        .expect("legacy runtime failure");

        assert_eq!(selected.deployment_id, None);
        assert!(!selected.deployment_id_malformed);
    }

    #[test]
    fn legacy_unlabelled_runtime_failure_applies_to_current_deployment() {
        let expected_deployment_id = Uuid::new_v4();
        let observed = classify_live_observation_for_deployment(
            KubernetesEvidence::Available(PodEvidence {
                found: true,
                phase: Some("Running".to_string()),
                ready: false,
                deployment_id: None,
                deployment_id_malformed: false,
                runtime_failure: Some(runtime_failure(None, false)),
            }),
            complete_tee(),
            observed_at(),
            Some(expected_deployment_id),
        );

        assert!(observed.runtime_failure_applies_to_latest(expected_deployment_id));
        assert!(!observed.runtime_failure_matches_deployment(expected_deployment_id));
    }

    #[test]
    fn malformed_runtime_failure_identity_never_applies_to_a_deployment() {
        let expected_deployment_id = Uuid::new_v4();
        let observed = classify_live_observation_for_deployment(
            KubernetesEvidence::Available(PodEvidence {
                found: true,
                phase: Some("Running".to_string()),
                ready: false,
                deployment_id: None,
                deployment_id_malformed: true,
                runtime_failure: Some(runtime_failure(None, true)),
            }),
            complete_tee(),
            observed_at(),
            Some(expected_deployment_id),
        );

        assert!(!observed.runtime_failure_applies_to_latest(expected_deployment_id));
        assert!(!observed.runtime_failure_matches_deployment(expected_deployment_id));
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
