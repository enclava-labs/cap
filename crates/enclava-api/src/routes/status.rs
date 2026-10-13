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
use std::{future::Future, net::SocketAddr, time::Duration};
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
    let (kubernetes, tee) = tokio::join!(
        probe_kubernetes(namespace, app_name, expected_deployment_id),
        probe_tee(state, namespace, app_name, domain, tee_domain)
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

async fn probe_tee(
    state: &AppState,
    namespace: &str,
    app_name: &str,
    domain: &str,
    tee_domain: Option<&str>,
) -> TeeEvidence {
    bounded_tee_probe(
        state,
        namespace,
        app_name,
        probe_tee_unbounded(state, namespace, app_name, domain, tee_domain),
        TEE_STATUS_PROBE_TIMEOUT,
    )
    .await
}

async fn bounded_tee_probe<F>(
    state: &AppState,
    namespace: &str,
    app_name: &str,
    probe: F,
    deadline: Duration,
) -> TeeEvidence
where
    F: Future<Output = TeeEvidence>,
{
    match tokio::time::timeout(deadline, probe).await {
        Ok(evidence) => evidence,
        Err(_) => {
            warn_tee_probe_failure(
                state,
                app_name,
                namespace,
                "deadline",
                &format!("TEE status probe exceeded the {deadline:?} bound"),
            );
            TeeEvidence::Unavailable
        }
    }
}

/// One structured warn per failed probe attempt, naming the failed stage and
/// its underlying error so the remediation domain (service wiring, network
/// policy, TLS material, proxy/ingress health) is readable from the log
/// instead of being collapsed into `evidence: tee_unavailable`.
///
/// The probe runs per status/observation request, so warns are rate-limited
/// per app: the first failure and every change of failure signature are
/// emitted; repeated identical failures and successes stay silent.
fn warn_tee_probe_failure(
    state: &AppState,
    app_name: &str,
    namespace: &str,
    stage: &str,
    detail: &str,
) {
    let signature = format!("{stage}\u{1}{detail}");
    if !tee_probe_failure_signature_changed(state, app_name, namespace, &signature) {
        return;
    }
    tracing::warn!(
        app = %app_name,
        namespace = %namespace,
        probe = "tee_status",
        stage,
        detail,
        "live TEE probe failed"
    );
}

/// Clear the rate-limit signature after a successful probe so a later
/// recurrence of the same failure is logged again rather than suppressed.
fn note_tee_probe_success(state: &AppState, app_name: &str, namespace: &str) {
    state
        .recent_tee_probe_failures
        .lock()
        .expect("TEE probe failure state mutex")
        .remove(&tee_probe_failure_key(app_name, namespace));
}

fn tee_probe_failure_key(app_name: &str, namespace: &str) -> String {
    format!("{namespace}/{app_name}")
}

/// Record a failure signature, returning whether it differs from the
/// previously recorded one for this app (and therefore should be logged).
fn tee_probe_failure_signature_changed(
    state: &AppState,
    app_name: &str,
    namespace: &str,
    signature: &str,
) -> bool {
    let mut recent = state
        .recent_tee_probe_failures
        .lock()
        .expect("TEE probe failure state mutex");
    let key = tee_probe_failure_key(app_name, namespace);
    let changed = recent.get(&key).map(String::as_str) != Some(signature);
    if changed {
        recent.insert(key, signature.to_string());
    }
    changed
}

async fn probe_tee_unbounded(
    state: &AppState,
    namespace: &str,
    app_name: &str,
    domain: &str,
    tee_domain: Option<&str>,
) -> TeeEvidence {
    let internal_transport = state.attestation.as_ref().is_some_and(|attestation| {
        enclava_engine::manifest::network_policy::cap_api_namespace_for_attestation(
            attestation,
            &state.api_url,
        )
        .is_some()
    });
    let (client, tee_status_url) = if internal_transport {
        // Socket-resolution failures already emit a structured warn inside
        // `resolve_internal_tee_socket`.
        let Some(socket) =
            crate::routes::logs::resolve_internal_tee_socket(app_name, namespace).await
        else {
            note_existing_tee_probe_failure(state, app_name, namespace, "resolve_socket");
            return TeeEvidence::Unavailable;
        };
        let client =
            match crate::routes::logs::build_resolved_tenant_tee_http_client(domain, socket) {
                Ok(client) => client,
                Err(error) => {
                    warn_tee_probe_failure(
                        state,
                        app_name,
                        namespace,
                        "build_client",
                        &format!("failed to build the internal-transport HTTP client: {error}"),
                    );
                    return TeeEvidence::Unavailable;
                }
            };
        (
            client,
            confidential_status_url(domain, tee_domain, Some(socket)),
        )
    } else {
        (
            state.tee_http_client.clone(),
            confidential_status_url(domain, tee_domain, None),
        )
    };
    let response = match client
        .get(&tee_status_url)
        .timeout(TEE_STATUS_PROBE_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            // The reqwest error chain distinguishes connect vs TLS vs
            // timeout; render it whole rather than collapsing to a category.
            warn_tee_probe_failure(
                state,
                app_name,
                namespace,
                "send",
                &format!("request to {tee_status_url} failed: {error}"),
            );
            return TeeEvidence::Unavailable;
        }
    };
    if !response.status().is_success() {
        warn_tee_probe_failure(
            state,
            app_name,
            namespace,
            "http_status",
            &format!("{tee_status_url} returned {}", response.status()),
        );
        return TeeEvidence::Unavailable;
    }
    match response.json::<Value>().await {
        Ok(body) if body.is_object() => {
            note_tee_probe_success(state, app_name, namespace);
            TeeEvidence::Available(tee_evidence_fields(&body))
        }
        Ok(_) => {
            // A 2xx body that is not a JSON object already surfaces as the
            // distinct `TeeEvidence::Malformed` reason; keep the warn for the
            // http_status -> body transition visible in logs.
            warn_tee_probe_failure(
                state,
                app_name,
                namespace,
                "body",
                &format!("{tee_status_url} returned a non-object JSON body"),
            );
            TeeEvidence::Malformed
        }
        Err(error) => {
            warn_tee_probe_failure(
                state,
                app_name,
                namespace,
                "body",
                &format!("{tee_status_url} returned a malformed body: {error}"),
            );
            TeeEvidence::Malformed
        }
    }
}

/// `resolve_internal_tee_socket` logs its own detailed warn; record only the
/// stage marker so the rate-limit state knows which stage failed.
fn note_existing_tee_probe_failure(state: &AppState, app_name: &str, namespace: &str, stage: &str) {
    tee_probe_failure_signature_changed(
        state,
        app_name,
        namespace,
        &format!("{stage}\u{1}(logged upstream)"),
    );
}

fn tee_evidence_fields(body: &Value) -> TeeEvidenceFields {
    let supplemental_fields_malformed = ["pod_status", "tee_status", "storage_status"]
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

fn confidential_status_url(
    domain: &str,
    tee_domain: Option<&str>,
    socket: Option<SocketAddr>,
) -> String {
    match socket {
        Some(socket) => format!(
            "https://{domain}:{}/.well-known/confidential/status",
            socket.port()
        ),
        None => format!(
            "https://{}/.well-known/confidential/status",
            tee_domain.unwrap_or(domain)
        ),
    }
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
    use std::{collections::BTreeMap, time::Duration};

    use chrono::{TimeZone, Utc};
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, Pod,
        PodCondition, PodStatus,
    };
    use kube::api::ObjectMeta;
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        AppState, KubernetesEvidence, LiveObservationReason, LiveObservationState, PodEvidence,
        RuntimeFailureEvidence, TeeEvidence, bounded_kubernetes_probe, bounded_tee_probe,
        classify_live_observation, classify_live_observation_for_deployment,
        confidential_status_url, effective_app_status, pod_is_ready, probe_tee,
        runtime_failure_evidence, select_runtime_failure, tee_evidence_fields,
    };
    use axum::http::StatusCode;
    use std::net::SocketAddr;

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
    fn confidential_status_probe_pins_ingress_domain_to_internal_service() {
        let socket = "10.43.13.109:443".parse().unwrap();
        assert_eq!(
            confidential_status_url(
                "app.example.test",
                Some("app.tee.example.test"),
                Some(socket)
            ),
            "https://app.example.test:443/.well-known/confidential/status"
        );
        assert_eq!(
            confidential_status_url("app.example.test", Some("app.tee.example.test"), None),
            "https://app.tee.example.test/.well-known/confidential/status"
        );
    }

    #[tokio::test]
    async fn tee_probe_deadline_covers_internal_service_resolution() {
        let state = probe_test_state(resolved_probe_client(closed_local_socket().await));
        let evidence = bounded_tee_probe(
            &state,
            "ns-110",
            "app-110",
            std::future::pending::<TeeEvidence>(),
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(evidence, TeeEvidence::Unavailable);
    }

    // --- Regression tests for #110: silent TEE probe failures -------------

    use std::sync::{Arc, Mutex};

    struct CapturedProbeLogWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedProbeLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("captured log mutex").extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn captured_warn_logs() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer({
                let logs = Arc::clone(&logs);
                move || CapturedProbeLogWriter(Arc::clone(&logs))
            })
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    fn captured_log_text(logs: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(logs.lock().expect("captured log mutex").clone())
            .expect("captured logs are UTF-8")
    }

    /// rustls cannot infer a process-level CryptoProvider when both aws-lc-rs
    /// and ring are in the dependency graph; select aws-lc-rs (the provider
    /// the workspace pins for kube/reqwest) once per test binary.
    fn install_test_crypto_provider() {
        use std::sync::Once;
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    /// Serve a TEE status endpoint over real TLS with a self-signed cert so
    /// `probe_tee`'s public-transport path exercises the full HTTP client.
    async fn spawn_status_server(status_code: StatusCode, body: &'static str) -> SocketAddr {
        use tokio_rustls::TlsAcceptor;

        install_test_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["app.example.test".to_string()])
            .expect("self-signed certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    cert.cert.der().to_vec(),
                )],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.signing_key.serialize_der().into(),
                ),
            )
            .expect("TLS server config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                // Read the client request before responding so reqwest sees a
                // complete exchange; connection is closed afterwards.
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                while let Ok(read) = stream.read(&mut buf).await
                    && read > 0
                {
                    request.extend_from_slice(&buf[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    status_code.as_u16(),
                    status_code.canonical_reason().unwrap_or("Unknown"),
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        address
    }

    fn probe_test_state(tee_http_client: reqwest::Client) -> AppState {
        let mut state = crate::test_support::lazy_state();
        state.tee_http_client = tee_http_client;
        state
    }

    /// A reqwest client that resolves `app.example.test` to the given local
    /// socket, trusts any certificate, and never consults a proxy.
    fn resolved_probe_client(socket: SocketAddr) -> reqwest::Client {
        install_test_crypto_provider();
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .resolve("app.example.test", socket)
            .https_only(true)
            .no_proxy()
            .build()
            .unwrap()
    }

    /// Bind an ephemeral port and drop the listener so the port is closed:
    /// probing it deterministically fails at the connect stage.
    async fn closed_local_socket() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    #[tokio::test]
    async fn tee_probe_send_failure_emits_structured_warn() {
        let (logs, _guard) = captured_warn_logs();
        let socket = closed_local_socket().await;
        let state = probe_test_state(resolved_probe_client(socket));
        let evidence = probe_tee(&state, "ns-110", "app-110", "app.example.test", None).await;

        assert_eq!(evidence, TeeEvidence::Unavailable);
        let text = captured_log_text(&logs);
        assert!(
            text.contains(r#"stage="send""#),
            "expected a send-stage warn, got: {text}"
        );
        assert!(text.contains("app=app-110"));
        assert!(text.contains("namespace=ns-110"));
        assert!(
            text.to_lowercase().contains("error"),
            "expected underlying error detail, got: {text}"
        );
    }

    #[tokio::test]
    async fn tee_probe_http_status_failure_emits_structured_warn() {
        let (logs, _guard) = captured_warn_logs();
        let address = spawn_status_server(
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"error\": \"unavailable\"}",
        )
        .await;
        let state = probe_test_state(resolved_probe_client(address));

        let evidence = probe_tee(&state, "ns-110", "app-110", "app.example.test", None).await;

        assert_eq!(evidence, TeeEvidence::Unavailable);
        let text = captured_log_text(&logs);
        assert!(
            text.contains(r#"stage="http_status""#),
            "expected an http_status-stage warn, got: {text}"
        );
        assert!(text.contains("503"), "expected the upstream status code");
    }

    #[tokio::test]
    async fn tee_probe_repeated_identical_failures_are_rate_limited() {
        let (logs, _guard) = captured_warn_logs();
        let socket = closed_local_socket().await;
        let state = probe_test_state(resolved_probe_client(socket));

        for _ in 0..3 {
            let evidence = probe_tee(&state, "ns-110", "app-110", "app.example.test", None).await;
            assert_eq!(evidence, TeeEvidence::Unavailable);
        }

        let text = captured_log_text(&logs);
        assert_eq!(
            text.matches("live TEE probe failed").count(),
            1,
            "identical consecutive failures must warn exactly once: {text}"
        );
    }

    #[tokio::test]
    async fn tee_probe_warns_again_after_signature_change_and_recovery() {
        let (logs, _guard) = captured_warn_logs();
        let closed = closed_local_socket().await;
        let state = probe_test_state(resolved_probe_client(closed));

        // First failure: warned.
        let _ = probe_tee(&state, "ns-110", "app-110", "app.example.test", None).await;
        // Success: clears the rate-limit signature (no warn, no failure).
        let address = spawn_status_server(
            StatusCode::OK,
            "{\"pod_status\": \"Running\", \"tee_status\": \"ready\", \"storage_status\": \"unlocked\", \"state\": \"unlocked\"}",
        )
        .await;
        let mut recovered = state.clone();
        recovered.tee_http_client = resolved_probe_client(address);
        let evidence = probe_tee(&recovered, "ns-110", "app-110", "app.example.test", None).await;
        assert!(matches!(evidence, TeeEvidence::Available(_)));
        // Same failure again after recovery: warned again.
        let _ = probe_tee(&state, "ns-110", "app-110", "app.example.test", None).await;

        let text = captured_log_text(&logs);
        assert_eq!(
            text.matches("live TEE probe failed").count(),
            2,
            "expected warn on first failure and re-warn after recovery: {text}"
        );
    }

    #[tokio::test]
    async fn tee_probe_deadline_failure_emits_structured_warn() {
        let (logs, _guard) = captured_warn_logs();
        let state = probe_test_state(resolved_probe_client(closed_local_socket().await));
        let evidence = bounded_tee_probe(
            &state,
            "ns-110",
            "app-110",
            std::future::pending::<TeeEvidence>(),
            Duration::from_millis(10),
        )
        .await;

        assert_eq!(evidence, TeeEvidence::Unavailable);
        let text = captured_log_text(&logs);
        assert!(
            text.contains(r#"stage="deadline""#),
            "expected a deadline-stage warn, got: {text}"
        );
    }
}
