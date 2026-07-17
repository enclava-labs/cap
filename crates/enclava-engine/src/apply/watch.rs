use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ContainerState, ContainerStatus, Pod};
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DeleteParams, ListParams};
use tokio::time::Instant;

use super::engine::{ApplyEngine, ApplyError};
use super::types::{DeployPhase, DeployStatus};

const STALE_TERMINATING_POD_FORCE_DELETE_BUFFER_SECONDS: i64 = 10;
pub const POD_TERMINAL_FAILURE_CODE: &str = "pod_failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerRuntimeStatus {
    Waiting,
    Terminated,
}

impl ContainerRuntimeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerRuntimeFailureCode {
    CrashLoopBackOff,
    CreateContainerConfigError,
    CreateContainerError,
    Error,
    ErrImagePull,
    ImagePullBackOff,
    InvalidImageName,
    RunContainerError,
    ContainerCannotRun,
    OomKilled,
    StartError,
}

impl ContainerRuntimeFailureCode {
    fn from_waiting_reason(reason: &str) -> Option<Self> {
        match reason {
            "CrashLoopBackOff" => Some(Self::CrashLoopBackOff),
            "CreateContainerConfigError" => Some(Self::CreateContainerConfigError),
            "CreateContainerError" => Some(Self::CreateContainerError),
            "Error" => Some(Self::Error),
            "ErrImagePull" => Some(Self::ErrImagePull),
            "ImagePullBackOff" => Some(Self::ImagePullBackOff),
            "InvalidImageName" => Some(Self::InvalidImageName),
            "RunContainerError" => Some(Self::RunContainerError),
            _ => None,
        }
    }

    fn from_terminated_reason(reason: &str) -> Option<Self> {
        match reason {
            "ContainerCannotRun" => Some(Self::ContainerCannotRun),
            "Error" => Some(Self::Error),
            "OOMKilled" => Some(Self::OomKilled),
            "StartError" => Some(Self::StartError),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::CrashLoopBackOff => "crash_loop_back_off",
            Self::CreateContainerConfigError => "create_container_config_error",
            Self::CreateContainerError => "create_container_error",
            Self::Error => "error",
            Self::ErrImagePull => "err_image_pull",
            Self::ImagePullBackOff => "image_pull_back_off",
            Self::InvalidImageName => "invalid_image_name",
            Self::RunContainerError => "run_container_error",
            Self::ContainerCannotRun => "container_cannot_run",
            Self::OomKilled => "oom_killed",
            Self::StartError => "start_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerRuntimeFailure {
    status: ContainerRuntimeStatus,
    code: ContainerRuntimeFailureCode,
    exit_code: Option<i32>,
}

impl ContainerRuntimeFailure {
    fn public_message(self) -> String {
        let mut message = format!(
            "container_runtime_failure status={} code={}",
            self.status.as_str(),
            self.code.as_str()
        );
        if let Some(exit_code) = self.exit_code {
            message.push_str(&format!(" exit_code={exit_code}"));
        }
        message
    }
}

/// A bounded runtime-failure summary safe to return across API boundaries.
///
/// Kubernetes state messages and workload-controlled names are deliberately
/// not retained. Only allowlisted runtime status/reason codes and a numeric
/// exit code can be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodRuntimeFailure {
    current: ContainerRuntimeFailure,
    previous: Option<ContainerRuntimeFailure>,
}

impl PodRuntimeFailure {
    pub fn public_message(self) -> String {
        let mut message = self.current.public_message();
        if let Some(previous) = self.previous {
            message.push_str("; previous_");
            message.push_str(&previous.public_message());
        }
        message
    }
}

pub fn pod_label_selector(statefulset_name: &str) -> String {
    format!("app={statefulset_name}")
}

/// Lightweight snapshot of a pod's state for phase classification.
/// Extracted from a k8s Pod object to keep classification logic pure and testable.
#[derive(Debug, Clone)]
pub struct PodSnapshot {
    pub phase: Option<String>,
    pub container_statuses_ready: bool,
    pub init_containers_done: bool,
    pub conditions_scheduled: bool,
}

impl PodSnapshot {
    /// Extract a PodSnapshot from a k8s Pod object.
    pub fn from_pod(pod: &Pod) -> Self {
        let status = pod.status.as_ref();
        let phase = status.and_then(|s| s.phase.clone());

        let container_statuses_ready = status
            .and_then(|s| s.container_statuses.as_ref())
            .map(|cs| !cs.is_empty() && cs.iter().all(|c| c.ready))
            .unwrap_or(false);

        let init_containers_done = status
            .and_then(|s| s.init_container_statuses.as_ref())
            .map(|ics| ics.iter().all(|c| c.ready))
            // No init containers means "done"
            .unwrap_or(true);

        let conditions_scheduled = status
            .and_then(|s| s.conditions.as_ref())
            .map(|conds| {
                conds
                    .iter()
                    .any(|c| c.type_ == "PodScheduled" && c.status == "True")
            })
            .unwrap_or(false);

        Self {
            phase,
            container_statuses_ready,
            init_containers_done,
            conditions_scheduled,
        }
    }
}

/// Classify a pod snapshot into a DeployPhase.
///
/// This is a pure function -- no K8s API calls. Fully unit-testable.
///
/// Phase mapping for CoCo (kata-qemu-snp) workloads:
/// - Pending + not scheduled -> PodsScheduled (waiting for node assignment)
/// - Pending + scheduled -> TeeBooting (kata VM starting)
/// - Running + not all ready -> Attesting (proxy is contacting KBS)
/// - Running + all ready -> Running (app is serving)
/// - Failed -> Failed
/// - Unknown -> TeeBooting (kubelet lost contact, common during TEE VM boot)
pub fn classify_pod_phase(snap: &PodSnapshot) -> DeployPhase {
    match snap.phase.as_deref() {
        Some("Pending") => {
            if snap.conditions_scheduled {
                DeployPhase::TeeBooting
            } else {
                DeployPhase::PodsScheduled
            }
        }
        Some("Running") => {
            if snap.container_statuses_ready {
                DeployPhase::Running
            } else {
                DeployPhase::Attesting
            }
        }
        Some("Failed") | Some("Error") => DeployPhase::Failed,
        Some("Succeeded") => {
            // StatefulSet pods should not Succeed (they're long-running), treat as unexpected
            DeployPhase::Failed
        }
        _ => {
            // Unknown or missing phase -- common during TEE boot when kubelet
            // temporarily loses contact with the kata VM
            DeployPhase::TeeBooting
        }
    }
}

fn terminated_failure(
    terminated: &k8s_openapi::api::core::v1::ContainerStateTerminated,
) -> Option<ContainerRuntimeFailure> {
    let reason = terminated.reason.as_deref().unwrap_or_default();
    Some(ContainerRuntimeFailure {
        status: ContainerRuntimeStatus::Terminated,
        code: ContainerRuntimeFailureCode::from_terminated_reason(reason)?,
        exit_code: Some(terminated.exit_code),
    })
}

fn state_failure(state: Option<&ContainerState>) -> Option<ContainerRuntimeFailure> {
    let state = state?;
    if let Some(terminated) = state.terminated.as_ref()
        && let Some(failure) = terminated_failure(terminated)
    {
        return Some(failure);
    }
    if let Some(waiting) = state.waiting.as_ref()
        && let Some(reason) = waiting.reason.as_deref()
        && let Some(code) = ContainerRuntimeFailureCode::from_waiting_reason(reason)
    {
        return Some(ContainerRuntimeFailure {
            status: ContainerRuntimeStatus::Waiting,
            code,
            exit_code: None,
        });
    }
    None
}

fn container_runtime_failure(status: &ContainerStatus) -> Option<PodRuntimeFailure> {
    Some(PodRuntimeFailure {
        current: state_failure(status.state.as_ref())?,
        previous: state_failure(status.last_state.as_ref()),
    })
}

/// Return a bounded fatal container runtime summary for a pod, if one exists.
///
/// Kubernetes can keep a pod phase at `Running` while an app container is in
/// `CrashLoopBackOff` or has a runtime `StartError`, so callers must inspect
/// container states rather than relying on pod phase alone.
pub fn pod_runtime_failure(pod: &Pod) -> Option<PodRuntimeFailure> {
    let status = pod.status.as_ref()?;
    for container in status
        .init_container_statuses
        .iter()
        .flat_map(|statuses| statuses.iter())
        .chain(
            status
                .container_statuses
                .iter()
                .flat_map(|statuses| statuses.iter()),
        )
    {
        if let Some(failure) = container_runtime_failure(container) {
            return Some(failure);
        }
    }
    None
}

/// Compatibility formatter for deployment-watch error storage. The returned
/// string contains only the bounded fields from [`PodRuntimeFailure`].
pub fn pod_runtime_failure_message(pod: &Pod) -> Option<String> {
    pod_runtime_failure(pod).map(PodRuntimeFailure::public_message)
}

/// Return the fixed code for a terminal pod phase without retaining pod names.
pub fn pod_terminal_failure_code(pod: &Pod) -> Option<&'static str> {
    matches!(
        classify_pod_phase(&PodSnapshot::from_pod(pod)),
        DeployPhase::Failed
    )
    .then_some(POD_TERMINAL_FAILURE_CODE)
}

pub fn stale_terminating_pod_needs_force_delete(pod: &Pod, now: Timestamp) -> bool {
    let Some(deleted_at) = pod.metadata.deletion_timestamp.as_ref() else {
        return false;
    };

    if pod
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|finalizers| !finalizers.is_empty())
    {
        return false;
    }

    let grace = pod
        .metadata
        .deletion_grace_period_seconds
        .or_else(|| {
            pod.spec
                .as_ref()
                .and_then(|spec| spec.termination_grace_period_seconds)
        })
        .unwrap_or(30)
        .max(0);
    let stale_after = grace + STALE_TERMINATING_POD_FORCE_DELETE_BUFFER_SECONDS;
    now.duration_since(deleted_at.0).as_secs() >= stale_after
}

/// Watch a StatefulSet rollout until it reaches a terminal state or times out.
///
/// Polls the StatefulSet and its pods at `config.poll_interval`. Returns
/// the final DeployStatus. The caller should have already called `apply_all`.
///
/// Terminal states:
/// - Running: all pods ready
/// - Failed: pod in failed/crashloop state
/// - TimedOut: exceeded `config.rollout_timeout`
pub async fn watch_rollout(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset_name: &str,
) -> Result<DeployStatus, ApplyError> {
    let sts_api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let pod_api: Api<Pod> = Api::namespaced(engine.client().clone(), namespace);

    let deadline = engine.config().rollout_timeout;
    let poll = engine.config().poll_interval;
    let start = Instant::now();

    let mut last_phase = DeployPhase::Applying;

    loop {
        if start.elapsed() >= deadline {
            return Ok(DeployStatus::timed_out(&format!(
                "rollout did not complete within {deadline:?}"
            )));
        }

        let sts = match sts_api.get(statefulset_name).await {
            Ok(sts) => sts,
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                return Err(ApplyError::RolloutFailed(format!(
                    "StatefulSet '{statefulset_name}' not found in namespace '{namespace}'"
                )));
            }
            Err(e) => return Err(e.into()),
        };

        let sts_status = sts.status.as_ref();
        let generation = sts.metadata.generation.unwrap_or(0);
        let observed_generation = sts_status.and_then(|s| s.observed_generation).unwrap_or(0);
        let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
        let ready = sts_status.and_then(|s| s.ready_replicas).unwrap_or(0);
        let current = sts_status.and_then(|s| s.current_replicas).unwrap_or(0);
        let updated = sts_status.and_then(|s| s.updated_replicas).unwrap_or(0);

        if observed_generation >= generation
            && ready >= desired
            && current >= desired
            && updated >= desired
            && desired > 0
        {
            tracing::info!(
                namespace = %namespace,
                statefulset = %statefulset_name,
                "rollout complete: all replicas ready"
            );
            return Ok(DeployStatus::with_phase(DeployPhase::Running));
        }

        // Inspect pods for more granular phase info
        let pods = pod_api
            .list(&ListParams::default().labels(&pod_label_selector(statefulset_name)))
            .await?;
        let now = Timestamp::now();

        for pod in &pods.items {
            if !stale_terminating_pod_needs_force_delete(pod, now) {
                continue;
            }

            let Some(pod_name) = pod.metadata.name.as_deref() else {
                continue;
            };

            tracing::warn!(
                namespace = %namespace,
                statefulset = %statefulset_name,
                pod = %pod_name,
                "force deleting stale terminating pod after grace period"
            );
            match pod_api
                .delete(pod_name, &DeleteParams::default().grace_period(0))
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(ae)) if ae.code == 404 => {}
                Err(kube::Error::Api(error)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        statefulset = %statefulset_name,
                        pod = %pod_name,
                        failure_code = "pod_force_delete_failed",
                        kubernetes_status_code = error.code,
                        "failed to force delete stale terminating pod"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        namespace = %namespace,
                        statefulset = %statefulset_name,
                        pod = %pod_name,
                        failure_code = "pod_force_delete_failed",
                        "failed to force delete stale terminating pod"
                    );
                }
            }
        }

        let mut worst_phase = DeployPhase::Running;

        for pod in &pods.items {
            let snap = PodSnapshot::from_pod(pod);
            let phase = classify_pod_phase(&snap);

            if let Some(msg) = pod_runtime_failure_message(pod) {
                tracing::warn!(%msg, "container runtime failure detected");
                return Ok(DeployStatus::failed(&msg));
            }

            // Track the "worst" (earliest) phase across pods
            if (phase as u8) < (worst_phase as u8) {
                worst_phase = phase;
            }

            // Pod in terminal failure
            if let Some(code) = pod_terminal_failure_code(pod) {
                tracing::warn!(failure_code = code, "pod entered terminal failure state");
                return Ok(DeployStatus::failed(code));
            }
        }

        // If no pods exist yet, we're still in Applying
        if pods.items.is_empty() {
            worst_phase = DeployPhase::Applying;
        }

        if worst_phase != last_phase {
            tracing::info!(
                namespace = %namespace,
                statefulset = %statefulset_name,
                phase = ?worst_phase,
                "rollout phase changed"
            );
            last_phase = worst_phase;
        }

        // Wait before next poll
        let remaining = deadline.saturating_sub(start.elapsed());
        let sleep_dur = poll.min(remaining);
        if sleep_dur.is_zero() {
            return Ok(DeployStatus::timed_out(&format!(
                "rollout did not complete within {deadline:?}"
            )));
        }
        tokio::time::sleep(sleep_dur).await;
    }
}
