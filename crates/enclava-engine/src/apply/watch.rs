use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DeleteParams, ListParams};
use tokio::time::Instant;

use super::engine::{ApplyEngine, ApplyError};
use super::types::{DeployPhase, DeployStatus};

const STALE_TERMINATING_POD_FORCE_DELETE_BUFFER_SECONDS: i64 = 10;

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
                Err(err) => {
                    tracing::warn!(
                        namespace = %namespace,
                        statefulset = %statefulset_name,
                        pod = %pod_name,
                        error = %err,
                        "failed to force delete stale terminating pod"
                    );
                }
            }
        }

        let mut worst_phase = DeployPhase::Running;

        for pod in &pods.items {
            let snap = PodSnapshot::from_pod(pod);
            let phase = classify_pod_phase(&snap);

            if let Some(statuses) = pod
                .status
                .as_ref()
                .and_then(|s| s.container_statuses.as_ref())
            {
                for cs in statuses {
                    if let Some(waiting) = cs.state.as_ref().and_then(|s| s.waiting.as_ref())
                        && let Some(reason) = &waiting.reason
                        && (reason == "CrashLoopBackOff" || reason == "Error")
                    {
                        let msg = format!(
                            "container '{}' in {}: {}",
                            cs.name,
                            reason,
                            waiting.message.as_deref().unwrap_or("no details")
                        );
                        tracing::warn!(%msg, "crash loop detected");
                        return Ok(DeployStatus::failed(&msg));
                    }
                }
            }

            // Track the "worst" (earliest) phase across pods
            if (phase as u8) < (worst_phase as u8) {
                worst_phase = phase;
            }

            // Pod in terminal failure
            if matches!(phase, DeployPhase::Failed) {
                let pod_name = pod.metadata.name.as_deref().unwrap_or("<unknown>");
                return Ok(DeployStatus::failed(&format!(
                    "pod '{pod_name}' entered Failed state"
                )));
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
