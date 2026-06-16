use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DeleteParams, ListParams};
use tokio::time::Instant;

use super::engine::{ApplyEngine, ApplyError};
use super::types::{DeployPhase, DeployStatus};

const STALE_TERMINATING_POD_FORCE_DELETE_BUFFER_SECONDS: i64 = 10;
const UNREADY_RUNNING_POD_RECREATE_AFTER_SECONDS: i64 = 600;

pub fn pod_label_selector(statefulset_name: &str) -> String {
    format!("app={statefulset_name}")
}

pub fn pod_is_stale_rollout_revision(pod: &Pod, update_revision: Option<&str>) -> bool {
    let Some(update_revision) = update_revision.filter(|revision| !revision.is_empty()) else {
        return false;
    };
    let Some(labels) = pod.metadata.labels.as_ref() else {
        return false;
    };
    labels
        .get("controller-revision-hash")
        .is_some_and(|pod_revision| pod_revision != update_revision)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KataPodRecreatePlan {
    pub pod_name: String,
    pub reason: String,
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

pub fn kata_start_error_needs_pod_recreate(pod: &Pod) -> Option<String> {
    let statuses = pod.status.as_ref()?.container_statuses.as_ref()?;

    for cs in statuses {
        let waiting_reason = cs
            .state
            .as_ref()
            .and_then(|state| state.waiting.as_ref())
            .and_then(|waiting| waiting.reason.as_deref());
        let waiting_message = cs
            .state
            .as_ref()
            .and_then(|state| state.waiting.as_ref())
            .and_then(|waiting| waiting.message.as_deref())
            .unwrap_or("");
        let terminated = cs
            .last_state
            .as_ref()
            .and_then(|state| state.terminated.as_ref());
        let terminated_reason = terminated.and_then(|terminated| terminated.reason.as_deref());
        let terminated_message = terminated
            .and_then(|terminated| terminated.message.as_deref())
            .unwrap_or("");

        let start_error = matches!(waiting_reason, Some("StartError"))
            || matches!(terminated_reason, Some("StartError"));
        if !start_error {
            continue;
        }

        let detail = format!("{waiting_message}\n{terminated_message}");
        let detail_lower = detail.to_ascii_lowercase();
        let looks_like_runtime_start_error = detail_lower.contains("failed to create shim task")
            || detail_lower.contains("failed to create containerd task")
            || detail_lower.contains("einval");
        if looks_like_runtime_start_error {
            return Some(format!(
                "container '{}' hit runtime StartError: {}",
                cs.name,
                terminated_message
                    .split('\n')
                    .next()
                    .filter(|line| !line.is_empty())
                    .unwrap_or(waiting_message)
            ));
        }
    }

    None
}

pub fn plan_kata_start_error_pod_recreates(pods: &[Pod]) -> Vec<KataPodRecreatePlan> {
    pods.iter()
        .filter_map(|pod| {
            let reason = kata_start_error_needs_pod_recreate(pod)?;
            let pod_name = pod.metadata.name.clone()?;
            Some(KataPodRecreatePlan { pod_name, reason })
        })
        .collect()
}

pub fn plan_stale_terminating_pod_force_deletes(
    pods: &[Pod],
    now: Timestamp,
) -> Vec<KataPodRecreatePlan> {
    pods.iter()
        .filter_map(|pod| {
            if !stale_terminating_pod_needs_force_delete(pod, now) {
                return None;
            }
            let pod_name = pod.metadata.name.clone()?;
            Some(KataPodRecreatePlan {
                pod_name,
                reason: "stale terminating pod exceeded deletion grace period".to_string(),
            })
        })
        .collect()
}

pub fn unready_running_pod_needs_recreate(pod: &Pod, now: Timestamp) -> Option<String> {
    if pod.metadata.deletion_timestamp.is_some() {
        return None;
    }

    let status = pod.status.as_ref()?;
    if status.phase.as_deref() != Some("Running") {
        return None;
    }

    let web = status
        .container_statuses
        .as_ref()?
        .iter()
        .find(|container| container.name == "web")?;
    if web.ready {
        return None;
    }

    let started_at = web
        .state
        .as_ref()
        .and_then(|state| state.running.as_ref())
        .and_then(|running| running.started_at.as_ref())?;
    let unready_seconds = now.duration_since(started_at.0).as_secs();
    if unready_seconds < UNREADY_RUNNING_POD_RECREATE_AFTER_SECONDS {
        return None;
    }

    Some(format!(
        "container '{}' has been running unready for {unready_seconds}s; recreate pod to recover hung app inside Kata sandbox",
        web.name
    ))
}

pub fn plan_unready_running_pod_recreates(
    pods: &[Pod],
    now: Timestamp,
) -> Vec<KataPodRecreatePlan> {
    pods.iter()
        .filter_map(|pod| {
            let reason = unready_running_pod_needs_recreate(pod, now)?;
            let pod_name = pod.metadata.name.clone()?;
            Some(KataPodRecreatePlan { pod_name, reason })
        })
        .collect()
}

fn unready_running_pod_delete_params() -> DeleteParams {
    DeleteParams::default().grace_period(0)
}

pub async fn recreate_kata_start_error_pods(
    client: kube::Client,
    namespace: &str,
    statefulset_name: &str,
) -> Result<Vec<KataPodRecreatePlan>, ApplyError> {
    let pod_api: Api<Pod> = Api::namespaced(client, namespace);
    let pods = pod_api
        .list(&ListParams::default().labels(&pod_label_selector(statefulset_name)))
        .await?;
    let recreate_plan = plan_kata_start_error_pod_recreates(&pods.items);

    for action in &recreate_plan {
        tracing::warn!(
            namespace = %namespace,
            statefulset = %statefulset_name,
            pod = %action.pod_name,
            reason = %action.reason,
            "deleting pod to recreate Kata sandbox after runtime StartError"
        );
        match pod_api
            .delete(&action.pod_name, &DeleteParams::default())
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(recreate_plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unready_running_pod_delete_uses_zero_grace() {
        assert_eq!(
            unready_running_pod_delete_params().grace_period_seconds,
            Some(0)
        );
    }
}

pub async fn force_delete_stale_terminating_pods(
    client: kube::Client,
    namespace: &str,
    statefulset_name: &str,
) -> Result<Vec<KataPodRecreatePlan>, ApplyError> {
    let pod_api: Api<Pod> = Api::namespaced(client, namespace);
    let pods = pod_api
        .list(&ListParams::default().labels(&pod_label_selector(statefulset_name)))
        .await?;
    let force_delete_plan = plan_stale_terminating_pod_force_deletes(&pods.items, Timestamp::now());

    for action in &force_delete_plan {
        tracing::warn!(
            namespace = %namespace,
            statefulset = %statefulset_name,
            pod = %action.pod_name,
            reason = %action.reason,
            "force deleting stale terminating pod after grace period"
        );
        match pod_api
            .delete(&action.pod_name, &DeleteParams::default().grace_period(0))
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(force_delete_plan)
}

pub async fn recreate_unready_running_pods(
    client: kube::Client,
    namespace: &str,
    statefulset_name: &str,
) -> Result<Vec<KataPodRecreatePlan>, ApplyError> {
    let pod_api: Api<Pod> = Api::namespaced(client, namespace);
    let pods = pod_api
        .list(&ListParams::default().labels(&pod_label_selector(statefulset_name)))
        .await?;
    let recreate_plan = plan_unready_running_pod_recreates(&pods.items, Timestamp::now());

    for action in &recreate_plan {
        tracing::warn!(
            namespace = %namespace,
            statefulset = %statefulset_name,
            pod = %action.pod_name,
            reason = %action.reason,
            "force deleting pod to recreate Kata sandbox after app container stayed unready"
        );
        match pod_api
            .delete(&action.pod_name, &unready_running_pod_delete_params())
            .await
        {
            Ok(_) => {}
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(recreate_plan)
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

    'watch: loop {
        if start.elapsed() >= deadline {
            return Ok(DeployStatus::timed_out(&format!(
                "rollout did not complete within {:?}",
                deadline
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
        let update_revision = sts_status.and_then(|s| s.update_revision.as_deref());

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

        for action in plan_stale_terminating_pod_force_deletes(&pods.items, now) {
            tracing::warn!(
                namespace = %namespace,
                statefulset = %statefulset_name,
                pod = %action.pod_name,
                reason = %action.reason,
                "force deleting stale terminating pod after grace period"
            );
            match pod_api
                .delete(&action.pod_name, &DeleteParams::default().grace_period(0))
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(ae)) if ae.code == 404 => {}
                Err(err) => {
                    tracing::warn!(
                        namespace = %namespace,
                        statefulset = %statefulset_name,
                        pod = %action.pod_name,
                        error = %err,
                        "failed to force delete stale terminating pod"
                    );
                }
            }
        }

        let mut worst_phase = DeployPhase::Running;

        for action in plan_kata_start_error_pod_recreates(&pods.items) {
            tracing::warn!(
                namespace = %namespace,
                statefulset = %statefulset_name,
                pod = %action.pod_name,
                reason = %action.reason,
                "deleting pod to recreate Kata sandbox after runtime StartError"
            );
            match pod_api
                .delete(&action.pod_name, &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(ae)) if ae.code == 404 => {}
                Err(err) => return Err(err.into()),
            }
            continue 'watch;
        }

        for pod in &pods.items {
            if pod_is_stale_rollout_revision(pod, update_revision) {
                tracing::info!(
                    namespace = %namespace,
                    statefulset = %statefulset_name,
                    pod = %pod.metadata.name.as_deref().unwrap_or("<unknown>"),
                    update_revision = ?update_revision,
                    "ignoring pod from previous StatefulSet revision during rollout"
                );
                continue;
            }

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
                "rollout did not complete within {:?}",
                deadline
            )));
        }
        tokio::time::sleep(sleep_dur).await;
    }
}
