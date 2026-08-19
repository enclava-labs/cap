use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim};
use kube::api::{Api, DeleteParams, ListParams};
use serde_json::json;
use tokio::time::Instant;

use crate::types::ConfidentialApp;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_existing_partial, delete_resource};
use super::teardown::notify_teardown_proxy;

/// Result of a single cleanup step.
#[derive(Debug, Clone)]
pub struct CleanupStep {
    pub name: String,
    pub success: bool,
    pub message: Option<String>,
}

/// Tracks the outcome of an ordered cleanup sequence.
/// Cleanup continues even if individual steps fail, collecting all results.
#[derive(Debug, Clone)]
pub struct CleanupReport {
    pub steps: Vec<CleanupStep>,
}

impl CleanupReport {
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    pub fn record_success(&mut self, step: &str) {
        self.steps.push(CleanupStep {
            name: step.to_string(),
            success: true,
            message: None,
        });
    }

    pub fn record_failure(&mut self, step: &str, message: &str) {
        self.steps.push(CleanupStep {
            name: step.to_string(),
            success: false,
            message: Some(message.to_string()),
        });
    }

    /// True if all steps succeeded.
    pub fn is_success(&self) -> bool {
        self.steps.iter().all(|s| s.success)
    }

    /// Returns (step_name, message) pairs for failed steps.
    pub fn failures(&self) -> Vec<(&str, &str)> {
        self.steps
            .iter()
            .filter(|s| !s.success)
            .map(|s| (s.name.as_str(), s.message.as_deref().unwrap_or("")))
            .collect()
    }
}

impl Default for CleanupReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Set a StatefulSet to zero or one replica and wait for the observed state.
pub async fn set_statefulset_desired_replicas(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    desired_replicas: i32,
    timeout_duration: Duration,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    if !matches!(desired_replicas, 0 | 1) {
        return Err(ApplyError::ManifestGeneration(
            "desired replicas must be zero or one".to_string(),
        ));
    }
    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);

    let patch = json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "spec": { "replicas": desired_replicas }
    });
    apply_existing_partial(&api, name, &patch, generation).await?;
    tracing::info!(namespace = %namespace, statefulset = %name, desired_replicas, "set StatefulSet desired replicas");

    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout_duration {
            return Err(ApplyError::CleanupStepFailed {
                step: "set_desired_replicas".to_string(),
                detail: format!("replicas did not converge within {timeout_duration:?}"),
            });
        }

        let sts = api.get(name).await?;
        let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
        let ready = sts
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
        let current = sts
            .status
            .as_ref()
            .and_then(|s| s.current_replicas)
            .unwrap_or(0);
        let updated = sts
            .status
            .as_ref()
            .and_then(|s| s.updated_replicas)
            .unwrap_or(0);

        if desired == desired_replicas
            && current == desired_replicas
            && ready == desired_replicas
            && updated == desired_replicas
        {
            tracing::info!(
                namespace = %namespace,
                statefulset = %name,
                desired_replicas,
                "StatefulSet replicas converged"
            );
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Scale a StatefulSet to 0 replicas and wait for all pods to terminate.
pub async fn scale_statefulset_to_zero(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    timeout_duration: Duration,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    set_statefulset_desired_replicas(engine, namespace, name, 0, timeout_duration, generation).await
}

/// Delete a StatefulSet.
pub async fn delete_statefulset(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);

    match delete_resource(&api, name, generation, DeleteParams::default()).await {
        Ok(true) => {
            tracing::info!(namespace = %namespace, statefulset = %name, "StatefulSet deleted");
            Ok(())
        }
        Ok(false) => {
            tracing::info!(
                namespace = %namespace,
                statefulset = %name,
                "StatefulSet already deleted"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Delete all PVCs in a namespace and wait for PV cleanup.
pub async fn delete_pvcs_and_wait(
    engine: &ApplyEngine,
    namespace: &str,
    timeout_duration: Duration,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let api: Api<PersistentVolumeClaim> = Api::namespaced(engine.client().clone(), namespace);

    // List all PVCs in the namespace
    let pvcs = api.list(&ListParams::default()).await?;

    if pvcs.items.is_empty() {
        tracing::info!(namespace = %namespace, "no PVCs to delete");
        return Ok(());
    }

    for pvc in &pvcs.items {
        let pvc_name = pvc.metadata.name.as_deref().unwrap_or("<unnamed>");
        match delete_resource(&api, pvc_name, generation, DeleteParams::default()).await {
            Ok(true) => {
                tracing::info!(namespace = %namespace, pvc = %pvc_name, "PVC delete requested");
            }
            Ok(false) => {
                tracing::info!(namespace = %namespace, pvc = %pvc_name, "PVC already gone");
            }
            Err(e) => {
                tracing::warn!(
                    namespace = %namespace,
                    pvc = %pvc_name,
                    error = %e,
                    "failed to delete PVC"
                );
            }
        }
    }

    // Wait for PVCs to be fully deleted
    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout_duration {
            let remaining = api.list(&ListParams::default()).await?;
            if !remaining.items.is_empty() {
                let names: Vec<_> = remaining
                    .items
                    .iter()
                    .filter_map(|p| p.metadata.name.as_deref())
                    .collect();
                tracing::warn!(
                    namespace = %namespace,
                    stuck_pvcs = ?names,
                    "PVC deletion timed out -- some PVCs may have stuck finalizers"
                );
                return Err(ApplyError::CleanupStepFailed {
                    step: "delete_pvcs".to_string(),
                    detail: format!(
                        "PVCs {names:?} not deleted within {timeout_duration:?} -- possible finalizer issue"
                    ),
                });
            }
            break;
        }

        let remaining = api.list(&ListParams::default()).await?;
        if remaining.items.is_empty() {
            tracing::info!(namespace = %namespace, "all PVCs deleted");
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    Ok(())
}

/// Delete a namespace and wait for it to be fully removed.
/// Handles the "namespace stuck in Terminating" case with a timeout.
pub async fn delete_namespace_and_wait(
    engine: &ApplyEngine,
    namespace: &str,
    timeout_duration: Duration,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let api: Api<Namespace> = Api::all(engine.client().clone());
    let delete_and_wait = async {
        match delete_resource(&api, namespace, generation, DeleteParams::default()).await {
            Ok(true) => {
                tracing::info!(namespace = %namespace, "namespace delete requested");
            }
            Ok(false) => {
                tracing::info!(namespace = %namespace, "namespace already deleted");
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        // Wait for the namespace to disappear.
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout_duration {
                tracing::warn!(
                    namespace = %namespace,
                    "namespace deletion timed out -- may be stuck in Terminating"
                );
                return Err(ApplyError::CleanupStepFailed {
                    step: "delete_namespace".to_string(),
                    detail: format!(
                        "namespace '{namespace}' stuck in Terminating after {timeout_duration:?}"
                    ),
                });
            }

            match api.get(namespace).await {
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    tracing::info!(namespace = %namespace, "namespace fully deleted");
                    return Ok(());
                }
                Ok(ns) => {
                    let phase = ns
                        .status
                        .as_ref()
                        .and_then(|s| s.phase.as_deref())
                        .unwrap_or("Unknown");
                    tracing::debug!(
                        namespace = %namespace,
                        phase = %phase,
                        "waiting for namespace deletion"
                    );
                }
                Err(e) => return Err(e.into()),
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };

    // The convergence deadline alone cannot bound a hung GET. Keep the whole
    // provider operation bounded so callers retain their durable fail-closed
    // fence instead of waiting forever.
    tokio::time::timeout(
        timeout_duration.saturating_add(Duration::from_secs(30)),
        delete_and_wait,
    )
    .await
    .map_err(|_| ApplyError::CleanupStepFailed {
        step: "delete_namespace".to_string(),
        detail: format!("namespace '{namespace}' provider operation exceeded its outer timeout"),
    })?
}

/// Ordered cleanup of all resources for a confidential app.
///
/// Follows the spec's teardown sequence:
/// 1. Notify attestation proxy to self-cleanup (best-effort)
/// 2. Scale StatefulSet to 0, wait for pod termination
/// 3. Delete StatefulSet
/// 4. Delete PVCs, wait for PV cleanup
/// 5. (KBS policy update is handled by the caller -- requires regenerating
///    the full policy from the API database, not an engine concern)
/// 6. Delete namespace
///
/// Each step is attempted regardless of whether previous steps failed.
/// Returns a CleanupReport with the outcome of every step.
///
/// `api_token`: if Some, used to authenticate the teardown proxy notification.
/// If None, the teardown proxy step is skipped.
pub async fn cleanup_app(
    engine: &ApplyEngine,
    app: &ConfidentialApp,
    api_token: Option<&str>,
    generation: MutationGeneration,
) -> CleanupReport {
    let mut report = CleanupReport::new();

    if let Some(token) = api_token {
        let domain = app.primary_domain();
        match notify_teardown_proxy(domain, token, engine.config().teardown_proxy_timeout).await {
            Ok(()) => report.record_success("notify_teardown_proxy"),
            Err(e) => {
                tracing::warn!(
                    app = %app.name,
                    error = %e,
                    "teardown proxy notification failed -- continuing cleanup"
                );
                report.record_failure("notify_teardown_proxy", &e.to_string());
            }
        }
    } else {
        tracing::info!(
            app = %app.name,
            "no API token provided -- skipping teardown proxy notification"
        );
        report.record_success("notify_teardown_proxy_skipped");
    }

    match scale_statefulset_to_zero(
        engine,
        &app.namespace,
        &app.name,
        engine.config().rollout_timeout,
        generation,
    )
    .await
    {
        Ok(()) => report.record_success("scale_to_zero"),
        Err(e) => {
            // 404 is fine -- StatefulSet may already be gone
            if matches!(&e, ApplyError::Kube(kube::Error::Api(ae)) if ae.code == 404) {
                tracing::info!(
                    app = %app.name,
                    "StatefulSet not found during scale -- already deleted"
                );
                report.record_success("scale_to_zero");
            } else {
                tracing::warn!(app = %app.name, error = %e, "scale to zero failed");
                report.record_failure("scale_to_zero", &e.to_string());
            }
        }
    }

    match delete_statefulset(engine, &app.namespace, &app.name, generation).await {
        Ok(()) => report.record_success("delete_statefulset"),
        Err(e) => {
            tracing::warn!(app = %app.name, error = %e, "delete StatefulSet failed");
            report.record_failure("delete_statefulset", &e.to_string());
        }
    }

    match delete_pvcs_and_wait(
        engine,
        &app.namespace,
        engine.config().pvc_delete_timeout,
        generation,
    )
    .await
    {
        Ok(()) => report.record_success("delete_pvcs"),
        Err(e) => {
            tracing::warn!(app = %app.name, error = %e, "PVC cleanup issue");
            report.record_failure("delete_pvcs", &e.to_string());
        }
    }

    match delete_namespace_and_wait(
        engine,
        &app.namespace,
        engine.config().namespace_delete_timeout,
        generation,
    )
    .await
    {
        Ok(()) => report.record_success("delete_namespace"),
        Err(e) => {
            tracing::warn!(
                app = %app.name,
                namespace = %app.namespace,
                error = %e,
                "namespace deletion issue"
            );
            report.record_failure("delete_namespace", &e.to_string());
        }
    }

    let success_count = report.steps.iter().filter(|s| s.success).count();
    let fail_count = report.steps.len() - success_count;
    tracing::info!(
        app = %app.name,
        namespace = %app.namespace,
        success_steps = success_count,
        failed_steps = fail_count,
        "cleanup complete"
    );

    report
}
