use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim};
use kube::api::{Api, DeleteParams, ListParams};
use serde_json::json;
use tokio::time::Instant;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_existing_partial, delete_resource};
use crate::manifest::volumes::CAP_VCT_NAMES;

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

    let current = api.get(name).await?;
    let live_generation = current
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(super::generation::MUTATION_GENERATION_ANNOTATION))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0);
    let observed = current.status.as_ref();
    if live_generation.is_some_and(|value| value == generation.get())
        && current
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1)
            == desired_replicas
        && observed
            .and_then(|status| status.current_replicas)
            .unwrap_or(0)
            == desired_replicas
        && observed
            .and_then(|status| status.ready_replicas)
            .unwrap_or(0)
            == desired_replicas
        && observed
            .and_then(|status| status.updated_replicas)
            .unwrap_or(0)
            == desired_replicas
    {
        return Ok(());
    }

    let patch = json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "spec": { "replicas": desired_replicas }
    });
    apply_existing_partial(
        &api,
        name,
        &patch,
        generation,
        &engine.config().field_manager,
    )
    .await?;
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

/// Delete CAP-owned PVCs in a namespace and wait for PV cleanup.
///
/// Only PVCs whose names match the StatefulSet volumeClaimTemplate pattern
/// `<vct>-<statefulset>-<ordinal>` for a CAP-rendered VCT name are selected
/// (#138): a namespace-colocated PVC created by another actor must not be
/// swept by tenant teardown. Matching is by name shape because VCT metadata
/// (labels) is immutable in Kubernetes and existing StatefulSets cannot be
/// relabeled.
pub async fn delete_pvcs_and_wait(
    engine: &ApplyEngine,
    namespace: &str,
    timeout_duration: Duration,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let api: Api<PersistentVolumeClaim> = Api::namespaced(engine.client().clone(), namespace);

    // List all PVCs in the namespace, keep only the CAP-owned name shapes.
    let pvcs: Vec<String> = api
        .list(&ListParams::default())
        .await?
        .items
        .iter()
        .filter(|pvc| {
            pvc.metadata
                .name
                .as_deref()
                .is_some_and(is_cap_owned_pvc_name)
        })
        .filter_map(|pvc| pvc.metadata.name.clone())
        .collect();

    if pvcs.is_empty() {
        tracing::info!(namespace = %namespace, "no PVCs to delete");
        return Ok(());
    }

    for pvc_name in &pvcs {
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
            let remaining: Vec<String> = api
                .list(&ListParams::default())
                .await?
                .items
                .iter()
                .filter(|pvc| {
                    pvc.metadata
                        .name
                        .as_deref()
                        .is_some_and(is_cap_owned_pvc_name)
                })
                .filter_map(|pvc| pvc.metadata.name.clone())
                .collect();
            if !remaining.is_empty() {
                tracing::warn!(
                    namespace = %namespace,
                    stuck_pvcs = ?remaining,
                    "PVC deletion timed out -- some PVCs may have stuck finalizers"
                );
                return Err(ApplyError::CleanupStepFailed {
                    step: "delete_pvcs".to_string(),
                    detail: format!(
                        "PVCs {remaining:?} not deleted within {timeout_duration:?} -- possible finalizer issue"
                    ),
                });
            }
            break;
        }

        let remaining = api.list(&ListParams::default()).await?;
        if !remaining.items.iter().any(|pvc| {
            pvc.metadata
                .name
                .as_deref()
                .is_some_and(is_cap_owned_pvc_name)
        }) {
            tracing::info!(namespace = %namespace, "all CAP-owned PVCs deleted");
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    Ok(())
}

/// True for PVC names created by a CAP StatefulSet:
/// `<vct>-<statefulset>-<ordinal>` where `<vct>` is one of the CAP-rendered
/// volumeClaimTemplate names and the trailing segment is the pod ordinal.
/// The StatefulSet (app) name may itself contain hyphens, so the VCT is
/// matched as a prefix, not by splitting on the last-but-one hyphen.
fn is_cap_owned_pvc_name(name: &str) -> bool {
    let Some((stem, ordinal)) = name.rsplit_once('-') else {
        return false;
    };
    if ordinal.is_empty() || !ordinal.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    CAP_VCT_NAMES.iter().any(|vct| {
        stem.strip_prefix(vct)
            .is_some_and(|rest| rest.starts_with('-') && rest.len() > 1)
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_owned_pvc_names_match() {
        // `<vct>-<statefulset>-<ordinal>` for every CAP VCT name, including
        // hyphenated StatefulSet (app) names.
        for vct in CAP_VCT_NAMES {
            for sts in ["app", "my-app", "a-b-c"] {
                for ordinal in ["0", "1", "12"] {
                    assert!(
                        is_cap_owned_pvc_name(&format!("{vct}-{sts}-{ordinal}")),
                        "{vct}-{sts}-{ordinal} must match"
                    );
                }
            }
        }
    }

    #[test]
    fn foreign_pvc_names_do_not_match() {
        for name in [
            "state",
            "state-0",
            "state-abc",
            "state--0",
            "stateless-app-0",
            "database-data-0",
            "tls-state",
            "state-app-",
            "state--",
        ] {
            assert!(!is_cap_owned_pvc_name(name), "{name} must not match");
        }
    }
}
