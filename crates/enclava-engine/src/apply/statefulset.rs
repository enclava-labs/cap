use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, ListParams, Preconditions};

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};
use super::watch::pod_label_selector;

const INIT_DATA_HASH_ANNOTATION: &str = "storage.enclava.dev/secure-pv-init-data-sha256";

/// Replace the StatefulSet exactly when CAP is its only non-status manager.
///
/// The StatefulSet carries attestation-critical fields: `image`, `runtimeClassName`,
/// `cc_init_data` annotations, and the signer-identity annotation. If a manager
/// outside the control plane has set any of these, replacing would silently
/// overwrite their value and a follower-attacker could mask their tampering by
/// re-claiming ownership on the next reconcile. We use no-force SSA in that case
/// so the API server surfaces the conflict instead. Exact replacement is needed
/// for CAP-created objects because their initial `Update` ownership otherwise
/// retains fields later omitted from the desired manifest.
///
/// On 409 Conflict: the API server returns a status object listing the conflicting
/// fields and managers. We log a structured warning and return the kube error so
/// the caller (deployer) can decide. Initial-create still works because there is
/// no existing object to conflict with.
pub async fn apply_statefulset(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset: &StatefulSet,
    generation: MutationGeneration,
) -> Result<StatefulSet, ApplyError> {
    let name = statefulset.metadata.name.as_deref().unwrap_or("<unnamed>");
    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match apply_resource(engine, &api, statefulset, generation, false, true).await {
        Ok(patched) => {
            replace_superseded_unready_pods(engine, namespace, &patched).await?;
            tracing::info!(
                namespace = %namespace,
                statefulset = %name,
                "StatefulSet converged"
            );
            Ok(patched)
        }
        Err(ApplyError::Kube(kube::Error::Api(ae))) if ae.code == 409 => {
            tracing::warn!(
                namespace = %namespace,
                statefulset = %name,
                code = ae.code,
                reason = %ae.reason,
                cause_count = ae.details.as_ref().map(|details| details.causes.len()).unwrap_or(0),
                "SSA conflict on attestation-critical resource: refusing to overwrite \
                 fields owned by another manager. Investigate before re-applying."
            );
            Err(ApplyError::Kube(kube::Error::Api(ae)))
        }
        Err(e) => Err(e),
    }
}

async fn replace_superseded_unready_pods(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset: &StatefulSet,
) -> Result<(), ApplyError> {
    let Some(spec) = statefulset.spec.as_ref() else {
        return Ok(());
    };
    // CAP has one replica; do not override partitioned or multi-replica rollout ordering.
    if spec.replicas.unwrap_or(1) != 1
        || spec.update_strategy.as_ref().is_some_and(|strategy| {
            strategy
                .type_
                .as_deref()
                .is_some_and(|kind| kind != "RollingUpdate")
                || strategy
                    .rolling_update
                    .as_ref()
                    .and_then(|rolling| rolling.partition)
                    .is_some_and(|partition| partition != 0)
        })
    {
        return Ok(());
    }
    let (Some(name), Some(owner_uid), Some(init_data_hash)) = (
        statefulset.metadata.name.as_deref(),
        statefulset.metadata.uid.as_deref(),
        spec.template
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.annotations.as_ref())
            .and_then(|annotations| annotations.get(INIT_DATA_HASH_ANNOTATION)),
    ) else {
        return Ok(());
    };
    let pods: Api<Pod> = Api::namespaced(engine.client().clone(), namespace);
    for pod in pods
        .list(&ListParams::default().labels(&pod_label_selector(name)))
        .await?
        .items
    {
        if !superseded_unready_pod(&pod, owner_uid, init_data_hash) {
            continue;
        }
        let pod_name = pod
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| ApplyError::MissingResourceIdentity("Pod".into()))?;
        let uid = pod
            .metadata
            .uid
            .ok_or_else(|| ApplyError::MissingResourceIdentity("Pod".into()))?;
        // OrderedReady cannot replace an unready old template; retain PVCs and normal termination.
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid),
                resource_version: None,
            }),
            ..Default::default()
        };
        match super::bounded_kube_write(pods.delete(pod_name, &params)).await {
            Ok(_) => {}
            Err(ApplyError::Kube(kube::Error::Api(error))) if matches!(error.code, 404 | 409) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn superseded_unready_pod(pod: &Pod, owner_uid: &str, init_data_hash: &str) -> bool {
    pod.metadata.deletion_timestamp.is_none()
        && pod
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| {
                owners.iter().any(|owner| {
                    owner.controller == Some(true)
                        && owner.kind == "StatefulSet"
                        && owner.uid == owner_uid
                })
            })
        && pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(INIT_DATA_HASH_ANNOTATION))
            .is_some_and(|observed| observed != init_data_hash)
        && pod
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "False")
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn interrupted_rollout_replaces_only_its_unready_superseded_pod() {
        let mut pod: Pod = serde_json::from_value(json!({
            "metadata": {
                "annotations": { INIT_DATA_HASH_ANNOTATION: "old-init-data" },
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "StatefulSet",
                    "name": "app", "uid": "current-set", "controller": true
                }]
            },
            "status": { "conditions": [{ "type": "Ready", "status": "False" }] }
        }))
        .unwrap();
        assert!(superseded_unready_pod(&pod, "current-set", "new-init-data"));
        assert!(!superseded_unready_pod(&pod, "other-set", "new-init-data"));
        assert!(!superseded_unready_pod(
            &pod,
            "current-set",
            "old-init-data"
        ));
        pod.status.as_mut().unwrap().conditions.as_mut().unwrap()[0].status = "True".into();
        assert!(!superseded_unready_pod(
            &pod,
            "current-set",
            "new-init-data"
        ));
        pod.status.as_mut().unwrap().conditions.as_mut().unwrap()[0].status = "Unknown".into();
        assert!(!superseded_unready_pod(
            &pod,
            "current-set",
            "new-init-data"
        ));
        pod.status.as_mut().unwrap().conditions.as_mut().unwrap()[0].status = "False".into();
        pod.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                "2026-10-20T11:00:00Z".parse().unwrap(),
            ));
        assert!(!superseded_unready_pod(
            &pod,
            "current-set",
            "new-init-data"
        ));
    }
}
