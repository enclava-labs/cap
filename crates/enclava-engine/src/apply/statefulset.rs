use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, ListParams, Preconditions};

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MUTATION_GENERATION_ANNOTATION, MutationGeneration, apply_resource};
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
            replace_superseded_unready_pods(engine, &api, namespace, &patched).await?;
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
    statefulsets: &Api<StatefulSet>,
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
    if !engine
        .creation_ledger()
        .is_some_and(|ledger| ledger.contains_name_uid(name, owner_uid))
    {
        return Ok(());
    }
    let pods: Api<Pod> = Api::namespaced(engine.client().clone(), namespace);
    for mut pod in pods
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
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity("Pod".into()))?;
        let uid = pod
            .metadata
            .uid
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity("Pod".into()))?;
        for attempt in 0..3 {
            if pod.metadata.uid.as_ref() != Some(&uid)
                || !superseded_unready_pod(&pod, owner_uid, init_data_hash)
            {
                break;
            }
            let live = statefulsets.get(name).await?;
            if live.metadata.uid != statefulset.metadata.uid
                || live.metadata.generation != statefulset.metadata.generation
                || live
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
                    != statefulset
                        .metadata
                        .annotations
                        .as_ref()
                        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
            {
                return Err(ApplyError::RolloutFailed(
                    "StatefulSet changed during interrupted rollout recovery".into(),
                ));
            }
            let resource_version = pod
                .metadata
                .resource_version
                .take()
                .ok_or_else(|| ApplyError::MissingResourceIdentity("Pod".into()))?;
            // OrderedReady cannot replace an unready old template; retain PVCs and normal termination.
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: Some(uid.clone()),
                    resource_version: Some(resource_version),
                }),
                ..Default::default()
            };
            match super::bounded_kube_write(pods.delete(&pod_name, &params)).await {
                Ok(_) => break,
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 404 => break,
                Err(ApplyError::Kube(kube::Error::Api(error)))
                    if error.code == 409 && attempt < 2 =>
                {
                    let Some(current) = pods.get_opt(&pod_name).await? else {
                        break;
                    };
                    pod = current;
                }
                Err(error) => return Err(error),
            }
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
        && !pod
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn interrupted_recovery_respects_provenance_generation_and_delete_conflicts() {
        use axum::http::{Method, Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tower::service_fn;

        let desired = json!({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {
                "name": "app", "namespace": "test", "uid": "set-uid", "generation": 2,
                "annotations": { (MUTATION_GENERATION_ANNOTATION): "2" }
            },
            "spec": {
                "replicas": 1, "serviceName": "app", "selector": { "matchLabels": {"app": "app"} },
                "template": {
                    "metadata": { "annotations": { (INIT_DATA_HASH_ANNOTATION): "new" } }
                }
            }
        });
        let old_pod = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": "app-0", "namespace": "test", "uid": "pod-uid", "resourceVersion": "10",
                "annotations": { (INIT_DATA_HASH_ANNOTATION): "old" },
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "StatefulSet",
                    "name": "app", "uid": "set-uid", "controller": true
                }]
            },
            "status": { "conditions": [{ "type": "Ready", "status": "False" }] }
        });
        let statefulset: StatefulSet = serde_json::from_value(desired.clone()).unwrap();
        let mode = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let deletes = Arc::new(AtomicUsize::new(0));
        let client = kube::Client::new(
            service_fn({
                let mode = Arc::clone(&mode);
                let requests = Arc::clone(&requests);
                let deletes = Arc::clone(&deletes);
                move |request: Request<Body>| {
                    let mode = mode.load(Ordering::SeqCst);
                    let requests = Arc::clone(&requests);
                    let deletes = Arc::clone(&deletes);
                    let mut desired = desired.clone();
                    let mut pod = old_pod.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        let (status, response) = match (request.method(), request.uri().path()) {
                            (&Method::GET, "/api/v1/namespaces/test/pods") => (
                                200,
                                json!({ "apiVersion": "v1", "kind": "PodList", "items": [pod] }),
                            ),
                            (&Method::GET, "/apis/apps/v1/namespaces/test/statefulsets/app") => {
                                if mode == 1 {
                                    desired["metadata"]["annotations"]
                                        [MUTATION_GENERATION_ANNOTATION] = json!("3");
                                } else if mode == 3 {
                                    desired["metadata"]["uid"] = json!("replacement-set");
                                }
                                (200, desired)
                            }
                            (&Method::DELETE, "/api/v1/namespaces/test/pods/app-0") => {
                                let body = request.into_body().collect().await.unwrap().to_bytes();
                                let params: serde_json::Value =
                                    serde_json::from_slice(&body).unwrap();
                                assert_eq!(
                                    params["preconditions"],
                                    json!({
                                        "uid": "pod-uid", "resourceVersion": "10"
                                    })
                                );
                                deletes.fetch_add(1, Ordering::SeqCst);
                                (
                                    409,
                                    json!({
                                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                        "reason": "Conflict", "message": "Pod changed", "code": 409
                                    }),
                                )
                            }
                            (&Method::GET, "/api/v1/namespaces/test/pods/app-0") => {
                                pod["metadata"]["resourceVersion"] = json!("11");
                                if mode == 2 {
                                    pod["metadata"]["uid"] = json!("replacement-pod");
                                } else {
                                    pod["status"]["conditions"][0]["status"] = json!("True");
                                }
                                (200, pod)
                            }
                            _ => panic!("Unexpected Kubernetes request: {request:?}"),
                        };
                        Ok::<_, std::io::Error>(
                            Response::builder()
                                .status(status)
                                .body(Body::from(serde_json::to_vec(&response).unwrap()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "test",
        );
        let engine = ApplyEngine::new(client.clone(), Default::default());
        let statefulsets = Api::namespaced(client, "test");
        replace_superseded_unready_pods(&engine, &statefulsets, "test", &statefulset)
            .await
            .unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 0);

        let ledger = Arc::new(super::super::creation_ledger::CreationLedgerBuffer::new());
        ledger.preload([("StatefulSet".into(), "app".into(), "set-uid".into())]);
        let engine = engine.with_creation_ledger(ledger);
        for scenario in 0..4 {
            mode.store(scenario, Ordering::SeqCst);
            deletes.store(0, Ordering::SeqCst);
            let result =
                replace_superseded_unready_pods(&engine, &statefulsets, "test", &statefulset).await;
            if matches!(scenario, 1 | 3) {
                assert!(matches!(result, Err(ApplyError::RolloutFailed(_))));
                assert_eq!(deletes.load(Ordering::SeqCst), 0);
            } else {
                result.unwrap();
                assert_eq!(deletes.load(Ordering::SeqCst), 1);
            }
        }
    }

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
        assert!(superseded_unready_pod(&pod, "current-set", "new-init-data"));
        pod.status.as_mut().unwrap().conditions = None;
        assert!(superseded_unready_pod(&pod, "current-set", "new-init-data"));
        pod.status = None;
        assert!(superseded_unready_pod(&pod, "current-set", "new-init-data"));
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
