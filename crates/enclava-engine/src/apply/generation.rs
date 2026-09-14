//! Kubernetes-side generation fencing for CAP-owned workload resources.
//!
//! A database lease prevents healthy CAP processes from writing concurrently,
//! but canceling a client future does not prove that the Kubernetes API server
//! canceled the request. Every update therefore carries the durable provider
//! generation and the resourceVersion observed immediately before the write.
//! A delayed older request conflicts after a newer write instead of replaying
//! over it.

use kube::{
    Api, Resource,
    api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{fmt::Debug, time::Duration};

use super::engine::{ApplyEngine, ApplyError};
use super::fields_v1::flatten_owned_paths;

pub const MUTATION_GENERATION_ANNOTATION: &str = "enclava.dev/cap-provider-mutation-generation";
// ponytail: bounded but patient — total worst-case conflict wait ≈ 60 s, well
// inside the 180 s mutation lease and job deadlines. Controllers routinely
// rewrite status for minutes; the old 12×≤200 ms (~1.9 s) budget terminally
// failed live deploys against ordinary concurrent writers (staging
// 2026-09-13: gens 3d869f2c/69dff1f3/4b1b3ef7, mutation_conflict_exhausted).
const MAX_CONFLICT_RETRIES: usize = 64;

fn conflict_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis((25 * (1 << attempt.min(5))).min(1000))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MutationGeneration(i64);

impl MutationGeneration {
    pub fn new(value: i64) -> Result<Self, ApplyError> {
        if value <= 0 {
            return Err(ApplyError::InvalidMutationGeneration(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

fn kind<K>() -> String {
    std::any::type_name::<K>()
        .rsplit("::")
        .next()
        .unwrap_or("KubernetesResource")
        .to_string()
}

fn live_generation<K>(resource: &K) -> Result<i64, ApplyError>
where
    K: Resource,
{
    let raw = resource
        .meta()
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION));
    match raw {
        None => Ok(0),
        Some(raw) => raw
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| ApplyError::InvalidLiveMutationGeneration {
                kind: kind::<K>(),
                name: resource
                    .meta()
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string()),
            }),
    }
}

fn ensure_not_stale<K>(resource: &K, desired: MutationGeneration) -> Result<(), ApplyError>
where
    K: Resource,
{
    let actual = live_generation(resource)?;
    if actual > desired.get() {
        return Err(ApplyError::StaleMutationGeneration {
            kind: kind::<K>(),
            name: resource
                .meta()
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            desired: desired.get(),
            actual,
        });
    }
    Ok(())
}

fn annotate<K>(resource: &mut K, generation: MutationGeneration)
where
    K: Resource,
{
    resource
        .meta_mut()
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            MUTATION_GENERATION_ANNOTATION.to_string(),
            generation.get().to_string(),
        );
}

fn only_trusted_field_managers<K>(resource: &K, field_manager: &str) -> bool
where
    K: Resource,
{
    resource
        .meta()
        .managed_fields
        .as_ref()
        .is_some_and(|entries| {
            !entries.is_empty()
                && entries.iter().all(|entry| {
                    entry.subresource.as_deref() == Some("status")
                        || entry.manager.as_deref() == Some(field_manager)
                })
        })
}

/// Fields the API server reported as `FieldManagerConflict` causes for a
/// 409, in owned-path notation (leading dot stripped).
fn field_manager_conflict_fields(status: &kube::core::Status) -> Vec<String> {
    status
        .details
        .as_ref()
        .map(|details| {
            details
                .causes
                .iter()
                .filter(|cause| cause.reason == "FieldManagerConflict")
                .map(|cause| cause.field.trim_start_matches('.').to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// True when no external (non-status, differently-managed) entry owns any of
/// the conflicting fields, so a forced apply can only reclaim fields this
/// manager itself owns. Absent, empty, or unattributable ownership fails
/// closed.
fn conflicts_reclaimable_by_force<K>(live: &K, conflicts: &[String], field_manager: &str) -> bool
where
    K: Resource,
{
    let Some(entries) = live
        .meta()
        .managed_fields
        .as_ref()
        .filter(|entries| !entries.is_empty())
    else {
        return false;
    };
    conflicts.iter().all(|conflict| {
        !conflict.is_empty()
            && entries.iter().all(|entry| {
                if entry.subresource.as_deref() == Some("status")
                    || entry.manager.as_deref() == Some(field_manager)
                {
                    return true;
                }
                match entry
                    .fields_v1
                    .as_ref()
                    .map(|fields| &fields.0)
                    .and_then(flatten_owned_paths)
                {
                    Some(owned) => owned.iter().all(|path| {
                        conflict != path
                            && !conflict.starts_with(&format!("{path}."))
                            && !conflict.starts_with(&format!("{path}["))
                    }),
                    None => false,
                }
            })
    })
}

fn verify_applied_generation<K>(
    resource: &K,
    generation: MutationGeneration,
) -> Result<(), ApplyError>
where
    K: Resource,
{
    let actual = live_generation(resource)?;
    if actual != generation.get() {
        return Err(ApplyError::ProviderGenerationNotApplied {
            kind: kind::<K>(),
            name: resource
                .meta()
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            expected: generation.get(),
            actual,
        });
    }
    Ok(())
}

/// Create or conditionally SSA-update a resource.
///
/// Initial creation uses POST rather than SSA's create-or-update behavior. A
/// concurrent creator therefore gets `AlreadyExists` and must re-read before
/// it can update. A POST records Update ownership, so a later SSA may force only
/// when every non-status field manager is the configured, trusted CAP manager.
/// An external manager therefore still makes attestation-critical updates fail
/// closed. Existing objects are SSA-patched with the exact observed resourceVersion.
/// Callers must durably prevent generation reclaim while an initial create
/// response is ambiguous, because an absent resource cannot itself hold a
/// tombstone.
///
/// When an external non-status manager owns unrelated fields (for example a
/// lingering replicas-only `kubectl-patch` entry), the untrusted path applies
/// without force, and this manager's own prior Update ownership of the
/// generation annotation then conflicts on every new generation. That
/// self-conflict is distinguished from transient resourceVersion conflicts via
/// `Status.details.causes[].reason == FieldManagerConflict`: when every
/// conflicting field is owned (per the freshly read managedFields) only by
/// this manager, the apply escalates to force exactly enough to reclaim its
/// own fields. Any conflict an external entry owns, or any ownership state
/// that cannot be attributed, fails closed promptly with the server's
/// structured causes instead of burning the conflict budget.
pub async fn apply_resource<K>(
    engine: &ApplyEngine,
    api: &Api<K>,
    resource: &K,
    generation: MutationGeneration,
    force: bool,
    exact_when_trusted: bool,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + Serialize + DeserializeOwned,
{
    let name = resource
        .meta()
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
    let post_params = PostParams {
        field_manager: Some(engine.config().field_manager.clone()),
        ..PostParams::default()
    };
    let mut force_against: Option<String> = None;
    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => Some(current),
            Err(kube::Error::Api(error)) if error.code == 404 => None,
            Err(error) => return Err(error.into()),
        };

        if let Some(current) = current {
            ensure_not_stale(&current, generation)?;
            let trusted = only_trusted_field_managers(&current, &engine.config().field_manager);
            // A forced reclaim is authorized only against the exact
            // resourceVersion whose ownership was classified: any foreign
            // write (including a pure ownership change) bumps the version,
            // silently deauthorizes the force, and falls back to the
            // no-force probe with a fresh classification.
            let authorized = force_against
                .as_deref()
                .is_some_and(|version| current.meta().resource_version.as_deref() == Some(version));
            let patch_params = if force || trusted || authorized {
                PatchParams::apply(&engine.config().field_manager).force()
            } else {
                PatchParams::apply(&engine.config().field_manager)
            };
            let resource_version = current
                .meta()
                .resource_version
                .clone()
                .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
            let mut desired = resource.clone();
            desired.meta_mut().resource_version = Some(resource_version.clone());
            annotate(&mut desired, generation);
            let applied = if exact_when_trusted && trusted {
                super::bounded_kube_write(api.replace(name, &post_params, &desired)).await
            } else {
                super::bounded_kube_write(api.patch(name, &patch_params, &Patch::Apply(&desired)))
                    .await
            };
            match applied {
                Ok(applied) => {
                    verify_applied_generation(&applied, generation)?;
                    return Ok(applied);
                }
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                    let conflicts = field_manager_conflict_fields(&error);
                    if conflicts.is_empty() {
                        // transient resourceVersion conflict: a forced
                        // reclaim never survives a version change
                        force_against = None;
                        tokio::time::sleep(conflict_retry_delay(attempt)).await;
                        continue;
                    }
                    if !authorized {
                        let mut stale_evidence = false;
                        let escalation = match api.get(name).await {
                            Ok(live) => {
                                // The failed PATCH's causes were evaluated
                                // against the exact version it submitted; a
                                // re-read at any other version cannot vouch
                                // for that cause list (a foreign writer may
                                // have taken fields the stale list omits).
                                // Re-probe instead of authorizing force.
                                let fresh =
                                    live.meta().resource_version.as_deref().is_some_and(
                                        |version| version == resource_version.as_str(),
                                    );
                                if !fresh {
                                    stale_evidence = true;
                                }
                                let reclaimable = fresh
                                    && conflicts_reclaimable_by_force(
                                        &live,
                                        &conflicts,
                                        &engine.config().field_manager,
                                    );
                                live.meta()
                                    .resource_version
                                    .clone()
                                    .filter(|version| !version.is_empty())
                                    .filter(|_| reclaimable)
                            }
                            Err(error) => return Err(error.into()),
                        };
                        if let Some(version) = escalation {
                            tracing::info!(
                                kind = kind::<K>(),
                                conflict_count = conflicts.len(),
                                "SSA conflicts limited to this manager's own Update ownership; forcing to reclaim own fields"
                            );
                            force_against = Some(version);
                            continue;
                        }
                        if stale_evidence {
                            // cause list predates the live object: fall back
                            // to a fresh no-force probe under the normal budget
                            tokio::time::sleep(conflict_retry_delay(attempt)).await;
                            continue;
                        }
                    }
                    tracing::warn!(
                        kind = kind::<K>(),
                        conflict_count = conflicts.len(),
                        "unresolved SSA field-manager conflict on externally owned fields; failing closed"
                    );
                    return Err(ApplyError::Kube(kube::Error::Api(error)));
                }
                Err(error) => return Err(error),
            }
        } else {
            let mut desired = resource.clone();
            desired.meta_mut().resource_version = None;
            desired.meta_mut().uid = None;
            annotate(&mut desired, generation);
            match super::bounded_kube_write(api.create(&post_params, &desired)).await {
                Ok(applied) => {
                    verify_applied_generation(&applied, generation)?;
                    return Ok(applied);
                }
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                    tokio::time::sleep(conflict_retry_delay(attempt)).await;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

/// Conditionally merge-patch an existing object with a partial JSON document.
///
/// The patch is attributed to `field_manager` so the API server records the
/// resulting Update ownership under the control plane's manager. Without it,
/// a merge PATCH defaults to an unrelated manager name, and its ownership of
/// the generation annotation would foreign-conflict every later apply.
pub async fn apply_existing_partial<K>(
    api: &Api<K>,
    name: &str,
    patch: &serde_json::Value,
    generation: MutationGeneration,
    field_manager: &str,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    let patch_params = PatchParams {
        field_manager: Some(field_manager.to_string()),
        ..PatchParams::default()
    };

    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => current,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Err(ApplyError::ResourceNotFound {
                    kind: kind::<K>(),
                    name: name.to_string(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        ensure_not_stale(&current, generation)?;
        let resource_version = current
            .meta()
            .resource_version
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        let mut desired = patch.clone();
        let metadata = desired
            .as_object_mut()
            .ok_or_else(|| ApplyError::ManifestGeneration("partial apply is not an object".into()))?
            .entry("metadata")
            .or_insert_with(|| serde_json::json!({}));
        let metadata = metadata.as_object_mut().ok_or_else(|| {
            ApplyError::ManifestGeneration("partial apply metadata is not an object".into())
        })?;
        metadata.insert("name".to_string(), serde_json::json!(name));
        metadata.insert(
            "resourceVersion".to_string(),
            serde_json::json!(resource_version),
        );
        let annotations = metadata
            .entry("annotations")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| {
                ApplyError::ManifestGeneration("partial apply annotations are not an object".into())
            })?;
        annotations.insert(
            MUTATION_GENERATION_ANNOTATION.to_string(),
            serde_json::json!(generation.get().to_string()),
        );

        // A partial SSA document would make this field manager relinquish
        // fields it owns but the patch omits. Preserve the prior merge-patch
        // behavior while adding an exact resourceVersion precondition and the
        // provider generation annotation.
        match super::bounded_kube_write(api.patch(name, &patch_params, &Patch::Merge(&desired)))
            .await
        {
            Ok(applied) => {
                verify_applied_generation(&applied, generation)?;
                return Ok(applied);
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                tokio::time::sleep(conflict_retry_delay(attempt)).await;
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

/// Delete the exact UID/resourceVersion observed after checking generation.
pub async fn delete_resource<K>(
    api: &Api<K>,
    name: &str,
    generation: MutationGeneration,
    mut delete_params: DeleteParams,
) -> Result<bool, ApplyError>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => current,
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        ensure_not_stale(&current, generation)?;
        let resource_version = current
            .meta()
            .resource_version
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        let uid = current
            .meta()
            .uid
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        delete_params.preconditions = Some(Preconditions {
            resource_version: Some(resource_version),
            uid: Some(uid),
        });
        match super::bounded_kube_write(api.delete(name, &delete_params)).await {
            Ok(_) => return Ok(true),
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 404 => {
                return Ok(false);
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                tokio::time::sleep(conflict_retry_delay(attempt)).await;
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::client::Body;
    use serde_json::{Value, json};
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use tower::service_fn;

    const RESOURCE_PATH: &str = "/api/v1/namespaces/fence-test/configmaps/fenced";
    const COLLECTION_PATH: &str = "/api/v1/namespaces/fence-test/configmaps";
    const STATEFULSET_PATH: &str = "/apis/apps/v1/namespaces/fence-test/statefulsets/fenced";

    #[test]
    fn conflict_retry_backoff_is_bounded() {
        assert_eq!(conflict_retry_delay(0), Duration::from_millis(25));
        assert_eq!(conflict_retry_delay(5), Duration::from_millis(800));
        assert_eq!(conflict_retry_delay(6), Duration::from_millis(800));
        assert_eq!(conflict_retry_delay(100), Duration::from_millis(800));
        // The total budget must stay patient (~45–90 s) so ordinary
        // controller churn cannot terminally fail a deployment, yet remain
        // far below the 180 s mutation lease and bounded job deadlines.
        let total: Duration = (0..MAX_CONFLICT_RETRIES).map(conflict_retry_delay).sum();
        assert!(total >= Duration::from_secs(45), "total {total:?}");
        assert!(total <= Duration::from_secs(90), "total {total:?}");
    }

    #[tokio::test]
    async fn concurrent_writer_churn_cannot_terminally_fail_apply() {
        // Regression (staging 2026-09-13): a Kubernetes controller bumping
        // resourceVersion for longer than the old ~1.9 s conflict budget made
        // apply_resource exhaust mutation conflicts and terminally fail the
        // deployment (live: gens 3d869f2c/69dff1f3/4b1b3ef7). A bounded
        // concurrent writer that stops must not defeat the apply.
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {"labels": {"app": "fenced"}},
                    "spec": {"containers": [{"name": "workload", "image": "example.test/workload:current"}]},
                },
            },
        }))
        .unwrap();

        // Controller-style concurrent writer: every PATCH/PUT of the fenced
        // resource is preempted by a resourceVersion bump for 2.5 s — beyond
        // the previous total budget (~1.9 s), inside the new one (~48 s).
        state.lock().unwrap().churn_until =
            Some(std::time::Instant::now() + Duration::from_millis(2500));

        let applied = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await;
        applied.expect("apply survives a bounded concurrent writer");
        let locked = state.lock().unwrap();
        assert_eq!(
            locked.resource.as_ref().unwrap()["metadata"]["annotations"]
                [MUTATION_GENERATION_ANNOTATION],
            "2"
        );
    }

    #[derive(Default)]
    struct Pause {
        next: bool,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    struct FakeState {
        resource: Option<Value>,
        next_resource_version: u64,
        pause_patch: Pause,
        pause_delete: Pause,
        pause_create: Pause,
        rejected_preconditions: usize,
        /// Server-side-apply PATCH requests received for the fenced resource.
        ssa_attempts: usize,
        /// When `Some`, the next forced SSA PATCH is preempted by a foreign
        /// writer that takes the container image and bumps the
        /// resourceVersion before the forced write is evaluated.
        hijack_next_force: Option<String>,
        /// When `Some`, the next no-force SSA PATCH that would return 409
        /// first has a foreign writer take `spec.template.spec.runtimeClassName`
        /// and bump the resourceVersion — then the already-evaluated (stale)
        /// cause list is returned, modeling the response-late race.
        hijack_next_conflict: Option<String>,
        /// PUT replacements received for the fenced resource.
        replace_attempts: usize,
        /// While `Some(until)`, every PATCH/PUT of the fenced resource first
        /// bumps its resourceVersion — a controller-style concurrent writer
        /// landing inside each read-modify-write window.
        churn_until: Option<std::time::Instant>,
    }

    impl FakeState {
        fn with_generation(generation: i64, value: &str) -> Self {
            Self {
                resource: Some(configmap_value(generation, "1", value)),
                next_resource_version: 2,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
            }
        }

        fn absent() -> Self {
            Self {
                resource: None,
                next_resource_version: 1,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
            }
        }

        fn with_statefulset() -> Self {
            Self {
                resource: Some(json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {
                        "name": "fenced",
                        "namespace": "fence-test",
                        "uid": "22222222-2222-2222-2222-222222222222",
                        "resourceVersion": "1",
                        "managedFields": [{
                            "manager": "enclava-platform",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {},
                        }],
                        "annotations": {
                            MUTATION_GENERATION_ANNOTATION: "1",
                            "unrelated-metadata": "preserved",
                        },
                    },
                    "spec": {
                        "replicas": 1,
                        "serviceName": "fenced-service",
                        "selector": { "matchLabels": { "app": "fenced" } },
                        "template": {
                            "metadata": {
                                "labels": { "app": "fenced" },
                                "annotations": { "unrelated-template": "preserved" },
                            },
                            "spec": {
                                "containers": [{
                                    "name": "workload",
                                    "image": "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }],
                            },
                        },
                    },
                })),
                next_resource_version: 2,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
            }
        }

        /// The tenant-c live shape (2026-09-14): CAP Update ownership of the
        /// generation annotation and workload spec, a separate
        /// replicas-only `kubectl-patch` Update entry from the drill, and a
        /// status-subresource writer. Provider generation 4.
        fn with_shared_statefulset() -> Self {
            Self {
                resource: Some(json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {
                        "name": "fenced",
                        "namespace": "fence-test",
                        "uid": "33333333-3333-3333-3333-333333333333",
                        "resourceVersion": "285805",
                        "managedFields": [
                            {
                                "manager": "enclava-platform",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {
                                    "f:metadata": {"f:annotations": {
                                        (format!("f:{}", MUTATION_GENERATION_ANNOTATION)): {},
                                    }},
                                    "f:spec": {
                                        "f:replicas": {},
                                        "f:serviceName": {},
                                        "f:template": {
                                            "f:metadata": {"f:annotations": {
                                                "f:unrelated-template": {},
                                            }},
                                        },
                                    },
                                },
                            },
                            {
                                "manager": "kubectl-patch",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {"f:spec": {"f:replicas": {}}},
                            },
                            {
                                "manager": "sts-controller",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {},
                                "subresource": "status",
                            },
                        ],
                        "annotations": {
                            MUTATION_GENERATION_ANNOTATION: "4",
                            "unrelated-metadata": "preserved",
                        },
                    },
                    "spec": {
                        "replicas": 1,
                        "serviceName": "fenced-service",
                        "selector": {"matchLabels": {"app": "fenced"}},
                        "template": {
                            "metadata": {
                                "labels": {"app": "fenced"},
                                "annotations": {"unrelated-template": "preserved"},
                            },
                            "spec": {
                                "containers": [{
                                    "name": "workload",
                                    "image": "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }],
                            },
                        },
                    },
                })),
                next_resource_version: 285806,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
            }
        }
    }

    fn configmap_value(generation: i64, resource_version: &str, value: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "namespace": "fence-test",
                "uid": "11111111-1111-1111-1111-111111111111",
                "resourceVersion": resource_version,
                "annotations": {
                    MUTATION_GENERATION_ANNOTATION: generation.to_string(),
                },
            },
            "data": { "value": value },
        })
    }

    fn desired(value: &str) -> ConfigMap {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "namespace": "fence-test",
            },
            "data": { "value": value },
        }))
        .expect("valid desired ConfigMap")
    }

    fn fake_client(state: Arc<Mutex<FakeState>>) -> kube::Client {
        kube::Client::new(
            service_fn(move |request| handle_request(request, Arc::clone(&state))),
            "default",
        )
    }

    async fn handle_request(
        request: Request<Body>,
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or_default().to_string();
        let content_type = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();

        if method == Method::GET && (path == RESOURCE_PATH || path == STATEFULSET_PATH) {
            return Ok(
                match state.lock().expect("fake state poisoned").resource.clone() {
                    Some(resource) => json_response(StatusCode::OK, resource),
                    None => status_response(StatusCode::NOT_FOUND, "NotFound"),
                },
            );
        }

        let pause = {
            let mut locked = state.lock().expect("fake state poisoned");
            let pause = match (method.clone(), path.as_str()) {
                (Method::PATCH, RESOURCE_PATH | STATEFULSET_PATH)
                | (Method::PUT, STATEFULSET_PATH) => &mut locked.pause_patch,
                (Method::DELETE, RESOURCE_PATH) => &mut locked.pause_delete,
                (Method::POST, COLLECTION_PATH) => &mut locked.pause_create,
                _ => {
                    return Err(io::Error::other(format!(
                        "unexpected fake Kubernetes request: {method} {path}"
                    )));
                }
            };
            if pause.next {
                pause.next = false;
                Some((pause.entered.clone(), pause.release.clone()))
            } else {
                None
            }
        };

        if let Some((entered, release)) = pause {
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                entered.notify_one();
                release.notified().await;
                let response = process_mutation(method, &query, &content_type, &body, state);
                let _ = response_tx.send(response);
            });
            return response_rx
                .await
                .map_err(|_| io::Error::other("detached provider response receiver closed"))?;
        }

        process_mutation(method, &query, &content_type, &body, state)
    }

    fn process_mutation(
        method: Method,
        query: &str,
        content_type: &str,
        body: &[u8],
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let payload: Value = serde_json::from_slice(body).map_err(io::Error::other)?;
        let mut locked = state.lock().expect("fake state poisoned");
        if matches!(method, Method::PATCH | Method::PUT)
            && locked
                .churn_until
                .is_some_and(|deadline| std::time::Instant::now() < deadline)
        {
            let rv = locked.next_resource_version;
            locked.next_resource_version += 1;
            if let Some(resource) = locked.resource.as_mut() {
                resource["metadata"]["resourceVersion"] = json!(rv.to_string());
            }
        }
        match method {
            Method::PUT => {
                let Some(current) = locked.resource.clone() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                if payload
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str)
                    != current
                        .pointer("/metadata/resourceVersion")
                        .and_then(Value::as_str)
                {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                let mut updated = payload;
                updated["metadata"]["uid"] = current["metadata"]["uid"].clone();
                updated["metadata"]["resourceVersion"] =
                    json!(locked.next_resource_version.to_string());
                let manager = query_param(query, "fieldManager").unwrap_or("fake-unknown");
                let owned = document_leaf_paths(&updated);
                record_update_ownership(&mut updated, &owned, manager, false);
                locked.replace_attempts += 1;
                locked.next_resource_version += 1;
                locked.resource = Some(updated);
                Ok(json_response(
                    StatusCode::OK,
                    locked.resource.clone().expect("resource was replaced"),
                ))
            }
            Method::PATCH => {
                let is_apply = content_type.contains("apply-patch");
                let force = query.contains("force=true");
                if is_apply
                    && force
                    && let Some(image) = locked.hijack_next_force.take()
                {
                    let bumped = locked.next_resource_version.to_string();
                    locked.next_resource_version += 1;
                    let resource = locked.resource.as_mut().expect("resource exists");
                    resource["spec"]["template"]["spec"]["containers"][0]["image"] = json!(image);
                    let managed = resource["metadata"]["managedFields"]
                        .as_array_mut()
                        .expect("managedFields present");
                    if !managed.iter().any(|entry| {
                        entry.get("manager").and_then(Value::as_str) == Some("tampering-controller")
                    }) {
                        managed.push(json!({
                            "manager": "tampering-controller",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {"f:spec": {"f:template": {"f:spec": {
                                "f:containers": {"k:{\"name\":\"workload\"}": {"f:image": {}}},
                            }}}},
                        }));
                    }
                    resource["metadata"]["resourceVersion"] = json!(bumped);
                }
                let Some(current) = locked.resource.clone() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                let expected = payload
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let actual = current
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                if expected != actual {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                let resource_version = locked.next_resource_version.to_string();
                locked.next_resource_version += 1;
                if is_apply {
                    // The API server defaults a PATCH without fieldManager to
                    // an unrelated manager name; merges sent by CAP carry it.
                    let manager = query_param(query, "fieldManager").unwrap_or("kubectl-patch");
                    locked.ssa_attempts += 1;
                    return Ok(apply_ssa(
                        &mut locked,
                        current,
                        &payload,
                        manager,
                        force,
                        resource_version,
                    ));
                }
                let mut updated = current;
                // ownership follows changed or added fields, as the API
                // server does for Update writers
                let owned: Vec<String> = document_leaf_paths(&payload)
                    .into_iter()
                    .filter(|path| {
                        value_at(&updated, path).as_ref() != value_at(&payload, path).as_ref()
                    })
                    .collect();
                merge_value(&mut updated, &payload);
                updated["metadata"]["resourceVersion"] = json!(resource_version);
                let manager = query_param(query, "fieldManager").unwrap_or("kubectl-patch");
                record_update_ownership(&mut updated, &owned, manager, true);
                locked.resource = Some(updated);
                Ok(json_response(
                    StatusCode::OK,
                    locked.resource.clone().expect("resource was updated"),
                ))
            }
            Method::POST => {
                if locked.resource.is_some() {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "AlreadyExists"));
                }
                let generation = payload
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        MUTATION_GENERATION_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| io::Error::other("create lacks generation"))?;
                let value = payload
                    .pointer("/data/value")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let resource_version = locked.next_resource_version.to_string();
                locked.next_resource_version += 1;
                let mut created = configmap_value(generation, &resource_version, value);
                let manager = query_param(query, "fieldManager").unwrap_or("fake-unknown");
                let owned = document_leaf_paths(&payload);
                record_update_ownership(&mut created, &owned, manager, false);
                locked.resource = Some(created);
                Ok(json_response(
                    StatusCode::CREATED,
                    locked.resource.clone().expect("resource was created"),
                ))
            }
            Method::DELETE => {
                let Some(current) = locked.resource.as_ref() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                let expected_rv = payload
                    .pointer("/preconditions/resourceVersion")
                    .and_then(Value::as_str);
                let expected_uid = payload
                    .pointer("/preconditions/uid")
                    .and_then(Value::as_str);
                let actual_rv = current
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let actual_uid = current.pointer("/metadata/uid").and_then(Value::as_str);
                if expected_rv != actual_rv || expected_uid != actual_uid {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                locked.resource = None;
                Ok(status_response(StatusCode::OK, "Success"))
            }
            _ => Err(io::Error::other("unexpected mutation method")),
        }
    }

    fn merge_value(target: &mut Value, patch: &Value) {
        let Value::Object(patch) = patch else {
            *target = patch.clone();
            return;
        };
        if !target.is_object() {
            *target = json!({});
        }
        let target = target.as_object_mut().expect("target was made an object");
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                merge_value(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }

    /// Test-local flattener for the fake API server. Deliberately NOT the
    /// production walker: it renders associative keys as `[name=x]` while
    /// the real API server quotes values (`[name="x"]`), so regressions
    /// that depend on bracket notation cannot silently pass through a
    /// shared formatter. Production rejects those entries fail-closed.
    fn fake_flatten_owned_paths(fields_v1: &Value) -> Option<Vec<String>> {
        fn walk(node: &Value, prefix: String, paths: &mut Vec<String>) -> Option<()> {
            let object = node.as_object()?;
            for (key, child) in object {
                let segment = match key.strip_prefix("f:") {
                    Some(field) => field.to_string(),
                    None => {
                        let list_key = key.strip_prefix("k:")?;
                        let value: std::collections::BTreeMap<String, Value> =
                            serde_json::from_str(list_key).ok()?;
                        if value.len() != 1 {
                            return None;
                        }
                        let (name, marker) = value.into_iter().next()?;
                        format!("[{}={}]", name, marker.as_str()?)
                    }
                };
                let path = if prefix.is_empty() || segment.starts_with('[') {
                    format!("{prefix}{segment}")
                } else {
                    format!("{prefix}.{segment}")
                };
                if child
                    .as_object()
                    .is_some_and(|children| children.is_empty())
                {
                    paths.push(path);
                } else {
                    walk(child, path, paths)?;
                }
            }
            Some(())
        }
        let mut paths = Vec::new();
        walk(fields_v1, String::new(), &mut paths)?;
        Some(paths)
    }

    fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
    }

    const OWNERSHIP_HOUSEKEEPING: &[&str] = &[
        "apiVersion",
        "kind",
        "name",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "managedFields",
    ];

    /// Apply-patch handling with SSA ownership semantics: owners conflict
    /// when the incoming apply modifies or adds one of their fields
    /// (identical values share ownership), same-manager Apply entries
    /// merge, and `force` accepts the write without modeling the server's
    /// field-by-field transfer out of losing owners.
    fn apply_ssa(
        state: &mut FakeState,
        current: Value,
        payload: &Value,
        manager: &str,
        force: bool,
        resource_version: String,
    ) -> Response<Body> {
        let mut conflicts: Vec<(String, String)> = Vec::new();
        if let Some(entries) = current
            .pointer("/metadata/managedFields")
            .and_then(Value::as_array)
        {
            for entry in entries {
                if entry.get("subresource").and_then(Value::as_str) == Some("status") {
                    continue;
                }
                let entry_manager = entry.get("manager").and_then(Value::as_str).unwrap_or("");
                let operation = entry
                    .get("operation")
                    .and_then(Value::as_str)
                    .unwrap_or("Update");
                if entry_manager == manager && operation == "Apply" {
                    continue;
                }
                let owned = entry.get("fieldsV1").and_then(fake_flatten_owned_paths);
                match owned {
                    None => conflicts.push((String::new(), entry_manager.to_string())),
                    Some(paths) => {
                        for path in paths {
                            let Some(desired) = value_at(payload, &path) else {
                                continue;
                            };
                            // Conflicts arise from modified or added fields
                            // for both Update and Apply ownership; applying
                            // an identical value shares ownership.
                            let conflicting = value_at(&current, &path).as_ref() != Some(&desired);
                            if conflicting {
                                conflicts.push((path, entry_manager.to_string()));
                            }
                        }
                    }
                }
            }
        }
        if !conflicts.is_empty() && !force {
            if let Some(runtime_class_name) = state.hijack_next_conflict.take() {
                // a foreign writer lands after the server evaluated the
                // conflicts but before the client reads the response: the
                // returned cause list is stale by construction
                let bumped = state.next_resource_version.to_string();
                state.next_resource_version += 1;
                if let Some(resource) = state.resource.as_mut() {
                    resource["spec"]["template"]["spec"]["runtimeClassName"] =
                        json!(runtime_class_name);
                    let managed = resource["metadata"]["managedFields"]
                        .as_array_mut()
                        .expect("managedFields present");
                    if !managed.iter().any(|entry| {
                        entry.get("manager").and_then(Value::as_str) == Some("tampering-controller")
                    }) {
                        managed.push(json!({
                            "manager": "tampering-controller",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {"f:spec": {"f:template": {"f:spec": {
                                "f:runtimeClassName": {},
                            }}}},
                        }));
                    }
                    resource["metadata"]["resourceVersion"] = json!(bumped);
                }
            }
            let causes: Vec<Value> = conflicts
                .iter()
                .map(|(field, loser)| {
                    json!({
                        "reason": "FieldManagerConflict",
                        "message": format!("conflict with \"{loser}\" using apps/v1"),
                        "field": format!(".{field}"),
                    })
                })
                .collect();
            return json_response(
                StatusCode::CONFLICT,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!(
                        "Apply failed with {} conflict{}: {}",
                        causes.len(),
                        if causes.len() == 1 { "" } else { "s" },
                        conflicts
                            .iter()
                            .map(|(_, loser)| format!("conflict with \"{loser}\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "reason": "Conflict",
                    "code": 409,
                    "details": { "causes": causes },
                }),
            );
        }
        let mut updated = current.clone();
        merge_value(&mut updated, payload);
        // ponytail: the fake does not model field-by-field ownership
        // transfer out of losing managers; the applier's Apply entry below
        // and the surviving foreign entries are what the regressions
        // assert. Add faithful transfer if a regression ever needs it.
        let owned_paths = document_leaf_paths(payload);
        updated["metadata"]["managedFields"] = updated
            .pointer("/metadata/managedFields")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if let Some(managed) = updated
            .pointer_mut("/metadata/managedFields")
            .and_then(Value::as_array_mut)
        {
            upsert_apply_entry(managed, manager, &owned_paths);
        }
        updated["metadata"]["resourceVersion"] = json!(resource_version);
        state.resource = Some(updated.clone());
        json_response(StatusCode::OK, updated)
    }

    /// Record Update ownership for a PUT/POST/merge-PATCH writer. Merge
    /// patches union into an existing entry; replaces rewrite it.
    fn record_update_ownership(resource: &mut Value, owned: &[String], manager: &str, merge: bool) {
        let metadata = resource
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .expect("mutation carries metadata");
        let entries = metadata
            .entry("managedFields")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("managedFields is an array");
        if merge {
            // Update writes acquire the changed fields, removing those
            // claims from other owners; entries left owning nothing drop.
            // ponytail: paths whose final segment contains dots (annotation
            // keys) are not removed from other owners — no fixture relies on
            // that transfer; add greedy matching if one ever does.
            for entry in entries.iter_mut().filter(|entry| {
                entry.get("manager").and_then(Value::as_str) != Some(manager)
                    && entry.get("subresource").is_none()
            }) {
                if let Some(fields) = entry.get_mut("fieldsV1") {
                    for path in owned {
                        remove_path(
                            fields,
                            &split_path(path)
                                .iter()
                                .map(|s| fkey_for(s))
                                .collect::<Vec<_>>(),
                        );
                    }
                }
            }
            entries.retain(|entry| {
                entry.get("subresource").is_some()
                    || entry
                        .get("fieldsV1")
                        .and_then(Value::as_object)
                        .is_some_and(|fields| !fields.is_empty())
            });
        }
        let existing = entries.iter_mut().find(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some(manager)
                && entry.get("subresource").is_none()
                && entry.get("operation").and_then(Value::as_str) == Some("Update")
        });
        match existing {
            Some(entry) if merge => {
                let mut tree = entry.get("fieldsV1").cloned().unwrap_or_else(|| json!({}));
                merge_fields_tree(&mut tree, &build_fields_tree(owned));
                entry["fieldsV1"] = tree;
            }
            _ => {
                entries.retain(|entry| {
                    entry.get("manager").and_then(Value::as_str) != Some(manager)
                        || entry.get("subresource").is_some()
                        || entry.get("operation").and_then(Value::as_str) != Some("Update")
                });
                entries.push(json!({
                    "manager": manager,
                    "operation": "Update",
                    "apiVersion": "v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": build_fields_tree(owned),
                }));
            }
        }
    }

    fn remove_path(node: &mut Value, keys: &[String]) {
        let Some((first, rest)) = keys.split_first() else {
            return;
        };
        let Some(child) = node.get_mut(first) else {
            return;
        };
        if rest.is_empty() {
            node.as_object_mut().map(|object| object.remove(first));
            return;
        }
        remove_path(child, rest);
        if child
            .as_object()
            .is_some_and(|children| children.is_empty())
        {
            node.as_object_mut().map(|object| object.remove(first));
        }
    }

    fn upsert_apply_entry(managed: &mut Vec<Value>, manager: &str, paths: &[String]) {
        let tree = build_fields_tree(paths);
        if let Some(entry) = managed.iter_mut().find(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some(manager)
                && entry.get("subresource").is_none()
                && entry.get("operation").and_then(Value::as_str) == Some("Apply")
        }) {
            let mut merged = entry.get("fieldsV1").cloned().unwrap_or_else(|| json!({}));
            merge_fields_tree(&mut merged, &tree);
            entry["fieldsV1"] = merged;
        } else {
            managed.push(json!({
                "manager": manager,
                "operation": "Apply",
                "apiVersion": "apps/v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": tree,
            }));
        }
    }

    fn merge_fields_tree(target: &mut Value, patch: &Value) {
        let Some(patch) = patch.as_object() else {
            return;
        };
        if !target.is_object() {
            *target = json!({});
        }
        let target = target.as_object_mut().expect("target was made an object");
        for (key, value) in patch {
            let entry = target.entry(key.clone()).or_insert_with(|| json!({}));
            if value
                .as_object()
                .is_some_and(|children| !children.is_empty())
                && entry.is_object()
            {
                merge_fields_tree(entry, value);
            } else if !entry.is_object() {
                *entry = value.clone();
            }
        }
    }

    /// Split a dotted path into segments, keeping associative `[...]`
    /// suffixes attached to their segment.
    fn split_path(path: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut depth = 0usize;
        for character in path.chars() {
            match character {
                '[' => {
                    depth += 1;
                    current.push(character);
                }
                ']' => {
                    depth = depth.saturating_sub(1);
                    current.push(character);
                }
                '.' if depth == 0 => {
                    if !current.is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(character),
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    /// Resolve an owned-path string against a document. Object keys are
    /// matched greedily so annotation keys containing dots resolve.
    fn value_at<'a>(node: &'a Value, rest: &str) -> Option<&'a Value> {
        if rest.is_empty() {
            return Some(node);
        }
        if rest.starts_with('[') {
            let end = rest.find(']')?;
            let marker = &rest[1..end];
            let (key, expected) = marker.split_once('=')?;
            let element = node
                .as_array()?
                .iter()
                .find(|element| element.get(key).and_then(Value::as_str) == Some(expected))?;
            return value_at(element, rest[end + 1..].trim_start_matches('.'));
        }
        let object = node.as_object()?;
        let key = object
            .keys()
            .filter(|key| rest.starts_with(key.as_str()))
            .filter(|key| {
                matches!(
                    rest.as_bytes().get(key.len()),
                    None | Some(b'.') | Some(b'[')
                )
            })
            .max_by_key(|key| key.len())?;
        let after = &rest[key.len()..];
        let after = after.strip_prefix('.').unwrap_or(after);
        value_at(object.get(key)?, after)
    }

    /// Leaf paths a document claims, in owned-path notation.
    fn document_leaf_paths(document: &Value) -> Vec<String> {
        let mut paths = Vec::new();
        collect_leaf_paths(document, String::new(), &mut paths);
        paths
    }

    fn collect_leaf_paths(node: &Value, prefix: String, paths: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    // identity and housekeeping fields are never owned; only
                    // top-level and metadata keys match, container names must
                    // survive so associative keys resolve
                    if (prefix.is_empty() || prefix == "metadata")
                        && OWNERSHIP_HOUSEKEEPING.contains(&key.as_str())
                    {
                        continue;
                    }
                    collect_leaf_paths(value, join_path(&prefix, key), paths);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let segment = match item.get("name").and_then(Value::as_str) {
                        Some(name) => format!("[name={name}]"),
                        None => format!("[{index}]"),
                    };
                    collect_leaf_paths(item, join_path(&prefix, &segment), paths);
                }
            }
            _ => paths.push(prefix),
        }
    }

    fn join_path(prefix: &str, segment: &str) -> String {
        if prefix.is_empty() {
            segment.to_string()
        } else if segment.starts_with('[') {
            format!("{prefix}{segment}")
        } else {
            format!("{prefix}.{segment}")
        }
    }

    fn build_fields_tree(paths: &[String]) -> Value {
        let mut root = json!({});
        for path in paths {
            let mut node = &mut root;
            for segment in split_path(path) {
                let key = fkey_for(&segment);
                node = node
                    .as_object_mut()
                    .expect("fields tree nodes are objects")
                    .entry(key)
                    .or_insert_with(|| json!({}));
            }
        }
        root
    }

    fn fkey_for(segment: &str) -> String {
        if let Some(marker) = segment
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
        {
            let (key, value) = marker.split_once('=').expect("associative marker");
            format!("k:{{\"{key}\":\"{value}\"}}")
        } else {
            format!("f:{segment}")
        }
    }

    fn json_response(status: StatusCode, value: Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&value).expect("serialize fake response"),
            ))
            .expect("build fake response")
    }

    fn status_response(status: StatusCode, reason: &str) -> Response<Body> {
        json_response(
            status,
            json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": if status.is_success() { "Success" } else { "Failure" },
                "reason": reason,
                "message": reason,
                "code": status.as_u16(),
            }),
        )
    }

    async fn wait_for_rejection(state: &Arc<Mutex<FakeState>>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state
                    .lock()
                    .expect("fake state poisoned")
                    .rejected_preconditions
                    > 0
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached provider handler completed");
    }

    #[tokio::test]
    async fn detached_old_ssa_cannot_overwrite_newer_generation() {
        let state = Arc::new(Mutex::new(FakeState::with_generation(1, "initial")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_patch.next = true;
            (
                locked.pause_patch.entered.clone(),
                locked.pause_patch.release.clone(),
            )
        };
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let old_engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let old_api: Api<ConfigMap> = Api::namespaced(old_engine.client().clone(), "fence-test");
        let old = tokio::spawn(async move {
            apply_resource(
                &old_engine,
                &old_api,
                &desired("old"),
                MutationGeneration::new(1).unwrap(),
                false,
                false,
            )
            .await
        });
        entered.notified().await;
        old.abort();
        let _ = old.await;

        apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            false,
        )
        .await
        .expect("new generation applies");
        release.notify_one();
        wait_for_rejection(&state).await;

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource.pointer("/data/value").and_then(Value::as_str),
            Some("new")
        );
        assert_eq!(
            resource
                .pointer(&format!(
                    "/metadata/annotations/{}",
                    MUTATION_GENERATION_ANNOTATION
                        .replace('~', "~0")
                        .replace('/', "~1")
                ))
                .and_then(Value::as_str),
            Some("2")
        );
    }

    #[tokio::test]
    async fn detached_old_delete_cannot_remove_replacement_generation() {
        let state = Arc::new(Mutex::new(FakeState::with_generation(1, "initial")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_delete.next = true;
            (
                locked.pause_delete.entered.clone(),
                locked.pause_delete.release.clone(),
            )
        };
        let old_api: Api<ConfigMap> =
            Api::namespaced(fake_client(Arc::clone(&state)), "fence-test");
        let old = tokio::spawn(async move {
            delete_resource(
                &old_api,
                "fenced",
                MutationGeneration::new(1).unwrap(),
                DeleteParams::default(),
            )
            .await
        });
        entered.notified().await;
        old.abort();
        let _ = old.await;

        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");
        apply_resource(
            &engine,
            &api,
            &desired("replacement"),
            MutationGeneration::new(2).unwrap(),
            false,
            false,
        )
        .await
        .expect("replacement generation applies");
        release.notify_one();
        wait_for_rejection(&state).await;

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().expect("replacement remains live");
        assert_eq!(
            resource.pointer("/data/value").and_then(Value::as_str),
            Some("replacement")
        );
    }

    #[tokio::test]
    async fn canceled_absent_create_can_still_land_at_provider() {
        let state = Arc::new(Mutex::new(FakeState::absent()));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_create.next = true;
            (
                locked.pause_create.entered.clone(),
                locked.pause_create.release.clone(),
            )
        };
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");
        let create = tokio::spawn(async move {
            apply_resource(
                &engine,
                &api,
                &desired("created-after-cancel"),
                MutationGeneration::new(1).unwrap(),
                false,
                false,
            )
            .await
        });
        entered.notified().await;
        create.abort();
        let _ = create.await;
        release.notify_one();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state.lock().unwrap().resource.is_some() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached create lands despite client cancellation");

        let locked = state.lock().unwrap();
        assert_eq!(
            locked
                .resource
                .as_ref()
                .and_then(|resource| resource.pointer("/data/value"))
                .and_then(Value::as_str),
            Some("created-after-cancel")
        );
    }

    #[test]
    fn trusted_update_owner_can_be_reclaimed_without_ignoring_external_managers() {
        let trusted: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "managedFields": [
                    {"manager": "enclava-platform", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": {}},
                    {"manager": "controller", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": {}, "subresource": "status"}
                ]
            }
        }))
        .unwrap();
        assert!(only_trusted_field_managers(&trusted, "enclava-platform"));

        let mut external = trusted;
        external.metadata.managed_fields.as_mut().unwrap().push(
            serde_json::from_value(json!({
                "manager": "kubectl",
                "operation": "Update",
                "apiVersion": "v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": {}
            }))
            .unwrap(),
        );
        assert!(!only_trusted_field_managers(&external, "enclava-platform"));
    }

    #[tokio::test]
    async fn exact_trusted_update_prunes_omitted_statefulset_fields() {
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        state.lock().unwrap().resource.as_mut().unwrap()["spec"]["template"]["spec"]["containers"]
            [0]["volumeMounts"] = json!([{
            "name": "obsolete",
            "mountPath": "/obsolete",
        }]);
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {"labels": {"app": "fenced"}},
                    "spec": {"containers": [{"name": "workload", "image": "example.test/workload:current"}]},
                },
            },
        }))
        .unwrap();

        apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect("trusted StatefulSet is replaced exactly");

        let locked = state.lock().unwrap();
        assert!(
            locked.resource.as_ref().unwrap()["spec"]["template"]["spec"]["containers"][0]
                .get("volumeMounts")
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_writer_churn_cannot_terminally_fail_partial_apply() {
        // Regression (staging 2026-09-13, gen e3cf547b): the partial merge
        // path retried 409s with NO delay, exhausting any retry budget in
        // milliseconds against a controller-style concurrent writer.
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        state.lock().unwrap().churn_until =
            Some(std::time::Instant::now() + Duration::from_millis(2500));

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(2).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("partial apply survives a bounded concurrent writer");
        let locked = state.lock().unwrap();
        assert_eq!(locked.resource.as_ref().unwrap()["spec"]["replicas"], 0);
    }

    #[tokio::test]
    async fn partial_statefulset_mutations_preserve_unrelated_owned_fields() {
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(2).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("conditional scale merge applies");
        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "cap.enclava.dev/tenant-ingress-restarted-at": "now",
                            },
                        },
                    },
                },
            }),
            MutationGeneration::new(3).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("conditional restart merge applies");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(0)));
        assert_eq!(
            resource
                .pointer("/spec/serviceName")
                .and_then(Value::as_str),
            Some("fenced-service")
        );
        assert_eq!(
            resource
                .pointer("/spec/template/spec/containers/0/name")
                .and_then(Value::as_str),
            Some("workload")
        );
        assert_eq!(
            resource
                .pointer("/spec/template/metadata/annotations/unrelated-template")
                .and_then(Value::as_str),
            Some("preserved")
        );
        assert_eq!(
            resource
                .pointer("/metadata/annotations/unrelated-metadata")
                .and_then(Value::as_str),
            Some("preserved")
        );
    }

    fn annotation_pointer() -> String {
        format!(
            "/metadata/annotations/{}",
            MUTATION_GENERATION_ANNOTATION
                .replace('~', "~0")
                .replace('/', "~1")
        )
    }

    fn desired_shared_statefulset(image: &str) -> StatefulSet {
        serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {
                        "labels": {"app": "fenced"},
                        "annotations": {"unrelated-template": "preserved"},
                    },
                    "spec": {
                        "runtimeClassName": "kata-clh-snp",
                        "containers": [{
                            "name": "workload",
                            "image": image,
                        }],
                    },
                },
            },
        }))
        .expect("valid desired StatefulSet")
    }

    #[tokio::test]
    async fn replicas_owner_cannot_block_new_generation_apply() {
        // Regression (staging tenant-c 2026-09-14, live gens
        // 170b352b/e3cf547b/966b7531): against the live object — CAP Update
        // ownership of the generation annotation plus a lingering
        // replicas-only kubectl-patch Update entry at provider generation 4 —
        // the no-force SSA path conflicted with CAP's own Update entry on
        // every new generation and exhausted the whole conflict budget with
        // MutationConflictExhausted. Succeeding against this exact state is
        // the fix's acceptance condition.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let applied = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await;
        applied.expect("new generation applies against the shared live object");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("5")
        );
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(1)));
        let managed = resource
            .pointer("/metadata/managedFields")
            .and_then(Value::as_array)
            .expect("managedFields present");
        // the replicas owner keeps its metadata: we reconciled our own
        // fields, we did not absorb the foreign entry
        let replicas_owner = managed
            .iter()
            .find(|entry| entry.get("manager").and_then(Value::as_str) == Some("kubectl-patch"))
            .expect("replicas owner survives the forced self-reclaim");
        assert!(
            replicas_owner
                .pointer("/fieldsV1/f:spec/f:replicas")
                .is_some()
        );
        assert!(managed.iter().any(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some("enclava-platform")
                && entry.get("operation").and_then(Value::as_str) == Some("Apply")
        }));
    }

    #[tokio::test]
    async fn externally_owned_field_change_fails_closed_promptly() {
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        {
            let mut locked = state.lock().unwrap();
            let resource = locked.resource.as_mut().unwrap();
            // an external manager owns the workload image and the live value
            // differs from the desired one (follower-attacker shape)
            resource["metadata"]["managedFields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "manager": "tampering-controller",
                    "operation": "Update",
                    "apiVersion": "apps/v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": {"f:spec": {"f:template": {"f:spec": {"f:containers": {
                        "k:{\"name\":\"workload\"}": {"f:image": {}},
                    }}}}},
                }));
            resource["spec"]["template"]["spec"]["containers"][0]["image"] = json!(
                "example.test/workload@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            );
        }
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("externally owned field change must fail closed");
        match error {
            ApplyError::Kube(kube::Error::Api(status)) => {
                assert_eq!(status.code, 409);
                let causes = status.details.expect("conflict details").causes;
                assert!(causes.iter().any(|cause| {
                    cause.reason == "FieldManagerConflict" && cause.field.contains("image")
                }));
            }
            other => panic!("expected a Kubernetes API conflict, got {other:?}"),
        }
        assert_eq!(
            state.lock().unwrap().ssa_attempts,
            1,
            "unresolved ownership conflicts must fail on the first attempt"
        );
        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[tokio::test]
    async fn dr_scale_resume_then_new_generation_apply_converges() {
        // The supported DR maintenance path must not create foreign
        // ownership that later deploys cannot pass: partials attributed to
        // the control plane's field manager stay self-reclaimable.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(5).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("DR scale to zero");
        assert_eq!(
            state.lock().unwrap().resource.as_ref().unwrap()["spec"]["replicas"],
            0
        );
        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 1 },
            }),
            MutationGeneration::new(5).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("DR resume to one");

        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(6).unwrap(),
            false,
            true,
        )
        .await
        .expect("new generation apply after DR scale/resume converges");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("6")
        );
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(1)));
        // real Update semantics: the DR merge patches (attributed to CAP's
        // field manager) acquired spec.replicas, so the replicas-only
        // foreign owner was left with nothing and dropped, and the final
        // generation apply ran as an exact trusted replacement
        assert!(
            resource
                .pointer("/metadata/managedFields")
                .and_then(Value::as_array)
                .expect("managedFields present")
                .iter()
                .all(|entry| {
                    entry.get("subresource").is_some()
                        || entry.get("manager").and_then(Value::as_str) == Some("enclava-platform")
                })
        );
        assert_eq!(
            locked.replace_attempts, 1,
            "final apply used exact replacement"
        );
        assert_eq!(
            locked.ssa_attempts, 0,
            "no SSA probing on the trusted object"
        );
    }

    #[tokio::test]
    async fn unattributable_ownership_fails_closed_instead_of_forcing() {
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        {
            let mut locked = state.lock().unwrap();
            let resource = locked.resource.as_mut().unwrap();
            // fields this walker cannot attribute must count as foreign
            let kubectl = resource["metadata"]["managedFields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry.get("manager").and_then(Value::as_str) == Some("kubectl-patch"))
                .expect("replicas owner present");
            kubectl["fieldsV1"] = json!({"v:\"opaque\"": {}});
        }
        let live: StatefulSet =
            serde_json::from_value(state.lock().unwrap().resource.clone().unwrap()).unwrap();
        assert!(!conflicts_reclaimable_by_force(
            &live,
            &["metadata.annotations.enclava.dev/cap-provider-mutation-generation".to_string()],
            "enclava-platform",
        ));

        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("unattributable ownership must fail closed");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        assert_eq!(state.lock().unwrap().ssa_attempts, 1);
    }

    #[tokio::test]
    async fn foreign_write_during_escalation_deauthorizes_the_force() {
        // A forced reclaim is authorized only against the exact
        // resourceVersion whose ownership was classified. A foreign writer
        // taking the container image between classification and the forced
        // write must bump the resourceVersion, void the authorization, and
        // make the next classification fail closed instead of
        // force-overwriting the foreign value.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        state.lock().unwrap().hijack_next_force = Some(
            "example.test/workload@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        );
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("ownership change during escalation must fail closed");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        let locked = state.lock().unwrap();
        // no-force probe (1), deauthorized forced write rejected by the
        // resourceVersion precondition before evaluation, re-classifying
        // no-force probe (2)
        assert_eq!(locked.ssa_attempts, 2);
        assert_eq!(
            locked.rejected_preconditions, 1,
            "the forced write must be rejected against the bumped version"
        );
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer("/spec/template/spec/containers/0/image")
                .and_then(Value::as_str),
            Some(
                "example.test/workload@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            ),
            "the foreign value must not be force-overwritten"
        );
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[tokio::test]
    async fn stale_conflict_evidence_cannot_authorize_force() {
        // The 409's causes were evaluated against the version the failed
        // PATCH submitted. If a foreign writer takes a field (here
        // runtimeClassName) between that evaluation and the classification
        // re-read, the stale cause list omits it: the mismatched
        // resourceVersion must void the escalation and the fresh probe must
        // fail closed on the foreign field.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        state.lock().unwrap().hijack_next_conflict = Some("kata-tampered".to_string());
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("stale cause evidence must not authorize force");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        let locked = state.lock().unwrap();
        // stale-evidence probe (1), fresh probe failing closed (2); no
        // forced write is ever submitted
        assert_eq!(locked.ssa_attempts, 2);
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer("/spec/template/spec/runtimeClassName")
                .and_then(Value::as_str),
            Some("kata-tampered"),
            "the foreign runtime class must not be force-overwritten"
        );
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[test]
    fn server_quoted_cause_fields_classify_against_owned_subtrees() {
        // Literal API-server cause notation, independent of any formatter:
        // associative markers arrive quoted as [name="workload"].
        let live: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "fenced",
                "managedFields": [
                    {"manager": "enclava-platform", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": {}},
                    {"manager": "kubectl-patch", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1",
                     "fieldsV1": {"f:spec": {"f:containers": {}}}},
                ],
            },
        }))
        .unwrap();
        // a coarse external owner of spec.containers covers the bracketed
        // descendant and blocks the force
        assert!(!conflicts_reclaimable_by_force(
            &live,
            &["spec.containers[name=\"workload\"].image".to_string()],
            "enclava-platform",
        ));
        // an unrelated external leaf does not cover the annotation
        assert!(conflicts_reclaimable_by_force(
            &live,
            &["metadata.annotations.enclava.dev/cap-provider-mutation-generation".to_string()],
            "enclava-platform",
        ));
    }
}
