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
use std::fmt::Debug;

use super::engine::{ApplyEngine, ApplyError};

pub const MUTATION_GENERATION_ANNOTATION: &str = "enclava.dev/cap-provider-mutation-generation";
const MAX_CONFLICT_RETRIES: usize = 12;

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
/// it can update. Existing objects are SSA-patched with the exact observed
/// resourceVersion. Callers must durably prevent generation reclaim while an
/// initial create response is ambiguous, because an absent resource cannot
/// itself hold a tombstone.
pub async fn apply_resource<K>(
    engine: &ApplyEngine,
    api: &Api<K>,
    resource: &K,
    generation: MutationGeneration,
    force: bool,
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
    let patch_params = if force {
        PatchParams::apply(&engine.config().field_manager).force()
    } else {
        PatchParams::apply(&engine.config().field_manager)
    };

    for _ in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => Some(current),
            Err(kube::Error::Api(error)) if error.code == 404 => None,
            Err(error) => return Err(error.into()),
        };

        if let Some(current) = current {
            ensure_not_stale(&current, generation)?;
            let resource_version = current
                .meta()
                .resource_version
                .clone()
                .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
            let mut desired = resource.clone();
            desired.meta_mut().resource_version = Some(resource_version);
            annotate(&mut desired, generation);
            match super::bounded_kube_write(api.patch(name, &patch_params, &Patch::Apply(&desired)))
                .await
            {
                Ok(applied) => {
                    verify_applied_generation(&applied, generation)?;
                    return Ok(applied);
                }
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => continue,
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
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => continue,
                Err(error) => return Err(error),
            }
        }
    }

    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

/// Conditionally merge-patch an existing object with a partial JSON document.
pub async fn apply_existing_partial<K>(
    api: &Api<K>,
    name: &str,
    patch: &serde_json::Value,
    generation: MutationGeneration,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    let patch_params = PatchParams::default();

    for _ in 0..MAX_CONFLICT_RETRIES {
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
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => continue,
            Err(error) => return Err(error),
        }
    }

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
    for _ in 0..MAX_CONFLICT_RETRIES {
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
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => continue,
            Err(error) => return Err(error),
        }
    }

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
                (Method::PATCH, RESOURCE_PATH | STATEFULSET_PATH) => &mut locked.pause_patch,
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
                let response = process_mutation(method, &body, state);
                let _ = response_tx.send(response);
            });
            return response_rx
                .await
                .map_err(|_| io::Error::other("detached provider response receiver closed"))?;
        }

        process_mutation(method, &body, state)
    }

    fn process_mutation(
        method: Method,
        body: &[u8],
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let payload: Value = serde_json::from_slice(body).map_err(io::Error::other)?;
        let mut locked = state.lock().expect("fake state poisoned");
        match method {
            Method::PATCH => {
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
                let mut updated = current;
                merge_value(&mut updated, &payload);
                updated["metadata"]["resourceVersion"] = json!(resource_version);
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
                locked.resource = Some(configmap_value(generation, &resource_version, value));
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
}
