use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, PostParams};

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{
    MUTATION_GENERATION_ANNOTATION, MutationGeneration, NAMESPACE_CREATED_BY_ANNOTATION,
    apply_resource_opt,
};

/// Apply a Namespace via server-side apply.
///
/// This must succeed before any namespaced resources are applied.
/// Namespace apply deliberately does NOT force: a pre-existing namespace
/// not created by CAP may carry externally owned fields, and force-apply
/// would clobber them (and steal field ownership). Conflicts on such a
/// namespace fail closed instead. CAP-created namespaces are owned solely
/// by the trusted field manager and apply unchanged.
///
/// Creation evidence: the apply first GETs the namespace. Only when that
/// GET observes absence does this apply create the namespace with a direct
/// POST carrying [`NAMESPACE_CREATED_BY_ANNOTATION`] set to this
/// generation — the stamp is bound to the POST itself, so a 409 loser of
/// the create race can never carry it. A live namespace at the probe is
/// adopted, never stamped (any caller-supplied stamp is stripped), and
/// existing evidence is preserved verbatim. Probe errors fail the step
/// closed (no write happens), so ownership evidence is never fabricated
/// under uncertainty.
pub async fn apply_namespace(
    engine: &ApplyEngine,
    namespace: &Namespace,
    generation: MutationGeneration,
) -> Result<Namespace, ApplyError> {
    let name = namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    let api: Api<Namespace> = Api::all(engine.client().clone());

    // The ownership probe and the apply are retried as a unit when the
    // namespace vanishes between them: only the direct stamped POST may
    // create a namespace, so a mid-flight deletion must re-enter the
    // probe→(POST|adopt) flow instead of letting SSA create an unstamped
    // replacement.
    for _vanish_attempt in 0..3 {
        // Creation-evidence probe: only an observed absence authorizes the
        // creation stamp. Any probe error aborts the step so evidence can never
        // be fabricated for a namespace that might pre-exist.
        let probe = match api.get_opt(name).await {
            Ok(None) => NamespaceProbe::Absent,
            Ok(Some(live)) => match live
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(NAMESPACE_CREATED_BY_ANNOTATION))
            {
                Some(existing) => NamespaceProbe::AdoptedWithEvidence(existing.clone()),
                // A live namespace without the annotation predates this scheme
                // or was never created by CAP: adopt without fabricating
                // evidence.
                None => NamespaceProbe::AdoptedWithoutEvidence,
            },
            Err(error) => {
                tracing::warn!(
                    namespace = %name,
                    error = %error,
                    "namespace pre-apply probe failed; failing closed without applying"
                );
                return Err(ApplyError::Kube(error));
            }
        };

        let mut manifest = namespace.clone();
        match &probe {
            // Observed absence: this apply creates the namespace with a direct
            // POST. The stamp is bound to the POST body: a 409 loser of the
            // create race must never carry it into the follow-up SSA.
            NamespaceProbe::Absent => {
                // The POST carries BOTH annotations: the mutation-generation
                // stamp (so the created namespace is classifiable by failed-
                // apply cleanup exactly like an SSA-patched one) and the
                // creation evidence bound to this POST.
                let annotations = manifest
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default);
                annotations.insert(
                    NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                    generation.get().to_string(),
                );
                annotations.insert(
                    MUTATION_GENERATION_ANNOTATION.to_string(),
                    generation.get().to_string(),
                );
                let post_params = PostParams {
                    field_manager: Some(engine.config().field_manager.clone()),
                    ..PostParams::default()
                };
                match super::bounded_kube_write(api.create(&post_params, &manifest)).await {
                    Ok(created) => {
                        verify_creation_stamp(&created, generation)?;
                        tracing::info!(namespace = %name, created = true, "namespace created via POST");
                        return Ok(created);
                    }
                    Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                        // Another creator won the race: adopt, never stamp.
                        tracing::info!(
                            namespace = %name,
                            "namespace create raced with another creator; adopting without creation evidence"
                        );
                        let live = api.get(name).await.map_err(ApplyError::Kube)?;
                        adopt_manifest(&mut manifest, &live);
                        let patched = match apply_resource_opt(
                            engine, &api, &manifest, generation, false, false, false,
                        )
                        .await
                        {
                            Ok(patched) => patched,
                            Err(ApplyError::VanishedResource { .. }) => continue,
                            Err(error) => return Err(error),
                        };
                        tracing::info!(
                            namespace = %name,
                            created = false,
                            "namespace applied via SSA after create race"
                        );
                        return Ok(patched);
                    }
                    Err(error) => return Err(error),
                }
            }
            // Adopted namespace with earlier creation evidence: preserve it
            // verbatim — an earlier CAP generation may legitimately have created
            // the namespace, and that evidence must survive re-applies.
            NamespaceProbe::AdoptedWithEvidence(existing) => {
                manifest
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default)
                    .insert(
                        NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                        existing.clone(),
                    );
            }
            // Adopted without evidence: never fabricate creation proof, and
            // strip any caller-supplied stamp so a public caller cannot smuggle
            // ownership evidence onto an adopted namespace.
            NamespaceProbe::AdoptedWithoutEvidence => {
                if let Some(annotations) = manifest.metadata.annotations.as_mut() {
                    annotations.remove(NAMESPACE_CREATED_BY_ANNOTATION);
                }
            }
        }

        let patched = match apply_resource_opt(
            engine, &api, &manifest, generation, false, false, false,
        )
        .await
        {
            Ok(patched) => patched,
            Err(ApplyError::VanishedResource { .. }) => continue,
            Err(error) => return Err(error),
        };

        tracing::info!(
            namespace = %name,
            created = matches!(probe, NamespaceProbe::Absent),
            "namespace applied via SSA"
        );
        return Ok(patched);
    } // vanish-race retry loop

    // The namespace kept vanishing between probe and apply across all
    // attempts: fail closed rather than create without evidence.
    Err(ApplyError::NamespaceNotReady(format!(
        "namespace '{name}' repeatedly vanished between probe and apply"
    )))
}

/// Confirm the created object actually carries BOTH ownership annotations:
/// the creation stamp AND this generation's mutation-generation annotation
/// (the API server or a mutating admission policy could have dropped or
/// rewritten either). A created namespace missing its mutation annotation
/// would later be classified foreign/adopted by failed-apply cleanup and
/// left uncompensated, so creation must fail closed instead.
fn verify_creation_stamp(
    created: &Namespace,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let annotations = created.metadata.annotations.as_ref();
    let parse = |key: &str| {
        annotations
            .and_then(|annotations| annotations.get(key))
            .and_then(|raw| raw.parse::<i64>().ok())
    };
    if parse(NAMESPACE_CREATED_BY_ANNOTATION) == Some(generation.get())
        && parse(MUTATION_GENERATION_ANNOTATION) == Some(generation.get())
    {
        Ok(())
    } else {
        Err(ApplyError::NamespaceNotReady(
            "created namespace lost its creation-evidence or mutation-generation annotation"
                .to_string(),
        ))
    }
}

/// After a lost create race, normalize the manifest to the adoption rules:
/// preserve the winner's creation evidence if any, otherwise strip the
/// stamp this manifest was about to carry.
fn adopt_manifest(manifest: &mut Namespace, live: &Namespace) {
    let existing = live
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(NAMESPACE_CREATED_BY_ANNOTATION))
        .cloned();
    match existing {
        Some(evidence) => {
            manifest
                .metadata
                .annotations
                .get_or_insert_with(Default::default)
                .insert(NAMESPACE_CREATED_BY_ANNOTATION.to_string(), evidence);
        }
        None => {
            if let Some(annotations) = manifest.metadata.annotations.as_mut() {
                annotations.remove(NAMESPACE_CREATED_BY_ANNOTATION);
            }
        }
    }
}

/// Outcome of the pre-apply namespace probe in [`apply_namespace`].
#[derive(Debug, Default)]
enum NamespaceProbe {
    /// The GET observed absence: this apply is the creator.
    #[default]
    Absent,
    /// A live namespace carries a previous generation's creation evidence.
    AdoptedWithEvidence(String),
    /// A live namespace without creation evidence: adopted, never stamped.
    AdoptedWithoutEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use kube::client::Body;
    use serde_json::{Value, json};
    use std::io;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    use super::super::generation::MUTATION_GENERATION_ANNOTATION;

    /// Shared fake Kubernetes API server for namespace apply. `live`
    /// controls the GET answer; the create POST either succeeds or 409s
    /// (`reject_create`), and after a rejected create the namespace is
    /// live (the race winner's object).
    #[derive(Clone, Default)]
    struct FakeServer {
        /// Annotations of the live namespace, if it is live at probe time.
        live: Option<std::collections::BTreeMap<String, String>>,
        /// 409 the create POST (another creator won the race).
        reject_create: bool,
        /// Annotations the race winner's namespace carries when it appears
        /// after a rejected create.
        winner_annotations: std::collections::BTreeMap<String, String>,
        /// 404 the SSA-time GET inside `apply_resource_opt` (the namespace
        /// vanished between the ownership probe and the apply): the apply
        /// must re-probe and create via the stamped POST, never let SSA
        /// create an unstamped replacement.
        vanish_before_patch: bool,
        /// Strip the mutation-generation annotation from the create
        /// response (a mutating admission policy rewrote it): the apply
        /// must fail closed instead of accepting the namespace.
        strip_mutation_from_create_response: bool,
    }

    #[derive(Default)]
    struct Recorded {
        gets: usize,
        /// The create POST body, if one was issued.
        create: Option<Value>,
        /// The SSA PATCH body, if one was issued.
        patch: Option<Value>,
    }

    async fn fake_namespace_server(
        config: FakeServer,
        recorded: Arc<Mutex<Recorded>>,
    ) -> kube::Client {
        // Flips to true after a rejected create: the winner's namespace
        // is now visible to GETs.
        let winner_appeared = Arc::new(Mutex::new(false));
        let service = service_fn(move |request: axum::http::Request<Body>| {
            let config = config.clone();
            let recorded = Arc::clone(&recorded);
            let winner_appeared = Arc::clone(&winner_appeared);
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .map_err(io::Error::other)?
                    .to_bytes();

                let live_annotations = if config.live.is_some() {
                    config.live.clone()
                } else if *winner_appeared.lock().expect("poisoned") {
                    Some(config.winner_annotations.clone())
                } else {
                    None
                };

                if method == axum::http::Method::GET && path == "/api/v1/namespaces/tenants" {
                    let mut locked = recorded.lock().expect("poisoned");
                    locked.gets += 1;
                    let gets = locked.gets;
                    drop(locked);
                    let live_annotations = if config.vanish_before_patch && gets > 1 {
                        // The namespace vanished after the ownership probe.
                        None
                    } else {
                        live_annotations
                    };
                    let response = match live_annotations {
                        Some(annotations) => {
                            let namespace = json!({
                                "apiVersion": "v1",
                                "kind": "Namespace",
                                "metadata": {
                                    "name": "tenants",
                                    "annotations": annotations,
                                    "resourceVersion": "1",
                                    "uid": "00000000-0000-0000-0000-000000000001",
                                }
                            });
                            axum::http::Response::builder()
                                .status(axum::http::StatusCode::OK)
                                .header(axum::http::header::CONTENT_TYPE, "application/json")
                                .body(Body::from(namespace.to_string().into_bytes()))
                        }
                        None => axum::http::Response::builder()
                            .status(axum::http::StatusCode::NOT_FOUND)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                r#"{"kind":"Status","reason":"NotFound","code":404}"#
                                    .as_bytes()
                                    .to_vec(),
                            )),
                    };
                    return response.map_err(|_| io::Error::other("build response"));
                }
                if method == axum::http::Method::POST && path == "/api/v1/namespaces" {
                    let mut value: Value =
                        serde_json::from_slice(&body).map_err(io::Error::other)?;
                    if config.strip_mutation_from_create_response
                        && let Some(annotations) = value
                            .pointer_mut("/metadata/annotations")
                            .and_then(Value::as_object_mut)
                    {
                        annotations.remove(MUTATION_GENERATION_ANNOTATION);
                    }
                    recorded.lock().expect("poisoned").create = Some(value.clone());
                    if config.reject_create {
                        *winner_appeared.lock().expect("poisoned") = true;
                        return axum::http::Response::builder()
                            .status(axum::http::StatusCode::CONFLICT)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                r#"{"kind":"Status","reason":"AlreadyExists","code":409}"#
                                    .as_bytes()
                                    .to_vec(),
                            ))
                            .map_err(|_| io::Error::other("build response"));
                    }
                    let response = echo_applied(value, axum::http::StatusCode::CREATED);
                    return Ok(response);
                }
                if method == axum::http::Method::PATCH && path == "/api/v1/namespaces/tenants" {
                    let value: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
                    recorded.lock().expect("poisoned").patch = Some(value.clone());
                    let response = echo_applied(value, axum::http::StatusCode::OK);
                    return Ok(response);
                }
                Err(io::Error::other(format!(
                    "unexpected fake request: {method} {path}"
                )))
            }
        });
        kube::Client::new(service, "default")
    }

    /// Echo an applied namespace object back with the mutation-generation
    /// annotation `apply_resource` verifies on the response.
    fn echo_applied(
        mut value: Value,
        status: axum::http::StatusCode,
    ) -> axum::http::Response<Body> {
        value["apiVersion"] = json!("v1");
        value["kind"] = json!("Namespace");
        let mut metadata = value
            .get_mut("metadata")
            .map(std::mem::take)
            .unwrap_or_else(|| json!({}));
        if metadata.get("name").is_none() {
            metadata["name"] = json!("tenants");
        }
        // The annotation is echoed verbatim from the request body (both the
        // stamped POST and apply_resource_opt's annotated writes carry it);
        // the fake must NOT inject it, or a response that legitimately lost
        // it (admission rewrite) could not be modeled.
        let annotations = metadata
            .get_mut("annotations")
            .map(std::mem::take)
            .unwrap_or_else(|| json!({}));
        metadata["annotations"] = annotations;
        metadata["resourceVersion"] = json!("2");
        metadata["uid"] = json!("00000000-0000-0000-0000-000000000001");
        value["metadata"] = metadata;
        axum::http::Response::builder()
            .status(status)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string().into_bytes()))
            .expect("build echo response")
    }

    fn test_namespace() -> Namespace {
        Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("tenants".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn generation(n: i64) -> MutationGeneration {
        MutationGeneration::new(n).expect("valid generation")
    }

    fn annotations_of(value: &Option<Value>) -> Option<&serde_json::Map<String, Value>> {
        value
            .as_ref()
            .and_then(|patch| patch.get("metadata"))
            .and_then(|metadata| metadata.get("annotations"))
            .and_then(|annotations| annotations.as_object())
    }

    #[tokio::test]
    async fn absent_namespace_is_created_with_creation_evidence() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(FakeServer::default(), Arc::clone(&recorded)).await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        assert!(
            locked.gets >= 1,
            "the pre-apply probe must observe absence before creating"
        );
        let create = locked.create.clone().expect("POST carried a body");
        let create_body = Some(create);
        let annotations = annotations_of(&create_body).expect("POST carried annotations");
        assert_eq!(
            annotations.get(NAMESPACE_CREATED_BY_ANNOTATION),
            Some(&json!("7")),
            "the POST body carries this generation's creation evidence"
        );
        assert_eq!(
            annotations.get(MUTATION_GENERATION_ANNOTATION),
            Some(&json!("7")),
            "the POST body also carries the mutation-generation annotation so cleanup can classify the created namespace"
        );
        assert!(
            locked.patch.is_none(),
            "no SSA patch is needed when the POST succeeds"
        );
    }

    #[tokio::test]
    async fn created_namespace_missing_mutation_annotation_fails_closed() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        // A mutating admission policy strips only the mutation-generation
        // annotation from the created object: without verification the
        // created namespace would later be classified foreign/adopted by
        // failed-apply cleanup and never compensated. Creation must fail.
        let client = fake_namespace_server(
            FakeServer {
                strip_mutation_from_create_response: true,
                ..Default::default()
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        let error = apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect_err("missing mutation annotation must fail creation");
        assert!(
            matches!(error, ApplyError::NamespaceNotReady(_)),
            "expected NamespaceNotReady, got {error:?}"
        );
    }

    #[tokio::test]
    async fn adopted_namespace_without_evidence_is_never_stamped() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(
            FakeServer {
                live: Some(Default::default()),
                ..Default::default()
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        assert!(
            locked.create.is_none(),
            "a live namespace must not be POST-created"
        );
        let annotations = annotations_of(&locked.patch).expect("SSA carried annotations");
        assert!(
            !annotations.contains_key(NAMESPACE_CREATED_BY_ANNOTATION),
            "a foreign pre-existing namespace must never gain creation evidence"
        );
    }

    #[tokio::test]
    async fn caller_supplied_stamp_is_stripped_from_adopted_namespace() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(
            FakeServer {
                live: Some(Default::default()),
                ..Default::default()
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        let mut smuggled = test_namespace();
        smuggled
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(NAMESPACE_CREATED_BY_ANNOTATION.to_string(), "7".to_string());
        apply_namespace(&engine, &smuggled, generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        let annotations = annotations_of(&locked.patch).expect("SSA carried annotations");
        assert!(
            !annotations.contains_key(NAMESPACE_CREATED_BY_ANNOTATION),
            "a caller-supplied creation stamp must be stripped on adoption"
        );
    }

    #[tokio::test]
    async fn prior_creators_evidence_survives_reapply() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(
            FakeServer {
                live: Some(std::collections::BTreeMap::from([(
                    NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                    "3".to_string(),
                )])),
                ..Default::default()
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        let annotations = annotations_of(&locked.patch).expect("SSA carried annotations");
        assert_eq!(
            annotations.get(NAMESPACE_CREATED_BY_ANNOTATION),
            Some(&json!("3")),
            "re-applies preserve the original creator's generation, not their own"
        );
    }

    #[tokio::test]
    async fn lost_create_race_adopts_without_stamping() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        // The probe sees absence; the create POST 409s; the winner's
        // namespace (without evidence) then appears.
        let client = fake_namespace_server(
            FakeServer {
                live: None,
                reject_create: true,
                winner_annotations: Default::default(),
                vanish_before_patch: false,
                strip_mutation_from_create_response: false,
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        assert!(
            locked.create.is_some(),
            "the create was attempted (and rejected)"
        );
        let annotations = annotations_of(&locked.patch).expect("SSA carried annotations");
        assert!(
            !annotations.contains_key(NAMESPACE_CREATED_BY_ANNOTATION),
            "a lost create race must fall back to adoption without the stamp"
        );
    }

    #[tokio::test]
    async fn lost_create_race_preserves_winners_evidence() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(
            FakeServer {
                live: None,
                reject_create: true,
                vanish_before_patch: false,
                strip_mutation_from_create_response: false,
                winner_annotations: std::collections::BTreeMap::from([(
                    NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                    "5".to_string(),
                )]),
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds");

        let locked = recorded.lock().expect("poisoned");
        let annotations = annotations_of(&locked.patch).expect("SSA carried annotations");
        assert_eq!(
            annotations.get(NAMESPACE_CREATED_BY_ANNOTATION),
            Some(&json!("5")),
            "the race winner's creation evidence is preserved, not overwritten"
        );
    }

    #[tokio::test]
    async fn vanished_namespace_reenters_stamped_create_flow() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let client = fake_namespace_server(
            FakeServer {
                live: Some(Default::default()),
                vanish_before_patch: true,
                ..Default::default()
            },
            Arc::clone(&recorded),
        )
        .await;
        let engine = ApplyEngine::new(client, Default::default());

        apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect("apply succeeds after vanish-race retry");

        let locked = recorded.lock().expect("poisoned");
        assert!(
            locked.create.is_some(),
            "the apply must re-enter the stamped-POST create flow after the namespace vanishes"
        );
        let create = locked.create.clone().expect("POST carried a body");
        let create_body = Some(create);
        let annotations = annotations_of(&create_body).expect("POST carried annotations");
        assert_eq!(
            annotations.get(NAMESPACE_CREATED_BY_ANNOTATION),
            Some(&json!("7")),
            "the replacement namespace is created WITH creation evidence"
        );
        assert_eq!(
            annotations.get(MUTATION_GENERATION_ANNOTATION),
            Some(&json!("7")),
            "the replacement namespace carries the mutation-generation annotation"
        );
    }

    #[tokio::test]
    async fn probe_error_fails_closed_without_applying() {
        let service = service_fn(|_request: axum::http::Request<Body>| async {
            Err::<axum::http::Response<Body>, std::io::Error>(std::io::Error::other(
                "api server down",
            ))
        });
        let client = kube::Client::new(service, "default");
        let engine = ApplyEngine::new(client, Default::default());

        let error = apply_namespace(&engine, &test_namespace(), generation(7))
            .await
            .expect_err("probe failure must fail the step");
        assert!(
            matches!(error, ApplyError::Kube(_)),
            "probe errors surface as kube errors, got {error:?}"
        );
    }
}
