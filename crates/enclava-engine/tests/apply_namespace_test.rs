/// Integration test: requires a running cluster.
/// Run with: cargo test -- --ignored
#[tokio::test]
#[ignore]
async fn apply_namespace_creates_and_updates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let ns = generate_namespace(&app);

    // First apply: creates
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    // Second apply: idempotent update
    apply_namespace(&engine, &ns, generation).await.unwrap();

    // Cleanup: delete namespace
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}

/// #138: namespace apply must not send `force=true` — a pre-existing
/// externally owned namespace must fail closed instead of being clobbered.
/// Uses a tower fake that records the SSA PATCH query string.
#[tokio::test]
async fn namespace_apply_does_not_force() {
    use axum::http::{Method, Request, Response, StatusCode};
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::testutil::sample_app;
    use http_body_util::BodyExt;
    use kube::client::Body;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    #[derive(Default)]
    struct Recorded {
        patch_queries: Vec<String>,
        resource: Option<serde_json::Value>,
    }

    let state = Arc::new(Mutex::new(Recorded::default()));
    let client_state = Arc::clone(&state);
    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| {
            let state = Arc::clone(&client_state);
            async move {
                let method = request.method().clone();
                let query = request.uri().query().unwrap_or_default().to_string();
                let path = request.uri().path().to_string();
                let _body = request
                    .into_body()
                    .collect()
                    .await
                    .map_err(std::io::Error::other)?
                    .to_bytes();
                let mut locked = state.lock().unwrap();
                if method == Method::GET && path.ends_with("/namespaces/cap-test-org-test-app") {
                    let resource = locked.resource.clone().unwrap_or_else(|| {
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "Namespace",
                            "metadata": {
                                "name": "cap-test-org-test-app",
                                "uid": "11111111-1111-1111-1111-111111111111",
                                "resourceVersion": "1",
                                "managedFields": [{
                                    "manager": "foreign-controller",
                                    "operation": "Update",
                                    "apiVersion": "v1",
                                    "fieldsType": "FieldsV1",
                                    "fieldsV1": {"f:metadata": {"f:labels": {"f:owner": {}}}},
                                }],
                            },
                        })
                    });
                    locked.resource = Some(resource.clone());
                    return Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Body::from(resource.to_string().into_bytes()))
                            .unwrap(),
                    );
                }
                if method == Method::PATCH {
                    locked.patch_queries.push(query.clone());
                    // An unforced SSA against foreign-owned fields returns a
                    // 409 FieldManagerConflict, which is the fail-closed
                    // outcome this test pins. force=true would have
                    // succeeded.
                    if query.contains("force=true") {
                        let applied = serde_json::json!({
                            "apiVersion": "v1", "kind": "Namespace",
                            "metadata": {"name": "cap-test-org-test-app", "resourceVersion": "2"},
                        });
                        locked.resource = Some(applied.clone());
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Body::from(applied.to_string().into_bytes()))
                            .unwrap());
                    }
                    let status = serde_json::json!({
                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "message": "Apply failed with 1 conflict: conflict with \"foreign-controller\" using v1",
                        "reason": "Conflict", "code": 409,
                        "details": {"causes": [{
                            "reason": "FieldManagerConflict",
                            "message": "conflict with \"foreign-controller\" using v1",
                            "field": ".metadata.labels.owner",
                        }]},
                    });
                    return Ok(Response::builder()
                        .status(StatusCode::CONFLICT)
                        .header("content-type", "application/json")
                        .body(Body::from(status.to_string().into_bytes()))
                        .unwrap());
                }
                Err(std::io::Error::other(format!(
                    "unexpected request {method} {path}"
                )))
            }
        }),
        "default",
    );

    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let ns = generate_namespace(&sample_app());

    // The apply must fail closed (foreign-owned namespace) and no request
    // may ever carry force=true.
    let outcome = apply_namespace(&engine, &ns, MutationGeneration::new(2).unwrap()).await;
    assert!(
        outcome.is_err(),
        "externally owned namespace must fail closed"
    );
    let queries = state.lock().unwrap().patch_queries.clone();
    assert!(!queries.is_empty(), "SSA must have been attempted");
    assert!(
        queries.iter().all(|q| !q.contains("force=true")),
        "namespace SSA must never force, got {queries:?}"
    );
}
