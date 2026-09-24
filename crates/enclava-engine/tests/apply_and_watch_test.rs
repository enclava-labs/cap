/// Integration test: requires a running cluster.
/// This test will likely time out because kata-qemu-snp runtime
/// won't be available in most test environments.
/// Validates the apply+watch integration path.
#[tokio::test]
#[ignore]
async fn apply_and_watch_completes_or_times_out() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;
    use std::time::Duration;

    let config = ApplyConfig {
        rollout_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_secs(2),
        ..Default::default()
    };
    let engine = ApplyEngine::try_with_config(config).await.unwrap();
    let app = sample_app();

    let status = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .unwrap();

    // In a test env without SEV-SNP, we expect timeout or failure, not Running
    assert!(
        status.is_terminal(),
        "expected terminal status, got {:?}",
        status.phase
    );

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}

/// Round-19 review (Codex P2): the engine's primary deployment entry must
/// run `validate_app` BEFORE `generate_all_manifests`. The checks were
/// previously opt-in and only the API-specific deploy paths invoked them,
/// so a CLI or service calling this public entry with a legacy/corrupt
/// `ConfidentialApp` reached Kubernetes with the malformed quantities,
/// domains, egress rules, or log-encryption metadata the change is meant
/// to block. The mock API double records every request: an invalid app
/// must fail validation with ZERO Kubernetes traffic.
#[tokio::test]
async fn apply_and_watch_rejects_invalid_app_before_any_kube_request() {
    use axum::http::{Request, Response};
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;
    use http_body_util::BodyExt as _;
    use kube::client::Body;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&requests);
    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| {
            let recorded = Arc::clone(&recorded);
            async move {
                recorded
                    .lock()
                    .unwrap()
                    .push(request.uri().path().to_string());
                let _ = request.into_body().collect().await;
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(200)
                        .body(Body::from(
                            serde_json::to_vec(&serde_json::json!({})).unwrap(),
                        ))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());

    let mut app = sample_app();
    // A legacy/corrupt value API admission would never persist.
    app.resources.cpu = "not-a-quantity".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("invalid app must be rejected at the deploy boundary");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "validation failure must surface as ManifestGeneration, got {err:?}"
    );
    assert_eq!(
        *requests.lock().unwrap(),
        Vec::<String>::new(),
        "an invalid app must never reach Kubernetes"
    );
}
