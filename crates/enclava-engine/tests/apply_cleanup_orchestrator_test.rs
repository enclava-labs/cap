/// Integration test: full cleanup cycle requires a running cluster.
#[tokio::test]
#[ignore]
async fn cleanup_app_handles_full_lifecycle() {
    use enclava_engine::apply::cleanup::cleanup_app;
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_all;
    use enclava_engine::manifest::generate_all_manifests;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let manifests = generate_all_manifests(&app);

    // Create all resources
    let generation = MutationGeneration::new(1).unwrap();
    apply_all(&engine, &manifests, generation).await.unwrap();

    // Cleanup
    let report = cleanup_app(&engine, &app, None, generation).await;
    // At least some steps should succeed
    assert!(!report.steps.is_empty());

    // Verify namespace is gone
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::Api;
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let result = ns_api.get(&app.namespace).await;
    assert!(result.is_err(), "namespace should be deleted");
}

/// Integration test: cleanup is resilient to missing resources.
#[tokio::test]
#[ignore]
async fn cleanup_app_handles_already_deleted() {
    use enclava_engine::apply::cleanup::cleanup_app;
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    // Cleanup with nothing deployed -- should not panic
    let report = cleanup_app(&engine, &app, None, MutationGeneration::new(1).unwrap()).await;
    assert!(!report.steps.is_empty());
}
