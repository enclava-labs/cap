/// Integration test: requires a running cluster.
/// Run with: cargo test -- --ignored
#[tokio::test]
#[ignore]
async fn apply_service_account_creates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::resources::apply_namespaced_resource;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::manifest::service_account::generate_service_account;
    use enclava_engine::testutil::sample_app;
    use k8s_openapi::api::core::v1::ServiceAccount;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    // Create namespace first
    let ns = generate_namespace(&app);
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    // Apply ServiceAccount
    let sa = generate_service_account(&app);
    let result: ServiceAccount =
        apply_namespaced_resource(&engine, &app.namespace, &sa, generation)
            .await
            .unwrap();
    assert_eq!(result.metadata.name.as_deref(), Some("cap-test-app-sa"));

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn apply_configmap_creates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::resources::apply_namespaced_resource;
    use enclava_engine::manifest::bootstrap::generate_bootstrap_configmap;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::testutil::sample_app;
    use k8s_openapi::api::core::v1::ConfigMap;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    let ns = generate_namespace(&app);
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    let cm = generate_bootstrap_configmap(&app);
    let result: ConfigMap = apply_namespaced_resource(&engine, &app.namespace, &cm, generation)
        .await
        .unwrap();
    assert!(result.metadata.name.is_some());

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}
