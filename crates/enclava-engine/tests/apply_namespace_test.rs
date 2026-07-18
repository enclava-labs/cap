use enclava_engine::apply::namespace::namespace_patch_params;

#[test]
fn patch_params_use_correct_field_manager() {
    let pp = namespace_patch_params("enclava-platform");
    assert_eq!(pp.field_manager.as_deref(), Some("enclava-platform"));
    assert!(pp.force);
}

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
