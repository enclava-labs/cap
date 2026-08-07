/// Integration test: requires a running cluster with kata-qemu-snp runtime.
/// Run with: cargo test -- --ignored
#[tokio::test]
#[ignore]
async fn apply_statefulset_creates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::statefulset::apply_statefulset;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::manifest::statefulset::generate_statefulset;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    // Create namespace first
    let ns = generate_namespace(&app);
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    // Apply StatefulSet
    let sts = generate_statefulset(&app);
    let result = apply_statefulset(&engine, &app.namespace, &sts, generation)
        .await
        .unwrap();
    assert_eq!(result.metadata.name.as_deref(), Some(&*app.name));

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}
