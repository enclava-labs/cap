use enclava_engine::apply::orchestrator::manifest_hash;
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::testutil::sample_app;

#[test]
fn manifest_hash_is_deterministic() {
    let app = sample_app();
    let manifests = generate_all_manifests(&app);
    let h1 = manifest_hash(&manifests);
    let h2 = manifest_hash(&manifests);
    assert_eq!(h1, h2);
}

#[test]
fn manifest_hash_is_64_hex_chars() {
    let app = sample_app();
    let manifests = generate_all_manifests(&app);
    let h = manifest_hash(&manifests);
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn manifest_hash_changes_with_different_app() {
    let app1 = sample_app();
    let mut app2 = sample_app();
    app2.name = "other-app".to_string();
    app2.namespace = "cap-test-org-other-app".to_string();

    let m1 = generate_all_manifests(&app1);
    let m2 = generate_all_manifests(&app2);

    assert_ne!(manifest_hash(&m1), manifest_hash(&m2));
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn apply_all_creates_full_stack() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_all;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let manifests = generate_all_manifests(&app);

    apply_all(&engine, &manifests, MutationGeneration::new(1).unwrap())
        .await
        .unwrap();

    // Verify namespace exists
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::Api;
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let ns = ns_api.get(&app.namespace).await.unwrap();
    assert_eq!(ns.metadata.name.as_deref(), Some(app.namespace.as_str()));

    // Verify StatefulSet exists
    use k8s_openapi::api::apps::v1::StatefulSet;
    let sts_api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), &app.namespace);
    let sts = sts_api.get(&app.name).await.unwrap();
    assert_eq!(sts.metadata.name.as_deref(), Some(app.name.as_str()));

    // Cleanup
    use kube::api::DeleteParams;
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}

/// Integration test: apply_all is idempotent.
#[tokio::test]
#[ignore]
async fn apply_all_is_idempotent() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_all;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let manifests = generate_all_manifests(&app);

    let generation = MutationGeneration::new(1).unwrap();
    apply_all(&engine, &manifests, generation).await.unwrap();
    // Second apply should succeed without errors
    apply_all(&engine, &manifests, generation).await.unwrap();

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}
