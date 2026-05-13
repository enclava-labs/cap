use enclava_engine::apply::drift::DriftResult;
use enclava_engine::apply::orchestrator::manifest_hash;
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::testutil::sample_app;

#[test]
fn drift_result_no_drift_when_hashes_match() {
    let result = DriftResult::compare("abc123", "abc123");
    assert!(!result.has_drift);
    assert_eq!(result.desired_hash, "abc123");
    assert_eq!(result.live_hash.as_deref(), Some("abc123"));
}

#[test]
fn drift_result_drifted_when_hashes_differ() {
    let result = DriftResult::compare("abc123", "def456");
    assert!(result.has_drift);
}

#[test]
fn drift_result_drifted_when_no_live_hash() {
    let result = DriftResult::missing("abc123");
    assert!(result.has_drift);
    assert!(result.live_hash.is_none());
}

#[test]
fn manifest_hash_is_consistent_for_drift() {
    let app = sample_app();
    let m1 = generate_all_manifests(&app);
    let m2 = generate_all_manifests(&app);
    assert_eq!(manifest_hash(&m1), manifest_hash(&m2));
}

#[test]
fn manifest_hash_changes_when_enclava_init_configmap_changes() {
    let app = sample_app();
    let mut m1 = generate_all_manifests(&app);
    let mut m2 = generate_all_manifests(&app);
    m2.enclava_init_configmap
        .data
        .as_mut()
        .unwrap()
        .insert("config.toml".to_string(), "tampered = true\n".to_string());

    assert_ne!(manifest_hash(&m1), manifest_hash(&m2));

    m1.enclava_init_configmap = m2.enclava_init_configmap.clone();
    assert_eq!(manifest_hash(&m1), manifest_hash(&m2));
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn check_drift_detects_missing_statefulset() {
    use enclava_engine::apply::drift::check_drift;
    use enclava_engine::apply::engine::ApplyEngine;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let manifests = generate_all_manifests(&app);

    let result = check_drift(&engine, &app, &manifests).await.unwrap();
    // No StatefulSet deployed -> drift detected
    assert!(result.has_drift);
    assert!(result.live_hash.is_none());
}

/// Integration test: no drift after fresh apply.
#[tokio::test]
#[ignore]
async fn check_drift_no_drift_after_apply() {
    use enclava_engine::apply::drift::check_drift;
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::orchestrator::apply_all;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();
    let manifests = generate_all_manifests(&app);

    apply_all(&engine, &manifests).await.unwrap();

    let result = check_drift(&engine, &app, &manifests).await.unwrap();
    assert!(!result.has_drift);

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}
