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
