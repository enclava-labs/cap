use enclava_engine::apply::cleanup::CleanupReport;

#[test]
fn cleanup_report_starts_empty() {
    let report = CleanupReport::new();
    assert!(report.steps.is_empty());
    assert!(report.is_success());
}

#[test]
fn cleanup_report_tracks_successes() {
    let mut report = CleanupReport::new();
    report.record_success("scale_to_zero");
    report.record_success("delete_statefulset");
    assert_eq!(report.steps.len(), 2);
    assert!(report.is_success());
}

#[test]
fn cleanup_report_tracks_failures() {
    let mut report = CleanupReport::new();
    report.record_success("scale_to_zero");
    report.record_failure("delete_pvcs", "PVC finalizer stuck after 120s");
    report.record_success("delete_namespace");
    assert_eq!(report.steps.len(), 3);
    assert!(!report.is_success());
}

#[test]
fn cleanup_report_failure_messages() {
    let mut report = CleanupReport::new();
    report.record_failure("delete_pvcs", "PVC finalizer stuck");
    let failures = report.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, "delete_pvcs");
    assert_eq!(failures[0].1, "PVC finalizer stuck");
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn cleanup_handles_nonexistent_namespace() {
    use enclava_engine::apply::cleanup::delete_namespace_and_wait;
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;

    let engine = ApplyEngine::try_default().await.unwrap();

    // Deleting a non-existent namespace should succeed (already gone)
    let result = delete_namespace_and_wait(
        &engine,
        "nonexistent-ns-for-cleanup-test",
        std::time::Duration::from_secs(5),
        MutationGeneration::new(1).unwrap(),
    )
    .await;
    assert!(result.is_ok());
}
