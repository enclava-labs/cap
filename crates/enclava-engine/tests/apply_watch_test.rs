use enclava_engine::apply::types::DeployPhase;
use enclava_engine::apply::watch::{
    PodSnapshot, classify_pod_phase, pod_label_selector, stale_terminating_pod_needs_force_delete,
};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use k8s_openapi::jiff::Timestamp;

#[test]
fn pending_pod_maps_to_pods_scheduled_or_tee_booting() {
    let snap = PodSnapshot {
        phase: Some("Pending".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    // Scheduled but not ready: TEE is booting
    assert_eq!(phase, DeployPhase::TeeBooting);
}

#[test]
fn pending_not_scheduled_maps_to_pods_scheduled() {
    let snap = PodSnapshot {
        phase: Some("Pending".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: false,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::PodsScheduled);
}

#[test]
fn running_ready_maps_to_running() {
    let snap = PodSnapshot {
        phase: Some("Running".to_string()),
        container_statuses_ready: true,
        init_containers_done: true,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Running);
}

#[test]
fn running_not_ready_maps_to_attesting() {
    let snap = PodSnapshot {
        phase: Some("Running".to_string()),
        container_statuses_ready: false,
        init_containers_done: true,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Attesting);
}

#[test]
fn failed_pod_maps_to_failed() {
    let snap = PodSnapshot {
        phase: Some("Failed".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Failed);
}

#[test]
fn unknown_phase_maps_to_tee_booting() {
    let snap = PodSnapshot {
        phase: Some("Unknown".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    // Unknown means the kubelet lost contact -- TEE VM may still be booting
    assert_eq!(phase, DeployPhase::TeeBooting);
}

#[test]
fn pod_label_selector_matches_generated_statefulset_labels() {
    assert_eq!(pod_label_selector("my-app"), "app=my-app");
}

#[test]
fn stale_terminating_pod_after_grace_needs_force_delete() {
    let deleted_at = Time(
        "2026-05-24T19:26:06Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let now = "2026-05-24T19:27:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let pod = Pod {
        metadata: ObjectMeta {
            deletion_timestamp: Some(deleted_at),
            deletion_grace_period_seconds: Some(30),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(stale_terminating_pod_needs_force_delete(&pod, now));
}

#[test]
fn fresh_or_finalized_terminating_pod_is_not_force_deleted() {
    let deleted_at = Time(
        "2026-05-24T19:26:06Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let fresh_now = "2026-05-24T19:26:20Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let stale_now = "2026-05-24T19:27:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let fresh_pod = Pod {
        metadata: ObjectMeta {
            deletion_timestamp: Some(deleted_at.clone()),
            deletion_grace_period_seconds: Some(30),
            ..Default::default()
        },
        ..Default::default()
    };
    let finalized_pod = Pod {
        metadata: ObjectMeta {
            deletion_timestamp: Some(deleted_at),
            deletion_grace_period_seconds: Some(30),
            finalizers: Some(vec!["example.com/finalizer".to_string()]),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!stale_terminating_pod_needs_force_delete(
        &fresh_pod, fresh_now
    ));
    assert!(!stale_terminating_pod_needs_force_delete(
        &finalized_pod,
        stale_now
    ));
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn watch_rollout_times_out_on_missing_statefulset() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::apply::watch::watch_rollout;
    use std::time::Duration;

    let config = ApplyConfig {
        rollout_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_secs(1),
        ..Default::default()
    };
    let engine = ApplyEngine::try_with_config(config).await.unwrap();

    let result = watch_rollout(&engine, "nonexistent-ns", "nonexistent-sts").await;
    assert!(result.is_err());
}
