use enclava_engine::apply::types::DeployPhase;
use enclava_engine::apply::watch::{
    PodSnapshot, classify_pod_phase, pod_label_selector, pod_runtime_failure_message,
    pod_terminal_failure_code, stale_terminating_pod_needs_force_delete,
};
use k8s_openapi::api::core::v1::{
    ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, Pod,
    PodStatus,
};
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
fn terminal_pod_failure_does_not_retain_workload_controlled_name() {
    const SENSITIVE_POD_NAME: &str = "customer-secret-project-pod";
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(SENSITIVE_POD_NAME.to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Failed".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let code = pod_terminal_failure_code(&pod).expect("terminal failure code");
    assert_eq!(code, "pod_failed");
    assert!(!code.contains(SENSITIVE_POD_NAME));
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
fn running_pod_with_crashloop_after_start_error_reports_runtime_failure() {
    const WAITING_SECRET: &str = "waiting-message-secret=tenant-api-key";
    const TERMINATED_SECRET: &str = "terminated-message-secret=tenant-private-key";
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("tenant-secret-pod-name".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                image: "example.test/web@sha256:abc".to_string(),
                image_id: "example.test/web@sha256:abc".to_string(),
                ready: false,
                restart_count: 3,
                state: Some(ContainerState {
                    waiting: Some(ContainerStateWaiting {
                        reason: Some("CrashLoopBackOff".to_string()),
                        message: Some(WAITING_SECRET.to_string()),
                    }),
                    ..Default::default()
                }),
                last_state: Some(ContainerState {
                    terminated: Some(ContainerStateTerminated {
                        reason: Some("StartError".to_string()),
                        exit_code: 128,
                        message: Some(TERMINATED_SECRET.to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let message = pod_runtime_failure_message(&pod).unwrap();
    assert_eq!(
        message,
        "container_runtime_failure status=waiting code=crash_loop_back_off; \
         previous_container_runtime_failure status=terminated code=start_error exit_code=128"
    );
    assert!(!message.contains(WAITING_SECRET));
    assert!(!message.contains(TERMINATED_SECRET));
    assert!(!message.contains("tenant-secret-pod-name"));
    assert!(!message.contains("web"));
    assert!(message.len() < 192);
}

#[test]
fn container_creating_is_not_a_runtime_failure() {
    let pod = Pod {
        status: Some(PodStatus {
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                image: "example.test/web@sha256:abc".to_string(),
                image_id: "example.test/web@sha256:abc".to_string(),
                ready: false,
                restart_count: 0,
                state: Some(ContainerState {
                    waiting: Some(ContainerStateWaiting {
                        reason: Some("ContainerCreating".to_string()),
                        message: Some("creating container".to_string()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(pod_runtime_failure_message(&pod).is_none());
}

#[test]
fn running_container_ignores_recovered_last_start_error() {
    let pod = Pod {
        status: Some(PodStatus {
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                image: "example.test/web@sha256:abc".to_string(),
                image_id: "example.test/web@sha256:abc".to_string(),
                ready: true,
                restart_count: 1,
                state: Some(ContainerState {
                    running: Some(Default::default()),
                    ..Default::default()
                }),
                last_state: Some(ContainerState {
                    terminated: Some(ContainerStateTerminated {
                        reason: Some("StartError".to_string()),
                        exit_code: 128,
                        message: Some("previous runtime start failed".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(pod_runtime_failure_message(&pod).is_none());
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
