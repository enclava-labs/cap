use enclava_engine::apply::types::DeployPhase;
use enclava_engine::apply::watch::{
    PodSnapshot, classify_pod_phase, kata_start_error_needs_pod_recreate,
    plan_kata_start_error_pod_recreates, plan_stale_terminating_pod_force_deletes,
    plan_unready_running_pod_recreates, pod_label_selector,
    stale_terminating_pod_needs_force_delete, unready_running_pod_needs_recreate,
};
use k8s_openapi::api::core::v1::{
    ContainerState, ContainerStateRunning, ContainerStateTerminated, ContainerStateWaiting,
    ContainerStatus, Pod, PodStatus,
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

#[test]
fn stale_terminating_repair_plan_selects_only_stale_unfinalized_pods() {
    let deleted_at = Time(
        "2026-06-15T08:00:00Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let stale_now = "2026-06-15T08:01:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let stale_pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            deletion_timestamp: Some(deleted_at.clone()),
            deletion_grace_period_seconds: Some(30),
            ..Default::default()
        },
        ..Default::default()
    };
    let finalized_pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-1".to_string()),
            deletion_timestamp: Some(deleted_at),
            deletion_grace_period_seconds: Some(30),
            finalizers: Some(vec!["example.com/finalizer".to_string()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let normal_pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-2".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let plan = plan_stale_terminating_pod_force_deletes(
        &[stale_pod, finalized_pod, normal_pod],
        stale_now,
    );

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].pod_name, "routstr-core-prod-0");
    assert!(plan[0].reason.contains("stale terminating"));
}

#[test]
fn kata_start_error_needs_whole_pod_recreate() {
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 6,
                state: Some(ContainerState {
                    waiting: Some(ContainerStateWaiting {
                        reason: Some("CrashLoopBackOff".to_string()),
                        message: Some(
                            "back-off restarting failed container=web pod=routstr-core-prod-0"
                                .to_string(),
                        ),
                    }),
                    ..Default::default()
                }),
                last_state: Some(ContainerState {
                    terminated: Some(ContainerStateTerminated {
                        exit_code: 128,
                        reason: Some("StartError".to_string()),
                        message: Some(
                            "failed to create containerd task: failed to create shim task: EINVAL: Invalid argument"
                                .to_string(),
                        ),
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

    let recreate = kata_start_error_needs_pod_recreate(&pod)
        .expect("Kata StartError should trigger whole-pod recreation");

    assert!(recreate.contains("web"));
    assert!(recreate.contains("StartError"));
    assert!(recreate.contains("failed to create shim task"));
}

#[test]
fn kata_start_error_repair_plan_selects_only_runtime_start_errors() {
    let runtime_failed_pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 6,
                last_state: Some(ContainerState {
                    terminated: Some(ContainerStateTerminated {
                        exit_code: 128,
                        reason: Some("StartError".to_string()),
                        message: Some(
                            "failed to create containerd task: failed to create shim task: EINVAL: Invalid argument"
                                .to_string(),
                        ),
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
    let app_crash_pod = Pod {
        metadata: ObjectMeta {
            name: Some("app-crash-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 4,
                state: Some(ContainerState {
                    waiting: Some(ContainerStateWaiting {
                        reason: Some("CrashLoopBackOff".to_string()),
                        message: Some("application exited with code 1".to_string()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let plan = plan_kata_start_error_pod_recreates(&[runtime_failed_pod, app_crash_pod]);

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].pod_name, "routstr-core-prod-0");
    assert!(plan[0].reason.contains("failed to create shim task"));
}

#[test]
fn long_running_unready_web_container_needs_whole_pod_recreate() {
    let started_at = Time(
        "2026-06-16T12:23:29Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let now = "2026-06-16T12:40:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 0,
                state: Some(ContainerState {
                    running: Some(ContainerStateRunning {
                        started_at: Some(started_at.clone()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let reason = unready_running_pod_needs_recreate(&pod, now)
        .expect("long-running unready web container should need pod recreation");

    assert!(reason.contains("web"));
    assert!(reason.contains("unready"));
}

#[test]
fn recent_unready_web_container_is_not_recreated_during_unlock_startup() {
    let started_at = Time(
        "2026-06-16T12:23:29Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let now = "2026-06-16T12:25:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 0,
                state: Some(ContainerState {
                    running: Some(ContainerStateRunning {
                        started_at: Some(started_at.clone()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    assert!(unready_running_pod_needs_recreate(&pod, now).is_none());
}

#[test]
fn unready_running_repair_plan_selects_only_stale_web_container() {
    let started_at = Time(
        "2026-06-16T12:23:29Z"
            .parse::<Timestamp>()
            .expect("timestamp parses"),
    );
    let now = "2026-06-16T12:40:00Z"
        .parse::<Timestamp>()
        .expect("timestamp parses");
    let stale_unready_pod = Pod {
        metadata: ObjectMeta {
            name: Some("routstr-core-prod-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: false,
                restart_count: 0,
                state: Some(ContainerState {
                    running: Some(ContainerStateRunning {
                        started_at: Some(started_at.clone()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let ready_pod = Pod {
        metadata: ObjectMeta {
            name: Some("healthy-0".to_string()),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                ready: true,
                restart_count: 0,
                state: Some(ContainerState {
                    running: Some(ContainerStateRunning {
                        started_at: Some(started_at),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let plan = plan_unready_running_pod_recreates(&[stale_unready_pod, ready_pod], now);

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].pod_name, "routstr-core-prod-0");
    assert!(plan[0].reason.contains("unready"));
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
