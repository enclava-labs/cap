use enclava_engine::apply::types::DeployPhase;
use enclava_engine::apply::watch::{
    PodSnapshot, classify_pod_phase, pod_label_selector, pod_matches_statefulset_update_revision,
    pod_runtime_failure_message, pod_terminal_failure_code, rollout_runtime_failure,
    stale_terminating_pod_needs_force_delete,
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
fn terminating_pod_does_not_fail_replacement_rollout() {
    let pod = Pod {
        metadata: ObjectMeta {
            deletion_timestamp: Some(Time(
                "2026-07-31T10:31:09Z"
                    .parse::<Timestamp>()
                    .expect("timestamp parses"),
            )),
            ..Default::default()
        },
        status: Some(PodStatus {
            phase: Some("Failed".to_string()),
            container_statuses: Some(vec![ContainerStatus {
                name: "web".to_string(),
                image: "example.test/web@sha256:abc".to_string(),
                image_id: "example.test/web@sha256:abc".to_string(),
                ready: false,
                restart_count: 0,
                state: Some(ContainerState {
                    terminated: Some(ContainerStateTerminated {
                        reason: Some("Error".to_string()),
                        exit_code: 137,
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
    assert!(pod_terminal_failure_code(&pod).is_none());
}

#[test]
fn pod_label_selector_matches_generated_statefulset_labels() {
    assert_eq!(pod_label_selector("my-app"), "app=my-app");
}

#[test]
fn stale_statefulset_revision_does_not_fail_replacement_rollout() {
    let pod = Pod {
        metadata: ObjectMeta {
            labels: Some(std::collections::BTreeMap::from([(
                "controller-revision-hash".to_string(),
                "app-old".to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!pod_matches_statefulset_update_revision(
        &pod,
        Some("app-new")
    ));
    assert!(pod_matches_statefulset_update_revision(
        &pod,
        Some("app-old")
    ));
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

    let result = watch_rollout(
        &engine,
        "nonexistent-ns",
        "nonexistent-sts",
        engine.config().rollout_timeout,
    )
    .await;
    assert!(matches!(
        result,
        Err(enclava_engine::apply::engine::ApplyError::RolloutFailed(_))
    ));
}

fn crashed_container(
    name: &str,
    restart_count: i32,
    waiting_reason: Option<&str>,
    terminated: (&str, i32),
) -> ContainerStatus {
    let terminated = ContainerState {
        terminated: Some(ContainerStateTerminated {
            reason: Some(terminated.0.to_string()),
            exit_code: terminated.1,
            ..Default::default()
        }),
        ..Default::default()
    };
    let (state, last_state) = match waiting_reason {
        Some(reason) => (
            ContainerState {
                waiting: Some(ContainerStateWaiting {
                    reason: Some(reason.to_string()),
                    message: None,
                }),
                ..Default::default()
            },
            Some(terminated),
        ),
        None => (terminated, None),
    };
    ContainerStatus {
        name: name.to_string(),
        restart_count,
        state: Some(state),
        last_state,
        ..Default::default()
    }
}

fn pod_with(container: ContainerStatus) -> Pod {
    Pod {
        status: Some(PodStatus {
            phase: Some("Running".to_string()),
            container_statuses: Some(vec![container]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn rollout_tolerates_first_enclava_init_restarts_then_fails() {
    // A Trustee restart makes enclava-init's policy fetch fail once: exit 1,
    // then CrashLoopBackOff until the kubelet restarts it.
    for restart_count in 0..2 {
        let exited = pod_with(crashed_container(
            "enclava-init",
            restart_count,
            None,
            ("Error", 1),
        ));
        assert!(rollout_runtime_failure(&exited).is_none());
        // The status surface still reports what the container is doing.
        assert!(pod_runtime_failure_message(&exited).is_some());
        let backing_off = pod_with(crashed_container(
            "enclava-init",
            restart_count,
            Some("CrashLoopBackOff"),
            ("Error", 1),
        ));
        assert!(rollout_runtime_failure(&backing_off).is_none());
    }
    // A failure that persists past the budget is terminal.
    let persistent = pod_with(crashed_container(
        "enclava-init",
        2,
        Some("CrashLoopBackOff"),
        ("Error", 1),
    ));
    assert_eq!(
        rollout_runtime_failure(&persistent)
            .expect("persistent init failure is terminal")
            .public_message(),
        "container_runtime_failure status=waiting code=crash_loop_back_off; \
         previous_container_runtime_failure status=terminated code=error exit_code=1"
    );
}

#[test]
fn rollout_still_fails_fast_on_definitive_failures() {
    let definitive = [
        // Any other container crashing is the workload's own failure.
        crashed_container("web", 0, None, ("Error", 1)),
        crashed_container("web", 0, Some("CrashLoopBackOff"), ("Error", 1)),
        // enclava-init failures that are not its generic exit 1.
        crashed_container("enclava-init", 0, None, ("OOMKilled", 137)),
        crashed_container("enclava-init", 0, None, ("StartError", 128)),
        crashed_container("enclava-init", 0, None, ("Error", 101)),
        crashed_container(
            "enclava-init",
            0,
            Some("CrashLoopBackOff"),
            ("StartError", 128),
        ),
        crashed_container("enclava-init", 0, Some("ImagePullBackOff"), ("Error", 1)),
    ];
    for container in definitive {
        let label = format!("{container:?}");
        assert!(
            rollout_runtime_failure(&pod_with(container)).is_some(),
            "must stay terminal on first sight: {label}"
        );
    }

    // A tolerated init restart never masks another container's failure.
    let mut pod = pod_with(crashed_container("enclava-init", 0, None, ("Error", 1)));
    pod.status
        .as_mut()
        .unwrap()
        .container_statuses
        .as_mut()
        .unwrap()
        .push(crashed_container("web", 0, None, ("Error", 2)));
    assert_eq!(
        rollout_runtime_failure(&pod).unwrap().public_message(),
        "container_runtime_failure status=terminated code=error exit_code=2"
    );
}
