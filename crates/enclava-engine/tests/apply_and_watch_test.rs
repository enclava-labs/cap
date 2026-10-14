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

/// Round-19 review (Codex P2): the engine's primary deployment entry must
/// run `validate_app` BEFORE `generate_all_manifests`. The checks were
/// previously opt-in and only the API-specific deploy paths invoked them,
/// so a CLI or service calling this public entry with a legacy/corrupt
/// `ConfidentialApp` reached Kubernetes with the malformed quantities,
/// domains, egress rules, or log-encryption metadata the change is meant
/// to block. The mock API double records every request: an invalid app
/// must fail validation with ZERO Kubernetes traffic.
#[tokio::test]
async fn apply_and_watch_rejects_invalid_app_before_any_kube_request() {
    use axum::http::{Request, Response};
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;
    use http_body_util::BodyExt as _;
    use kube::client::Body;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&requests);
    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| {
            let recorded = Arc::clone(&recorded);
            async move {
                recorded
                    .lock()
                    .unwrap()
                    .push(request.uri().path().to_string());
                let _ = request.into_body().collect().await;
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(200)
                        .body(Body::from(
                            serde_json::to_vec(&serde_json::json!({})).unwrap(),
                        ))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());

    let mut app = sample_app();
    // A legacy/corrupt value API admission would never persist.
    app.resources.cpu = "not-a-quantity".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("invalid app must be rejected at the deploy boundary");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "validation failure must surface as ManifestGeneration, got {err:?}"
    );
    assert_eq!(
        *requests.lock().unwrap(),
        Vec::<String>::new(),
        "an invalid app must never reach Kubernetes"
    );
}

/// Shared mock-Kube fixture: records every request path, answers PVC and
/// pod single-object GETs from `pvcs`/`pods` (name → object JSON), 404s
/// names not in the maps, and returns a kube-apiserver-style Status error
/// for everything when `fail_lookups` is set (or for other requests — the
/// apply then fails, which is fine: evidence inspection runs before any
/// mutation).
fn evidence_mock_client(
    pvcs: std::collections::HashMap<String, serde_json::Value>,
    pods: std::collections::HashMap<String, serde_json::Value>,
    fail_lookups: bool,
) -> (kube::Client, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::http::{Request, Response};
    use http_body_util::BodyExt as _;
    use kube::client::Body;
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&requests);
    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| {
            let recorded = Arc::clone(&recorded);
            let pvcs = pvcs.clone();
            let pods = pods.clone();
            async move {
                let path = request.uri().path().to_string();
                recorded.lock().unwrap().push(path.clone());
                let _ = request.into_body().collect().await;
                let object = path
                    .strip_prefix(
                        "/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/",
                    )
                    .and_then(|name| pvcs.get(name))
                    .or_else(|| {
                        path.strip_prefix("/api/v1/namespaces/cap-test-org-test-app/pods/")
                            .and_then(|name| pods.get(name))
                    });
                let probed = path.contains("/persistentvolumeclaims/") || path.contains("/pods/");
                let (status, body) = match (fail_lookups, object) {
                    (false, Some(object)) => (200, object.clone()),
                    (false, None) if probed => (
                        404,
                        serde_json::json!({
                            "kind": "Status", "apiVersion": "v1",
                            "status": "Failure", "code": 404, "reason": "NotFound",
                        }),
                    ),
                    _ => (
                        500,
                        serde_json::json!({
                            "kind": "Status", "apiVersion": "v1",
                            "status": "Failure", "code": 500, "reason": "InternalError",
                        }),
                    ),
                };
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(status)
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    (client, requests)
}

fn pvc_mock_client(
    pvcs: std::collections::HashMap<String, serde_json::Value>,
    fail_lookups: bool,
) -> (kube::Client, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    evidence_mock_client(pvcs, std::collections::HashMap::new(), fail_lookups)
}

/// PVC with NO creation timestamp: existence alone, never evidence.
fn pvc_entry(name: &str, deletion_timestamp: Option<&str>) -> (String, serde_json::Value) {
    let mut metadata = serde_json::json!({
        "name": name,
        "namespace": "cap-test-org-test-app",
    });
    if let Some(ts) = deletion_timestamp {
        metadata["deletionTimestamp"] = serde_json::json!(ts);
    }
    (
        name.to_string(),
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": metadata,
        }),
    )
}

/// PVC with a populated creation timestamp — the minimum an initialized
/// claim must carry.
fn created_pvc_entry(name: &str, creation_timestamp: &str) -> (String, serde_json::Value) {
    let (name, mut pvc) = pvc_entry(name, None);
    pvc["metadata"]["creationTimestamp"] = serde_json::json!(creation_timestamp);
    (name, pvc)
}

/// Ordinal-0 workload pod: `claim_names` are the PVCs its volumes mount,
/// `ready` toggles the Ready condition, `created` its creation timestamp.
fn pod_entry(
    claim_names: &[&str],
    ready: bool,
    created: &str,
    deletion_timestamp: Option<&str>,
) -> (String, serde_json::Value) {
    let volumes: Vec<serde_json::Value> = claim_names
        .iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "persistentVolumeClaim": { "claimName": name },
            })
        })
        .collect();
    let mut metadata = serde_json::json!({
        "name": "test-app-0",
        "namespace": "cap-test-org-test-app",
        "creationTimestamp": created,
    });
    if let Some(ts) = deletion_timestamp {
        metadata["deletionTimestamp"] = serde_json::json!(ts);
    }
    (
        "test-app-0".to_string(),
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": metadata,
            "spec": { "volumes": volumes, "containers": [{"name": "app"}] },
            "status": {
                "conditions": [{
                    "type": "Ready",
                    "status": if ready { "True" } else { "False" },
                }],
            },
        }),
    )
}

/// Fresh volumes: with no provisioned claims in the cluster, a sub-floor
/// size (below the 32 MiB LUKS2 fresh-format floor) must be refused at the
/// boundary — API admission never runs for direct callers, and letting it
/// render a claim enclava-init refuses at first boot strands the app on an
/// unformattable, unresizable StatefulSet template.
#[tokio::test]
async fn apply_and_watch_refuses_fresh_sub_floor_volumes() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = pvc_mock_client(std::collections::HashMap::new(), false);
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("fresh sub-floor volume must be refused");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "floor refusal must surface as ManifestGeneration, got {err:?}"
    );
    assert!(
        err.to_string().contains("at least 32Mi"),
        "refusal must name the floor: {err}"
    );
    let calls = requests.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/state-test-app-0",
            "/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/tls-state-test-app-0",
        ],
        "the single pre-apply inspection probes every claim once: {calls:?}"
    );
}

/// Live-proof grandfathering: a surviving ordinal-0 claim PROVEN by the
/// Ready pod mounting it keeps a pre-floor size operable — its LUKS header
/// exists; the runtime probe never runs. The apply then proceeds; whatever
/// it fails on afterwards must NOT be the floor.
#[tokio::test]
async fn apply_and_watch_keeps_provisioned_sub_floor_volumes_operable() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = evidence_mock_client(
        [
            created_pvc_entry("state-test-app-0", "2026-01-01T00:00:00Z"),
            created_pvc_entry("tls-state-test-app-0", "2026-01-01T00:00:00Z"),
        ]
        .into_iter()
        .collect(),
        [pod_entry(
            &["state-test-app-0", "tls-state-test-app-0"],
            true,
            "2026-01-02T00:00:00Z",
            None,
        )]
        .into_iter()
        .collect(),
        false,
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();
    app.storage.tls_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("the mock cannot complete a real apply");
    assert!(
        !err.to_string().contains("at least 32Mi"),
        "initialized sub-floor volumes must not hit the floor: {err}"
    );
    assert!(
        requests.lock().unwrap().len() > 3,
        "apply must proceed past the floor check"
    );
}

/// A claim that exists but is TERMINATING is not provisioning evidence:
/// the replacement the StatefulSet controller creates is formatted fresh,
/// so the floor must apply.
#[tokio::test]
async fn apply_and_watch_refuses_terminating_claim_sub_floor() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, _requests) = pvc_mock_client(
        [pvc_entry("state-test-app-0", Some("2026-10-14T00:00:00Z"))]
            .into_iter()
            .collect(),
        false,
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("a terminating claim must not exempt the floor");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "floor refusal must surface as ManifestGeneration, got {err:?}"
    );
    assert!(
        err.to_string().contains("at least 32Mi"),
        "refusal must name the floor: {err}"
    );
}

/// Only the EXACT `<vct>-<workload>-0` claim counts: a `state-test-app-1`
/// object (wrong ordinal — impossible for a replicas:1 StatefulSet anyway)
/// must not exempt the missing ordinal-0 claim.
#[tokio::test]
async fn apply_and_watch_refuses_wrong_ordinal_claim_sub_floor() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, _requests) = pvc_mock_client(
        [pvc_entry("state-test-app-1", None)].into_iter().collect(),
        false,
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("a wrong-ordinal claim must not exempt the floor");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "floor refusal must surface as ManifestGeneration, got {err:?}"
    );
}

/// Per-claim granularity: if only one claim was ever provisioned (e.g. the
/// tls-state PVC was deleted), the missing claim is provisioned FRESH by
/// this render and its size is checked independently.
#[tokio::test]
async fn apply_and_watch_refuses_missing_claim_sub_floor_size() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, _requests) = pvc_mock_client(
        [pvc_entry("state-test-app-0", None)].into_iter().collect(),
        false,
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.tls_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("a fresh sub-floor tls claim must be refused");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "floor refusal must surface as ManifestGeneration, got {err:?}"
    );
    assert!(
        err.to_string().contains("tls_data"),
        "refusal must name the tls_storage field: {err}"
    );
}

/// Fail closed: a claim lookup error (unreachable/RBAC-denied apiserver)
/// must abort the apply rather than silently waive the floor.
#[tokio::test]
async fn apply_and_watch_fails_closed_on_claim_lookup_error() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = pvc_mock_client(std::collections::HashMap::new(), true);
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("lookup errors must abort, not waive");
    assert!(
        matches!(err, ApplyError::Kube(_)),
        "lookup failure must surface as the kube error, got {err:?}"
    );
    let calls = requests.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec!["/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/state-test-app-0"],
        "exactly one claim probe attempted: {calls:?}"
    );
}

/// The single pre-apply inspection probes EVERY claim regardless of size:
/// the same verdict gates the floor and sizes the rollout budget. A lookup
/// failure aborts the apply even for at-floor sizes — fail closed on
/// evidence, never assume.
#[tokio::test]
async fn apply_and_watch_inspects_every_claim_before_apply() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = pvc_mock_client(std::collections::HashMap::new(), true);
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let app = sample_app(); // 10Gi/2Gi — both above the floor

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("evidence lookup errors must abort, not waive");
    assert!(
        matches!(err, ApplyError::Kube(_)),
        "lookup failure must surface as the kube error, got {err:?}"
    );
    let calls = requests.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec!["/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/state-test-app-0"],
        "claims are probed at any size; the first failure aborts: {calls:?}"
    );
}

/// The core regression: a bound-but-unformatted claim is NOT initialization
/// evidence. A surviving PVC with a creation timestamp but no recorded
/// healthy deployment and no Ready pod mounting it is still provisioned
/// FRESH — a 24Mi request must hit the floor.
#[tokio::test]
async fn apply_and_watch_refuses_bound_but_unformatted_claim() {
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, _requests) = evidence_mock_client(
        [
            created_pvc_entry("state-test-app-0", "2026-01-01T00:00:00Z"),
            created_pvc_entry("tls-state-test-app-0", "2026-01-01T00:00:00Z"),
        ]
        .into_iter()
        .collect(),
        std::collections::HashMap::new(),
        false,
    );
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let mut app = sample_app();
    app.storage.app_data.size = "24Mi".to_string();

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("a bound-but-unproven claim must not waive the floor");
    assert!(
        matches!(err, ApplyError::ManifestGeneration(_)),
        "floor refusal must surface as ManifestGeneration, got {err:?}"
    );
}

/// Direct verdict tests for `inspect_fresh_volume_claims` — the evidence
/// contract the API floor guard and rollout budget share.
mod fresh_claim_evidence {
    use super::{created_pvc_entry, evidence_mock_client, pod_entry, pvc_entry};
    use enclava_engine::apply::engine::{ApplyEngine, ApplyError};
    use enclava_engine::apply::orchestrator::{FreshVolumeClaims, inspect_fresh_volume_claims};
    use enclava_engine::apply::types::ApplyConfig;

    const NAMESPACE: &str = "cap-test-org-test-app";
    const WORKLOAD: &str = "test-app";
    const CREATED_JAN1: &str = "2026-01-01T00:00:00Z";
    // Epoch milliseconds for the fixed RFC3339 anchors used below.
    const JAN1_MILLIS: i64 = 1_767_225_600_000;
    const JAN2_MILLIS: i64 = 1_767_312_000_000;

    async fn inspect(
        pvcs: std::collections::HashMap<String, serde_json::Value>,
        pods: std::collections::HashMap<String, serde_json::Value>,
        mask: FreshVolumeClaims,
        initialized_at_millis: Option<i64>,
    ) -> Result<FreshVolumeClaims, ApplyError> {
        let (client, _requests) = evidence_mock_client(pvcs, pods, false);
        let engine = ApplyEngine::new(client, ApplyConfig::default());
        inspect_fresh_volume_claims(&engine, NAMESPACE, WORKLOAD, mask, initialized_at_millis).await
    }

    /// A recorded healthy deployment in a LATER second than the claim's
    /// creation proves initialization even with the pod long gone — a
    /// proven legacy volume survives pod loss, crashes, and replacements.
    #[tokio::test]
    async fn recorded_healthy_deployment_proves_surviving_claim() {
        let claims = inspect(
            [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                .into_iter()
                .collect(),
            std::collections::HashMap::new(),
            FreshVolumeClaims::ALL,
            Some(JAN2_MILLIS),
        )
        .await
        .expect("lookup succeeds");
        assert!(!claims.app_data, "history after claim creation is proof");
        assert!(claims.tls_data, "missing tls claim stays fresh");
    }

    /// Same-bucket ambiguity must fail closed: a healthy completion at
    /// 10.5s cannot distinguish a claim truly created at 10.1s from a
    /// blank replacement created at 10.8s (both report "10s"), so a healthy
    /// timestamp in the SAME whole second never proves the claim.
    #[tokio::test]
    async fn same_second_replacement_cannot_borrow_healthy_proof() {
        for healthy_millis in [
            JAN1_MILLIS,       // same reported second as the claim
            JAN1_MILLIS + 500, // subsecond precision still shares the bucket
        ] {
            let claims = inspect(
                [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                    .into_iter()
                    .collect(),
                std::collections::HashMap::new(),
                FreshVolumeClaims::ALL,
                Some(healthy_millis),
            )
            .await
            .expect("lookup succeeds");
            assert!(
                claims.app_data,
                "healthy {healthy_millis} shares the claim's second bucket — no proof"
            );
        }
    }

    /// A claim recreated AFTER the last healthy deployment cannot borrow
    /// that deployment's proof — the live PVC's creation timestamp is newer
    /// than the evidence.
    #[tokio::test]
    async fn recreated_claim_cannot_borrow_old_healthy_proof() {
        let claims = inspect(
            [created_pvc_entry(
                "state-test-app-0",
                "2026-01-02T00:00:00Z",
            )]
            .into_iter()
            .collect(),
            std::collections::HashMap::new(),
            FreshVolumeClaims::ALL,
            Some(JAN1_MILLIS),
        )
        .await
        .expect("lookup succeeds");
        assert!(
            claims.app_data,
            "a claim created after the healthy deployment is fresh"
        );
    }

    /// The Ready pod path: a surviving claim mounted by the live Ready
    /// ordinal-0 pod is initialized even with no deployment history —
    /// workloads running on the device prove it initialized.
    #[tokio::test]
    async fn ready_pod_mounting_claim_is_live_proof() {
        let claims = inspect(
            [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                .into_iter()
                .collect(),
            [pod_entry(
                &["state-test-app-0"],
                true,
                "2026-01-02T00:00:00Z",
                None,
            )]
            .into_iter()
            .collect(),
            FreshVolumeClaims {
                app_data: true,
                tls_data: false,
            },
            None,
        )
        .await
        .expect("lookup succeeds");
        assert!(!claims.app_data, "a Ready pod mounting the claim is proof");
    }

    /// A Ready pod created in the SAME whole second as the claim cannot
    /// prove it mounts this claim's volume — second-precision timestamps
    /// cannot order the two objects, and the pod may still hold the deleted
    /// claim's volume handle. Only a later-second pod counts.
    #[tokio::test]
    async fn same_second_ready_pod_cannot_prove_claim() {
        let claims = inspect(
            [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                .into_iter()
                .collect(),
            [pod_entry(&["state-test-app-0"], true, CREATED_JAN1, None)]
                .into_iter()
                .collect(),
            FreshVolumeClaims {
                app_data: true,
                tls_data: false,
            },
            None,
        )
        .await
        .expect("lookup succeeds");
        assert!(
            claims.app_data,
            "a same-second Ready pod may be running on the old volume"
        );
    }

    /// Pod shape is precise: a pod created BEFORE the claim (the claim was
    /// recreated under it), a non-Ready pod, and a terminating pod all fail
    /// to prove initialization.
    #[tokio::test]
    async fn stale_unready_or_terminating_pod_is_no_proof() {
        for pod in [
            pod_entry(&["state-test-app-0"], true, "2025-12-31T00:00:00Z", None),
            pod_entry(&["state-test-app-0"], false, "2026-01-02T00:00:00Z", None),
            pod_entry(
                &["state-test-app-0"],
                true,
                "2026-01-02T00:00:00Z",
                Some("2026-01-03T00:00:00Z"),
            ),
        ] {
            let claims = inspect(
                [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                    .into_iter()
                    .collect(),
                [pod].into_iter().collect(),
                FreshVolumeClaims {
                    app_data: true,
                    tls_data: false,
                },
                None,
            )
            .await
            .expect("lookup succeeds");
            assert!(claims.app_data, "pod must not prove this claim");
        }
    }

    /// A Ready pod mounting a DIFFERENT claim name never proves the target
    /// claim — volume identity is part of the evidence.
    #[tokio::test]
    async fn pod_mounting_other_claim_is_no_proof() {
        let claims = inspect(
            [created_pvc_entry("state-test-app-0", CREATED_JAN1)]
                .into_iter()
                .collect(),
            [pod_entry(
                &["other-claim"],
                true,
                "2026-01-02T00:00:00Z",
                None,
            )]
            .into_iter()
            .collect(),
            FreshVolumeClaims {
                app_data: true,
                tls_data: false,
            },
            None,
        )
        .await
        .expect("lookup succeeds");
        assert!(claims.app_data, "an unrelated mount proves nothing");
    }

    /// A claim whose creation timestamp is missing is unprovable — fresh.
    #[tokio::test]
    async fn claim_without_creation_timestamp_is_fresh() {
        let claims = inspect(
            [pvc_entry("state-test-app-0", None)].into_iter().collect(),
            std::collections::HashMap::new(),
            FreshVolumeClaims {
                app_data: true,
                tls_data: false,
            },
            Some(JAN1_MILLIS),
        )
        .await
        .expect("lookup succeeds");
        assert!(claims.app_data, "a timestampless claim is fresh");
    }

    /// Partial verdicts stay per-claim: history proves the surviving state
    /// claim while the bound-but-unformatted tls claim stays fresh.
    #[tokio::test]
    async fn verdict_is_per_claim() {
        let claims = inspect(
            [
                created_pvc_entry("state-test-app-0", CREATED_JAN1),
                created_pvc_entry("tls-state-test-app-0", "2026-01-05T00:00:00Z"),
            ]
            .into_iter()
            .collect(),
            std::collections::HashMap::new(),
            FreshVolumeClaims::ALL,
            Some(JAN2_MILLIS),
        )
        .await
        .expect("lookup succeeds");
        assert!(!claims.app_data, "history proves the state claim");
        assert!(claims.tls_data, "the newer tls claim is fresh");
    }

    /// `NONE` performs no Kubernetes I/O — the API floor admission for
    /// normal sizes must stay read-free.
    #[tokio::test]
    async fn none_mask_issues_no_requests() {
        let (client, requests) = evidence_mock_client(
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            true,
        );
        let engine = ApplyEngine::new(client, ApplyConfig::default());
        let claims = inspect_fresh_volume_claims(
            &engine,
            NAMESPACE,
            WORKLOAD,
            FreshVolumeClaims::NONE,
            None,
        )
        .await
        .expect("NONE never touches the cluster");
        assert!(!claims.app_data);
        assert!(!claims.tls_data);
        assert!(
            requests.lock().unwrap().is_empty(),
            "NONE must not issue Kubernetes I/O"
        );
    }
}
