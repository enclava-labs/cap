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

/// Shared mock-Kube fixture: records every request path, answers PVC
/// single-object GETs from `pvcs` (name → object JSON), 404s claims not in
/// the map, and returns a kube-apiserver-style Status error for everything
/// when `fail_lookups` is set (or for non-PVC requests — the apply then
/// fails, which is fine: the floor check runs before any mutation).
fn pvc_mock_client(
    pvcs: std::collections::HashMap<String, serde_json::Value>,
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
            async move {
                let path = request.uri().path().to_string();
                recorded.lock().unwrap().push(path.clone());
                let _ = request.into_body().collect().await;
                let claim = path.strip_prefix(
                    "/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/",
                );
                let (status, body) = match (fail_lookups, claim.and_then(|c| pvcs.get(c))) {
                    (false, Some(pvc)) => (200, pvc.clone()),
                    (false, None) if claim.is_some() => (
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
        vec!["/api/v1/namespaces/cap-test-org-test-app/persistentvolumeclaims/state-test-app-0"],
        "only the exact claim probe may run before refusal: {calls:?}"
    );
}

/// Grandfathering: a live ordinal-0 claim is provisioned — reapply of an
/// app with a pre-floor size must pass the floor check (its LUKS header
/// exists; the runtime probe never runs). The apply then proceeds; whatever
/// it fails on afterwards must NOT be the floor.
#[tokio::test]
async fn apply_and_watch_keeps_provisioned_sub_floor_volumes_operable() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = pvc_mock_client(
        [
            pvc_entry("state-test-app-0", None),
            pvc_entry("tls-state-test-app-0", None),
        ]
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
        "provisioned sub-floor volumes must not hit the floor: {err}"
    );
    assert!(
        requests.lock().unwrap().len() > 2,
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

/// Sizes at or above the floor need no provisioning evidence at all: the
/// check must not issue Kubernetes I/O for the common path.
#[tokio::test]
async fn apply_and_watch_skips_claim_lookups_at_or_above_floor() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::orchestrator::apply_and_watch;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::testutil::sample_app;

    let (client, requests) = pvc_mock_client(std::collections::HashMap::new(), true);
    let engine = ApplyEngine::new(client, ApplyConfig::default());
    let app = sample_app(); // 10Gi/2Gi — both above the floor

    let err = apply_and_watch(&engine, &app, MutationGeneration::new(1).unwrap())
        .await
        .expect_err("the mock cannot complete a real apply");
    let _ = err;
    let calls = requests.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .all(|path| !path.contains("persistentvolumeclaims")),
        "no PVC lookups for at-floor sizes: {calls:?}"
    );
}
