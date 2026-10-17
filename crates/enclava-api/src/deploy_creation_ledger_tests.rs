use enclava_engine::apply::creation_ledger::{CreationLedgerBuffer, CreationRecord};
use enclava_engine::apply::engine::ApplyError;
use http_body_util::BodyExt;

fn partial_create_engine(
    failing_collection: &'static str,
) -> (ApplyEngine, Arc<CreationLedgerBuffer>) {
    let ledger = Arc::new(CreationLedgerBuffer::new());
    let client = kube::Client::new(
        tower::service_fn(
            move |request: http::Request<kube::client::Body>| async move {
                let path = request.uri().path().to_string();
                let method = request.method().clone();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let (code, response) = if path.contains(failing_collection) {
                    (
                        403,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "Forbidden", "message": "injected later-step failure", "code": 403
                        }),
                    )
                } else if method == http::Method::POST {
                    let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    value["metadata"]["uid"] = "observed-create-uid".into();
                    value["metadata"]["resourceVersion"] = "1".into();
                    value["metadata"]["creationTimestamp"] = "2026-10-17T00:00:00Z".into();
                    (201, value)
                } else {
                    assert_eq!(method, http::Method::GET);
                    (
                        404,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Failure",
                            "reason": "NotFound", "message": "absent", "code": 404
                        }),
                    )
                };
                Ok::<_, std::io::Error>(
                    http::Response::builder()
                        .status(code)
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&response).unwrap(),
                        ))
                        .unwrap(),
                )
            },
        ),
        "default",
    );
    (
        ApplyEngine::new(client, Default::default()).with_creation_ledger(ledger.clone()),
        ledger,
    )
}

fn regression_manifests() -> enclava_engine::manifest::GeneratedManifests {
    let app = queued_apply_app();
    let snapshot = queued_apply_snapshot('a');
    let spec = build_confidential_app_from_rows(
        &app,
        Uuid::new_v4(),
        &test_attestation_config(),
        "api-signing-key",
        "https://api.enclava.dev",
        &snapshot.containers,
        &snapshot.resources,
    )
    .unwrap();
    generate_all_manifests(&spec)
}

async fn assert_partial_batch_drained(
    step: Result<(), ApplyError>,
    ledger: &CreationLedgerBuffer,
    expected_kind: &str,
) {
    let mut persisted = Vec::new();
    let result = complete_creation_step(step, async {
        persisted = ledger.drain_pending();
        Ok(())
    })
    .await;
    assert!(
        matches!(result, Err(DeployError::Apply(ApplyError::Kube(kube::Error::Api(ref e)))) if e.code == 403)
    );
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].kind, expected_kind);
    assert_eq!(persisted[0].uid, "observed-create-uid");
    assert!(ledger.drain_pending().is_empty());
}

#[tokio::test]
async fn standard_batch_failure_drains_earlier_service_account_creation() {
    let (engine, ledger) = partial_create_engine("/resourcequotas/");
    let step = apply_standard_resources(
        &engine,
        &regression_manifests(),
        MutationGeneration::new(7).unwrap(),
    )
    .await;
    assert_partial_batch_drained(step, &ledger, "ServiceAccount").await;
}

#[tokio::test]
async fn gateway_batch_failure_drains_earlier_envoy_proxy_creation() {
    let (engine, ledger) = partial_create_engine("/gateways/");
    let manifests = regression_manifests();
    let step = apply_gateway_resources(
        &engine,
        "cap-queued-app",
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
        MutationGeneration::new(7).unwrap(),
    )
    .await;
    assert_partial_batch_drained(step, &ledger, "EnvoyProxy").await;
}

#[tokio::test]
async fn missing_ingress_configmap_creation_is_recorded_before_restart() {
    let (engine, ledger) = partial_create_engine("/never-fails/");
    let manifests = regression_manifests();
    let step = apply_namespaced_resource(
        &engine,
        "cap-queued-app",
        &manifests.ingress_configmap,
        MutationGeneration::new(7).unwrap(),
    )
    .await;
    let mut persisted = Vec::<CreationRecord>::new();
    complete_creation_step(step, async {
        persisted = ledger.drain_pending();
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].kind, "ConfigMap");
    assert_eq!(
        persisted[0].name,
        manifests.ingress_configmap.metadata.name.unwrap()
    );
}

#[tokio::test]
async fn original_step_error_survives_failed_persistence_after_gate_runs() {
    let mut ran = false;
    let result = complete_creation_step::<()>(
        Err(ApplyError::CreationEvidenceLost {
            kind: "ConfigMap".to_string(),
            name: "ingress-config".to_string(),
            key: "cap-created".to_string(),
        }),
        async {
            ran = true;
            Err(DeployError::Db(sqlx::Error::PoolClosed))
        },
    )
    .await;
    assert!(ran);
    assert!(
        matches!(result, Err(DeployError::Apply(ApplyError::CreationEvidenceLost { ref kind, ref name, ref key }))
            if kind == "ConfigMap" && name == "ingress-config" && key == "cap-created")
    );
}

#[tokio::test]
async fn successful_step_does_not_ignore_persistence_failure() {
    let result = complete_creation_step(Ok(()), async {
        Err(DeployError::Db(sqlx::Error::PoolClosed))
    })
    .await;
    assert!(matches!(
        result,
        Err(DeployError::Db(sqlx::Error::PoolClosed))
    ));
}
