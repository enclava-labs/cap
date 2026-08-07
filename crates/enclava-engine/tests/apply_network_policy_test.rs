use enclava_engine::apply::network_policy::{cilium_api_resource, value_to_dynamic_object};
use serde_json::json;

#[test]
fn cilium_api_resource_has_correct_group() {
    let ar = cilium_api_resource();
    assert_eq!(ar.group, "cilium.io");
    assert_eq!(ar.version, "v2");
    assert_eq!(ar.kind, "CiliumNetworkPolicy");
}

#[test]
fn value_to_dynamic_object_preserves_name_and_namespace() {
    let val = json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "tenant-isolation",
            "namespace": "cap-test-org-test-app"
        },
        "spec": {
            "endpointSelector": {}
        }
    });

    let dyn_obj = value_to_dynamic_object(&val).unwrap();
    assert_eq!(dyn_obj.metadata.name.as_deref(), Some("tenant-isolation"));
    assert_eq!(
        dyn_obj.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn value_to_dynamic_object_rejects_missing_metadata() {
    let val = json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "spec": {}
    });

    let result = value_to_dynamic_object(&val);
    assert!(result.is_err());
}

/// Integration test: requires a running cluster with Cilium CRDs installed.
#[tokio::test]
#[ignore]
async fn apply_cilium_network_policy_creates() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::generation::MutationGeneration;
    use enclava_engine::apply::namespace::apply_namespace;
    use enclava_engine::apply::network_policy::apply_network_policy;
    use enclava_engine::manifest::namespace::generate_namespace;
    use enclava_engine::manifest::network_policy::generate_network_policy;
    use enclava_engine::testutil::sample_app;

    let engine = ApplyEngine::try_default().await.unwrap();
    let app = sample_app();

    let ns = generate_namespace(&app);
    let generation = MutationGeneration::new(1).unwrap();
    apply_namespace(&engine, &ns, generation).await.unwrap();

    let np = generate_network_policy(&app);
    apply_network_policy(&engine, &app.namespace, &np, generation)
        .await
        .unwrap();

    // Cleanup
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{Api, DeleteParams};
    let ns_api: Api<Namespace> = Api::all(engine.client().clone());
    let _ = ns_api
        .delete(&app.namespace, &DeleteParams::default())
        .await;
}
