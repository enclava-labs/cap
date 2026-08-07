use kube::api::{Api, ApiResource, DynamicObject};
use serde_json::Value;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};

/// Returns the ApiResource descriptor for CiliumNetworkPolicy.
/// This avoids a runtime discovery call -- we know the CRD schema.
pub fn cilium_api_resource() -> ApiResource {
    ApiResource {
        group: "cilium.io".to_string(),
        version: "v2".to_string(),
        api_version: "cilium.io/v2".to_string(),
        kind: "CiliumNetworkPolicy".to_string(),
        plural: "ciliumnetworkpolicies".to_string(),
    }
}

/// Convert a serde_json::Value (from Plan 2's network_policy generator)
/// into a kube-rs DynamicObject suitable for SSA.
pub fn value_to_dynamic_object(val: &Value) -> Result<DynamicObject, ApplyError> {
    let metadata = val.get("metadata").ok_or_else(|| {
        ApplyError::ManifestGeneration("CiliumNetworkPolicy missing metadata".to_string())
    })?;

    let name = metadata
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApplyError::ManifestGeneration("CiliumNetworkPolicy missing metadata.name".to_string())
        })?;

    let namespace = metadata.get("namespace").and_then(|v| v.as_str());

    let labels = metadata
        .get("labels")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok());

    let annotations = metadata
        .get("annotations")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok());

    // Build the DynamicObject data map from everything except apiVersion/kind/metadata
    let mut data = serde_json::Map::new();
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            if k != "apiVersion" && k != "kind" && k != "metadata" {
                data.insert(k.clone(), v.clone());
            }
        }
    }

    let mut dyn_obj = DynamicObject::new(name, &cilium_api_resource());
    dyn_obj.metadata.namespace = namespace.map(|s| s.to_string());
    dyn_obj.metadata.labels = labels;
    dyn_obj.metadata.annotations = annotations;
    dyn_obj.data = Value::Object(data);

    Ok(dyn_obj)
}

/// Apply a CiliumNetworkPolicy via server-side apply using DynamicObject.
///
/// CiliumNetworkPolicy is a CRD not in k8s-openapi. The input Value comes
/// from Plan 2's `generate_network_policy()`. We convert it to a DynamicObject
/// and use the untyped API with a hardcoded ApiResource to avoid runtime discovery.
pub async fn apply_network_policy(
    engine: &ApplyEngine,
    namespace: &str,
    policy_value: &Value,
    generation: MutationGeneration,
) -> Result<DynamicObject, ApplyError> {
    let dyn_obj = value_to_dynamic_object(policy_value)?;

    let name = dyn_obj.metadata.name.as_deref().unwrap_or("<unnamed>");

    let ar = cilium_api_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(engine.client().clone(), namespace, &ar);
    let patched = apply_resource(engine, &api, &dyn_obj, generation, false, false).await?;

    tracing::info!(
        namespace = %namespace,
        name = %name,
        "CiliumNetworkPolicy applied via SSA (DynamicObject, no-force)"
    );

    Ok(patched)
}
