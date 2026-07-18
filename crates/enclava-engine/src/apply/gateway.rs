use kube::api::{Api, ApiResource, DynamicObject};
use serde_json::Value;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};

fn api_resource(group: &str, version: &str, kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: group.to_string(),
        version: version.to_string(),
        api_version: format!("{group}/{version}"),
        kind: kind.to_string(),
        plural: plural.to_string(),
    }
}

fn envoy_proxy_api_resource() -> ApiResource {
    api_resource(
        "gateway.envoyproxy.io",
        "v1alpha1",
        "EnvoyProxy",
        "envoyproxies",
    )
}

fn gateway_api_resource() -> ApiResource {
    api_resource("gateway.networking.k8s.io", "v1", "Gateway", "gateways")
}

fn tls_route_api_resource() -> ApiResource {
    api_resource(
        "gateway.networking.k8s.io",
        "v1alpha3",
        "TLSRoute",
        "tlsroutes",
    )
}

fn value_to_dynamic_object(val: &Value, ar: &ApiResource) -> Result<DynamicObject, ApplyError> {
    let metadata = val.get("metadata").ok_or_else(|| {
        ApplyError::ManifestGeneration("Gateway resource missing metadata".to_string())
    })?;

    let name = metadata
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApplyError::ManifestGeneration("Gateway resource missing metadata.name".to_string())
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

    let mut data = serde_json::Map::new();
    if let Some(obj) = val.as_object() {
        for (key, value) in obj {
            if key != "apiVersion" && key != "kind" && key != "metadata" {
                data.insert(key.clone(), value.clone());
            }
        }
    }

    let mut dyn_obj = DynamicObject::new(name, ar);
    dyn_obj.metadata.namespace = namespace.map(str::to_string);
    dyn_obj.metadata.labels = labels;
    dyn_obj.metadata.annotations = annotations;
    dyn_obj.data = Value::Object(data);
    Ok(dyn_obj)
}

async fn apply_dynamic_resource(
    engine: &ApplyEngine,
    namespace: &str,
    value: &Value,
    ar: &ApiResource,
    generation: MutationGeneration,
) -> Result<DynamicObject, ApplyError> {
    let dyn_obj = value_to_dynamic_object(value, ar)?;
    let name = dyn_obj.metadata.name.as_deref().unwrap_or("<unnamed>");
    let api: Api<DynamicObject> = Api::namespaced_with(engine.client().clone(), namespace, ar);
    let patched = apply_resource(engine, &api, &dyn_obj, generation, false).await?;

    tracing::info!(
        namespace = %namespace,
        name = %name,
        kind = %ar.kind,
        "Gateway resource applied via SSA (no-force)"
    );

    Ok(patched)
}

pub async fn apply_gateway_resources(
    engine: &ApplyEngine,
    namespace: &str,
    envoy_proxy: &Value,
    gateway: &Value,
    tls_route: &Value,
    tee_tls_route: &Value,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    apply_dynamic_resource(
        engine,
        namespace,
        envoy_proxy,
        &envoy_proxy_api_resource(),
        generation,
    )
    .await?;
    apply_dynamic_resource(
        engine,
        namespace,
        gateway,
        &gateway_api_resource(),
        generation,
    )
    .await?;
    apply_dynamic_resource(
        engine,
        namespace,
        tls_route,
        &tls_route_api_resource(),
        generation,
    )
    .await?;
    apply_dynamic_resource(
        engine,
        namespace,
        tee_tls_route,
        &tls_route_api_resource(),
        generation,
    )
    .await?;
    Ok(())
}
