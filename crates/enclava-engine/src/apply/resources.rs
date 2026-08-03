use k8s_openapi::NamespaceResourceScope;
use kube::Resource;
use kube::api::Api;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};

/// Apply a typed namespaced Kubernetes resource via server-side apply.
///
/// Works for ServiceAccount, ResourceQuota, Service, ConfigMap, and any
/// k8s-openapi type that implements the required traits.
pub async fn apply_namespaced_resource<K>(
    engine: &ApplyEngine,
    namespace: &str,
    resource: &K,
    generation: MutationGeneration,
) -> Result<K, ApplyError>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + Debug + Serialize + DeserializeOwned,
    <K as Resource>::DynamicType: Default,
{
    let name = resource.meta().name.as_deref().unwrap_or("<unnamed>");

    let api: Api<K> = Api::namespaced(engine.client().clone(), namespace);
    let patched = apply_resource(engine, &api, resource, generation, false).await?;

    tracing::info!(
        kind = %K::kind(&Default::default()),
        namespace = %namespace,
        name = %name,
        "resource applied via SSA (no-force)"
    );

    Ok(patched)
}

/// Apply multiple namespaced resources of different types.
/// Convenience wrapper that applies SA, Quota, Service, and ConfigMaps in sequence.
pub async fn apply_standard_resources(
    engine: &ApplyEngine,
    manifests: &crate::manifest::GeneratedManifests,
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let ns = manifests
        .namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    apply_namespaced_resource(engine, ns, &manifests.service_account, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.resource_quota, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.service, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.sni_route_configmap, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.bootstrap_configmap, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.startup_configmap, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.ingress_configmap, generation).await?;
    apply_namespaced_resource(engine, ns, &manifests.enclava_init_configmap, generation).await?;
    if let Some(configmap) = &manifests.verification_material_configmap {
        apply_namespaced_resource(engine, ns, configmap, generation).await?;
    }

    tracing::info!(namespace = %ns, "all standard resources applied");
    Ok(())
}
