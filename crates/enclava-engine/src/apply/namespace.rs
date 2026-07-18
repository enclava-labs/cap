use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, Patch, PatchParams};

use super::engine::{ApplyEngine, ApplyError};

/// Build SSA PatchParams for the given field manager.
pub fn namespace_patch_params(field_manager: &str) -> PatchParams {
    PatchParams::apply(field_manager).force()
}

/// Apply a Namespace via server-side apply.
///
/// This must succeed before any namespaced resources are applied.
/// Uses SSA with force to claim ownership of all fields.
pub async fn apply_namespace(
    engine: &ApplyEngine,
    namespace: &Namespace,
) -> Result<Namespace, ApplyError> {
    let name = namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    let api: Api<Namespace> = Api::all(engine.client().clone());
    let pp = namespace_patch_params(&engine.config().field_manager);

    let patched = super::bounded_kube_write(api.patch(name, &pp, &Patch::Apply(namespace))).await?;

    tracing::info!(namespace = %name, "namespace applied via SSA");
    Ok(patched)
}
