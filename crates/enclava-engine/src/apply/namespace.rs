use k8s_openapi::api::core::v1::Namespace;
use kube::api::Api;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};

/// Apply a Namespace via server-side apply.
///
/// This must succeed before any namespaced resources are applied.
/// Namespace apply deliberately does NOT force: a pre-existing namespace
/// not created by CAP may carry externally owned fields, and force-apply
/// would clobber them (and steal field ownership). Conflicts on such a
/// namespace fail closed instead. CAP-created namespaces are owned solely
/// by the trusted field manager and apply unchanged.
pub async fn apply_namespace(
    engine: &ApplyEngine,
    namespace: &Namespace,
    generation: MutationGeneration,
) -> Result<Namespace, ApplyError> {
    let name = namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    let api: Api<Namespace> = Api::all(engine.client().clone());
    let patched = apply_resource(engine, &api, namespace, generation, false, false).await?;

    tracing::info!(namespace = %name, "namespace applied via SSA");
    Ok(patched)
}
