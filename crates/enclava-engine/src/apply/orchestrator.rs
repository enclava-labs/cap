use sha2::{Digest, Sha256};

use crate::manifest::{GeneratedManifests, generate_all_manifests};
use crate::types::ConfidentialApp;

use super::engine::{ApplyEngine, ApplyError};
use super::gateway::apply_gateway_resources;
use super::namespace::apply_namespace;
use super::network_policy::apply_network_policy;
use super::resources::apply_standard_resources;
use super::statefulset::apply_statefulset;
use super::types::{DeployPhase, DeployStatus};
use super::watch::watch_rollout;

/// Annotation key used to store the manifest hash on the StatefulSet.
/// Used by drift detection to compare desired vs live state.
pub const MANIFEST_HASH_ANNOTATION: &str = "enclava.dev/manifest-hash";

/// Compute a deterministic SHA256 hash of all generated manifests.
///
/// Used for drift detection: if the live StatefulSet's annotation differs
/// from this hash, the manifests have drifted and need re-application.
/// The hash covers every generated resource serialized as sorted JSON.
pub fn manifest_hash(manifests: &GeneratedManifests) -> String {
    let mut hasher = Sha256::new();

    // Hash each manifest as canonicalized JSON (serde_json sorts map keys
    // by default when serializing from typed structs).
    let parts: Vec<serde_json::Value> = vec![
        serde_json::to_value(&manifests.namespace).unwrap_or_default(),
        serde_json::to_value(&manifests.service_account).unwrap_or_default(),
        manifests.network_policy.clone(),
        serde_json::to_value(&manifests.resource_quota).unwrap_or_default(),
        serde_json::to_value(&manifests.service).unwrap_or_default(),
        serde_json::to_value(&manifests.sni_route_configmap).unwrap_or_default(),
        manifests.envoy_proxy.clone(),
        manifests.gateway.clone(),
        manifests.tls_route.clone(),
        serde_json::to_value(&manifests.bootstrap_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.startup_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.ingress_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.enclava_init_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.statefulset).unwrap_or_default(),
        manifests.kbs_owner_binding.1.clone(),
    ];

    for part in &parts {
        let bytes = serde_json::to_vec(part).unwrap_or_default();
        hasher.update(&bytes);
    }

    hex::encode(hasher.finalize())
}

/// Apply all generated manifests to the cluster in the correct order.
///
/// Sequence:
/// 1. Namespace (must exist before anything namespaced)
/// 2. Standard namespaced resources (SA, ResourceQuota, Service, ConfigMaps)
/// 3. CiliumNetworkPolicy (CRD, via DynamicObject)
/// 4. Gateway API resources (EnvoyProxy, Gateway, TLSRoute)
/// 5. StatefulSet (last, because it references SA, ConfigMaps, and Service)
///
/// Each resource is applied via SSA with field manager "enclava-platform".
/// The manifest hash is stored as an annotation on the StatefulSet for drift detection.
pub async fn apply_all(
    engine: &ApplyEngine,
    manifests: &GeneratedManifests,
) -> Result<(), ApplyError> {
    let ns_name = manifests
        .namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    // Step 1: Namespace
    apply_namespace(engine, &manifests.namespace).await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    // Step 2: Standard namespaced resources
    apply_standard_resources(engine, manifests).await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    // Step 3: CiliumNetworkPolicy
    apply_network_policy(engine, ns_name, &manifests.network_policy).await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    // Step 4: Gateway API routing resources
    apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 4/5: Gateway API resources applied");

    // Step 5: StatefulSet (with manifest hash annotation for drift detection)
    let mut sts = manifests.statefulset.clone();
    let hash = manifest_hash(manifests);

    // Inject manifest hash annotation
    let annotations = sts
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    annotations.insert(MANIFEST_HASH_ANNOTATION.to_string(), hash.clone());

    apply_statefulset(engine, ns_name, &sts).await?;
    tracing::info!(
        namespace = %ns_name,
        manifest_hash = %hash,
        "step 5/5: StatefulSet applied"
    );

    tracing::info!(namespace = %ns_name, "apply_all complete");
    Ok(())
}

/// Apply all manifests for a ConfidentialApp and watch the rollout to completion.
///
/// This is the primary entry point for deploying an app. It:
/// 1. Generates all manifests from the ConfidentialApp spec
/// 2. Applies them in order via SSA
/// 3. Watches the StatefulSet rollout until healthy, failed, or timed out
///
/// Returns the final DeployStatus.
pub async fn apply_and_watch(
    engine: &ApplyEngine,
    app: &ConfidentialApp,
) -> Result<DeployStatus, ApplyError> {
    // Generate manifests
    let manifests = generate_all_manifests(app);

    // Phase 11: cc_init_data binds runtime_class. Refuse to deploy if the
    // rendered Pod's runtimeClassName diverges from what cc_init_data committed.
    crate::manifest::cc_init_data::verify_runtime_class_binding(&manifests.statefulset)
        .map_err(ApplyError::ManifestGeneration)?;

    // Apply all
    apply_all(engine, &manifests).await?;

    // Watch rollout
    let status = watch_rollout(engine, &app.namespace, &app.name).await?;

    match status.phase {
        DeployPhase::Running => {
            tracing::info!(
                app = %app.name,
                namespace = %app.namespace,
                "deployment successful -- app is running"
            );
        }
        DeployPhase::Failed => {
            tracing::error!(
                app = %app.name,
                namespace = %app.namespace,
                message = ?status.message,
                "deployment failed"
            );
        }
        DeployPhase::TimedOut => {
            tracing::warn!(
                app = %app.name,
                namespace = %app.namespace,
                message = ?status.message,
                "deployment timed out"
            );
        }
        _ => {}
    }

    Ok(status)
}
