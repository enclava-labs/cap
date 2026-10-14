use sha2::{Digest, Sha256};

use crate::manifest::{GeneratedManifests, generate_all_manifests};
use crate::types::ConfidentialApp;

use super::engine::{ApplyEngine, ApplyError};
use super::gateway::apply_gateway_resources;
use super::generation::MutationGeneration;
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
        manifests.tee_tls_route.clone(),
        serde_json::to_value(&manifests.bootstrap_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.startup_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.ingress_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.enclava_init_configmap).unwrap_or_default(),
        serde_json::to_value(&manifests.verification_material_configmap).unwrap_or_default(),
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
    generation: MutationGeneration,
) -> Result<(), ApplyError> {
    let ns_name = manifests
        .namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::NamespaceNotReady("namespace has no name".to_string()))?;

    apply_namespace(engine, &manifests.namespace, generation).await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    apply_standard_resources(engine, manifests, generation).await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    apply_network_policy(engine, ns_name, &manifests.network_policy, generation).await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
        generation,
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 4/5: Gateway API resources applied");

    let mut sts = manifests.statefulset.clone();
    let hash = manifest_hash(manifests);

    // Inject manifest hash annotation
    let annotations = sts
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    annotations.insert(MANIFEST_HASH_ANNOTATION.to_string(), hash.clone());

    apply_statefulset(engine, ns_name, &sts, generation).await?;
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
    generation: MutationGeneration,
) -> Result<DeployStatus, ApplyError> {
    // Validate at the engine's primary deployment boundary (round-19
    // review P2): validate_app was only invoked on the API-specific deploy
    // paths, so a CLI or service calling this public entry directly with
    // a legacy/corrupt ConfidentialApp could reach Kubernetes with
    // malformed quantities, domains, egress rules, or log-encryption
    // metadata. Manifest generation runs on the SAME input, so reject
    // before generating anything.
    crate::validate::validate_app(app).map_err(|err| {
        ApplyError::ManifestGeneration(format!("confidential app validation failed: {err}"))
    })?;

    enforce_fresh_volume_floor(engine, app).await?;

    // Generate manifests
    let manifests = generate_all_manifests(app);

    crate::manifest::cc_init_data::verify_runtime_class_binding(&manifests.statefulset, app)
        .map_err(ApplyError::ManifestGeneration)?;

    // Apply all
    apply_all(engine, &manifests, generation).await?;

    // Watch rollout. The budget grows with the volumes' first-boot work:
    // a fresh device is fully zero-scanned before format, so the timeout is
    // computed from the exact rendered sizes, not a flat constant.
    let rollout_timeout = engine
        .config()
        .rollout_timeout_for_storage(&app.storage.app_data.size, &app.storage.tls_data.size)
        .map_err(ApplyError::ManifestGeneration)?;
    let status = watch_rollout(engine, &app.namespace, &app.name, rollout_timeout).await?;

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

/// Refuse a fresh volume request below the 32 MiB LUKS2 fresh-format floor.
///
/// `validate_app` intentionally checks only quantity grammar — the spec
/// carries no provisioning state, and a hard floor would lock out reapplies
/// of apps whose volumes predate it (sub-floor LUKS2 volumes activate; the
/// runtime probe never sees them). Here the engine asks the cluster: a
/// live ordinal-0 claim is provisioned and keeps operating; a missing or
/// terminating one is provisioned FRESH by this render, and enclava-init
/// refuses to format a device below the floor — so reject it at the
/// boundary instead of leaving the app unstartable on a StatefulSet
/// volumeClaimTemplate that can never be resized.
///
/// Fails closed on lookup errors: a refused apply retries cleanly, a
/// missed check bricks. A claim racing to be created mid-check errs on
/// refusal; a claim racing to be deleted leaves the app already unable to
/// boot, and refusing is the only recoverable outcome anyway.
pub async fn enforce_fresh_volume_floor(
    engine: &ApplyEngine,
    app: &ConfidentialApp,
) -> Result<(), ApplyError> {
    let claims = sub_floor_fresh_claims(
        engine,
        &app.namespace,
        &app.name,
        &app.storage.app_data.size,
        &app.storage.tls_data.size,
    )
    .await?;
    if claims.app_data {
        crate::validate::validate_persistent_volume_size_for_fresh_provisioning(
            "storage.app_data.size",
            &app.storage.app_data.size,
        )
        .map_err(ApplyError::ManifestGeneration)?;
    }
    if claims.tls_data {
        crate::validate::validate_persistent_volume_size_for_fresh_provisioning(
            "storage.tls_data.size",
            &app.storage.tls_data.size,
        )
        .map_err(ApplyError::ManifestGeneration)?;
    }
    Ok(())
}

/// Per-claim fresh-volume verdicts used to gate the 32 MiB floor. `true`
/// means the size is sub-floor AND the claim has no live ordinal-0 PVC, so
/// the floor must be enforced for it; `false` means the size is at or above
/// the floor (nothing to check) or the claim is already provisioned
/// (grandfathered — a surviving sub-floor volume activates).
#[derive(Debug, Clone, Copy, Default)]
pub struct FreshVolumeClaims {
    /// state volume (`storage`/`app_data_size` → VCT `state`)
    pub app_data: bool,
    /// tls-state volume (`tls_storage`/`tls_data_size` → VCT `tls-state`)
    pub tls_data: bool,
}

impl FreshVolumeClaims {
    /// Both claims need the fresh-format floor (e.g. app creation, where no
    /// cluster lookup is performed).
    pub const ALL: Self = Self {
        app_data: true,
        tls_data: true,
    };

    /// No claim needs the floor.
    pub const NONE: Self = Self {
        app_data: false,
        tls_data: false,
    };
}

/// Which of an app's persistent-volume claims a sub-floor size would
/// provision FRESH — i.e. the generated `<vct>-<workload>-0` PVC has no
/// live object. Verdicts are produced only for sizes below the floor;
/// sizes at or above it short-circuit without any Kubernetes I/O. A claim
/// that exists but is terminating does not count as provisioned. Fails
/// closed: lookup errors propagate and never grant the waiver.
///
/// `workload` is the generated StatefulSet name (`ConfidentialApp.name`,
/// which the API renders from `apps.name`), not a guessed resource name.
pub async fn sub_floor_fresh_claims(
    engine: &ApplyEngine,
    namespace: &str,
    workload: &str,
    app_data_size: &str,
    tls_data_size: &str,
) -> Result<FreshVolumeClaims, ApplyError> {
    use k8s_openapi::api::core::v1::PersistentVolumeClaim;
    use kube::api::Api;

    let app_data_sub_floor = crate::validate::is_sub_floor_volume_size(app_data_size);
    let tls_data_sub_floor = crate::validate::is_sub_floor_volume_size(tls_data_size);
    if !app_data_sub_floor && !tls_data_sub_floor {
        return Ok(FreshVolumeClaims::NONE);
    }

    let pvc_api: Api<PersistentVolumeClaim> = Api::namespaced(engine.client().clone(), namespace);

    async fn claim_is_fresh(
        pvc_api: &Api<PersistentVolumeClaim>,
        claim_name: &str,
    ) -> Result<bool, ApplyError> {
        Ok(match pvc_api.get_opt(claim_name).await? {
            Some(pvc) => pvc.metadata.deletion_timestamp.is_some(),
            None => true,
        })
    }

    let mut claims = FreshVolumeClaims::NONE;
    if app_data_sub_floor {
        claims.app_data = claim_is_fresh(
            &pvc_api,
            &crate::manifest::volumes::provisioned_claim_name("state", workload),
        )
        .await?;
    }
    if tls_data_sub_floor {
        claims.tls_data = claim_is_fresh(
            &pvc_api,
            &crate::manifest::volumes::provisioned_claim_name("tls-state", workload),
        )
        .await?;
    }
    Ok(claims)
}
