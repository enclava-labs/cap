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

    // Inspect every claim ONCE before the first provider mutation: the same
    // verdict gates the fresh-format floor and sizes the rollout budget, so
    // a redeploy of initialized volumes keeps the base deadline while claims
    // lacking positive initialization evidence add the first-boot allowance.
    // Live Kubernetes state is the only admissible proof — a surviving claim
    // counts as initialized only while a later-created Ready pod mounts it;
    // everything else fails closed (refusal or base budget), never a
    // destructive recovery.
    let fresh_volume_claims =
        inspect_fresh_volume_claims(engine, &app.namespace, &app.name, FreshVolumeClaims::ALL)
            .await?;
    enforce_floor_on_claims(app, fresh_volume_claims)?;
    let manifests = generate_all_manifests(app);

    crate::manifest::cc_init_data::verify_runtime_class_binding(&manifests.statefulset, app)
        .map_err(ApplyError::ManifestGeneration)?;

    apply_all(engine, &manifests, generation).await?;

    // Watch rollout. The budget grows only with claims that lack positive
    // initialization evidence: a fresh device is fully zero-scanned before
    // format, while an initialized volume is just opened.
    let rollout_timeout = engine
        .config()
        .rollout_timeout_for_storage(
            &app.storage.app_data.size,
            &app.storage.tls_data.size,
            fresh_volume_claims,
        )
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

/// Enforce the 32 MiB LUKS2 fresh-format floor against an already-computed
/// claim verdict: every claim flagged fresh must request at least the
/// floor. Claims without positive initialization evidence are provisioned
/// FRESH by this render, and enclava-init refuses to format a device below
/// the floor — so reject at the boundary instead of leaving the app
/// unstartable on a StatefulSet volumeClaimTemplate that can never be
/// resized.
pub fn enforce_floor_on_claims(
    app: &ConfidentialApp,
    claims: FreshVolumeClaims,
) -> Result<(), ApplyError> {
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

/// Per-claim fresh-volume verdicts. `true` means the claim lacks positive
/// initialization evidence — it is missing, terminating, or never proven
/// initialized — so this render provisions it FRESH: the 32 MiB floor and
/// the first-boot rollout allowance apply to it. `false` means the claim
/// was not inspected or proven initialized.
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

/// Positive initialization evidence for the app's persistent-volume claims,
/// per requested claim. `true` in the returned verdict means the checked
/// claim LACKS positive initialization evidence — it is missing,
/// terminating, has no creation timestamp, or exists but was never proven
/// initialized — so it is provisioned FRESH by this render. `false` means
/// the claim was not requested ([`FreshVolumeClaims::NONE`] performs no
/// Kubernetes I/O at all) or positive evidence exists.
///
/// Positive evidence requires the EXACT surviving ordinal-0 claim
/// `<vct>-<workload>-0` (`state`/`tls-state` VCTs, replicas:1 workload) with
/// a populated creation timestamp, AND the live ordinal-0 pod
/// `<workload>-0` non-terminating and Ready, mounting THIS exact claim,
/// created in a LATER whole second than the claim — the workload is
/// currently running on the initialized device.
///
/// Live Kubernetes state is the ONLY admissible evidence: database
/// deployment history is not consulted because independent DB and
/// Kubernetes clocks cannot order a row against a claim, and a healthy
/// status can be published by a password-timeout redeploy without opening
/// storage. Strict precedence is deliberate and fails closed: Kubernetes
/// `creationTimestamp` serializes only whole seconds, so a same-second
/// pod/claim pair cannot prove ordering — a Ready pod created in the same
/// second as a replacement claim could be running on the deleted volume's
/// handle. The tradeoff is availability, never format authorization: a
/// legitimately initialized legacy claim with no live pod proof reads as
/// unproven — a sub-floor one must regain live readiness before its size is
/// re-admitted (or be resized above the floor).
///
/// PVC existence, `Bound` phase, watching/applying deployment status, and
/// manifest-hash markers are NOT evidence: a bound-but-unformatted claim
/// stays fresh. Unknown-legacy claims (present but unproven) fail closed as
/// fresh — a refusal or base budget, never a destructive recovery; this
/// evidence only ever WAIVES the size floor and the first-boot time
/// allowance, never authorizes format/wipe.
///
/// `workload` is the generated StatefulSet name (`ConfidentialApp.name`,
/// which the API renders from `apps.name`), not a guessed resource name.
/// Fails closed: lookup errors propagate and never grant the waiver.
pub async fn inspect_fresh_volume_claims(
    engine: &ApplyEngine,
    namespace: &str,
    workload: &str,
    claims_to_check: FreshVolumeClaims,
) -> Result<FreshVolumeClaims, ApplyError> {
    use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
    use kube::api::{Api, ListParams};

    if !claims_to_check.app_data && !claims_to_check.tls_data {
        return Ok(FreshVolumeClaims::NONE);
    }

    let pvc_api: Api<PersistentVolumeClaim> = Api::namespaced(engine.client().clone(), namespace);
    let pod_api: Api<Pod> = Api::namespaced(engine.client().clone(), namespace);
    let pod_name = crate::manifest::volumes::provisioned_pod_name(workload);
    // The pod fetch is lazy and shared: both claims reuse the same pod.
    let mut live_pod: Option<Option<Pod>> = None;

    async fn claim_is_fresh(
        pvc_api: &Api<PersistentVolumeClaim>,
        pod_api: &Api<Pod>,
        pod_name: &str,
        live_pod: &mut Option<Option<Pod>>,
        claim_name: &str,
    ) -> Result<bool, ApplyError> {
        let Some(pvc) = pvc_api.get_opt(claim_name).await? else {
            return Ok(true);
        };
        if pvc.metadata.deletion_timestamp.is_some() {
            return Ok(true);
        }
        let Some(created) = pvc.metadata.creation_timestamp else {
            return Ok(true);
        };
        let pvc_millis = created.0.as_millisecond();
        if live_pod.is_none() {
            // Pod GET is withheld to preserve the log-access boundary.
            let params = ListParams::default()
                .fields(&format!("metadata.name={pod_name}"))
                .limit(1);
            *live_pod = Some(pod_api.list(&params).await?.items.pop());
        }
        Ok(!pod_proves_claim_initialized(
            live_pod.as_ref().and_then(|pod| pod.as_ref()),
            claim_name,
            pvc_millis,
        ))
    }

    let mut claims = FreshVolumeClaims::NONE;
    if claims_to_check.app_data {
        claims.app_data = claim_is_fresh(
            &pvc_api,
            &pod_api,
            &pod_name,
            &mut live_pod,
            &crate::manifest::volumes::provisioned_claim_name("state", workload),
        )
        .await?;
    }
    if claims_to_check.tls_data {
        claims.tls_data = claim_is_fresh(
            &pvc_api,
            &pod_api,
            &pod_name,
            &mut live_pod,
            &crate::manifest::volumes::provisioned_claim_name("tls-state", workload),
        )
        .await?;
    }
    Ok(claims)
}

/// Whether the live ordinal-0 pod proves `claim_name` is initialized: the
/// pod is not terminating, reports Ready, mounts exactly this claim, and
/// was created in a LATER whole second than the claim. Same-second
/// equality proves nothing (see the `inspect_fresh_volume_claims`
/// timestamp note): both timestamps carry only second precision, so the
/// pod could still be running on the deleted claim's volume handle.
fn pod_proves_claim_initialized(
    pod: Option<&k8s_openapi::api::core::v1::Pod>,
    claim_name: &str,
    pvc_millis: i64,
) -> bool {
    let Some(pod) = pod else { return false };
    if pod.metadata.deletion_timestamp.is_some() {
        return false;
    }
    let Some(pod_created) = pod.metadata.creation_timestamp.as_ref() else {
        return false;
    };
    if pod_created.0.as_millisecond() <= pvc_millis {
        return false;
    }
    let mounts_claim = pod.spec.as_ref().is_some_and(|spec| {
        spec.volumes.as_ref().is_some_and(|volumes| {
            volumes.iter().any(|volume| {
                volume
                    .persistent_volume_claim
                    .as_ref()
                    .is_some_and(|claim| claim.claim_name == claim_name)
            })
        })
    });
    if !mounts_claim {
        return false;
    }
    pod.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        })
}
