use k8s_openapi::api::apps::v1::StatefulSet;
use kube::api::Api;

use super::engine::{ApplyEngine, ApplyError};
use super::generation::{MutationGeneration, apply_resource};

/// Replace the StatefulSet exactly when CAP is its only non-status manager.
///
/// The StatefulSet carries attestation-critical fields: `image`, `runtimeClassName`,
/// `cc_init_data` annotations, and the signer-identity annotation. If a manager
/// outside the control plane has set any of these, replacing would silently
/// overwrite their value and a follower-attacker could mask their tampering by
/// re-claiming ownership on the next reconcile. We use no-force SSA in that case
/// so the API server surfaces the conflict instead. Exact replacement is needed
/// for CAP-created objects because their initial `Update` ownership otherwise
/// retains fields later omitted from the desired manifest.
///
/// On 409 Conflict: the API server returns a status object listing the conflicting
/// fields and managers. We log a structured warning and return the kube error so
/// the caller (deployer) can decide. Initial-create still works because there is
/// no existing object to conflict with.
pub async fn apply_statefulset(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset: &StatefulSet,
    generation: MutationGeneration,
) -> Result<StatefulSet, ApplyError> {
    let name = statefulset.metadata.name.as_deref().unwrap_or("<unnamed>");
    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match apply_resource(engine, &api, statefulset, generation, false, true).await {
        Ok(patched) => {
            tracing::info!(
                namespace = %namespace,
                statefulset = %name,
                "StatefulSet converged"
            );
            Ok(patched)
        }
        Err(ApplyError::Kube(kube::Error::Api(ae))) if ae.code == 409 => {
            tracing::warn!(
                namespace = %namespace,
                statefulset = %name,
                conflict = %ae.message,
                "SSA conflict on attestation-critical resource: refusing to overwrite \
                 fields owned by another manager. Investigate before re-applying."
            );
            Err(ApplyError::Kube(kube::Error::Api(ae)))
        }
        Err(e) => Err(e),
    }
}
