use k8s_openapi::api::apps::v1::StatefulSet;
use kube::api::{Api, Patch, PatchParams};

use super::engine::{ApplyEngine, ApplyError};

/// Apply the StatefulSet via SSA WITHOUT `force` (Phase 11).
///
/// The StatefulSet carries attestation-critical fields: `image`, `runtimeClassName`,
/// `cc_init_data` annotations, and the signer-identity annotation. If a manager
/// outside the control plane has set any of these, force-applying would silently
/// overwrite their value and a follower-attacker could mask their tampering by
/// re-claiming ownership on the next reconcile. We surface the conflict instead.
///
/// On 409 Conflict: the API server returns a status object listing the conflicting
/// fields and managers. We log a structured warning and return the kube error so
/// the caller (deployer) can decide. Initial-create still works because there is
/// no existing object to conflict with.
pub async fn apply_statefulset(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset: &StatefulSet,
) -> Result<StatefulSet, ApplyError> {
    let name = statefulset.metadata.name.as_deref().unwrap_or("<unnamed>");
    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let pp = PatchParams::apply(&engine.config().field_manager);

    match super::bounded_kube_write(api.patch(name, &pp, &Patch::Apply(statefulset))).await {
        Ok(patched) => {
            tracing::info!(
                namespace = %namespace,
                statefulset = %name,
                "StatefulSet applied via SSA (no-force)"
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
