//! Kubernetes-side generation fencing for CAP-owned workload resources.
//!
//! A database lease prevents healthy CAP processes from writing concurrently,
//! but canceling a client future does not prove that the Kubernetes API server
//! canceled the request. Every update therefore carries the durable provider
//! generation and the resourceVersion observed immediately before the write.
//! A delayed older request conflicts after a newer write instead of replaying
//! over it.

use kube::{
    Api, Resource,
    api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions},
};
use serde::{Serialize, de::DeserializeOwned};
use std::{fmt::Debug, time::Duration};

use super::creation_ledger::{CreationRecord, LineageProvenance, creation_lineage_provenance};
use super::engine::{ApplyEngine, ApplyError};
use super::fields_v1::flatten_owned_paths;

pub const MUTATION_GENERATION_ANNOTATION: &str = "enclava.dev/cap-provider-mutation-generation";

/// Annotation stamped by `apply_namespace` only when it observed the
/// namespace absent immediately before creating it. Proves CREATION by a
/// CAP apply, as opposed to the mutation-generation annotation which only
/// proves this apply last wrote the object. Teardown paths that delete a
/// whole namespace require this evidence so a pre-existing namespace that
/// CAP merely adopted (non-force SSA tolerates it) is never destroyed.
pub const NAMESPACE_CREATED_BY_ANNOTATION: &str = "enclava.dev/cap-namespace-created-by-generation";

/// Annotation stamped by `apply_resource` only on the initial-create POST
/// path. Proves CREATION by a CAP apply, as opposed to
/// [`MUTATION_GENERATION_ANNOTATION`], which is also stamped when an
/// existing (possibly foreign, pre-existing) object is SSA-patched.
/// Compensating cleanup in adopted namespaces requires this evidence before
/// deleting a namespaced object: last-writer proof alone would authorize
/// deleting a pre-existing object CAP merely patched. Later applies copy
/// the live evidence forward (`preserve_creation_evidence`) so it survives
/// re-applies verbatim and is never fabricated for adopted objects.
pub const RESOURCE_CREATED_BY_ANNOTATION: &str = "enclava.dev/cap-resource-created-by-generation";
// ponytail: bounded but patient — total worst-case conflict wait ≈ 60 s, well
// inside the 180 s mutation lease and job deadlines. Controllers routinely
// rewrite status for minutes; the old 12×≤200 ms (~1.9 s) budget terminally
// failed live deploys against ordinary concurrent writers (staging
// 2026-09-13: gens 3d869f2c/69dff1f3/4b1b3ef7, mutation_conflict_exhausted).
const MAX_CONFLICT_RETRIES: usize = 64;

fn conflict_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis((25 * (1 << attempt.min(5))).min(1000))
}

/// Codex P2 (compensating create): a successful POST has ALREADY created the
/// object by the time post-create verification runs. If a mutating admission
/// policy dropped or rewrote the creation annotation, failing closed without
/// compensation leaves the object behind with no valid creation evidence:
/// failed-apply cleanup then classifies it as adopted/foreign and never
/// deletes it (in an adopted namespace it can survive as a live StatefulSet
/// or registry Secret indefinitely). Compensate the EXACT object the POST
/// response identified — a UID-preconditioned DELETE can never hit a
/// same-named replacement — before propagating the verification error.
///
/// devin 🔴 follow-up: this runs synchronously before the failed apply
/// returns, and `fail_apply_job_with_mutation` holds the mutation lease —
/// shared fences included — for the whole span. Raw client requests can sit
/// on the ~295 s client timeout when the API server stalls after the POST,
/// holding those fences far past the 30 s `bounded_kube_write` cap every
/// other apply write obeys. Every request is now bounded by the remaining
/// budget of a total compensation deadline (and the same per-request cap);
/// a timeout is UNRESOLVED, not success — reported loudly below with a
/// stable `error_code` so operators can find the object (the failed-apply
/// cleanup will not remove it: it fails the creation-evidence gate).
pub(super) async fn compensate_created_object<K>(api: &Api<K>, name: &str, created: &K)
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    // grok (minor): a missing UID would leave the precondition unpinned —
    // never issue a name-only DELETE that could hit a same-named
    // replacement. Fail loudly instead.
    let Some(uid) = created.meta().uid.clone() else {
        tracing::error!(
            kind = kind::<K>(),
            name,
            error_code = "compensation_unpinned_uid",
            "just-created object has no UID; compensating delete would be unpinned — leaving the object for manual removal"
        );
        return;
    };
    let deadline = tokio::time::Instant::now() + COMPENSATE_TOTAL_TIMEOUT;
    let mut accepted = false;
    for attempt in 0..3 {
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid.clone()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        match bounded_compensation(deadline, api.delete(name, &params)).await {
            Ok(_) => {
                accepted = true;
                break;
            }
            Err(CompensationError::Gone) => return,
            Err(CompensationError::Timeout) => {
                // devin 🔴: budget exhausted while the API server stalls.
                // Stop hammering it: the fence hold is the cost, and the
                // object is unresolved either way.
                tracing::error!(
                    kind = kind::<K>(),
                    name,
                    error_code = "compensation_timeout_unresolved",
                    "compensating delete of a just-created object exceeded its bounded budget; leaving the object unresolved — failed-apply cleanup will NOT remove it, manual removal required"
                );
                return;
            }
            Err(CompensationError::Kube(error)) => {
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    attempt,
                    error = %error,
                    "compensating delete of a just-created object failed; retrying"
                );
                if tokio::time::Instant::now() + conflict_retry_delay(attempt) >= deadline {
                    break;
                }
                tokio::time::sleep(conflict_retry_delay(attempt)).await;
            }
        }
    }
    if !accepted {
        tracing::error!(
            kind = kind::<K>(),
            name,
            error_code = "compensation_delete_unresolved",
            "compensating delete failed; the object may remain without valid creation evidence"
        );
        return;
    }
    // grok (minor): an accepted DELETE can sit on a finalizer, and the
    // failed-apply cleanup will never remove this object afterwards (it
    // fails the creation-evidence gate). Confirm actual absence before
    // returning; a stuck object needs manual removal, so say so loudly.
    for wait in 0..5 {
        if tokio::time::Instant::now() + Duration::from_secs(2) >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        match bounded_compensation(deadline, api.get_opt(name)).await {
            Ok(None) => return,
            Ok(Some(_)) => {
                if wait == 4 {
                    tracing::error!(
                        kind = kind::<K>(),
                        name,
                        error_code = "compensation_delete_unresolved",
                        "compensating delete was accepted but the object is not gone (finalizer?); failed-apply cleanup will NOT remove it — manual removal required"
                    );
                }
            }
            Err(CompensationError::Timeout) => {
                tracing::error!(
                    kind = kind::<K>(),
                    name,
                    error_code = "compensation_timeout_unresolved",
                    "could not confirm compensating delete removed the object within the bounded budget; leaving it unresolved — manual removal required"
                );
                return;
            }
            Err(CompensationError::Gone) | Err(CompensationError::Kube(_)) => {
                // Gone cannot occur on get_opt; a transport failure on the
                // confirming read leaves the outcome undecidable within the
                // budget — report it and stop (the earlier log lines carry
                // the reconciliation evidence).
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    "could not confirm compensating delete removed the object"
                );
                return;
            }
        }
    }
}

/// Total budget for one compensating delete + absence confirmation. Sized
/// below the 180 s mutation lease so the shared fences this apply holds are
/// released well before their reclaim, while still covering three bounded
/// DELETE attempts plus the finalizer grace window the confirmation poll
/// observes (`conflict_retry_delay`'s worst-case conflict wait is ~60 s and
/// is spent inside this budget, not on top of it).
const COMPENSATE_TOTAL_TIMEOUT: Duration = Duration::from_secs(90);

/// Per-request cap for compensation requests, matching `bounded_kube_write`
/// so a stalled API server cannot stretch a single request past the budget
/// every other apply write obeys.
const COMPENSATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A compensation request that ended without a decision.
#[derive(Debug)]
enum CompensationError {
    /// The object is already absent (404): the compensation is complete.
    Gone,
    /// The request ran out of its bounded budget (total deadline or the
    /// per-request cap). Unresolved, not failed — see the caller's log.
    Timeout,
    /// A transport/API error the caller may retry within the budget.
    Kube(kube::Error),
}

/// Bound one compensation request by BOTH the remaining total compensation
/// budget and the per-request cap (devin 🔴: raw calls could otherwise hold
/// the mutation lease for the client's ~295 s timeout per request).
async fn bounded_compensation<F, T>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<T, CompensationError>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    let per_request = tokio::time::Instant::now() + COMPENSATE_REQUEST_TIMEOUT;
    match tokio::time::timeout_at(deadline.min(per_request), future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(kube::Error::Api(error))) if error.code == 404 => Err(CompensationError::Gone),
        Ok(Err(error)) => Err(CompensationError::Kube(error)),
        Err(_) => Err(CompensationError::Timeout),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MutationGeneration(i64);

impl MutationGeneration {
    pub fn new(value: i64) -> Result<Self, ApplyError> {
        if value <= 0 {
            return Err(ApplyError::InvalidMutationGeneration(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

fn kind<K>() -> String {
    std::any::type_name::<K>()
        .rsplit("::")
        .next()
        .unwrap_or("KubernetesResource")
        .to_string()
}

fn live_generation<K>(resource: &K) -> Result<i64, ApplyError>
where
    K: Resource,
{
    let raw = resource
        .meta()
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION));
    match raw {
        None => Ok(0),
        Some(raw) => raw
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| ApplyError::InvalidLiveMutationGeneration {
                kind: kind::<K>(),
                name: resource
                    .meta()
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string()),
            }),
    }
}

fn ensure_not_stale<K>(resource: &K, desired: MutationGeneration) -> Result<(), ApplyError>
where
    K: Resource,
{
    let actual = live_generation(resource)?;
    if actual > desired.get() {
        return Err(ApplyError::StaleMutationGeneration {
            kind: kind::<K>(),
            name: resource
                .meta()
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            desired: desired.get(),
            actual,
        });
    }
    Ok(())
}

fn annotate<K>(resource: &mut K, generation: MutationGeneration)
where
    K: Resource,
{
    resource
        .meta_mut()
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            MUTATION_GENERATION_ANNOTATION.to_string(),
            generation.get().to_string(),
        );
}

/// Confirm a created object actually carries this generation's creation
/// evidence (the API server or a mutating admission policy could have
/// dropped or rewritten the annotation). Fail closed: an object missing
/// its evidence can never be classified as CAP-created by compensating
/// cleanup.
fn verify_creation_evidence<K>(
    created: &K,
    generation: MutationGeneration,
) -> Result<(), ApplyError>
where
    K: Resource,
{
    let stamped = created
        .meta()
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION))
        .and_then(|raw| raw.parse::<i64>().ok());
    if stamped == Some(generation.get()) {
        Ok(())
    } else {
        Err(ApplyError::ProviderGenerationNotApplied {
            kind: kind::<K>(),
            name: created
                .meta()
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            expected: generation.get(),
            actual: stamped.unwrap_or(0),
        })
    }
}

/// Remove any creation-evidence annotations from a desired write. Evidence
/// is re-added only from the live object in `preserve_creation_evidence`;
/// callers cannot smuggle it in.
fn strip_creation_evidence<K>(resource: &mut K)
where
    K: Resource,
{
    if let Some(annotations) = resource.meta_mut().annotations.as_mut() {
        annotations.remove(RESOURCE_CREATED_BY_ANNOTATION);
        annotations.remove(NAMESPACE_CREATED_BY_ANNOTATION);
    }
}

/// Stamp creation evidence on a resource this apply is creating via POST.
fn annotate_created<K>(resource: &mut K, generation: MutationGeneration)
where
    K: Resource,
{
    resource
        .meta_mut()
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            RESOURCE_CREATED_BY_ANNOTATION.to_string(),
            generation.get().to_string(),
        );
}

const CREATION_EVIDENCE_KEYS: [&str; 2] = [
    RESOURCE_CREATED_BY_ANNOTATION,
    NAMESPACE_CREATED_BY_ANNOTATION,
];

/// Settle the live object's creation lineage against the engine's ledger
/// (cap#272). `None` when no ledger is attached: the caller then keeps the
/// legacy annotation+manager trust (deletion authority is enforced in the
/// API's ledger-gated sweep, not here).
fn attached_lineage_provenance<K>(engine: &ApplyEngine, live: &K) -> Option<LineageProvenance>
where
    K: Resource,
{
    let ledger = engine.creation_ledger()?;
    let meta = live.meta();
    Some(creation_lineage_provenance(
        meta.name.as_deref(),
        meta.uid.as_deref(),
        meta.creation_timestamp
            .as_ref()
            .map(|ts| ts.0.to_string())
            .as_deref(),
        Some(ledger.as_ref()),
    ))
}

/// Record an object this apply just created via its own POST — the only
/// moment creation is provable (cap#272). The control plane drains and
/// durably persists these records after each apply step; an object whose
/// row cannot be persisted is compensated by the caller.
pub(crate) fn record_created_object<K>(
    engine: &ApplyEngine,
    created: &K,
    namespace: Option<&str>,
    generation: MutationGeneration,
) where
    K: Resource + Serialize,
{
    let Some(ledger) = engine.creation_ledger() else {
        return;
    };
    let meta = created.meta();
    let (Some(name), Some(uid)) = (meta.name.clone(), meta.uid.clone()) else {
        tracing::warn!(
            kind = kind::<K>(),
            "created object response lacks name/uid; cannot record creation provenance (cap#272)"
        );
        return;
    };
    // DynamicObject (CiliumNetworkPolicy, Gateway, TLSRoute, EnvoyProxy)
    // round-trips its TypeMeta, so the real Kubernetes kind is recoverable
    // from the response; typed k8s-openapi structs drop it and fall back
    // to the Rust type name, which equals the Kubernetes kind for every
    // typed resource this crate applies.
    let kind = serde_json::to_value(created)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .filter(|kind| !kind.is_empty())
        .unwrap_or_else(|| kind::<K>());
    ledger.record(CreationRecord {
        kind,
        name,
        namespace: namespace.map(str::to_string),
        uid,
        mutation_generation: generation.get(),
    });
}

/// The creation-evidence pairs `preserve_creation_evidence` stamps for this
/// live object: only keys whose annotation the CAP field manager owns on
/// `current` (see the provenance note there). The update path re-checks
/// these pairs against the write response so a mutating admission webhook
/// that drops or rewrites them cannot turn a CAP-created object into an
/// unattributable one while the apply still reports success.
fn preserved_creation_evidence<K>(current: &K, field_manager: &str) -> Vec<(&'static str, String)>
where
    K: Resource,
{
    CREATION_EVIDENCE_KEYS
        .iter()
        .filter_map(|&key| {
            let evidence = current
                .meta()
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(key))?
                .clone();
            // Provenance: only evidence whose annotation key is OWNED by this
            // control plane's field manager is preserved. Tenant manifests can
            // set arbitrary annotations on pre-existing objects; without this
            // check a forged stamp would be preserved, stamped with the
            // current mutation generation, and later deleted by compensating
            // cleanup as though CAP had created the object.
            if !annotation_owned_by_manager(current, key, field_manager) {
                tracing::warn!(
                    key,
                    "live creation evidence lacks CAP field-manager provenance; refusing to preserve it"
                );
                return None;
            }
            Some((key, evidence))
        })
        .collect()
}

/// Copy the live object's creation evidence (if any) onto the desired
/// write. Re-applying an object CAP created must not silently drop the
/// evidence: an apply omitting a map key it owns can prune it, which would
/// make a CAP-created object look adopted forever after. Evidence is only
/// ever copied from the object the write is preconditioned on — the same
/// GET whose resourceVersion gates the patch — so a same-named replacement
/// can never inherit the predecessor's evidence, and evidence is never
/// fabricated for an object whose creation was not observed by this code
/// path. Both evidence keys are covered: the generic
/// RESOURCE_CREATED_BY stamp and the namespace-specific
/// NAMESPACE_CREATED_BY stamp (namespaces apply through this same path).
fn preserve_creation_evidence<K>(desired: &mut K, current: &K, field_manager: &str)
where
    K: Resource,
{
    for (key, evidence) in preserved_creation_evidence(current, field_manager) {
        desired
            .meta_mut()
            .annotations
            .get_or_insert_with(Default::default)
            .insert(key.to_string(), evidence);
    }
}

/// Confirm the write response still carries every creation-evidence pair
/// that was preserved from the preconditioned live object. A mutating
/// admission webhook can drop or rewrite the annotation while leaving the
/// mutation-generation annotation intact; accepting that response would
/// let a later failed-apply sweep classify the still-live CAP-created
/// object as `Foreign` (no evidence) and silently clear cleanup evidence
/// over a partially updated resource. Fail closed instead: the loss is
/// unresolved and must surface as a distinct apply failure.
fn verify_preserved_creation_evidence<K>(
    applied: &K,
    expected: &[(&'static str, String)],
) -> Result<(), ApplyError>
where
    K: Resource,
{
    for (key, expected_value) in expected {
        let actual = applied
            .meta()
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(*key));
        if actual != Some(expected_value) {
            return Err(ApplyError::CreationEvidenceLost {
                kind: kind::<K>(),
                name: applied
                    .meta()
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string()),
                key: key.to_string(),
            });
        }
    }
    Ok(())
}

/// Best-effort, bounded restore of creation evidence a mutating admission
/// webhook stripped from an ACCEPTED update: the write is already
/// persisted, so unlike the create path (which deletes its object) the
/// only safe compensation is to re-stamp the exact evidence pairs the
/// preconditioned object proved were ours. Only the same-UID object — the
/// one this failed update was preconditioned on — is ever touched, and
/// each restore patch is resourceVersion-fenced.
///
/// Every read AND write is bounded by the shared compensation budget
/// (devin 🔴 round 9): this runs while the apply worker still holds its
/// mutation lease and shared provider fences, so a stalled API server
/// must not stretch a raw GET to the client's ~295 s read timeout and
/// block unrelated deployments. A read that exhausts the budget is
/// treated as unresolved evidence, not an infinite wait.
///
/// Returns the live object when every expected evidence pair is
/// verifiably present — restored by this loop's patch or already
/// re-stamped by another CAP writer. A restored same-UID object is
/// attributable again, so the caller reports SUCCESS instead of
/// `CreationEvidenceLost` (devin 🔴/Codex P2 round 9): that error makes
/// the API layer persist the permanent, app-wide `creation_evidence_lost`
/// marker, which has no automatic clearing path and would keep unrelated
/// unmarked sweep targets unresolved until operator intervention.
/// Returns `None` when the loss stays unresolved: the caller fails
/// closed and the adopted-namespace sweep counts unmarked live targets
/// as unresolved.
async fn compensate_stripped_evidence<K>(
    api: &Api<K>,
    name: &str,
    preconditioned: &K,
    expected: &[(&'static str, String)],
    field_manager: &str,
) -> Option<K>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    const RESTORE_ATTEMPTS: usize = 3;
    // Same budget rationale as the create-compensation path: the whole
    // restore, reads included, must release the worker's shared fences
    // well before the 180 s mutation lease reclaim.
    let deadline = tokio::time::Instant::now() + COMPENSATE_TOTAL_TIMEOUT;
    for attempt in 0..RESTORE_ATTEMPTS {
        let live = match bounded_compensation(deadline, api.get(name)).await {
            Ok(live) => live,
            Err(CompensationError::Gone) => {
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    "object vanished before its webhook-stripped creation evidence could be restored"
                );
                return None;
            }
            Err(CompensationError::Timeout) => {
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    "re-read to restore webhook-stripped creation evidence timed out; treating the loss as unresolved instead of holding shared fences"
                );
                return None;
            }
            Err(CompensationError::Kube(error)) => {
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    error = %error,
                    "cannot re-read object to restore webhook-stripped creation evidence"
                );
                return None;
            }
        };
        // Never restore onto a same-named replacement: only the exact
        // object whose evidence the failed update carried.
        if live.meta().uid != preconditioned.meta().uid {
            tracing::warn!(
                kind = kind::<K>(),
                name,
                "live object no longer matches the failed update's UID; not restoring creation evidence"
            );
            return None;
        }
        let restored = |object: &K| {
            expected.iter().all(|(key, value)| {
                object
                    .meta()
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(*key))
                    == Some(value)
            })
        };
        if restored(&live) {
            // Someone (an earlier restore attempt that raced the response,
            // or another CAP writer) already re-stamped it.
            return Some(live);
        }
        let mut annotations = serde_json::Map::new();
        for (key, value) in expected {
            annotations.insert(key.to_string(), serde_json::json!(value));
        }
        let mut patch = serde_json::json!({"metadata": {"annotations": annotations}});
        // Fence the restore onto the exact version just read so a foreign
        // write landing mid-restore cannot be overwritten.
        if let Some(resource_version) = live.meta().resource_version.clone() {
            patch["metadata"]["resourceVersion"] = serde_json::json!(resource_version);
        }
        let params = PatchParams {
            field_manager: Some(field_manager.to_string()),
            ..PatchParams::default()
        };
        match super::bounded_kube_write(api.patch(name, &params, &Patch::Merge(&patch))).await {
            Ok(patched) if restored(&patched) => {
                tracing::info!(
                    kind = kind::<K>(),
                    name,
                    "restored creation evidence a webhook stripped from an accepted update; the restored object is attributable again, so the apply succeeds"
                );
                return Some(patched);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = kind::<K>(),
                    name,
                    error = %error,
                    "creation-evidence restore patch rejected; retrying within the restore budget"
                );
            }
        }
        // Keep the retry backoff inside the total budget: never sleep
        // past the deadline the shared fences are held under.
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        tokio::time::sleep(conflict_retry_delay(attempt).min(deadline - now)).await;
    }
    tracing::error!(
        kind = kind::<K>(),
        name,
        error_code = "creation_evidence_restore_unresolved",
        "could not restore webhook-stripped creation evidence; object stays unresolved for the failure sweep"
    );
    None
}

/// True when a managed-fields entry authored by `field_manager` (non-status)
/// owns `metadata.annotations.<key>` on the live object. The walk follows
/// ONLY the f:metadata -> f:annotations -> f:<key> chain and ignores
/// sibling branches: a real control-plane entry mixes annotation ownership
/// with associative-list paths (`k:` container keys) that the general
/// FieldsV1 flattener refuses to attribute — rejecting the whole entry
/// there would drop creation evidence on every StatefulSet reapply. Fails
/// closed when managed fields are absent entirely.
pub fn annotation_owned_by_manager<K>(
    resource: &K,
    annotation_key: &str,
    field_manager: &str,
) -> bool
where
    K: Resource,
{
    let Some(entries) = resource.meta().managed_fields.as_ref() else {
        return false;
    };
    if entries.is_empty() {
        return false;
    }
    entries.iter().any(|entry| {
        if entry.subresource.as_deref() == Some("status") {
            return false;
        }
        if entry.manager.as_deref() != Some(field_manager) {
            return false;
        }
        entry
            .fields_v1
            .as_ref()
            .is_some_and(|fields| owns_annotation_path(&fields.0, annotation_key))
    })
}

/// Walk f:metadata -> f:annotations -> f:<key> within one FieldsV1
/// document, ignoring every other branch.
fn owns_annotation_path(fields_v1: &serde_json::Value, annotation_key: &str) -> bool {
    fields_v1
        .pointer("/f:metadata/f:annotations")
        .and_then(|annotations| annotations.get(format!("f:{annotation_key}")))
        .is_some()
}

fn only_trusted_field_managers<K>(resource: &K, field_manager: &str) -> bool
where
    K: Resource,
{
    resource
        .meta()
        .managed_fields
        .as_ref()
        .is_some_and(|entries| {
            !entries.is_empty()
                && entries.iter().all(|entry| {
                    entry.subresource.as_deref() == Some("status")
                        || entry.manager.as_deref() == Some(field_manager)
                })
        })
}

/// Fields the API server reported as `FieldManagerConflict` causes for a
/// 409, in owned-path notation (leading dot stripped).
fn field_manager_conflict_fields(status: &kube::core::Status) -> Vec<String> {
    status
        .details
        .as_ref()
        .map(|details| {
            details
                .causes
                .iter()
                .filter(|cause| cause.reason == "FieldManagerConflict")
                .map(|cause| cause.field.trim_start_matches('.').to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// True when no external (non-status, differently-managed) entry owns any of
/// the conflicting fields, so a forced apply can only reclaim fields this
/// manager itself owns. Absent, empty, or unattributable ownership fails
/// closed.
fn conflicts_reclaimable_by_force<K>(live: &K, conflicts: &[String], field_manager: &str) -> bool
where
    K: Resource,
{
    let Some(entries) = live
        .meta()
        .managed_fields
        .as_ref()
        .filter(|entries| !entries.is_empty())
    else {
        return false;
    };
    conflicts.iter().all(|conflict| {
        !conflict.is_empty()
            && entries.iter().all(|entry| {
                if entry.subresource.as_deref() == Some("status")
                    || entry.manager.as_deref() == Some(field_manager)
                {
                    return true;
                }
                match entry
                    .fields_v1
                    .as_ref()
                    .map(|fields| &fields.0)
                    .and_then(flatten_owned_paths)
                {
                    Some(owned) => owned.iter().all(|path| {
                        conflict != path
                            && !conflict.starts_with(&format!("{path}."))
                            && !conflict.starts_with(&format!("{path}["))
                    }),
                    None => false,
                }
            })
    })
}

fn verify_applied_generation<K>(
    resource: &K,
    generation: MutationGeneration,
) -> Result<(), ApplyError>
where
    K: Resource,
{
    let actual = live_generation(resource)?;
    if actual != generation.get() {
        return Err(ApplyError::ProviderGenerationNotApplied {
            kind: kind::<K>(),
            name: resource
                .meta()
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            expected: generation.get(),
            actual,
        });
    }
    Ok(())
}

/// Create or conditionally SSA-update a resource.
///
/// Initial creation uses POST rather than SSA's create-or-update behavior. A
/// concurrent creator therefore gets `AlreadyExists` and must re-read before
/// it can update. A POST records Update ownership, so a later SSA may force only
/// when every non-status field manager is the configured, trusted CAP manager.
/// An external manager therefore still makes attestation-critical updates fail
/// closed. Existing objects are SSA-patched with the exact observed resourceVersion.
/// Callers must durably prevent generation reclaim while an initial create
/// response is ambiguous, because an absent resource cannot itself hold a
/// tombstone.
///
/// When an external non-status manager owns unrelated fields (for example a
/// lingering replicas-only `kubectl-patch` entry), the untrusted path applies
/// without force, and this manager's own prior Update ownership of the
/// generation annotation then conflicts on every new generation. That
/// self-conflict is distinguished from transient resourceVersion conflicts via
/// `Status.details.causes[].reason == FieldManagerConflict`: when every
/// conflicting field is owned (per the freshly read managedFields) only by
/// this manager, the apply escalates to force exactly enough to reclaim its
/// own fields. Any conflict an external entry owns, or any ownership state
/// that cannot be attributed, fails closed promptly with the server's
/// structured causes instead of burning the conflict budget.
pub async fn apply_resource<K>(
    engine: &ApplyEngine,
    api: &Api<K>,
    resource: &K,
    generation: MutationGeneration,
    force: bool,
    exact_when_trusted: bool,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + Serialize + DeserializeOwned,
{
    apply_resource_opt(
        engine,
        api,
        resource,
        generation,
        force,
        exact_when_trusted,
        true,
    )
    .await
}

/// Like [`apply_resource`] but with an explicit `allow_create` flag. When
/// false, an object that vanishes between the ownership probe and the SSA
/// attempt returns [`ApplyError::VanishedResource`] instead of creating a
/// replacement — used by the namespace adoption flow, where only the
/// direct stamped POST may create.
#[allow(clippy::too_many_arguments)]
pub async fn apply_resource_opt<K>(
    engine: &ApplyEngine,
    api: &Api<K>,
    resource: &K,
    generation: MutationGeneration,
    force: bool,
    exact_when_trusted: bool,
    allow_create: bool,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + Serialize + DeserializeOwned,
{
    let name = resource
        .meta()
        .name
        .as_deref()
        .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
    let post_params = PostParams {
        field_manager: Some(engine.config().field_manager.clone()),
        ..PostParams::default()
    };
    let mut force_against: Option<String> = None;
    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => Some(current),
            Err(kube::Error::Api(error)) if error.code == 404 => None,
            Err(error) => return Err(error.into()),
        };

        if let Some(current) = current {
            ensure_not_stale(&current, generation)?;
            let trusted = only_trusted_field_managers(&current, &engine.config().field_manager);
            // A forced reclaim is authorized only against the exact
            // resourceVersion whose ownership was classified: any foreign
            // write (including a pure ownership change) bumps the version,
            // silently deauthorizes the force, and falls back to the
            // no-force probe with a fresh classification.
            let authorized = force_against
                .as_deref()
                .is_some_and(|version| current.meta().resource_version.as_deref() == Some(version));
            let patch_params = if force || trusted || authorized {
                PatchParams::apply(&engine.config().field_manager).force()
            } else {
                PatchParams::apply(&engine.config().field_manager)
            };
            let resource_version = current
                .meta()
                .resource_version
                .clone()
                .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
            let mut desired = resource.clone();
            desired.meta_mut().resource_version = Some(resource_version.clone());
            annotate(&mut desired, generation);
            // Never drop creation evidence on re-apply, and never carry
            // caller-supplied evidence onto an object that does not already
            // have it: a CAP-created object must stay classifiable as such,
            // and a pre-existing (possibly replaced) object must never gain
            // fabricated evidence. Only evidence read from THIS live object
            // — the one the write is preconditioned on — survives.
            strip_creation_evidence(&mut desired);
            // cap#272: creation evidence observed on a live object is only
            // preservable when the object's lineage is provable — a
            // recorded ledger row or grandfathered by the migration
            // cutover. A tenant-forged annotation backed by a
            // client-selected field-manager name is NOT preserved: the
            // apply then omits the key it owns and SSA prunes the forged
            // stamp, so the object settles as adopted instead of carrying
            // fabricated creation authority. Engines without an attached
            // ledger keep the legacy trust.
            let expected_evidence = match attached_lineage_provenance(engine, &current) {
                Some(LineageProvenance::Unproven) => {
                    tracing::warn!(
                        kind = kind::<K>(),
                        name,
                        "live creation evidence has no recorded lineage and is not grandfathered; refusing to preserve it (cap#272)"
                    );
                    Vec::new()
                }
                _ => preserved_creation_evidence(&current, &engine.config().field_manager),
            };
            // Preservation and verification use the SAME (possibly empty)
            // pair set: an unproven lineage stamps nothing, so the apply
            // omits the key this manager owns and SSA prunes the forged
            // stamp instead of re-stamping it with fresh authority.
            if !expected_evidence.is_empty() {
                preserve_creation_evidence(&mut desired, &current, &engine.config().field_manager);
            }
            let applied = if exact_when_trusted && trusted {
                super::bounded_kube_write(api.replace(name, &post_params, &desired)).await
            } else {
                super::bounded_kube_write(api.patch(name, &patch_params, &Patch::Apply(&desired)))
                    .await
            };
            match applied {
                Ok(applied) => {
                    // Codex P2 round 9: verify the preserved creation
                    // evidence INDEPENDENTLY of the generation marker. A
                    // webhook that strips BOTH annotations must still be
                    // classified as evidence loss — returning the
                    // generation error first would skip compensation and
                    // leave an unattributable CAP-created object that a
                    // later adopted-namespace sweep could classify as
                    // foreign and clear cleanup evidence over.
                    if let Err(evidence_error) =
                        verify_preserved_creation_evidence(&applied, &expected_evidence)
                    {
                        // The write is already persisted, so first try to
                        // re-stamp the stripped evidence on the same UID.
                        if let Some(restored) = compensate_stripped_evidence(
                            api,
                            name,
                            &current,
                            &expected_evidence,
                            &engine.config().field_manager,
                        )
                        .await
                        {
                            // devin 🔴/Codex P2 round 9: a VERIFIED restore
                            // makes the same-UID object attributable again,
                            // so this must not surface as
                            // `CreationEvidenceLost` — the API layer would
                            // persist the permanent, app-wide marker and
                            // keep unrelated unmarked sweep targets
                            // unresolved until operator intervention.
                            // Report success with the object actually live;
                            // the restore patch cannot repair a stripped
                            // generation marker, so that (non-permanent)
                            // failure still surfaces here.
                            verify_applied_generation(&restored, generation)?;
                            return Ok(restored);
                        }
                        return Err(evidence_error);
                    }
                    verify_applied_generation(&applied, generation)?;
                    return Ok(applied);
                }
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                    let conflicts = field_manager_conflict_fields(&error);
                    if conflicts.is_empty() {
                        // transient resourceVersion conflict: a forced
                        // reclaim never survives a version change
                        force_against = None;
                        tokio::time::sleep(conflict_retry_delay(attempt)).await;
                        continue;
                    }
                    if !authorized {
                        let mut stale_evidence = false;
                        let escalation = match api.get(name).await {
                            Ok(live) => {
                                // The failed PATCH's causes were evaluated
                                // against the exact version it submitted; a
                                // re-read at any other version cannot vouch
                                // for that cause list (a foreign writer may
                                // have taken fields the stale list omits).
                                // Re-probe instead of authorizing force.
                                let fresh =
                                    live.meta().resource_version.as_deref().is_some_and(
                                        |version| version == resource_version.as_str(),
                                    );
                                if !fresh {
                                    stale_evidence = true;
                                }
                                let reclaimable = fresh
                                    && conflicts_reclaimable_by_force(
                                        &live,
                                        &conflicts,
                                        &engine.config().field_manager,
                                    );
                                live.meta()
                                    .resource_version
                                    .clone()
                                    .filter(|version| !version.is_empty())
                                    .filter(|_| reclaimable)
                            }
                            Err(error) => return Err(error.into()),
                        };
                        if let Some(version) = escalation {
                            tracing::info!(
                                kind = kind::<K>(),
                                conflict_count = conflicts.len(),
                                "SSA conflicts limited to this manager's own Update ownership; forcing to reclaim own fields"
                            );
                            force_against = Some(version);
                            continue;
                        }
                        if stale_evidence {
                            // cause list predates the live object: fall back
                            // to a fresh no-force probe under the normal budget
                            tokio::time::sleep(conflict_retry_delay(attempt)).await;
                            continue;
                        }
                    }
                    tracing::warn!(
                        kind = kind::<K>(),
                        conflict_count = conflicts.len(),
                        "unresolved SSA field-manager conflict on externally owned fields; failing closed"
                    );
                    return Err(ApplyError::Kube(kube::Error::Api(error)));
                }
                Err(error) => return Err(error),
            }
        } else if allow_create {
            let mut desired = resource.clone();
            desired.meta_mut().resource_version = None;
            desired.meta_mut().uid = None;
            annotate(&mut desired, generation);
            // This POST is the creation: stamp creation-specific evidence so
            // failed-apply cleanup can distinguish a CAP-created object from
            // a pre-existing one this apply merely SSA-patched.
            annotate_created(&mut desired, generation);
            match super::bounded_kube_write(api.create(&post_params, &desired)).await {
                Ok(applied) => {
                    // An admission rewrite that drops the creation evidence
                    // would leave the created object forever unsweepable in
                    // an adopted namespace: fail closed — but Codex P2 says
                    // COMPENSATE first, the POST already created it.
                    if let Err(verify_error) = verify_applied_generation(&applied, generation)
                        .and_then(|()| verify_creation_evidence(&applied, generation))
                    {
                        compensate_created_object(api, name, &applied).await;
                        return Err(verify_error);
                    }
                    // cap#272: record the creation at the only moment it is
                    // provable — this POST's own response. The control plane
                    // persists the record before the apply may proceed.
                    record_created_object(engine, &applied, api.namespace(), generation);
                    return Ok(applied);
                }
                Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                    tokio::time::sleep(conflict_retry_delay(attempt)).await;
                    continue;
                }
                Err(error) => return Err(error),
            }
        } else {
            // Creation is disallowed for this caller: the object was
            // observed live at the ownership probe but is gone now. Signal
            // the vanish so the caller re-probes instead of silently
            // creating an unstamped replacement (namespace adoption flow).
            return Err(ApplyError::VanishedResource {
                kind: kind::<K>(),
                name: name.to_string(),
            });
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

/// Conditionally merge-patch an existing object with a partial JSON document.
///
/// The patch is attributed to `field_manager` so the API server records the
/// resulting Update ownership under the control plane's manager. Without it,
/// a merge PATCH defaults to an unrelated manager name, and its ownership of
/// the generation annotation would foreign-conflict every later apply.
pub async fn apply_existing_partial<K>(
    api: &Api<K>,
    name: &str,
    patch: &serde_json::Value,
    generation: MutationGeneration,
    field_manager: &str,
) -> Result<K, ApplyError>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    let patch_params = PatchParams {
        field_manager: Some(field_manager.to_string()),
        ..PatchParams::default()
    };

    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => current,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Err(ApplyError::ResourceNotFound {
                    kind: kind::<K>(),
                    name: name.to_string(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        ensure_not_stale(&current, generation)?;
        // Codex P2: this merge patch updates a live object that may carry
        // CAP creation evidence; capture the manager-owned pairs now so the
        // write response can be verified for their survival (a webhook that
        // strips them must not yield a silent success on this path either).
        let expected_evidence = preserved_creation_evidence(&current, field_manager);
        let resource_version = current
            .meta()
            .resource_version
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        let mut desired = patch.clone();
        let metadata = desired
            .as_object_mut()
            .ok_or_else(|| ApplyError::ManifestGeneration("partial apply is not an object".into()))?
            .entry("metadata")
            .or_insert_with(|| serde_json::json!({}));
        let metadata = metadata.as_object_mut().ok_or_else(|| {
            ApplyError::ManifestGeneration("partial apply metadata is not an object".into())
        })?;
        metadata.insert("name".to_string(), serde_json::json!(name));
        metadata.insert(
            "resourceVersion".to_string(),
            serde_json::json!(resource_version),
        );
        let annotations = metadata
            .entry("annotations")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| {
                ApplyError::ManifestGeneration("partial apply annotations are not an object".into())
            })?;
        annotations.insert(
            MUTATION_GENERATION_ANNOTATION.to_string(),
            serde_json::json!(generation.get().to_string()),
        );

        // A partial SSA document would make this field manager relinquish
        // fields it owns but the patch omits. Preserve the prior merge-patch
        // behavior while adding an exact resourceVersion precondition and the
        // provider generation annotation.
        match super::bounded_kube_write(api.patch(name, &patch_params, &Patch::Merge(&desired)))
            .await
        {
            Ok(applied) => {
                // Same fail-closed rule as the SSA update path: creation
                // evidence preserved from the preconditioned object must
                // survive the response — checked INDEPENDENTLY of the
                // generation marker (Codex P2 round 9), with the bounded
                // same-UID compensating restore first on loss. A verified
                // restore reports success instead of the permanent
                // `CreationEvidenceLost` classification.
                if let Err(evidence_error) =
                    verify_preserved_creation_evidence(&applied, &expected_evidence)
                {
                    if let Some(restored) = compensate_stripped_evidence(
                        api,
                        name,
                        &current,
                        &expected_evidence,
                        field_manager,
                    )
                    .await
                    {
                        verify_applied_generation(&restored, generation)?;
                        return Ok(restored);
                    }
                    return Err(evidence_error);
                }
                verify_applied_generation(&applied, generation)?;
                return Ok(applied);
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                tokio::time::sleep(conflict_retry_delay(attempt)).await;
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

/// Delete the exact UID/resourceVersion observed after checking generation.
pub async fn delete_resource<K>(
    api: &Api<K>,
    name: &str,
    generation: MutationGeneration,
    mut delete_params: DeleteParams,
) -> Result<bool, ApplyError>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    for attempt in 0..MAX_CONFLICT_RETRIES {
        let current = match api.get(name).await {
            Ok(current) => current,
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        ensure_not_stale(&current, generation)?;
        let resource_version = current
            .meta()
            .resource_version
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        let uid = current
            .meta()
            .uid
            .clone()
            .ok_or_else(|| ApplyError::MissingResourceIdentity(kind::<K>()))?;
        delete_params.preconditions = Some(Preconditions {
            resource_version: Some(resource_version),
            uid: Some(uid),
        });
        match super::bounded_kube_write(api.delete(name, &delete_params)).await {
            Ok(_) => return Ok(true),
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 404 => {
                return Ok(false);
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                tokio::time::sleep(conflict_retry_delay(attempt)).await;
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    tracing::warn!(
        kind = kind::<K>(),
        retries = MAX_CONFLICT_RETRIES,
        "mutation conflicts exhausted (kind only; names excluded)"
    );
    Err(ApplyError::MutationConflictExhausted {
        kind: kind::<K>(),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::client::Body;
    use serde_json::{Value, json};
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use tower::service_fn;

    const RESOURCE_PATH: &str = "/api/v1/namespaces/fence-test/configmaps/fenced";
    const COLLECTION_PATH: &str = "/api/v1/namespaces/fence-test/configmaps";
    const STATEFULSET_PATH: &str = "/apis/apps/v1/namespaces/fence-test/statefulsets/fenced";

    #[test]
    fn creation_evidence_is_stripped_then_rederived_from_live_only() {
        // A caller smuggles creation evidence onto a desired write for an
        // existing object: the existing-object path must strip it and re-add
        // ONLY what the live object carries, so a replaced same-named object
        // can never inherit the predecessor's evidence (Codex P1 round 6).
        use k8s_openapi::api::core::v1::ConfigMap;

        let mut desired: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "annotations": {
                    RESOURCE_CREATED_BY_ANNOTATION: "9",
                    NAMESPACE_CREATED_BY_ANNOTATION: "9",
                },
            },
            "data": {"value": "x"},
        }))
        .unwrap();
        let live_with_evidence: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "annotations": { RESOURCE_CREATED_BY_ANNOTATION: "3" },
            },
        }))
        .unwrap();
        let live_without_evidence: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "fenced"},
        }))
        .unwrap();

        strip_creation_evidence(&mut desired);
        assert!(
            desired
                .meta()
                .annotations
                .as_ref()
                .is_none_or(|a| !a.contains_key(RESOURCE_CREATED_BY_ANNOTATION)),
            "smuggled evidence must be stripped"
        );
        // Give the live object trusted-manager provenance for its evidence.
        let mut trusted_live = live_with_evidence;
        trusted_live.metadata.managed_fields = Some(vec![
            serde_json::from_value(json!({
                "manager": "enclava-platform",
                "operation": "Update",
                "apiVersion": "v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": {
                    "f:metadata": {"f:annotations": {
                        ("f:".to_string() + RESOURCE_CREATED_BY_ANNOTATION): {},
                    }},
                },
            }))
            .unwrap(),
        ]);
        preserve_creation_evidence(&mut desired, &trusted_live, "enclava-platform");
        assert_eq!(
            desired
                .meta()
                .annotations
                .as_ref()
                .and_then(|a| a.get(RESOURCE_CREATED_BY_ANNOTATION)),
            Some(&"3".to_string()),
            "evidence is re-derived from the live object only, verbatim"
        );

        let mut desired2: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "annotations": { RESOURCE_CREATED_BY_ANNOTATION: "9" },
            },
        }))
        .unwrap();
        strip_creation_evidence(&mut desired2);
        // A live object without provenance entries at all: nothing is
        // preserved (fail closed).
        let mut trusted_live2 = live_without_evidence;
        trusted_live2.metadata.managed_fields = Some(vec![
            serde_json::from_value(json!({
                "manager": "enclava-platform",
                "operation": "Update",
                "apiVersion": "v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": {
                    "f:metadata": {"f:annotations": {
                        ("f:".to_string() + RESOURCE_CREATED_BY_ANNOTATION): {},
                    }},
                },
            }))
            .unwrap(),
        ]);
        preserve_creation_evidence(&mut desired2, &trusted_live2, "enclava-platform");
        assert!(
            desired2
                .meta()
                .annotations
                .as_ref()
                .is_none_or(|a| !a.contains_key(RESOURCE_CREATED_BY_ANNOTATION)),
            "a live object without evidence must never gain it"
        );

        // Forged evidence (annotation present) WITHOUT CAP field-manager
        // provenance: must NOT be preserved — the tenant set it manually.
        let mut desired3: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "fenced"},
        }))
        .unwrap();
        let forged: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "annotations": { RESOURCE_CREATED_BY_ANNOTATION: "2" },
            },
        }))
        .unwrap();
        preserve_creation_evidence(&mut desired3, &forged, "enclava-platform");
        assert!(
            desired3
                .meta()
                .annotations
                .as_ref()
                .is_none_or(|a| !a.contains_key(RESOURCE_CREATED_BY_ANNOTATION)),
            "forged evidence without CAP provenance must not be preserved"
        );
    }
    #[test]
    fn conflict_retry_backoff_is_bounded() {
        assert_eq!(conflict_retry_delay(0), Duration::from_millis(25));
        assert_eq!(conflict_retry_delay(5), Duration::from_millis(800));
        assert_eq!(conflict_retry_delay(6), Duration::from_millis(800));
        assert_eq!(conflict_retry_delay(100), Duration::from_millis(800));
        // The total budget must stay patient (~45–90 s) so ordinary
        // controller churn cannot terminally fail a deployment, yet remain
        // far below the 180 s mutation lease and bounded job deadlines.
        let total: Duration = (0..MAX_CONFLICT_RETRIES).map(conflict_retry_delay).sum();
        assert!(total >= Duration::from_secs(45), "total {total:?}");
        assert!(total <= Duration::from_secs(90), "total {total:?}");
    }

    #[tokio::test]
    async fn concurrent_writer_churn_cannot_terminally_fail_apply() {
        // Regression (staging 2026-09-13): a Kubernetes controller bumping
        // resourceVersion for longer than the old ~1.9 s conflict budget made
        // apply_resource exhaust mutation conflicts and terminally fail the
        // deployment (live: gens 3d869f2c/69dff1f3/4b1b3ef7). A bounded
        // concurrent writer that stops must not defeat the apply.
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {"labels": {"app": "fenced"}},
                    "spec": {"containers": [{"name": "workload", "image": "example.test/workload:current"}]},
                },
            },
        }))
        .unwrap();

        // Controller-style concurrent writer: every PATCH/PUT of the fenced
        // resource is preempted by a resourceVersion bump for 2.5 s — beyond
        // the previous total budget (~1.9 s), inside the new one (~48 s).
        state.lock().unwrap().churn_until =
            Some(std::time::Instant::now() + Duration::from_millis(2500));

        let applied = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await;
        applied.expect("apply survives a bounded concurrent writer");
        let locked = state.lock().unwrap();
        assert_eq!(
            locked.resource.as_ref().unwrap()["metadata"]["annotations"]
                [MUTATION_GENERATION_ANNOTATION],
            "2"
        );
    }

    /// A live ConfigMap this control plane created: CAP field-manager
    /// ownership of the creation-evidence annotation (the create POST's
    /// Update attribution) plus both annotations.
    fn cap_created_configmap() -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "namespace": "fence-test",
                "uid": "11111111-1111-1111-1111-111111111111",
                "resourceVersion": "1",
                "managedFields": [{
                    "manager": "enclava-platform",
                    "operation": "Update",
                    "apiVersion": "v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": {"f:metadata": {"f:annotations": {
                        ("f:".to_string() + RESOURCE_CREATED_BY_ANNOTATION): {},
                    }}},
                }],
                "annotations": {
                    MUTATION_GENERATION_ANNOTATION: "1",
                    RESOURCE_CREATED_BY_ANNOTATION: "1",
                },
            },
            "data": {"value": "old"},
        })
    }

    #[tokio::test]
    async fn update_response_losing_creation_evidence_is_restored_and_succeeds() {
        // Codex P2 / devin 🔴 round 9: a mutating admission webhook can
        // drop RESOURCE_CREATED_BY_ANNOTATION from an accepted update while
        // leaving the mutation-generation annotation intact. Accepting the
        // stripped response verbatim would let a later failed-apply sweep
        // classify the still-live CAP-created object as Foreign (no
        // evidence) and silently clear cleanup evidence over it — but a
        // VERIFIED compensating restore makes the same-UID object
        // attributable again, so the apply must NOT surface the permanent,
        // app-wide `CreationEvidenceLost` classification (whose marker has
        // no automatic clearing path); it reports success with the
        // restored live object.
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        // One-shot webhook: strips the update itself, spares the
        // compensating restore patch.
        state.webhook_strips_evidence_writes = 1;
        let state = Arc::new(Mutex::new(state));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let restored = apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect("a verified evidence restore must not fail the apply nor set the permanent marker");
        // The returned object is the live one carrying the restored
        // evidence AND the accepted update's generation stamp.
        let annotations = restored.meta().annotations.as_ref().expect("annotations");
        assert_eq!(
            annotations.get(RESOURCE_CREATED_BY_ANNOTATION),
            Some(&"1".to_string()),
            "the restored object handed back carries the re-stamped evidence"
        );
        assert_eq!(
            annotations.get(MUTATION_GENERATION_ANNOTATION),
            Some(&"2".to_string()),
            "the restored object handed back carries the new generation"
        );
        // The compensating restore re-stamped the evidence onto the same
        // UID: a later failure sweep can classify the object again.
        let live = state.lock().unwrap().resource.clone().expect("stored");
        assert_eq!(
            live.pointer("/metadata/annotations")
                .and_then(Value::as_object)
                .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION)),
            Some(&json!("1")),
            "compensation restores the stripped creation evidence"
        );
    }

    #[tokio::test]
    async fn deterministic_webhook_stripping_evidence_stays_unresolved() {
        // A webhook that strips the annotation from EVERY write also
        // defeats the compensating restore. The apply still fails closed
        // with the distinct error — never a silent success — and the
        // restore budget is bounded, not an infinite loop.
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        state.webhook_strips_evidence_writes = usize::MAX;
        let engine = ApplyEngine::new(fake_client(Arc::new(Mutex::new(state))), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let error = apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("a deterministically stripping webhook must never yield a silent success");
        assert!(matches!(error, ApplyError::CreationEvidenceLost { .. }));
        // The compensating restore merge patch is stripped too (the fake
        // arms the webhook on merge patches as well), so the live object
        // stays evidence-less and the bounded restore budget is what keeps
        // this terminating. Nothing is silently accepted: the distinct
        // failure code persists on the deployment row, and the
        // adopted-namespace sweep counts unmarked live targets as
        // unresolved while a `creation_evidence_lost` row is in its row
        // set (see unmarked_target_is_unresolved in enclava-api).
    }

    #[tokio::test]
    async fn webhook_stripping_generation_and_evidence_classifies_evidence_loss() {
        // Codex P2 round 9: a webhook that rewrites BOTH the
        // mutation-generation annotation and the creation evidence in
        // the same accepted update must still be classified as
        // `CreationEvidenceLost` — returning the generation error first
        // would skip compensation and never set the app-level marker,
        // leaving an unattributable object a later sweep could classify
        // as foreign and clear cleanup evidence over.
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        state.webhook_strips_evidence_writes = usize::MAX;
        state.webhook_strips_generation_writes = usize::MAX;
        let engine = ApplyEngine::new(fake_client(Arc::new(Mutex::new(state))), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let error = apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("a both-markers-stripping webhook must fail closed");
        assert!(
            matches!(error, ApplyError::CreationEvidenceLost { .. }),
            "evidence loss must outrank the generation error, got: {error:?}"
        );
    }

    #[tokio::test]
    async fn restored_evidence_with_stripped_generation_reports_generation_error() {
        // The complementary half of Codex P2 round 9: a ONE-SHOT webhook
        // strips both markers; the compensating restore re-stamps the
        // evidence (attributable again) but cannot repair the stripped
        // generation annotation. The apply then fails with the
        // NON-permanent generation error — never `CreationEvidenceLost`,
        // so the app-level unresolved marker is not set for an object
        // whose evidence was verified back onto it.
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        state.webhook_strips_evidence_writes = 1;
        state.webhook_strips_generation_writes = 1;
        let state = Arc::new(Mutex::new(state));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let error = apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("a stripped generation marker must still fail the apply");
        assert!(
            matches!(error, ApplyError::ProviderGenerationNotApplied { .. }),
            "an evidence-restored object must not be classified creation_evidence_lost, got: {error:?}"
        );
        // The evidence was restored onto the same UID before failing.
        let live = state.lock().unwrap().resource.clone().expect("stored");
        assert_eq!(
            live.pointer("/metadata/annotations")
                .and_then(Value::as_object)
                .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION)),
            Some(&json!("1")),
            "compensation restores the stripped creation evidence even when the generation marker was stripped too"
        );
    }

    #[tokio::test]
    async fn partial_apply_response_losing_creation_evidence_is_restored_and_succeeds() {
        // Codex P2 round 9: the merge-patch path (apply_existing_partial —
        // replica resets, ingress restarts) enforces the same evidence
        // verification as the SSA update path, and a VERIFIED restore
        // there reports success too — the permanent app-level
        // `creation_evidence_lost` marker must only be set when the loss
        // stays unresolved.
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        state.webhook_strips_evidence_writes = 1;
        let state = Arc::new(Mutex::new(state));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let restored = apply_existing_partial(
            &api,
            "fenced",
            &serde_json::json!({"data": {"value": "partial"}}),
            MutationGeneration::new(2).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("a verified evidence restore after a partial apply must not fail the apply");
        assert_eq!(
            restored
                .meta()
                .annotations
                .as_ref()
                .and_then(|a| a.get(RESOURCE_CREATED_BY_ANNOTATION)),
            Some(&"1".to_string()),
            "the restored object handed back carries the re-stamped evidence"
        );
        // The compensating restore re-stamped the evidence on the same UID.
        let live = state.lock().unwrap().resource.clone().expect("stored");
        assert_eq!(
            live.pointer("/metadata/annotations")
                .and_then(Value::as_object)
                .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION)),
            Some(&json!("1")),
            "compensation restores the stripped creation evidence after a partial apply"
        );
    }

    #[tokio::test]
    async fn accepted_update_keeps_preserved_creation_evidence() {
        // The same CAP-created object WITHOUT a hostile webhook: the apply
        // succeeds and both the response and the stored object keep the
        // preserved evidence verbatim (guards against the verification
        // above rejecting well-behaved updates).
        let mut state = FakeState::with_generation(1, "old");
        state.resource = Some(cap_created_configmap());
        let state = Arc::new(Mutex::new(state));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let applied = apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect("a well-behaved update of a CAP-created object succeeds");

        let annotations = applied
            .meta()
            .annotations
            .as_ref()
            .expect("applied object carries annotations");
        assert_eq!(
            annotations.get(RESOURCE_CREATED_BY_ANNOTATION),
            Some(&"1".to_string()),
            "creation evidence survives the accepted response verbatim"
        );
        assert_eq!(
            annotations.get(MUTATION_GENERATION_ANNOTATION),
            Some(&"2".to_string()),
            "the update still stamps the new generation"
        );
        let live = state
            .lock()
            .unwrap()
            .resource
            .clone()
            .expect("stored object");
        let live_annotations = live
            .pointer("/metadata/annotations")
            .and_then(Value::as_object)
            .expect("stored object carries annotations");
        assert_eq!(
            live_annotations.get(RESOURCE_CREATED_BY_ANNOTATION),
            Some(&json!("1")),
            "creation evidence survives in the stored object verbatim"
        );
    }

    #[derive(Default)]
    struct Pause {
        next: bool,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    struct FakeState {
        resource: Option<Value>,
        next_resource_version: u64,
        pause_patch: Pause,
        pause_delete: Pause,
        pause_create: Pause,
        rejected_preconditions: usize,
        /// Server-side-apply PATCH requests received for the fenced resource.
        ssa_attempts: usize,
        /// When `Some`, the next forced SSA PATCH is preempted by a foreign
        /// writer that takes the container image and bumps the
        /// resourceVersion before the forced write is evaluated.
        hijack_next_force: Option<String>,
        /// When `Some`, the next no-force SSA PATCH that would return 409
        /// first has a foreign writer take `spec.template.spec.runtimeClassName`
        /// and bump the resourceVersion — then the already-evaluated (stale)
        /// cause list is returned, modeling the response-late race.
        hijack_next_conflict: Option<String>,
        /// PUT replacements received for the fenced resource.
        replace_attempts: usize,
        /// While `Some(until)`, every PATCH/PUT of the fenced resource first
        /// bumps its resourceVersion — a controller-style concurrent writer
        /// landing inside each read-modify-write window.
        churn_until: Option<std::time::Instant>,
        /// When nonzero, the next N accepted PATCH/PUT writes of the fenced
        /// resource have the creation-evidence annotation stripped from the
        /// persisted object and their response — a mutating admission
        /// webhook that drops `RESOURCE_CREATED_BY_ANNOTATION` on updates
        /// (a countdown models one-shot vs deterministic webhooks).
        webhook_strips_evidence_writes: usize,
        /// When nonzero, the same webhook strikes ALSO drop the
        /// mutation-generation annotation — modeling a webhook that
        /// rewrites both markers in one accepted update (Codex P2
        /// round 9). An independent countdown; when both counters are
        /// armed, one write consumes a strike from each.
        webhook_strips_generation_writes: usize,
    }

    impl FakeState {
        fn with_generation(generation: i64, value: &str) -> Self {
            Self {
                resource: Some(configmap_value(generation, "1", value)),
                next_resource_version: 2,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
                webhook_strips_evidence_writes: 0,
                webhook_strips_generation_writes: 0,
            }
        }

        fn absent() -> Self {
            Self {
                resource: None,
                next_resource_version: 1,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
                webhook_strips_evidence_writes: 0,
                webhook_strips_generation_writes: 0,
            }
        }

        fn with_statefulset() -> Self {
            Self {
                resource: Some(json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {
                        "name": "fenced",
                        "namespace": "fence-test",
                        "uid": "22222222-2222-2222-2222-222222222222",
                        "resourceVersion": "1",
                        "managedFields": [{
                            "manager": "enclava-platform",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {},
                        }],
                        "annotations": {
                            MUTATION_GENERATION_ANNOTATION: "1",
                            "unrelated-metadata": "preserved",
                        },
                    },
                    "spec": {
                        "replicas": 1,
                        "serviceName": "fenced-service",
                        "selector": { "matchLabels": { "app": "fenced" } },
                        "template": {
                            "metadata": {
                                "labels": { "app": "fenced" },
                                "annotations": { "unrelated-template": "preserved" },
                            },
                            "spec": {
                                "containers": [{
                                    "name": "workload",
                                    "image": "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }],
                            },
                        },
                    },
                })),
                next_resource_version: 2,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
                webhook_strips_evidence_writes: 0,
                webhook_strips_generation_writes: 0,
            }
        }

        /// The tenant-c live shape (2026-09-14): CAP Update ownership of the
        /// generation annotation and workload spec, a separate
        /// replicas-only `kubectl-patch` Update entry from the drill, and a
        /// status-subresource writer. Provider generation 4.
        fn with_shared_statefulset() -> Self {
            Self {
                resource: Some(json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {
                        "name": "fenced",
                        "namespace": "fence-test",
                        "uid": "33333333-3333-3333-3333-333333333333",
                        "resourceVersion": "285805",
                        "managedFields": [
                            {
                                "manager": "enclava-platform",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {
                                    "f:metadata": {"f:annotations": {
                                        (format!("f:{}", MUTATION_GENERATION_ANNOTATION)): {},
                                    }},
                                    "f:spec": {
                                        "f:replicas": {},
                                        "f:serviceName": {},
                                        "f:template": {
                                            "f:metadata": {"f:annotations": {
                                                "f:unrelated-template": {},
                                            }},
                                        },
                                    },
                                },
                            },
                            {
                                "manager": "kubectl-patch",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {"f:spec": {"f:replicas": {}}},
                            },
                            {
                                "manager": "sts-controller",
                                "operation": "Update",
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {},
                                "subresource": "status",
                            },
                        ],
                        "annotations": {
                            MUTATION_GENERATION_ANNOTATION: "4",
                            "unrelated-metadata": "preserved",
                        },
                    },
                    "spec": {
                        "replicas": 1,
                        "serviceName": "fenced-service",
                        "selector": {"matchLabels": {"app": "fenced"}},
                        "template": {
                            "metadata": {
                                "labels": {"app": "fenced"},
                                "annotations": {"unrelated-template": "preserved"},
                            },
                            "spec": {
                                "containers": [{
                                    "name": "workload",
                                    "image": "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }],
                            },
                        },
                    },
                })),
                next_resource_version: 285806,
                pause_patch: Pause::default(),
                pause_delete: Pause::default(),
                pause_create: Pause::default(),
                rejected_preconditions: 0,
                ssa_attempts: 0,
                hijack_next_force: None,
                hijack_next_conflict: None,
                replace_attempts: 0,
                churn_until: None,
                webhook_strips_evidence_writes: 0,
                webhook_strips_generation_writes: 0,
            }
        }
    }

    fn configmap_value(generation: i64, resource_version: &str, value: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "namespace": "fence-test",
                "uid": "11111111-1111-1111-1111-111111111111",
                "resourceVersion": resource_version,
                "annotations": {
                    MUTATION_GENERATION_ANNOTATION: generation.to_string(),
                },
            },
            "data": { "value": value },
        })
    }

    fn desired(value: &str) -> ConfigMap {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "namespace": "fence-test",
            },
            "data": { "value": value },
        }))
        .expect("valid desired ConfigMap")
    }

    fn fake_client(state: Arc<Mutex<FakeState>>) -> kube::Client {
        kube::Client::new(
            service_fn(move |request| handle_request(request, Arc::clone(&state))),
            "default",
        )
    }

    async fn handle_request(
        request: Request<Body>,
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let query = request.uri().query().unwrap_or_default().to_string();
        let content_type = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();

        if method == Method::GET && (path == RESOURCE_PATH || path == STATEFULSET_PATH) {
            return Ok(
                match state.lock().expect("fake state poisoned").resource.clone() {
                    Some(resource) => json_response(StatusCode::OK, resource),
                    None => status_response(StatusCode::NOT_FOUND, "NotFound"),
                },
            );
        }

        let pause = {
            let mut locked = state.lock().expect("fake state poisoned");
            let pause = match (method.clone(), path.as_str()) {
                (Method::PATCH, RESOURCE_PATH | STATEFULSET_PATH)
                | (Method::PUT, RESOURCE_PATH | STATEFULSET_PATH) => &mut locked.pause_patch,
                (Method::DELETE, RESOURCE_PATH) => &mut locked.pause_delete,
                (Method::POST, COLLECTION_PATH) => &mut locked.pause_create,
                _ => {
                    return Err(io::Error::other(format!(
                        "unexpected fake Kubernetes request: {method} {path}"
                    )));
                }
            };
            if pause.next {
                pause.next = false;
                Some((pause.entered.clone(), pause.release.clone()))
            } else {
                None
            }
        };

        if let Some((entered, release)) = pause {
            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                entered.notify_one();
                release.notified().await;
                let response = process_mutation(method, &query, &content_type, &body, state);
                let _ = response_tx.send(response);
            });
            return response_rx
                .await
                .map_err(|_| io::Error::other("detached provider response receiver closed"))?;
        }

        process_mutation(method, &query, &content_type, &body, state)
    }

    fn process_mutation(
        method: Method,
        query: &str,
        content_type: &str,
        body: &[u8],
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let payload: Value = serde_json::from_slice(body).map_err(io::Error::other)?;
        let mut locked = state.lock().expect("fake state poisoned");
        if matches!(method, Method::PATCH | Method::PUT)
            && locked
                .churn_until
                .is_some_and(|deadline| std::time::Instant::now() < deadline)
        {
            let rv = locked.next_resource_version;
            locked.next_resource_version += 1;
            if let Some(resource) = locked.resource.as_mut() {
                resource["metadata"]["resourceVersion"] = json!(rv.to_string());
            }
        }
        match method {
            Method::PUT => {
                let Some(current) = locked.resource.clone() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                if payload
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str)
                    != current
                        .pointer("/metadata/resourceVersion")
                        .and_then(Value::as_str)
                {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                let mut updated = payload;
                updated["metadata"]["uid"] = current["metadata"]["uid"].clone();
                updated["metadata"]["resourceVersion"] =
                    json!(locked.next_resource_version.to_string());
                let manager = query_param(query, "fieldManager").unwrap_or("fake-unknown");
                let owned = document_leaf_paths(&updated);
                record_update_ownership(&mut updated, &owned, manager, false);
                maybe_webhook_strip(&mut locked, &mut updated);
                locked.replace_attempts += 1;
                locked.next_resource_version += 1;
                locked.resource = Some(updated);
                Ok(json_response(
                    StatusCode::OK,
                    locked.resource.clone().expect("resource was replaced"),
                ))
            }
            Method::PATCH => {
                let is_apply = content_type.contains("apply-patch");
                let force = query.contains("force=true");
                if is_apply
                    && force
                    && let Some(image) = locked.hijack_next_force.take()
                {
                    let bumped = locked.next_resource_version.to_string();
                    locked.next_resource_version += 1;
                    let resource = locked.resource.as_mut().expect("resource exists");
                    resource["spec"]["template"]["spec"]["containers"][0]["image"] = json!(image);
                    let managed = resource["metadata"]["managedFields"]
                        .as_array_mut()
                        .expect("managedFields present");
                    if !managed.iter().any(|entry| {
                        entry.get("manager").and_then(Value::as_str) == Some("tampering-controller")
                    }) {
                        managed.push(json!({
                            "manager": "tampering-controller",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {"f:spec": {"f:template": {"f:spec": {
                                "f:containers": {"k:{\"name\":\"workload\"}": {"f:image": {}}},
                            }}}},
                        }));
                    }
                    resource["metadata"]["resourceVersion"] = json!(bumped);
                }
                let Some(current) = locked.resource.clone() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                let expected = payload
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let actual = current
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                if expected != actual {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                let resource_version = locked.next_resource_version.to_string();
                locked.next_resource_version += 1;
                if is_apply {
                    // The API server defaults a PATCH without fieldManager to
                    // an unrelated manager name; merges sent by CAP carry it.
                    let manager = query_param(query, "fieldManager").unwrap_or("kubectl-patch");
                    locked.ssa_attempts += 1;
                    return Ok(apply_ssa(
                        &mut locked,
                        current,
                        &payload,
                        manager,
                        force,
                        resource_version,
                    ));
                }
                let mut updated = current;
                // ownership follows changed or added fields, as the API
                // server does for Update writers
                let owned: Vec<String> = document_leaf_paths(&payload)
                    .into_iter()
                    .filter(|path| {
                        value_at(&updated, path).as_ref() != value_at(&payload, path).as_ref()
                    })
                    .collect();
                merge_value(&mut updated, &payload);
                updated["metadata"]["resourceVersion"] = json!(resource_version);
                let manager = query_param(query, "fieldManager").unwrap_or("kubectl-patch");
                record_update_ownership(&mut updated, &owned, manager, true);
                maybe_webhook_strip(&mut locked, &mut updated);
                locked.resource = Some(updated);
                Ok(json_response(
                    StatusCode::OK,
                    locked.resource.clone().expect("resource was updated"),
                ))
            }
            Method::POST => {
                if locked.resource.is_some() {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "AlreadyExists"));
                }
                let generation = payload
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        MUTATION_GENERATION_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| io::Error::other("create lacks generation"))?;
                let value = payload
                    .pointer("/data/value")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let resource_version = locked.next_resource_version.to_string();
                locked.next_resource_version += 1;
                let mut created = configmap_value(generation, &resource_version, value);
                let manager = query_param(query, "fieldManager").unwrap_or("fake-unknown");
                let owned = document_leaf_paths(&payload);
                record_update_ownership(&mut created, &owned, manager, false);
                locked.resource = Some(created);
                Ok(json_response(
                    StatusCode::CREATED,
                    locked.resource.clone().expect("resource was created"),
                ))
            }
            Method::DELETE => {
                let Some(current) = locked.resource.as_ref() else {
                    return Ok(status_response(StatusCode::NOT_FOUND, "NotFound"));
                };
                let expected_rv = payload
                    .pointer("/preconditions/resourceVersion")
                    .and_then(Value::as_str);
                let expected_uid = payload
                    .pointer("/preconditions/uid")
                    .and_then(Value::as_str);
                let actual_rv = current
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let actual_uid = current.pointer("/metadata/uid").and_then(Value::as_str);
                if expected_rv != actual_rv || expected_uid != actual_uid {
                    locked.rejected_preconditions += 1;
                    return Ok(status_response(StatusCode::CONFLICT, "Conflict"));
                }
                locked.resource = None;
                Ok(status_response(StatusCode::OK, "Success"))
            }
            _ => Err(io::Error::other("unexpected mutation method")),
        }
    }

    fn merge_value(target: &mut Value, patch: &Value) {
        let Value::Object(patch) = patch else {
            *target = patch.clone();
            return;
        };
        if !target.is_object() {
            *target = json!({});
        }
        let target = target.as_object_mut().expect("target was made an object");
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                merge_value(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }

    /// Test-local flattener for the fake API server. Deliberately NOT the
    /// production walker: it renders associative keys as `[name=x]` while
    /// the real API server quotes values (`[name="x"]`), so regressions
    /// that depend on bracket notation cannot silently pass through a
    /// shared formatter. Production rejects those entries fail-closed.
    fn fake_flatten_owned_paths(fields_v1: &Value) -> Option<Vec<String>> {
        fn walk(node: &Value, prefix: String, paths: &mut Vec<String>) -> Option<()> {
            let object = node.as_object()?;
            for (key, child) in object {
                let segment = match key.strip_prefix("f:") {
                    Some(field) => field.to_string(),
                    None => {
                        let list_key = key.strip_prefix("k:")?;
                        let value: std::collections::BTreeMap<String, Value> =
                            serde_json::from_str(list_key).ok()?;
                        if value.len() != 1 {
                            return None;
                        }
                        let (name, marker) = value.into_iter().next()?;
                        format!("[{}={}]", name, marker.as_str()?)
                    }
                };
                let path = if prefix.is_empty() || segment.starts_with('[') {
                    format!("{prefix}{segment}")
                } else {
                    format!("{prefix}.{segment}")
                };
                if child
                    .as_object()
                    .is_some_and(|children| children.is_empty())
                {
                    paths.push(path);
                } else {
                    walk(child, path, paths)?;
                }
            }
            Some(())
        }
        let mut paths = Vec::new();
        walk(fields_v1, String::new(), &mut paths)?;
        Some(paths)
    }

    fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
    }

    const OWNERSHIP_HOUSEKEEPING: &[&str] = &[
        "apiVersion",
        "kind",
        "name",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "managedFields",
    ];

    /// Apply-patch handling with SSA ownership semantics: owners conflict
    /// when the incoming apply modifies or adds one of their fields
    /// (identical values share ownership), same-manager Apply entries
    /// merge, and `force` accepts the write without modeling the server's
    /// field-by-field transfer out of losing owners.
    fn apply_ssa(
        state: &mut FakeState,
        current: Value,
        payload: &Value,
        manager: &str,
        force: bool,
        resource_version: String,
    ) -> Response<Body> {
        let mut conflicts: Vec<(String, String)> = Vec::new();
        if let Some(entries) = current
            .pointer("/metadata/managedFields")
            .and_then(Value::as_array)
        {
            for entry in entries {
                if entry.get("subresource").and_then(Value::as_str) == Some("status") {
                    continue;
                }
                let entry_manager = entry.get("manager").and_then(Value::as_str).unwrap_or("");
                let operation = entry
                    .get("operation")
                    .and_then(Value::as_str)
                    .unwrap_or("Update");
                if entry_manager == manager && operation == "Apply" {
                    continue;
                }
                let owned = entry.get("fieldsV1").and_then(fake_flatten_owned_paths);
                match owned {
                    None => conflicts.push((String::new(), entry_manager.to_string())),
                    Some(paths) => {
                        for path in paths {
                            let Some(desired) = value_at(payload, &path) else {
                                continue;
                            };
                            // Conflicts arise from modified or added fields
                            // for both Update and Apply ownership; applying
                            // an identical value shares ownership.
                            let conflicting = value_at(&current, &path).as_ref() != Some(&desired);
                            if conflicting {
                                conflicts.push((path, entry_manager.to_string()));
                            }
                        }
                    }
                }
            }
        }
        if !conflicts.is_empty() && !force {
            if let Some(runtime_class_name) = state.hijack_next_conflict.take() {
                // a foreign writer lands after the server evaluated the
                // conflicts but before the client reads the response: the
                // returned cause list is stale by construction
                let bumped = state.next_resource_version.to_string();
                state.next_resource_version += 1;
                if let Some(resource) = state.resource.as_mut() {
                    resource["spec"]["template"]["spec"]["runtimeClassName"] =
                        json!(runtime_class_name);
                    let managed = resource["metadata"]["managedFields"]
                        .as_array_mut()
                        .expect("managedFields present");
                    if !managed.iter().any(|entry| {
                        entry.get("manager").and_then(Value::as_str) == Some("tampering-controller")
                    }) {
                        managed.push(json!({
                            "manager": "tampering-controller",
                            "operation": "Update",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {"f:spec": {"f:template": {"f:spec": {
                                "f:runtimeClassName": {},
                            }}}},
                        }));
                    }
                    resource["metadata"]["resourceVersion"] = json!(bumped);
                }
            }
            let causes: Vec<Value> = conflicts
                .iter()
                .map(|(field, loser)| {
                    json!({
                        "reason": "FieldManagerConflict",
                        "message": format!("conflict with \"{loser}\" using apps/v1"),
                        "field": format!(".{field}"),
                    })
                })
                .collect();
            return json_response(
                StatusCode::CONFLICT,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!(
                        "Apply failed with {} conflict{}: {}",
                        causes.len(),
                        if causes.len() == 1 { "" } else { "s" },
                        conflicts
                            .iter()
                            .map(|(_, loser)| format!("conflict with \"{loser}\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "reason": "Conflict",
                    "code": 409,
                    "details": { "causes": causes },
                }),
            );
        }
        let mut updated = current.clone();
        merge_value(&mut updated, payload);
        // ponytail: the fake does not model field-by-field ownership
        // transfer out of losing managers; the applier's Apply entry below
        // and the surviving foreign entries are what the regressions
        // assert. Add faithful transfer if a regression ever needs it.
        let owned_paths = document_leaf_paths(payload);
        updated["metadata"]["managedFields"] = updated
            .pointer("/metadata/managedFields")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if let Some(managed) = updated
            .pointer_mut("/metadata/managedFields")
            .and_then(Value::as_array_mut)
        {
            upsert_apply_entry(managed, manager, &owned_paths);
        }
        updated["metadata"]["resourceVersion"] = json!(resource_version);
        maybe_webhook_strip(state, &mut updated);
        state.resource = Some(updated.clone());
        json_response(StatusCode::OK, updated)
    }

    /// Consume webhook strikes (when armed) and strip the armed
    /// annotations from an accepted write: both the persisted object and
    /// the returned response lack them.
    fn maybe_webhook_strip(state: &mut FakeState, resource: &mut Value) {
        if state.webhook_strips_evidence_writes > 0 {
            state.webhook_strips_evidence_writes -= 1;
            webhook_strip_annotation(resource, RESOURCE_CREATED_BY_ANNOTATION);
        }
        if state.webhook_strips_generation_writes > 0 {
            state.webhook_strips_generation_writes -= 1;
            webhook_strip_annotation(resource, MUTATION_GENERATION_ANNOTATION);
        }
    }

    /// Model a mutating admission webhook that drops an annotation from
    /// an accepted write: both the persisted object and the returned
    /// response lack it.
    fn webhook_strip_annotation(resource: &mut Value, key: &str) {
        if let Some(annotations) = resource
            .pointer_mut("/metadata/annotations")
            .and_then(Value::as_object_mut)
        {
            annotations.remove(key);
        }
    }

    /// Record Update ownership for a PUT/POST/merge-PATCH writer. Merge
    /// patches union into an existing entry; replaces rewrite it.
    fn record_update_ownership(resource: &mut Value, owned: &[String], manager: &str, merge: bool) {
        let metadata = resource
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .expect("mutation carries metadata");
        let entries = metadata
            .entry("managedFields")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("managedFields is an array");
        if merge {
            // Update writes acquire the changed fields, removing those
            // claims from other owners; entries left owning nothing drop.
            // ponytail: paths whose final segment contains dots (annotation
            // keys) are not removed from other owners — no fixture relies on
            // that transfer; add greedy matching if one ever does.
            for entry in entries.iter_mut().filter(|entry| {
                entry.get("manager").and_then(Value::as_str) != Some(manager)
                    && entry.get("subresource").is_none()
            }) {
                if let Some(fields) = entry.get_mut("fieldsV1") {
                    for path in owned {
                        remove_path(
                            fields,
                            &split_path(path)
                                .iter()
                                .map(|s| fkey_for(s))
                                .collect::<Vec<_>>(),
                        );
                    }
                }
            }
            entries.retain(|entry| {
                entry.get("subresource").is_some()
                    || entry
                        .get("fieldsV1")
                        .and_then(Value::as_object)
                        .is_some_and(|fields| !fields.is_empty())
            });
        }
        let existing = entries.iter_mut().find(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some(manager)
                && entry.get("subresource").is_none()
                && entry.get("operation").and_then(Value::as_str) == Some("Update")
        });
        match existing {
            Some(entry) if merge => {
                let mut tree = entry.get("fieldsV1").cloned().unwrap_or_else(|| json!({}));
                merge_fields_tree(&mut tree, &build_fields_tree(owned));
                entry["fieldsV1"] = tree;
            }
            _ => {
                entries.retain(|entry| {
                    entry.get("manager").and_then(Value::as_str) != Some(manager)
                        || entry.get("subresource").is_some()
                        || entry.get("operation").and_then(Value::as_str) != Some("Update")
                });
                entries.push(json!({
                    "manager": manager,
                    "operation": "Update",
                    "apiVersion": "v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": build_fields_tree(owned),
                }));
            }
        }
    }

    fn remove_path(node: &mut Value, keys: &[String]) {
        let Some((first, rest)) = keys.split_first() else {
            return;
        };
        let Some(child) = node.get_mut(first) else {
            return;
        };
        if rest.is_empty() {
            node.as_object_mut().map(|object| object.remove(first));
            return;
        }
        remove_path(child, rest);
        if child
            .as_object()
            .is_some_and(|children| children.is_empty())
        {
            node.as_object_mut().map(|object| object.remove(first));
        }
    }

    fn upsert_apply_entry(managed: &mut Vec<Value>, manager: &str, paths: &[String]) {
        let tree = build_fields_tree(paths);
        if let Some(entry) = managed.iter_mut().find(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some(manager)
                && entry.get("subresource").is_none()
                && entry.get("operation").and_then(Value::as_str) == Some("Apply")
        }) {
            let mut merged = entry.get("fieldsV1").cloned().unwrap_or_else(|| json!({}));
            merge_fields_tree(&mut merged, &tree);
            entry["fieldsV1"] = merged;
        } else {
            managed.push(json!({
                "manager": manager,
                "operation": "Apply",
                "apiVersion": "apps/v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": tree,
            }));
        }
    }

    fn merge_fields_tree(target: &mut Value, patch: &Value) {
        let Some(patch) = patch.as_object() else {
            return;
        };
        if !target.is_object() {
            *target = json!({});
        }
        let target = target.as_object_mut().expect("target was made an object");
        for (key, value) in patch {
            let entry = target.entry(key.clone()).or_insert_with(|| json!({}));
            if value
                .as_object()
                .is_some_and(|children| !children.is_empty())
                && entry.is_object()
            {
                merge_fields_tree(entry, value);
            } else if !entry.is_object() {
                *entry = value.clone();
            }
        }
    }

    /// Split a dotted path into segments, keeping associative `[...]`
    /// suffixes attached to their segment.
    fn split_path(path: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut depth = 0usize;
        for character in path.chars() {
            match character {
                '[' => {
                    depth += 1;
                    current.push(character);
                }
                ']' => {
                    depth = depth.saturating_sub(1);
                    current.push(character);
                }
                '.' if depth == 0 => {
                    if !current.is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(character),
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    /// Resolve an owned-path string against a document. Object keys are
    /// matched greedily so annotation keys containing dots resolve.
    fn value_at<'a>(node: &'a Value, rest: &str) -> Option<&'a Value> {
        if rest.is_empty() {
            return Some(node);
        }
        if rest.starts_with('[') {
            let end = rest.find(']')?;
            let marker = &rest[1..end];
            let (key, expected) = marker.split_once('=')?;
            let element = node
                .as_array()?
                .iter()
                .find(|element| element.get(key).and_then(Value::as_str) == Some(expected))?;
            return value_at(element, rest[end + 1..].trim_start_matches('.'));
        }
        let object = node.as_object()?;
        let key = object
            .keys()
            .filter(|key| rest.starts_with(key.as_str()))
            .filter(|key| {
                matches!(
                    rest.as_bytes().get(key.len()),
                    None | Some(b'.') | Some(b'[')
                )
            })
            .max_by_key(|key| key.len())?;
        let after = &rest[key.len()..];
        let after = after.strip_prefix('.').unwrap_or(after);
        value_at(object.get(key)?, after)
    }

    /// Leaf paths a document claims, in owned-path notation.
    fn document_leaf_paths(document: &Value) -> Vec<String> {
        let mut paths = Vec::new();
        collect_leaf_paths(document, String::new(), &mut paths);
        paths
    }

    fn collect_leaf_paths(node: &Value, prefix: String, paths: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    // identity and housekeeping fields are never owned; only
                    // top-level and metadata keys match, container names must
                    // survive so associative keys resolve
                    if (prefix.is_empty() || prefix == "metadata")
                        && OWNERSHIP_HOUSEKEEPING.contains(&key.as_str())
                    {
                        continue;
                    }
                    collect_leaf_paths(value, join_path(&prefix, key), paths);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let segment = match item.get("name").and_then(Value::as_str) {
                        Some(name) => format!("[name={name}]"),
                        None => format!("[{index}]"),
                    };
                    collect_leaf_paths(item, join_path(&prefix, &segment), paths);
                }
            }
            _ => paths.push(prefix),
        }
    }

    fn join_path(prefix: &str, segment: &str) -> String {
        if prefix.is_empty() {
            segment.to_string()
        } else if segment.starts_with('[') {
            format!("{prefix}{segment}")
        } else {
            format!("{prefix}.{segment}")
        }
    }

    fn build_fields_tree(paths: &[String]) -> Value {
        let mut root = json!({});
        for path in paths {
            let mut node = &mut root;
            for segment in split_path(path) {
                let key = fkey_for(&segment);
                node = node
                    .as_object_mut()
                    .expect("fields tree nodes are objects")
                    .entry(key)
                    .or_insert_with(|| json!({}));
            }
        }
        root
    }

    fn fkey_for(segment: &str) -> String {
        if let Some(marker) = segment
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
        {
            let (key, value) = marker.split_once('=').expect("associative marker");
            format!("k:{{\"{key}\":\"{value}\"}}")
        } else {
            format!("f:{segment}")
        }
    }

    fn json_response(status: StatusCode, value: Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&value).expect("serialize fake response"),
            ))
            .expect("build fake response")
    }

    fn status_response(status: StatusCode, reason: &str) -> Response<Body> {
        json_response(
            status,
            json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": if status.is_success() { "Success" } else { "Failure" },
                "reason": reason,
                "message": reason,
                "code": status.as_u16(),
            }),
        )
    }

    async fn wait_for_rejection(state: &Arc<Mutex<FakeState>>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state
                    .lock()
                    .expect("fake state poisoned")
                    .rejected_preconditions
                    > 0
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached provider handler completed");
    }

    #[tokio::test]
    async fn detached_old_ssa_cannot_overwrite_newer_generation() {
        let state = Arc::new(Mutex::new(FakeState::with_generation(1, "initial")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_patch.next = true;
            (
                locked.pause_patch.entered.clone(),
                locked.pause_patch.release.clone(),
            )
        };
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");

        let old_engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let old_api: Api<ConfigMap> = Api::namespaced(old_engine.client().clone(), "fence-test");
        let old = tokio::spawn(async move {
            apply_resource(
                &old_engine,
                &old_api,
                &desired("old"),
                MutationGeneration::new(1).unwrap(),
                false,
                false,
            )
            .await
        });
        entered.notified().await;
        old.abort();
        let _ = old.await;

        apply_resource(
            &engine,
            &api,
            &desired("new"),
            MutationGeneration::new(2).unwrap(),
            false,
            false,
        )
        .await
        .expect("new generation applies");
        release.notify_one();
        wait_for_rejection(&state).await;

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource.pointer("/data/value").and_then(Value::as_str),
            Some("new")
        );
        assert_eq!(
            resource
                .pointer(&format!(
                    "/metadata/annotations/{}",
                    MUTATION_GENERATION_ANNOTATION
                        .replace('~', "~0")
                        .replace('/', "~1")
                ))
                .and_then(Value::as_str),
            Some("2")
        );
    }

    #[tokio::test]
    async fn detached_old_delete_cannot_remove_replacement_generation() {
        let state = Arc::new(Mutex::new(FakeState::with_generation(1, "initial")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_delete.next = true;
            (
                locked.pause_delete.entered.clone(),
                locked.pause_delete.release.clone(),
            )
        };
        let old_api: Api<ConfigMap> =
            Api::namespaced(fake_client(Arc::clone(&state)), "fence-test");
        let old = tokio::spawn(async move {
            delete_resource(
                &old_api,
                "fenced",
                MutationGeneration::new(1).unwrap(),
                DeleteParams::default(),
            )
            .await
        });
        entered.notified().await;
        old.abort();
        let _ = old.await;

        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");
        apply_resource(
            &engine,
            &api,
            &desired("replacement"),
            MutationGeneration::new(2).unwrap(),
            false,
            false,
        )
        .await
        .expect("replacement generation applies");
        release.notify_one();
        wait_for_rejection(&state).await;

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().expect("replacement remains live");
        assert_eq!(
            resource.pointer("/data/value").and_then(Value::as_str),
            Some("replacement")
        );
    }

    #[tokio::test]
    async fn canceled_absent_create_can_still_land_at_provider() {
        let state = Arc::new(Mutex::new(FakeState::absent()));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_create.next = true;
            (
                locked.pause_create.entered.clone(),
                locked.pause_create.release.clone(),
            )
        };
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "fence-test");
        let create = tokio::spawn(async move {
            apply_resource(
                &engine,
                &api,
                &desired("created-after-cancel"),
                MutationGeneration::new(1).unwrap(),
                false,
                false,
            )
            .await
        });
        entered.notified().await;
        create.abort();
        let _ = create.await;
        release.notify_one();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state.lock().unwrap().resource.is_some() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached create lands despite client cancellation");

        let locked = state.lock().unwrap();
        assert_eq!(
            locked
                .resource
                .as_ref()
                .and_then(|resource| resource.pointer("/data/value"))
                .and_then(Value::as_str),
            Some("created-after-cancel")
        );
    }

    #[test]
    fn trusted_update_owner_can_be_reclaimed_without_ignoring_external_managers() {
        let trusted: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "fenced",
                "managedFields": [
                    {"manager": "enclava-platform", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": {}},
                    {"manager": "controller", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": {}, "subresource": "status"}
                ]
            }
        }))
        .unwrap();
        assert!(only_trusted_field_managers(&trusted, "enclava-platform"));

        let mut external = trusted;
        external.metadata.managed_fields.as_mut().unwrap().push(
            serde_json::from_value(json!({
                "manager": "kubectl",
                "operation": "Update",
                "apiVersion": "v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": {}
            }))
            .unwrap(),
        );
        assert!(!only_trusted_field_managers(&external, "enclava-platform"));
    }

    #[tokio::test]
    async fn exact_trusted_update_prunes_omitted_statefulset_fields() {
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        state.lock().unwrap().resource.as_mut().unwrap()["spec"]["template"]["spec"]["containers"]
            [0]["volumeMounts"] = json!([{
            "name": "obsolete",
            "mountPath": "/obsolete",
        }]);
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {"labels": {"app": "fenced"}},
                    "spec": {"containers": [{"name": "workload", "image": "example.test/workload:current"}]},
                },
            },
        }))
        .unwrap();

        apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(2).unwrap(),
            false,
            true,
        )
        .await
        .expect("trusted StatefulSet is replaced exactly");

        let locked = state.lock().unwrap();
        assert!(
            locked.resource.as_ref().unwrap()["spec"]["template"]["spec"]["containers"][0]
                .get("volumeMounts")
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_writer_churn_cannot_terminally_fail_partial_apply() {
        // Regression (staging 2026-09-13, gen e3cf547b): the partial merge
        // path retried 409s with NO delay, exhausting any retry budget in
        // milliseconds against a controller-style concurrent writer.
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        state.lock().unwrap().churn_until =
            Some(std::time::Instant::now() + Duration::from_millis(2500));

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(2).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("partial apply survives a bounded concurrent writer");
        let locked = state.lock().unwrap();
        assert_eq!(locked.resource.as_ref().unwrap()["spec"]["replicas"], 0);
    }

    #[tokio::test]
    async fn partial_statefulset_mutations_preserve_unrelated_owned_fields() {
        let state = Arc::new(Mutex::new(FakeState::with_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(2).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("conditional scale merge applies");
        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "cap.enclava.dev/tenant-ingress-restarted-at": "now",
                            },
                        },
                    },
                },
            }),
            MutationGeneration::new(3).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("conditional restart merge applies");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(0)));
        assert_eq!(
            resource
                .pointer("/spec/serviceName")
                .and_then(Value::as_str),
            Some("fenced-service")
        );
        assert_eq!(
            resource
                .pointer("/spec/template/spec/containers/0/name")
                .and_then(Value::as_str),
            Some("workload")
        );
        assert_eq!(
            resource
                .pointer("/spec/template/metadata/annotations/unrelated-template")
                .and_then(Value::as_str),
            Some("preserved")
        );
        assert_eq!(
            resource
                .pointer("/metadata/annotations/unrelated-metadata")
                .and_then(Value::as_str),
            Some("preserved")
        );
    }

    fn annotation_pointer() -> String {
        format!(
            "/metadata/annotations/{}",
            MUTATION_GENERATION_ANNOTATION
                .replace('~', "~0")
                .replace('/', "~1")
        )
    }

    fn desired_shared_statefulset(image: &str) -> StatefulSet {
        serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "fenced", "namespace": "fence-test"},
            "spec": {
                "replicas": 1,
                "serviceName": "fenced-service",
                "selector": {"matchLabels": {"app": "fenced"}},
                "template": {
                    "metadata": {
                        "labels": {"app": "fenced"},
                        "annotations": {"unrelated-template": "preserved"},
                    },
                    "spec": {
                        "runtimeClassName": "kata-clh-snp",
                        "containers": [{
                            "name": "workload",
                            "image": image,
                        }],
                    },
                },
            },
        }))
        .expect("valid desired StatefulSet")
    }

    #[tokio::test]
    async fn replicas_owner_cannot_block_new_generation_apply() {
        // Regression (staging tenant-c 2026-09-14, live gens
        // 170b352b/e3cf547b/966b7531): against the live object — CAP Update
        // ownership of the generation annotation plus a lingering
        // replicas-only kubectl-patch Update entry at provider generation 4 —
        // the no-force SSA path conflicted with CAP's own Update entry on
        // every new generation and exhausted the whole conflict budget with
        // MutationConflictExhausted. Succeeding against this exact state is
        // the fix's acceptance condition.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let applied = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await;
        applied.expect("new generation applies against the shared live object");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("5")
        );
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(1)));
        let managed = resource
            .pointer("/metadata/managedFields")
            .and_then(Value::as_array)
            .expect("managedFields present");
        // the replicas owner keeps its metadata: we reconciled our own
        // fields, we did not absorb the foreign entry
        let replicas_owner = managed
            .iter()
            .find(|entry| entry.get("manager").and_then(Value::as_str) == Some("kubectl-patch"))
            .expect("replicas owner survives the forced self-reclaim");
        assert!(
            replicas_owner
                .pointer("/fieldsV1/f:spec/f:replicas")
                .is_some()
        );
        assert!(managed.iter().any(|entry| {
            entry.get("manager").and_then(Value::as_str) == Some("enclava-platform")
                && entry.get("operation").and_then(Value::as_str) == Some("Apply")
        }));
    }

    #[tokio::test]
    async fn externally_owned_field_change_fails_closed_promptly() {
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        {
            let mut locked = state.lock().unwrap();
            let resource = locked.resource.as_mut().unwrap();
            // an external manager owns the workload image and the live value
            // differs from the desired one (follower-attacker shape)
            resource["metadata"]["managedFields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "manager": "tampering-controller",
                    "operation": "Update",
                    "apiVersion": "apps/v1",
                    "fieldsType": "FieldsV1",
                    "fieldsV1": {"f:spec": {"f:template": {"f:spec": {"f:containers": {
                        "k:{\"name\":\"workload\"}": {"f:image": {}},
                    }}}}},
                }));
            resource["spec"]["template"]["spec"]["containers"][0]["image"] = json!(
                "example.test/workload@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            );
        }
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("externally owned field change must fail closed");
        match error {
            ApplyError::Kube(kube::Error::Api(status)) => {
                assert_eq!(status.code, 409);
                let causes = status.details.expect("conflict details").causes;
                assert!(causes.iter().any(|cause| {
                    cause.reason == "FieldManagerConflict" && cause.field.contains("image")
                }));
            }
            other => panic!("expected a Kubernetes API conflict, got {other:?}"),
        }
        assert_eq!(
            state.lock().unwrap().ssa_attempts,
            1,
            "unresolved ownership conflicts must fail on the first attempt"
        );
        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[tokio::test]
    async fn dr_scale_resume_then_new_generation_apply_converges() {
        // The supported DR maintenance path must not create foreign
        // ownership that later deploys cannot pass: partials attributed to
        // the control plane's field manager stay self-reclaimable.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");

        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 0 },
            }),
            MutationGeneration::new(5).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("DR scale to zero");
        assert_eq!(
            state.lock().unwrap().resource.as_ref().unwrap()["spec"]["replicas"],
            0
        );
        apply_existing_partial(
            &api,
            "fenced",
            &json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "spec": { "replicas": 1 },
            }),
            MutationGeneration::new(5).unwrap(),
            "enclava-platform",
        )
        .await
        .expect("DR resume to one");

        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(6).unwrap(),
            false,
            true,
        )
        .await
        .expect("new generation apply after DR scale/resume converges");

        let locked = state.lock().unwrap();
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("6")
        );
        assert_eq!(resource.pointer("/spec/replicas"), Some(&json!(1)));
        // real Update semantics: the DR merge patches (attributed to CAP's
        // field manager) acquired spec.replicas, so the replicas-only
        // foreign owner was left with nothing and dropped, and the final
        // generation apply ran as an exact trusted replacement
        assert!(
            resource
                .pointer("/metadata/managedFields")
                .and_then(Value::as_array)
                .expect("managedFields present")
                .iter()
                .all(|entry| {
                    entry.get("subresource").is_some()
                        || entry.get("manager").and_then(Value::as_str) == Some("enclava-platform")
                })
        );
        assert_eq!(
            locked.replace_attempts, 1,
            "final apply used exact replacement"
        );
        assert_eq!(
            locked.ssa_attempts, 0,
            "no SSA probing on the trusted object"
        );
    }

    #[tokio::test]
    async fn unattributable_ownership_fails_closed_instead_of_forcing() {
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        {
            let mut locked = state.lock().unwrap();
            let resource = locked.resource.as_mut().unwrap();
            // fields this walker cannot attribute must count as foreign
            let kubectl = resource["metadata"]["managedFields"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry.get("manager").and_then(Value::as_str) == Some("kubectl-patch"))
                .expect("replicas owner present");
            kubectl["fieldsV1"] = json!({"v:\"opaque\"": {}});
        }
        let live: StatefulSet =
            serde_json::from_value(state.lock().unwrap().resource.clone().unwrap()).unwrap();
        assert!(!conflicts_reclaimable_by_force(
            &live,
            &["metadata.annotations.enclava.dev/cap-provider-mutation-generation".to_string()],
            "enclava-platform",
        ));

        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("unattributable ownership must fail closed");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        assert_eq!(state.lock().unwrap().ssa_attempts, 1);
    }

    #[tokio::test]
    async fn foreign_write_during_escalation_deauthorizes_the_force() {
        // A forced reclaim is authorized only against the exact
        // resourceVersion whose ownership was classified. A foreign writer
        // taking the container image between classification and the forced
        // write must bump the resourceVersion, void the authorization, and
        // make the next classification fail closed instead of
        // force-overwriting the foreign value.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        state.lock().unwrap().hijack_next_force = Some(
            "example.test/workload@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        );
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("ownership change during escalation must fail closed");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        let locked = state.lock().unwrap();
        // no-force probe (1), deauthorized forced write rejected by the
        // resourceVersion precondition before evaluation, re-classifying
        // no-force probe (2)
        assert_eq!(locked.ssa_attempts, 2);
        assert_eq!(
            locked.rejected_preconditions, 1,
            "the forced write must be rejected against the bumped version"
        );
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer("/spec/template/spec/containers/0/image")
                .and_then(Value::as_str),
            Some(
                "example.test/workload@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            ),
            "the foreign value must not be force-overwritten"
        );
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[tokio::test]
    async fn stale_conflict_evidence_cannot_authorize_force() {
        // The 409's causes were evaluated against the version the failed
        // PATCH submitted. If a foreign writer takes a field (here
        // runtimeClassName) between that evaluation and the classification
        // re-read, the stale cause list omits it: the mismatched
        // resourceVersion must void the escalation and the fresh probe must
        // fail closed on the foreign field.
        let state = Arc::new(Mutex::new(FakeState::with_shared_statefulset()));
        state.lock().unwrap().hijack_next_conflict = Some("kata-tampered".to_string());
        let engine = ApplyEngine::new(fake_client(Arc::clone(&state)), Default::default());
        let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), "fence-test");
        let desired = desired_shared_statefulset(
            "example.test/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let error = apply_resource(
            &engine,
            &api,
            &desired,
            MutationGeneration::new(5).unwrap(),
            false,
            true,
        )
        .await
        .expect_err("stale cause evidence must not authorize force");
        assert!(matches!(
            error,
            ApplyError::Kube(kube::Error::Api(status)) if status.code == 409
        ));
        let locked = state.lock().unwrap();
        // stale-evidence probe (1), fresh probe failing closed (2); no
        // forced write is ever submitted
        assert_eq!(locked.ssa_attempts, 2);
        let resource = locked.resource.as_ref().unwrap();
        assert_eq!(
            resource
                .pointer("/spec/template/spec/runtimeClassName")
                .and_then(Value::as_str),
            Some("kata-tampered"),
            "the foreign runtime class must not be force-overwritten"
        );
        assert_eq!(
            resource
                .pointer(&annotation_pointer())
                .and_then(Value::as_str),
            Some("4"),
            "live object untouched"
        );
    }

    #[test]
    fn server_quoted_cause_fields_classify_against_owned_subtrees() {
        // Literal API-server cause notation, independent of any formatter:
        // associative markers arrive quoted as [name="workload"].
        let live: StatefulSet = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {
                "name": "fenced",
                "managedFields": [
                    {"manager": "enclava-platform", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": {}},
                    {"manager": "kubectl-patch", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1",
                     "fieldsV1": {"f:spec": {"f:containers": {}}}},
                ],
            },
        }))
        .unwrap();
        // a coarse external owner of spec.containers covers the bracketed
        // descendant and blocks the force
        assert!(!conflicts_reclaimable_by_force(
            &live,
            &["spec.containers[name=\"workload\"].image".to_string()],
            "enclava-platform",
        ));
        // an unrelated external leaf does not cover the annotation
        assert!(conflicts_reclaimable_by_force(
            &live,
            &["metadata.annotations.enclava.dev/cap-provider-mutation-generation".to_string()],
            "enclava-platform",
        ));
    }
}
