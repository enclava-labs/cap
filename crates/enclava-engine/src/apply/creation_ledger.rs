//! Server-recorded creation provenance for objects CAP creates (cap#272).
//!
//! Kubernetes does not authenticate or reserve field-manager strings: a
//! tenant of an adopted namespace can pre-create a target-shaped object
//! carrying the creation annotation and submit the write with
//! `fieldManager=enclava-platform`, producing a managed-fields entry
//! indistinguishable from CAP's own. The annotation+manager check alone is
//! therefore client-selectable evidence, and destructive cleanup must not
//! rest on it. Creation is provable at exactly one moment — the create POST
//! response observed by this control plane — so the apply records
//! (kind, name, uid) there, persists it durably, and cleanup matches the
//! live object's UID against that ledger.
//!
//! Migration semantics ([`CREATION_LEDGER_CUTOVER`]): objects created
//! before the cutover instant are grandfathered under the legacy
//! annotation+manager check (one-time, bounded trust at migration time —
//! a forgery planted before the cutover is accepted exactly once and can
//! never repeat, because a post-cutover object needs a ledger row no
//! tenant write can produce). Objects created after the cutover without a
//! recorded row are UNPROVEN: their claimed creation evidence authorizes
//! nothing, and the failed-apply sweep keeps them unresolved (fail closed,
//! retryable) instead of deleting or silently skipping them.

use std::collections::HashSet;
use std::sync::Mutex;

/// UTC instant (RFC 3339, second precision) separating grandfathered
/// objects from ledger-required ones. Objects whose creationTimestamp is
/// at or before this instant keep the legacy annotation+manager authority;
/// objects created after it must match a recorded ledger row. Set at the
/// cap#272 close-out and frozen forever after — moving it forward would
/// retroactively legitimize post-cutover forgeries.
pub const CREATION_LEDGER_CUTOVER: &str = "2026-10-17T00:00:00Z";

/// One server-observed creation: the (kind, name, uid) of an object this
/// control plane created via its own POST, recorded at the only moment
/// creation is provable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreationRecord {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub uid: String,
    pub mutation_generation: i64,
}

/// How a live object's claimed creation provenance settles against the
/// ledger and the migration cutover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageProvenance {
    /// The (name, uid) pair was recorded by a CAP create POST.
    Recorded,
    /// The object predates the ledger cutover: the legacy
    /// annotation+manager check remains authoritative (bounded one-time
    /// migration trust).
    Grandfathered,
    /// Created after the cutover with no recorded row: the claimed
    /// evidence authorizes nothing (deletion refuses; the sweep stays
    /// incomplete over it).
    Unproven,
}

/// Whether an object's raw creationTimestamp (RFC 3339, as serialized by
/// the API server) is at or before [`CREATION_LEDGER_CUTOVER`], truncated
/// to second precision so fractional-second encodings compare correctly.
pub fn creation_predates_ledger_cutover(raw_creation_timestamp: &str) -> bool {
    let object_seconds = raw_creation_timestamp.get(..19);
    let cutover_seconds = CREATION_LEDGER_CUTOVER.get(..19);
    match (object_seconds, cutover_seconds) {
        (Some(object), Some(cutover)) => object <= cutover,
        // An unparseable or partial timestamp proves nothing: only a
        // recorded row can carry a post-cutover object.
        _ => false,
    }
}

type Key = (String, String, String);

/// Shared, thread-safe creation-ledger handle attachable to an
/// [`crate::apply::engine::ApplyEngine`].
///
/// The engine appends a [`CreationRecord`] for every object its own create
/// POST produces and consults the recorded key set when deciding whether
/// creation evidence read from a LIVE object may be preserved across an
/// update. The control plane seeds the set with the app's durable ledger
/// rows before the apply starts and drains the pending records after each
/// apply step, persisting them before the apply may proceed — an object
/// whose row cannot be persisted is compensated (deleted) and the apply
/// fails closed, so "created but unrecorded" cannot leak into cleanup.
///
/// When no ledger is attached, the engine keeps its legacy preserve
/// behavior (annotation + field-manager provenance): the ledger-enforced
/// DELETION authority lives in the API's sweep, not in this type.
#[derive(Debug, Default)]
pub struct CreationLedgerBuffer {
    inner: Mutex<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    pending: Vec<CreationRecord>,
    known: HashSet<Key>,
}

impl CreationLedgerBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the recorded key set with the app's durable ledger rows
    /// ((kind, name, uid) triples loaded from the database).
    pub fn preload(&self, rows: impl IntoIterator<Item = Key>) {
        let mut state = self.inner.lock().expect("creation ledger lock");
        state.known.extend(rows);
    }

    /// Append a creation observed by this apply. The record is pending
    /// until the control plane drains and durably persists it; the key
    /// becomes matchable immediately for later steps of the same apply.
    pub fn record(&self, record: CreationRecord) {
        let mut state = self.inner.lock().expect("creation ledger lock");
        state
            .known
            .insert((record.kind.clone(), record.name.clone(), record.uid.clone()));
        state.pending.push(record);
    }

    /// Take (and clear) the records accumulated since the last drain.
    pub fn drain_pending(&self) -> Vec<CreationRecord> {
        let mut state = self.inner.lock().expect("creation ledger lock");
        std::mem::take(&mut state.pending)
    }

    /// Whether (kind, name, uid) is a recorded CAP creation (preloaded
    /// durable rows plus this apply's own observations).
    pub fn contains(&self, kind: &str, name: &str, uid: &str) -> bool {
        let state = self.inner.lock().expect("creation ledger lock");
        state
            .known
            .contains(&(kind.to_string(), name.to_string(), uid.to_string()))
    }

    /// Whether (name, uid) is recorded under ANY kind. UIDs are
    /// cluster-unique, so a kind-less caller (generic cleanup code that
    /// only has the live object's metadata) still resolves exactly.
    pub fn contains_name_uid(&self, name: &str, uid: &str) -> bool {
        let state = self.inner.lock().expect("creation ledger lock");
        state
            .known
            .iter()
            .any(|(_, known_name, known_uid)| known_name == name && known_uid == uid)
    }
}

/// Settle a live object's creation provenance against a ledger and the
/// migration cutover. `None` ledger means the caller runs without ledger
/// enforcement (engine-only usage); provenance then falls back to
/// [`LineageProvenance::Grandfathered`] semantics and the CALLER decides
/// whether that is acceptable (the API's cleanup paths never pass `None`).
pub fn creation_lineage_provenance(
    name: Option<&str>,
    uid: Option<&str>,
    raw_creation_timestamp: Option<&str>,
    ledger: Option<&CreationLedgerBuffer>,
) -> LineageProvenance {
    let Some((name, uid)) = name.zip(uid) else {
        // No identity to match: only the cutover can speak for the object.
        return match raw_creation_timestamp.is_some_and(creation_predates_ledger_cutover) {
            true => LineageProvenance::Grandfathered,
            false => LineageProvenance::Unproven,
        };
    };
    if ledger.is_some_and(|ledger| ledger.contains_name_uid(name, uid)) {
        return LineageProvenance::Recorded;
    }
    if raw_creation_timestamp.is_some_and(creation_predates_ledger_cutover) {
        return LineageProvenance::Grandfathered;
    }
    LineageProvenance::Unproven
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutover_comparison_is_second_precise() {
        assert!(creation_predates_ledger_cutover("2026-10-13T09:43:08Z"));
        assert!(creation_predates_ledger_cutover(
            "2026-10-17T00:00:00.123456Z"
        ));
        assert!(!creation_predates_ledger_cutover("2026-10-17T00:00:01Z"));
        assert!(!creation_predates_ledger_cutover("2026-10-18T00:00:00Z"));
        // Unparseable input never grandfather-fails open.
        assert!(!creation_predates_ledger_cutover(""));
        assert!(!creation_predates_ledger_cutover("garbage"));
    }

    #[test]
    fn provenance_requires_record_or_cutover() {
        let ledger = CreationLedgerBuffer::new();
        ledger.preload([(
            "Secret".to_string(),
            "pull-secret".to_string(),
            "uid-1".to_string(),
        )]);

        assert_eq!(
            creation_lineage_provenance(
                Some("pull-secret"),
                Some("uid-1"),
                Some("2026-10-18T00:00:00Z"),
                Some(&ledger),
            ),
            LineageProvenance::Recorded
        );
        // Post-cutover, unrecorded: the forged-evidence case (cap#272).
        assert_eq!(
            creation_lineage_provenance(
                Some("pull-secret"),
                Some("uid-forged"),
                Some("2026-10-18T00:00:00Z"),
                Some(&ledger),
            ),
            LineageProvenance::Unproven
        );
        // Pre-cutover: grandfathered migration trust.
        assert_eq!(
            creation_lineage_provenance(
                Some("old-service"),
                Some("uid-legacy"),
                Some("2026-10-14T00:00:00Z"),
                Some(&ledger),
            ),
            LineageProvenance::Grandfathered
        );
        // No identity and no timestamp: nothing speaks for the object.
        assert_eq!(
            creation_lineage_provenance(None, None, None, Some(&ledger),),
            LineageProvenance::Unproven
        );
    }

    #[test]
    fn drain_pending_keeps_known_matchable() {
        let ledger = CreationLedgerBuffer::new();
        ledger.record(CreationRecord {
            kind: "Secret".to_string(),
            name: "pull-secret".to_string(),
            namespace: Some("tenant-ns".to_string()),
            uid: "uid-9".to_string(),
            mutation_generation: 4,
        });
        assert!(ledger.contains("Secret", "pull-secret", "uid-9"));
        let drained = ledger.drain_pending();
        assert_eq!(drained.len(), 1);
        assert!(drain_pending_returns_nothing_after_drain(&ledger));
        // The drained key stays matchable for later steps of the apply.
        assert!(ledger.contains("Secret", "pull-secret", "uid-9"));
    }

    fn drain_pending_returns_nothing_after_drain(ledger: &CreationLedgerBuffer) -> bool {
        ledger.drain_pending().is_empty()
    }
}
