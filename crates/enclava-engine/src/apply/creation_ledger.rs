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
//! Migration is opt-in through [`CreationLedgerBuffer::with_legacy_cutover`].
//! There is no compiled-in date: a date before binary activation strands CAP
//! objects created during rollout. With no trusted cutoff, all unrecorded
//! objects are UNPROVEN (including old objects), never deletion authority.
//!
//! Operator activation: quiesce CAP mutations and namespace writers, drain old
//! binaries, deploy ledger-capable binaries everywhere, then record the actual
//! activation instant as a fixed absolute timestamp. Audit legacy objects before
//! enabling that cutoff consistently on every control-plane replica. Preserve
//! it across restarts/upgrades; NEVER advance it to unblock cleanup. Advancing
//! it deliberately grants trust to additional, potentially forged objects.
//! A future cutoff is rejected rather than opening an ongoing forgery window.
//!
//! This is bounded *legacy trust*, not proof or a one-use authorization: an
//! unrecorded UID created at/before activation can retain legacy annotation+
//! manager authority for its lifetime, including a forgery already planted at
//! activation. Only a new UID after activation must have a ledger record.
//! Operators unwilling to accept that risk must leave migration disabled and
//! recover legacy objects through independently audited provenance. The cutoff
//! must come from trusted control-plane configuration, never tenant input.

use std::collections::HashSet;
use std::sync::Mutex;

use k8s_openapi::jiff::Timestamp;

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
    /// annotation+manager check remains authoritative for this UID's lifetime
    /// under the explicit bounded migration trust decision.
    Grandfathered,
    /// Created after the cutover with no recorded row: the claimed
    /// evidence authorizes nothing (deletion refuses; the sweep stays
    /// incomplete over it).
    Unproven,
}

/// Parse an absolute instant, including the space-separated Chrono Display
/// form used by callers as well as Kubernetes RFC 3339. Missing timezone,
/// malformed dates, and incomplete timestamps cannot establish provenance.
fn parse_creation_timestamp(raw: &str) -> Option<Timestamp> {
    let normalized = raw.strip_suffix(" UTC").map(|raw| format!("{raw}Z"));
    normalized.as_deref().unwrap_or(raw).parse().ok()
}

/// Compare full instants, preserving subseconds and normalizing offsets.
/// There is deliberately no implicit/global cutoff.
pub fn creation_predates_ledger_cutover(raw_creation_timestamp: &str, cutover: Timestamp) -> bool {
    parse_creation_timestamp(raw_creation_timestamp).is_some_and(|object| object <= cutover)
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
    legacy_cutover: Option<Timestamp>,
}

#[derive(Debug, Default)]
struct LedgerState {
    pending: Vec<CreationRecord>,
    known: HashSet<Key>,
}

impl CreationLedgerBuffer {
    /// No implicit legacy trust: only recorded creations are authoritative.
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicit operator-approved, absolute activation boundary. `observed_at`
    /// is the trusted control-plane time at configuration load, not object
    /// metadata. Future boundaries fail closed. The boundary is immutable for
    /// this handle; see module documentation before granting legacy trust.
    pub fn with_legacy_cutover(raw_cutover: &str, observed_at: Timestamp) -> Result<Self, String> {
        let cutover = parse_creation_timestamp(raw_cutover)
            .ok_or_else(|| "creation ledger cutoff must be an absolute timestamp".to_string())?;
        if cutover > observed_at {
            return Err("creation ledger cutoff cannot be in the future".to_string());
        }
        Ok(Self {
            legacy_cutover: Some(cutover),
            ..Self::default()
        })
    }

    fn grandfathers(&self, raw_timestamp: &str) -> bool {
        self.legacy_cutover
            .is_some_and(|cutover| creation_predates_ledger_cutover(raw_timestamp, cutover))
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

/// Settle a live object's creation provenance against an explicit ledger.
/// Missing ledger/cutoff, missing timestamp, and invalid timestamp never grant
/// legacy trust. Engine-only callers that intentionally retain legacy behavior
/// handle absence of a ledger before calling this function.
pub fn creation_lineage_provenance(
    name: Option<&str>,
    uid: Option<&str>,
    raw_creation_timestamp: Option<&str>,
    ledger: Option<&CreationLedgerBuffer>,
) -> LineageProvenance {
    if let Some((name, uid)) = name.zip(uid)
        && ledger.is_some_and(|ledger| ledger.contains_name_uid(name, uid))
    {
        return LineageProvenance::Recorded;
    }
    if raw_creation_timestamp
        .is_some_and(|timestamp| ledger.is_some_and(|ledger| ledger.grandfathers(timestamp)))
    {
        return LineageProvenance::Grandfathered;
    }
    LineageProvenance::Unproven
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration_ledger() -> CreationLedgerBuffer {
        CreationLedgerBuffer::with_legacy_cutover(
            "2026-10-17T12:00:00Z",
            "2026-10-17T12:00:00Z".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn cutover_compares_parsed_instants_without_truncation() {
        let ledger = migration_ledger();
        for legacy in [
            "2026-10-13T09:43:08Z",
            "2026-10-17T12:00:00Z",
            "2026-10-17 12:00:00 UTC",
            "2026-10-17 12:00:00+00:00",
            "2026-10-17T13:00:00+01:00",
            // CAP creations during rollout after the old midnight cutoff.
            "2026-10-17T11:59:59.999999999Z",
        ] {
            assert!(ledger.grandfathers(legacy), "{legacy}");
        }
        for unproven in [
            "2026-10-17T12:00:00.000000001Z",
            "2026-10-17 12:00:00.000000001 UTC",
            "2026-10-17 12:00:01+00:00",
            "2026-10-17T11:00:01-01:00",
            "2026-10-18T00:00:00Z",
            "",
            "garbage",
            "2026-10-13T09:43:08garbage",
            "2026-10-13T09:43:08",
            "2026-02-30T00:00:00Z",
            "2026-10-13",
        ] {
            assert!(!ledger.grandfathers(unproven), "{unproven}");
        }
    }

    #[test]
    fn absent_cutover_or_ledger_never_grants_legacy_trust() {
        let ledger = CreationLedgerBuffer::new();
        for handle in [None, Some(&ledger)] {
            for identity in [(None, None), (Some("legacy"), Some("uid"))] {
                assert_eq!(
                    creation_lineage_provenance(
                        identity.0,
                        identity.1,
                        Some("2026-10-13T00:00:00Z"),
                        handle,
                    ),
                    LineageProvenance::Unproven,
                );
            }
        }
    }

    #[test]
    fn activation_must_be_explicit_valid_and_not_future() {
        let now = "2026-10-17T12:00:00Z".parse().unwrap();
        for invalid in [
            "",
            "garbage",
            "2026-10-17",
            "2026-10-17T12:00:00.000000001Z",
        ] {
            assert!(CreationLedgerBuffer::with_legacy_cutover(invalid, now).is_err());
        }
        assert!(CreationLedgerBuffer::with_legacy_cutover("2026-10-17T12:00:00Z", now).is_ok());
        // Configuration is per handle, not a mutable global inherited by tests
        // or a fresh ledger: granting legacy trust cannot change strict ones.
        let migration = migration_ledger();
        let strict = CreationLedgerBuffer::new();
        assert!(migration.grandfathers("2026-10-13T00:00:00Z"));
        assert!(!strict.grandfathers("2026-10-13T00:00:00Z"));
    }

    #[test]
    fn provenance_requires_record_or_cutover() {
        let ledger = migration_ledger();
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
    fn recorded_identity_does_not_require_a_cutoff_or_timestamp() {
        let ledger = CreationLedgerBuffer::new();
        ledger.preload([("Secret".into(), "owned".into(), "uid".into())]);
        for timestamp in [None, Some("not a timestamp"), Some("2026-10-18T00:00:00Z")] {
            assert_eq!(
                creation_lineage_provenance(Some("owned"), Some("uid"), timestamp, Some(&ledger)),
                LineageProvenance::Recorded,
            );
            assert_eq!(
                creation_lineage_provenance(
                    Some("owned"),
                    Some("replacement-uid"),
                    timestamp,
                    Some(&ledger)
                ),
                LineageProvenance::Unproven,
            );
        }
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
