-- Signer-rotation tokens are bearer tokens with a 600s TTL. Bind each jti
-- to the exact rotation it authorized and mark it consumed inside the
-- rotation transaction, so a captured token cannot be replayed within its
-- validity window (issue #119).
CREATE TABLE consumed_signer_rotation_tokens (
    jti        text PRIMARY KEY,
    user_id    uuid NOT NULL,
    org_id     uuid NOT NULL,
    app_id     uuid NOT NULL,
    subject    text NOT NULL,
    issuer     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

-- Rotation must also withdraw KBS trust from the previous signer as soon as
-- the new identity is committed, not only at the next deployment. workload_
-- artifacts rows are immutable by trigger (0038), so revocation is recorded
-- in a side table keyed by descriptor hash; the signed-policy selector
-- refuses any artifact with a withdrawal row.
CREATE TABLE withdrawn_signer_artifacts (
    descriptor_core_hash bytea PRIMARY KEY
        REFERENCES workload_artifacts(descriptor_core_hash) ON DELETE CASCADE,
    app_id       uuid NOT NULL,
    rotated_out_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_withdrawn_signer_artifacts_app
    ON withdrawn_signer_artifacts (app_id);

-- Fence the backfill window BEFORE reading: without this lock an old API
-- could commit a signer change between the backfill snapshot below and
-- the trigger installation at the end of this transaction, escaping both
-- (no withdrawal row, no debt).  SHARE ROW EXCLUSIVE excludes every apps
-- write (INSERT/UPDATE/DELETE), so any in-flight identity change commits
-- first -- and is captured by the backfill snapshot -- while any writer
-- that arrives behind the lock waits for this transaction, which installs
-- the trigger before it commits, so the resumed write fires it.  Plain
-- SELECT readers are unaffected.
LOCK TABLE apps IN SHARE ROW EXCLUSIVE MODE;

-- Backfill: an app whose current signer identity differs from an artifact's
-- signed descriptor identity has already been rotated; withdraw those
-- artifacts so the selector stops re-admitting them. Unlike the runtime
-- withdrawal (which matches the exact rotated-out identity), this backfill
-- withdraws any descriptor signer_identity object that no longer equals the
-- app's currently pinned identity; only rows with the object present are
-- considered.
INSERT INTO withdrawn_signer_artifacts (
    descriptor_core_hash, app_id, rotated_out_at
)
SELECT artifact.descriptor_core_hash, artifact.app_id, now()
  FROM workload_artifacts AS artifact
  JOIN apps AS app ON app.id = artifact.app_id
 WHERE app.signer_identity_subject IS NOT NULL
   AND artifact.descriptor_payload ? 'signer_identity'
   AND (
        artifact.descriptor_payload -> 'signer_identity' ->> 'subject'
            IS DISTINCT FROM app.signer_identity_subject
        OR artifact.descriptor_payload -> 'signer_identity' ->> 'issuer'
            IS DISTINCT FROM app.signer_identity_issuer
   )
ON CONFLICT DO NOTHING;

-- The withdrawn candidate set changes the signed-policy body, so the
-- generation must advance or the withdrawal-aware reconciler would report a
-- same-generation content change as PolicyGenerationConflict and exit with no
-- bump left to recover.  The bump MUST NOT be performed here, though.  With
-- DATABASE_MIGRATION_MODE=verify (deploy/api/deployment.yaml) this
-- migration runs in a rollout step that precedes the new binary while a
-- previous replica is still live: that replica's 30-second reconciler would
-- consume a direct desired_generation bump using the pre-#119 unfiltered
-- candidate query and publish the OLD policy body at the new generation.
-- The new binary would then compute the filtered hash at the
-- already-published generation and crash-loop on PolicyGenerationConflict
-- with no bump left to recover.
--
-- The bump is therefore OWED, not performed: this counter is a
-- signer-withdrawal-specific debt that only a withdrawal-aware reconciler
-- may interpret.  It is a SEPARATE column from selector_bumps_owed (the
-- keyring-membership debt, migration 0058) on purpose: a binary aware of
-- only one debt must never consume the other's marker -- it would publish
-- through a selector that does not apply the other filter and hit the
-- same conflict.  A reconciler aware of both debts publishes the fully
-- filtered candidate set as generation desired_generation
-- + selector_bumps_owed + withdrawal_bumps_owed while leaving
-- desired_generation untouched, and only after that ConfigMap replace
-- succeeded does consume_deferred_policy_debts
-- (crates/enclava-api/src/kbs.rs) commit BOTH increments in a single
-- compare-and-set on the exact (desired_generation,
-- selector_bumps_owed, withdrawal_bumps_owed) triple the run published
-- at -- the counters are never committed one before the other.  A
-- rotation landing mid-run moves its counter, fails the CAS, and makes
-- the next attempt republish at the strictly higher generation with a
-- fresh candidate set.
--
-- A pre-0052 reconciler therefore never sees the owed generation as a raw
-- desired generation.  Before the replace it keeps finding an unchanged
-- generation whose unfiltered hash matches the published body and stays
-- quiescent; between the replace and the commit it finds the annotated
-- generation ahead of its own and treats it as superseded; after the commit
-- the same content-bound annotation turns any late unfiltered
-- republication into a same-generation conflict.  Every crash window lands
-- in one of those three states.
--
-- Unsigned-only installs (desired_generation = 0) are never owed anything,
-- so rotation cannot flip them into signed-policy mode (where an empty
-- artifact set would deny every workload); the debt invariant is
-- withdrawal_bumps_owed > 0 => desired_generation > 0.
ALTER TABLE kbs_signed_policy_reconciliation
    ADD COLUMN withdrawal_bumps_owed bigint NOT NULL DEFAULT 0
        CHECK (withdrawal_bumps_owed >= 0);

UPDATE kbs_signed_policy_reconciliation
   SET withdrawal_bumps_owed = 1,
       updated_at = clock_timestamp()
 WHERE singleton
   AND desired_generation > 0
   AND EXISTS (SELECT 1 FROM withdrawn_signer_artifacts);

-- The same rollout window has a second hole: a pre-0052 replica serving
-- between migration-apply and binary-replace can commit a rotate_signer
-- (its route only rewrites the apps row) with no withdrawal rows, no jti
-- consumption, and no generation intent -- the rotated-out signer would
-- stay authorized in Trustee indefinitely and silently.  The fence for
-- identity writers therefore lives in the shared database, not in either
-- binary: this AFTER UPDATE trigger fires inside EVERY apps signer-identity
-- change -- the pre-0052 route, the post-0052 route, or manual SQL -- and
-- (1) withdraws the retained artifacts signed under the rotated-out
-- identity, (2) carries the new identity into kbs_tls_bindings (the legacy
-- Rego render source, so an unsigned install stops admitting the old
-- signer at the next render too), and (3) owes one deferred withdrawal
-- bump while signed-policy mode is active.  rotate_signer is the sole
-- identity-change surface: generic deploy metadata only fills identity
-- when (subject, issuer) is (NULL, NULL) and rejects mismatches, so the
-- initial-set path (old identity NULL) matches no artifact and owes
-- nothing.  A rollback to a withdrawn artifact stays refused by the
-- selector -- fail-closed is intentional for a rotated-out signer.
--
-- Scope note, honestly stated: this trigger fences SIGNER-IDENTITY writers,
-- the #119 revocation channel.  The other desired_generation writers
-- (signed deploy accept, unlock, rollback, app delete) still bump
-- desired_generation directly in both binaries, and a pre-0052 replica
-- committing one of those after the post-0052 reconciler consumed its debt
-- could publish an unfiltered set at the bumped generation and wedge the
-- new binary.  That sequence requires two API binaries alive at once after
-- the new reconciler ran; deploy/api/deployment.yaml uses strategy Recreate
-- and the drain runbook requires draining old API pods before the new
-- binary, so the overlap window is the migration step alone -- inside which
-- the migration's own debt (owed >= 1) is still unconsumed and forces the
-- new reconciler's first publication strictly ahead of anything the old
-- replica wrote.  The drain contract, not this trigger, is the fence for
-- those writers.
CREATE FUNCTION enforce_signer_rotation_withdrawal() RETURNS trigger
AS $$
BEGIN
    UPDATE kbs_tls_bindings
       SET signer_identity_subject = NEW.signer_identity_subject,
           signer_identity_issuer  = NEW.signer_identity_issuer,
           updated_at              = now()
     WHERE app_id = NEW.id;

    INSERT INTO withdrawn_signer_artifacts (
        descriptor_core_hash, app_id
    )
    SELECT artifact.descriptor_core_hash, artifact.app_id
      FROM workload_artifacts AS artifact
     WHERE artifact.app_id = NEW.id
       AND artifact.descriptor_payload -> 'signer_identity' ->> 'subject'
           = OLD.signer_identity_subject
       AND artifact.descriptor_payload -> 'signer_identity' ->> 'issuer'
           = OLD.signer_identity_issuer
    ON CONFLICT DO NOTHING;

    UPDATE kbs_signed_policy_reconciliation
       SET withdrawal_bumps_owed = withdrawal_bumps_owed + 1,
           updated_at = clock_timestamp()
     WHERE singleton
       AND desired_generation > 0;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER apps_signer_rotation_withdrawal
    AFTER UPDATE OF signer_identity_subject, signer_identity_issuer ON apps
    FOR EACH ROW
    WHEN (
        OLD.signer_identity_subject IS NOT NULL
        AND OLD.signer_identity_issuer IS NOT NULL
        AND (
             OLD.signer_identity_subject IS DISTINCT FROM NEW.signer_identity_subject
             OR OLD.signer_identity_issuer IS DISTINCT FROM NEW.signer_identity_issuer
        )
    )
    EXECUTE FUNCTION enforce_signer_rotation_withdrawal();
