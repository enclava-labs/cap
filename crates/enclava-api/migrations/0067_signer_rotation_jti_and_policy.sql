-- Lock apps before acquiring the artifact FK lock to preserve writer ordering.
-- Hold through backfill and trigger installation so queued old writers cannot
-- escape both revocation mechanisms.
LOCK TABLE apps IN SHARE ROW EXCLUSIVE MODE;

-- Consume each signer-rotation token inside the identity-change transaction.
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

-- Previously rotated identities must also lose their retained artifacts.
-- Missing signer_identity objects remain outside this backfill.
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
-- signer-withdrawal-specific debt that only the post-0052 reconciler -- the
-- one refusing withdrawn_signer_artifacts hashes in
-- load_signed_policy_candidates -- may interpret.  It is deliberately NOT
-- the selector_bumps_owed counter from the open keyring-membership change
-- (#130): a 178-era reconciler filtering by keyring membership but not by
-- signer withdrawal would consume a shared marker with a
-- withdrawal-unaware selector and hit the same conflict.  The reconciler
-- publishes the filtered candidate set as generation
-- desired_generation + withdrawal_bumps_owed while leaving
-- desired_generation untouched, and only after that ConfigMap replace
-- succeeded does consume_deferred_withdrawal_bumps
-- (crates/enclava-api/src/kbs.rs) commit the increment, guarded by a
-- compare-and-set on the exact (desired_generation,
-- withdrawal_bumps_owed) pair the run published at.  A rotation landing
-- mid-run changes the pair, fails the CAS, and makes the next attempt
-- republish at the strictly higher generation with a fresh candidate set.
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
-- Rotations that committed before this migration also left the legacy Rego
-- render source stale: kbs_tls_bindings still holds the rotated-out signer,
-- and reconcile_legacy_rego_policy_with_client keeps authorizing the old
-- identity from that row. Align every live binding with the app's committed
-- identity here; the trigger below keeps future writers in step. Bindings
-- created by unsigned deployments (NULL signer) of an app that has since
-- received its initial identity are repaired by the same statement.
UPDATE kbs_tls_bindings AS binding
   SET signer_identity_subject = app.signer_identity_subject,
       signer_identity_issuer  = app.signer_identity_issuer,
       updated_at              = now()
  FROM apps AS app
 WHERE app.id = binding.app_id
   AND binding.deleted_at IS NULL
   AND (
        binding.signer_identity_subject IS DISTINCT FROM app.signer_identity_subject
        OR binding.signer_identity_issuer  IS DISTINCT FROM app.signer_identity_issuer
   );

-- Do not bump desired_generation during migration: an old API could publish
-- its unfiltered body at that generation before the new selector starts.
-- Keep withdrawal debt distinct from the keyring-membership debt in 0058,
-- since a binary must understand each filter before consuming its counter.
-- The new reconciler publishes at desired + selector debt + withdrawal debt,
-- then commits both counters with a single CAS on the observed triple.
-- A writer changing either counter during publication forces a fresh retry.
-- Unsigned installations must remain unsigned, even when artifacts are empty.
ALTER TABLE kbs_signed_policy_reconciliation
    ADD COLUMN withdrawal_bumps_owed bigint NOT NULL DEFAULT 0
        CHECK (withdrawal_bumps_owed >= 0);

UPDATE kbs_signed_policy_reconciliation
   SET withdrawal_bumps_owed = 1,
       updated_at = clock_timestamp()
 WHERE singleton
   AND desired_generation > 0
   AND EXISTS (SELECT 1 FROM withdrawn_signer_artifacts);

-- Database enforcement covers old API writers between migration and binary
-- replacement. Carry the committed identity into the legacy binding and
-- withdraw the previous identity in the same transaction. Revocation is owed
-- only when an old identity existed: the initial set (NULL -> identity)
-- changes the binding but withdraws nothing and bumps nothing, since no
-- artifact can be signed under a missing identity.
--
-- This fences identity/keyring revocations, not every generation writer.
-- Deploy, unlock, rollback and app-delete paths can still bump generations
-- directly. Preserve Recreate ordering: drain old APIs before starting the
-- new reconciler, rather than running both binary versions concurrently.
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
       AND OLD.signer_identity_subject IS NOT NULL
       AND OLD.signer_identity_issuer  IS NOT NULL
       AND artifact.descriptor_payload -> 'signer_identity' ->> 'subject'
           = OLD.signer_identity_subject
       AND artifact.descriptor_payload -> 'signer_identity' ->> 'issuer'
           = OLD.signer_identity_issuer
    ON CONFLICT DO NOTHING;

    UPDATE kbs_signed_policy_reconciliation
       SET withdrawal_bumps_owed = withdrawal_bumps_owed + 1,
           updated_at = clock_timestamp()
     WHERE singleton
       AND desired_generation > 0
       AND OLD.signer_identity_subject IS NOT NULL
       AND OLD.signer_identity_issuer  IS NOT NULL;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER apps_signer_rotation_withdrawal
    AFTER UPDATE OF signer_identity_subject, signer_identity_issuer ON apps
    FOR EACH ROW
    WHEN (
        OLD.signer_identity_subject IS DISTINCT FROM NEW.signer_identity_subject
        OR OLD.signer_identity_issuer IS DISTINCT FROM NEW.signer_identity_issuer
    )
    EXECUTE FUNCTION enforce_signer_rotation_withdrawal();
