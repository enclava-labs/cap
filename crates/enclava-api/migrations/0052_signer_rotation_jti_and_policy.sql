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
-- replacement. Withdraw the previous identity and update the legacy binding
-- in the same transaction; initial identity assignment owes no revocation.
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
