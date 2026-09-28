-- #130 follow-up: KBS candidate loading parses the latest keyring payload of
-- every org in a single query (load_signed_policy_candidates in
-- crates/enclava-api/src/kbs.rs). Until now the "payloads are always
-- well-formed JSON" invariant was enforced only by the put_keyring /
-- rotate_org_owner handlers; a malformed row inserted by a future backfill
-- script, manual psql fix, or new writer would abort candidate loading for
-- EVERY org simultaneously (reconciler errors, stale policy stays live in
-- Trustee). Enforce the shape at the database level instead: the payload must
-- be a JSON object whose "members" entry is an array -- exactly the shape the
-- selector CTE requires to never raise. Malformed payloads fail the INSERT
-- (the constraint raises on non-UTF-8 or invalid JSON), and the selector
-- itself still fails closed per org through the INNER JOIN.
--
-- Both comparisons are wrapped in IS TRUE: a SQL CHECK treats a NULL result
-- as passing, so a JSON object that omits "members" entirely would otherwise
-- satisfy the constraint (NULL = 'array' evaluates to NULL, which passes a
-- CHECK). IS TRUE makes a missing "members" key an explicit violation.
--
-- Repair pass first (review finding on this PR): the CHECK below evaluates
-- every EXISTING row, and a row whose payload PostgreSQL cannot even parse
-- as jsonb aborts the whole migration.  Such rows are producible by the
-- pre-0058 writers: put_keyring / rotate_org_owner deserialize into
-- SignedOrgKeyring (which ignores unknown fields) but persist the
-- client-supplied payload verbatim, so an extra field carrying a `\u0000`
-- escape -- accepted by serde_json, unrepresentable in jsonb -- could be
-- stored by any binary running before the handler guard added in this PR.
--
-- Take ACCESS EXCLUSIVE on org_keyrings BEFORE inspecting/deleting (review
-- finding): this migration runs in the rollout step while a pre-0058 replica
-- may still be live, and its unguarded writer can INSERT a NUL payload that
-- races this transaction -- a row committed between the DELETE below and
-- ADD CONSTRAINT's scan would abort the migration and stall the rollout.
-- The lock makes concurrent keyring INSERTs (RowExclusive) wait until this
-- transaction commits; they then evaluate against the new CHECK and fail
-- cleanly there, which is the bounded, drain-contract-delimited behavior
-- for old-binary writers.  Keyring reads (the old reconciler's selector)
-- block only for the duration of this migration transaction.
LOCK TABLE org_keyrings IN ACCESS EXCLUSIVE MODE;
--
-- Blast radius rule (follow-up review finding): keyrings retain every
-- version and the selector treats the highest surviving version as the
-- current authority, so deleting ONLY a malformed row could promote an
-- older generation and re-authorize signers that the malformed (but
-- otherwise valid, owner-signed) version had revoked -- e.g. v2 removing
-- Alice while carrying a bad `memo`, whose deletion would make v1
-- (Alice+Bob) current again.  Two cases, then:
--
--   * LATEST version malformed: the org's current authority is
--     untrustworthy and no older version may be promoted over it, so the
--     org loses ALL keyring rows.  That is the fail-closed outcome the
--     selector already guarantees for a missing keyring (INNER JOIN drop),
--     it can never resurrect a revoked signer, and the org recovers by
--     uploading a fresh owner-signed keyring (the version-1 initial-upload
--     path).
--   * Malformed row strictly BELOW a clean current version: deleting just
--     the malformed rows cannot change authority (the clean max version
--     stays current, nothing is promoted), so the live keyring and the
--     audit-retained valid versions are preserved and only the bad rows go.
--
-- A RAISE NOTICE records both cases per org for operators, and every row
-- the repair removes is copied verbatim into org_keyring_repairs (payload,
-- signature, signing key, original created_at) before the DELETE: NOTICEs
-- evaporate with the migration log, while an operator restoring an org
-- whose only keyring was removed needs the exact affected org/version/
-- payload recorded durably (review finding).
--
-- The helper swallows parse errors via an EXCEPTION block because the bare
-- cast would raise, not return false, and SQL does not guarantee OR
-- short-circuit ordering.  Rows that are valid jsonb but the wrong shape
-- are removed by the same predicate.
CREATE FUNCTION org_keyrings_payload_matches_shape(payload bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN (jsonb_typeof(convert_from(payload, 'UTF8')::jsonb) = 'object') IS TRUE
       AND (jsonb_typeof(
            convert_from(payload, 'UTF8')::jsonb -> 'members'
        ) = 'array') IS TRUE;
EXCEPTION
    WHEN OTHERS THEN RETURN false;
END;
$$;

-- Orgs whose CURRENT (highest) version is malformed: nothing may be
-- promoted over a corrupt authority, so these lose every row.  Plain TEMP
-- table with an explicit drop below -- ON COMMIT DROP would vanish
-- immediately under statement-autocommit runners (psql -f), before the
-- DO/DELETE blocks that read it.
CREATE TEMP TABLE org_keyrings_shape_quarantined AS
SELECT org_id,
       max(version) AS latest_version
  FROM org_keyrings
 GROUP BY org_id
HAVING NOT org_keyrings_payload_matches_shape(
    (SELECT keyring_payload FROM org_keyrings k2
      WHERE k2.org_id = org_keyrings.org_id
        AND k2.version = max(org_keyrings.version))
);

DO $$
DECLARE
    affected record;
BEGIN
    FOR affected IN
        SELECT org_id,
               string_agg('v' || version, ', ' ORDER BY version) AS versions,
               bool_or(org_id IN (SELECT org_id FROM org_keyrings_shape_quarantined)) AS quarantined
          FROM org_keyrings
         WHERE NOT org_keyrings_payload_matches_shape(keyring_payload)
            OR org_id IN (SELECT org_id FROM org_keyrings_shape_quarantined)
         GROUP BY org_id
    LOOP
        IF affected.quarantined THEN
            RAISE NOTICE 'migration 0058: malformed CURRENT keyring for org % (versions % present); dropping ALL of this org''s keyring rows -- no older generation may be promoted; the org must upload a fresh owner-signed keyring (originals archived in org_keyring_repairs)',
                affected.org_id, affected.versions;
        ELSE
            RAISE NOTICE 'migration 0058: dropping malformed historical keyring rows for org % (versions %); the clean current version is untouched (dropped originals archived in org_keyring_repairs)',
                affected.org_id, affected.versions;
        END IF;
    END LOOP;
END;
$$;

-- Durable repair record: one row per removed keyring generation, in the
-- exact set the DELETE below removes (same predicate, same snapshot).
-- signing_key_id is deliberately not a foreign key -- this is provenance
-- data for operator restores and must not block user_signing_keys cleanup.
CREATE TABLE org_keyring_repairs (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         bigint NOT NULL,
    keyring_payload bytea NOT NULL,
    signature       bytea NOT NULL,
    signing_key_id  uuid,
    created_at      timestamptz NOT NULL,
    repaired_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version)
);

INSERT INTO org_keyring_repairs
    (org_id, version, keyring_payload, signature, signing_key_id, created_at)
SELECT org_id, version, keyring_payload, signature, signing_key_id, created_at
  FROM org_keyrings
 WHERE org_id IN (SELECT org_id FROM org_keyrings_shape_quarantined)
    OR NOT org_keyrings_payload_matches_shape(keyring_payload);

DELETE FROM org_keyrings
 WHERE org_id IN (SELECT org_id FROM org_keyrings_shape_quarantined)
    OR NOT org_keyrings_payload_matches_shape(keyring_payload);

DROP TABLE org_keyrings_shape_quarantined;

DROP FUNCTION org_keyrings_payload_matches_shape(bytea);

ALTER TABLE org_keyrings
    ADD CONSTRAINT org_keyrings_payload_wellformed CHECK (
        (jsonb_typeof(convert_from(keyring_payload, 'UTF8')::jsonb) = 'object') IS TRUE
        AND (jsonb_typeof(
            convert_from(keyring_payload, 'UTF8')::jsonb -> 'members'
        ) = 'array') IS TRUE
    );

-- #130 rollout safety: load_signed_policy_candidates now filters candidates
-- by current keyring membership, so on any install where a rotated-out
-- signer's artifact was already applied (the exact production state issue
-- #130 fixes), the desired policy hash changes at an UNCHANGED
-- desired_generation.  Startup reconciliation treats that as
-- PolicyGenerationConflict and exits before the API is ready, and no runtime
-- bump can rescue it because no keyring write can reach a refusing API.  A
-- generation bump is owed.
--
-- It must NOT be performed here, though.  With DATABASE_MIGRATION_MODE=verify
-- (deploy/api/deployment.yaml) this migration runs in a rollout step that
-- precedes the new binary while a previous replica is still live: that
-- replica's 30-second reconciler would consume a direct bump using the old,
-- unfiltered candidate query and publish the old policy body at the new
-- generation.  The new binary would then compute the filtered hash at the
-- already-published generation and crash-loop on PolicyGenerationConflict
-- with no bump left to recover.
--
-- The owed bump must ALSO survive keyring writes committed by a pre-0050
-- replica during the rollout itself: put_keyring and rotate_org_owner only
-- take the per-org signing-authority lane, and the old binary enqueues
-- nothing, so a rolling-upgrade replica can still commit a keyring change
-- after the new reconciler loaded its candidate set.  A boolean marker
-- cleared by the reconciler would lose that write's owed bump -- the clear
-- and the late write race on unrelated state -- so the debt is a COUNTER,
-- and the writer's own INSERT re-arms it through a row trigger inside the
-- writer's transaction: the debt is durable across keyring writes from ANY
-- binary.  The reconciler publishes the filtered candidate set as
-- generation desired_generation + selector_bumps_owed (plus any
-- signer-withdrawal debt owed alongside it, migration 0052) while leaving
-- desired_generation itself untouched, and only after that replace
-- succeeded does consume_deferred_policy_debts
-- (crates/enclava-api/src/kbs.rs) commit the increments, guarded by a
-- single compare-and-set on the exact (desired_generation,
-- selector_bumps_owed, withdrawal_bumps_owed) triple the run published
-- at.  Both debt counters are always consumed together -- committing
-- one before the other would advance desired_generation while the
-- other debt still points past it.  A keyring write that lands mid-run
-- moves its counter, fails the CAS, and makes the next attempt republish
-- at the strictly higher generation with a fresh candidate set, so a
-- candidate set that went stale mid-run is never recorded as the final
-- state of a generation.
--
-- A pre-0050 reconciler therefore never sees the owed generation as a raw
-- desired generation.  Before the replace it keeps finding an unchanged
-- generation whose unfiltered hash matches the published body and stays
-- quiescent; between the replace and the commit it finds an annotated
-- generation ahead of its own and treats it as superseded; and after the
-- commit the same content-bound generation annotation turns any late
-- unfiltered republication into a same-generation conflict.  Every crash
-- window lands in one of those three states, so the failure mode above is
-- unreachable.  Unsigned-only installs (desired_generation = 0) are never
-- owed anything -- the trigger mirrors that predicate -- and the debt
-- invariant is selector_bumps_owed > 0 => desired_generation > 0.
--
-- Scope note, honestly stated: this trigger fences KEYRING writers, the
-- #130 revocation channel.  The other desired_generation writers (signed
-- deploy accept, unlock, rollback, app delete) still bump desired_generation
-- directly in both binaries, and a pre-0050 replica committing one of those
-- AFTER the post-0050 reconciler consumed its debt could publish an
-- unfiltered set at the bumped generation and wedge the new binary.  That
-- sequence requires two API binaries alive at once after the new reconciler
-- ran; deploy/api/deployment.yaml uses strategy Recreate and
-- runbooks/paas-config-token-idempotency.md requires draining old API pods
-- before the new binary, so the overlap window is the migration step alone --
-- inside which the migration's own debt (owed >= 1) is still unconsumed and
-- forces the new reconciler's first publication strictly ahead of anything
-- the old replica wrote.  The drain contract, not this trigger, is the
-- fence for those writers.
ALTER TABLE kbs_signed_policy_reconciliation
    ADD COLUMN selector_bumps_owed bigint NOT NULL DEFAULT 0
        CHECK (selector_bumps_owed >= 0);

UPDATE kbs_signed_policy_reconciliation
   SET selector_bumps_owed = 1,
       updated_at = clock_timestamp()
 WHERE singleton
   AND desired_generation > 0;

CREATE FUNCTION owe_selector_bump() RETURNS trigger
AS $$
BEGIN
    UPDATE kbs_signed_policy_reconciliation
       SET selector_bumps_owed = selector_bumps_owed + 1,
           updated_at = clock_timestamp()
     WHERE singleton
       AND desired_generation > 0;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Every org_keyrings INSERT -- put_keyring, rotate_org_owner, whichever
-- binary runs them -- owes one selector generation bump while signed-policy
-- mode is active.  The trigger runs inside the writer's transaction, so the
-- debt commits atomically with the keyring change that caused it.
CREATE TRIGGER org_keyrings_owe_selector_bump
    AFTER INSERT ON org_keyrings
    FOR EACH ROW EXECUTE FUNCTION owe_selector_bump();
