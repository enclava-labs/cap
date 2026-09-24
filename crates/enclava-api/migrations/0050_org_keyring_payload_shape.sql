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
-- generation desired_generation + selector_bumps_owed while leaving
-- desired_generation itself untouched, and only after that replace
-- succeeded does consume_deferred_selector_bumps
-- (crates/enclava-api/src/kbs.rs) commit the increment, guarded by a
-- compare-and-set on the exact (desired_generation, selector_bumps_owed)
-- pair the run published at.  A keyring write that lands mid-run changes
-- the pair, fails the CAS, and makes the next attempt republish at the
-- strictly higher generation with a fresh candidate set, so a candidate set
-- that went stale mid-run is never recorded as the final state of a
-- generation.
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
