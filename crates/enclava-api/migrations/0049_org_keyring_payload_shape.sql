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

-- #130 rollout safety: load_signed_policy_candidates now filters candidates by
-- current keyring membership, so on any install where a rotated-out signer's
-- artifact was already applied (the exact production state issue #130 fixes),
-- the desired policy hash changes at an UNCHANGED desired_generation. Startup
-- reconciliation treats that as PolicyGenerationConflict and exits(1) before
-- the API is ready, and the runtime generation bump in
-- enqueue_signed_policy_reconciliation_if_active can never run because no
-- keyring write can reach the API. Bump the generation here -- same UPDATE the
-- runtime helper uses -- so the first reconcile on the new build treats the
-- filtered candidate set as a new generation and replaces the policy body
-- instead of crash-looping. Unsigned-only installs (desired_generation = 0)
-- stay untouched, matching enqueue_signed_policy_reconciliation_if_active.
UPDATE kbs_signed_policy_reconciliation
   SET desired_generation = desired_generation + 1,
       updated_at = clock_timestamp()
 WHERE singleton
   AND desired_generation > 0;
