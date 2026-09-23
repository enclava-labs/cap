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
-- Instead record the owed bump as a pending marker that only the post-0049
-- implementation interprets: consume_deferred_selector_bump
-- (crates/enclava-api/src/kbs.rs) performs the actual desired_generation
-- increment at the start of a reconciliation run held under the global KBS
-- mutation fence and converges the filtered candidate set within that same
-- fenced run.  A pre-0049 reconciler therefore never sees the owed
-- generation as a raw desired generation: it keeps finding an unchanged
-- generation whose unfiltered hash matches the published body and stays
-- quiescent, and once the bumped generation is published its content-bound
-- generation annotation turns any late unfiltered republication into a
-- same-generation conflict.  Unsigned-only installs (desired_generation = 0)
-- are not marked, matching enqueue_signed_policy_reconciliation_if_active;
-- the marker invariant is selector_bump_pending => desired_generation > 0.
ALTER TABLE kbs_signed_policy_reconciliation
    ADD COLUMN selector_bump_pending boolean NOT NULL DEFAULT false;

UPDATE kbs_signed_policy_reconciliation
   SET selector_bump_pending = true,
       updated_at = clock_timestamp()
 WHERE singleton
   AND desired_generation > 0;
