-- Durable namespace-fence provenance for retry-exhaustion compensation
-- (#260 review, rounds 1-2): the APPEND-ONLY set of kubernetes_namespace
-- fence generations claimed by this deployment's apply attempts. Each
-- claiming attempt appends its generation in a dedicated transaction
-- committed BEFORE any provider execution of that attempt, so the record
-- survives provider-call and lease-loss failures and is never replaced by
-- a later attempt that exits before any namespace write (a preflight-only
-- attempt). The exhaustion compensation that runs after the requeue loop
-- exhausts classifies and sweeps the leftover namespace against this set
-- — the generations the failing attempts actually could have stamped —
-- never the fresh generation its reacquired fence carries.
-- Existing active deployments may already have stamped a namespace before
-- provenance recording existed. Later claims cannot recover that history.
-- Keep those jobs retryable instead of exhausting with an incomplete set;
-- new deployments have complete provenance from their first claim onward.
ALTER TABLE deployments
    ADD COLUMN namespace_fence_generations BIGINT[],
    ADD COLUMN namespace_fence_provenance_incomplete BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE deployments
   SET namespace_fence_provenance_incomplete = TRUE
 WHERE status IN ('pending', 'applying', 'watching');

-- Appending a new claim MUST NOT clear the incomplete flag. A legacy job can
-- still complete normally, be superseded, or be deleted; automatic exhaustion
-- cannot safely assume its unrecorded provider state has been compensated.

ALTER TABLE deployments
    ADD CONSTRAINT deployments_namespace_fence_generations_positive
    CHECK (namespace_fence_generations IS NULL
           OR 0::bigint < ALL (namespace_fence_generations));
