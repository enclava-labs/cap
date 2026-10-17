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
-- NULL/empty on rows written before this column existed; compensation
-- then keeps the pre-existing conservative classification.
ALTER TABLE deployments
    ADD COLUMN namespace_fence_generations BIGINT[];

ALTER TABLE deployments
    ADD CONSTRAINT deployments_namespace_fence_generations_positive
    CHECK (namespace_fence_generations IS NULL
           OR 0::bigint < ALL (namespace_fence_generations));
