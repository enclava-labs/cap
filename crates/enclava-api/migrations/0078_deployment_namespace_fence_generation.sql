-- Durable namespace-fence provenance for retry-exhaustion compensation
-- (#260 review): the kubernetes_namespace fence generation claimed by this
-- deployment's latest apply attempt. Each claiming attempt records the
-- generation under the authority lane BEFORE any provider write, so the
-- compensation that runs after the requeue loop exhausts can classify and
-- sweep the leftover namespace against the generation the failing attempts
-- actually stamped — not the fresh generation its reacquired fence claims.
-- NULL on rows written before this column existed; compensation then keeps
-- the pre-existing conservative classification.
ALTER TABLE deployments
    ADD COLUMN namespace_fence_generation BIGINT;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_namespace_fence_generation_positive
    CHECK (namespace_fence_generation IS NULL OR namespace_fence_generation > 0);
