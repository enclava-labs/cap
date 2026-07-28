-- A restored Postgres authority is not converged until Kubernetes reflects
-- the restored desired workload set. Keep this witness in the restored
-- database so an API process that crashes during reconciliation refuses every
-- later startup until the same restore generation is fully re-applied.

ALTER TABLE cap_runtime_authority
    ADD COLUMN kubernetes_reconciled_restore_generation bigint NOT NULL DEFAULT 0
        CHECK (kubernetes_reconciled_restore_generation >= 0);

-- Installing this migration during an ordinary upgrade is not a database
-- restore. Existing Kubernetes state already belongs to the stored authority,
-- so initialize the witness to the current generation. A later explicit
-- restore-generation advance deliberately leaves this value behind.
UPDATE cap_runtime_authority
   SET kubernetes_reconciled_restore_generation = restore_generation
 WHERE singleton;

ALTER TABLE cap_runtime_authority
    ADD CONSTRAINT cap_runtime_authority_kubernetes_reconciliation_not_ahead
    CHECK (kubernetes_reconciled_restore_generation <= restore_generation);

COMMENT ON COLUMN cap_runtime_authority.kubernetes_reconciled_restore_generation IS
    'Highest restore generation whose desired workloads were re-applied and whose CAP-owned orphan namespaces were removed before API startup';
