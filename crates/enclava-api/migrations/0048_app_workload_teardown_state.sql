-- Persist whether confidential teardown is required across the deleting
-- phase, and when a successful TEE teardown last completed. Retries must
-- not infer either fact from status='deleting' after later cleanup steps.
ALTER TABLE apps
    ADD COLUMN workload_teardown_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN workload_teardown_completed_at TIMESTAMPTZ;

UPDATE apps
   SET workload_teardown_required = true
 WHERE status IN ('running', 'deleting');
