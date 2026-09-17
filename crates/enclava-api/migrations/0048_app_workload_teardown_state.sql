-- Persist whether confidential teardown is required across the deleting
-- phase, and when a successful TEE teardown last completed. Retries must
-- not infer either fact from status='deleting' after later cleanup steps.
ALTER TABLE apps
    ADD COLUMN workload_teardown_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN workload_teardown_completed_at TIMESTAMPTZ;

-- Only running apps gain a teardown requirement. Rows already in
-- 'deleting' started under pre-0048 best-effort semantics: their teardown
-- may have run (or their workload may already be gone), it cannot be
-- verified retroactively, and the attestation-proxy teardown endpoint is
-- not idempotent — requiring a fresh call would wedge those deletes at 502
-- forever. Not-required reproduces the old retry convergence.
UPDATE apps
   SET workload_teardown_required = true
 WHERE status = 'running';
