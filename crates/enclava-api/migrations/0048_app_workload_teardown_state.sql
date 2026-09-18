-- Persist whether confidential teardown is required across the deleting
-- phase, and when a successful TEE teardown last completed. Retries must
-- not infer either fact from status='deleting' after later cleanup steps.
--
-- No backfill. The delete route records workload_teardown_required from the
-- pre-delete status in the same UPDATE that enters 'deleting', so every
-- delete started by this code sets it for itself. Pre-0048 rows keep the
-- false default: a backfill (of 'running' or 'deleting' rows) would only be
-- read by a new replica retrying a delete that an old replica started under
-- best-effort semantics, where the workload may already be gone and the
-- proxy's non-idempotent teardown endpoint would wedge the retry at 502
-- forever. False reproduces the old retry convergence for those rows.
ALTER TABLE apps
    ADD COLUMN workload_teardown_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN workload_teardown_completed_at TIMESTAMPTZ;
