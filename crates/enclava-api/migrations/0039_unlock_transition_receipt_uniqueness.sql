-- A transition timestamp is strictly monotonic per app. Enforce the same
-- replay invariant in PostgreSQL so a writer that misses the application-row
-- lock still cannot persist a duplicate receipt concurrently.
DROP INDEX IF EXISTS idx_unlock_transition_receipts_app_timestamp;

CREATE UNIQUE INDEX idx_unlock_transition_receipts_app_timestamp
    ON unlock_transition_receipts(app_id, receipt_timestamp DESC);
