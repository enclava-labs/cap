-- Drain legacy unlock writers before installing the receipt/deployment link.
-- The preprod rollout still uses Recreate so an old binary cannot begin a new
-- request after this migration commits.
LOCK TABLE apps IN ACCESS EXCLUSIVE MODE;
LOCK TABLE unlock_transition_receipts IN ACCESS EXCLUSIVE MODE;

ALTER TABLE unlock_transition_receipts
    ADD COLUMN deployment_id UUID REFERENCES deployments(id);

-- A transition timestamp is strictly monotonic per app. Enforce the same
-- replay invariant in PostgreSQL so a writer that misses the application-row
-- lock still cannot persist a duplicate receipt concurrently.
DROP INDEX IF EXISTS idx_unlock_transition_receipts_app_timestamp;

CREATE UNIQUE INDEX idx_unlock_transition_receipts_app_timestamp
    ON unlock_transition_receipts(app_id, receipt_timestamp DESC);

CREATE UNIQUE INDEX idx_unlock_transition_receipts_deployment
    ON unlock_transition_receipts(deployment_id)
    WHERE deployment_id IS NOT NULL;

-- Existing receipts predate deployment linkage and remain readable. All
-- writes performed by a new (or accidentally surviving old) API binary must
-- link the receipt to the atomic redeployment operation.
CREATE FUNCTION reject_unlinked_unlock_transition_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.deployment_id IS NULL THEN
        RAISE EXCEPTION 'unlock transition receipt requires deployment_id'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER unlock_transition_receipt_requires_deployment
    BEFORE INSERT OR UPDATE OF deployment_id ON unlock_transition_receipts
    FOR EACH ROW
    EXECUTE FUNCTION reject_unlinked_unlock_transition_receipt();
