-- Durable desired/applied authority for the global signed Trustee policy.
-- A generation is enqueued in the same transaction that changes deployment
-- authority.  ConfigMap publication and Trustee rollout are then converged
-- independently, so a crash after either external step remains retryable.
CREATE TABLE kbs_signed_policy_reconciliation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    desired_generation bigint NOT NULL CHECK (desired_generation >= 0),
    configmap_generation bigint NOT NULL DEFAULT 0
        CHECK (configmap_generation >= 0),
    applied_generation bigint NOT NULL DEFAULT 0
        CHECK (applied_generation >= 0),
    configmap_policy_sha256 bytea,
    applied_policy_sha256 bytea,
    configmap_resource_version text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (configmap_generation <= desired_generation),
    CHECK (applied_generation <= configmap_generation),
    CHECK (
        (configmap_generation = 0 AND configmap_policy_sha256 IS NULL)
        OR
        (configmap_generation > 0
            AND octet_length(configmap_policy_sha256) = 32)
    ),
    CHECK (
        (applied_generation = 0 AND applied_policy_sha256 IS NULL)
        OR
        (applied_generation > 0
            AND octet_length(applied_policy_sha256) = 32)
    )
);

-- Existing signed artifacts, including pre-0038 healthy deployments without
-- apply-job rows, require one bootstrap reconciliation after this migration.
INSERT INTO kbs_signed_policy_reconciliation (
    singleton,
    desired_generation,
    configmap_generation,
    applied_generation
)
SELECT true,
       CASE WHEN EXISTS (SELECT 1 FROM workload_artifacts) THEN 1 ELSE 0 END,
       0,
       0;

-- Deployment identity is app-scoped authority.  Keep pre-0039 receipts with a
-- NULL deployment_id readable, but require every linked receipt to prove that
-- the deployment belongs to the same app.
ALTER TABLE unlock_transition_receipts
    DROP CONSTRAINT unlock_transition_receipts_deployment_id_fkey,
    ADD CONSTRAINT unlock_transition_receipts_deployment_app_fkey
        FOREIGN KEY (deployment_id, app_id)
        REFERENCES deployments(id, app_id);

-- A receipt is signed historical authority.  Every column, including its row
-- identity and insertion timestamp, is immutable.
CREATE FUNCTION reject_unlock_transition_receipt_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'unlock transition receipts are immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER unlock_transition_receipt_is_immutable
    BEFORE UPDATE ON unlock_transition_receipts
    FOR EACH ROW
    EXECUTE FUNCTION reject_unlock_transition_receipt_update();

-- Direct deletion must not erase signed history.  During an app FK cascade the
-- parent row is already absent, so ordinary app teardown remains possible.
CREATE FUNCTION reject_live_unlock_transition_receipt_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM apps WHERE id = OLD.app_id) THEN
        RAISE EXCEPTION 'live app unlock transition receipts cannot be deleted'
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER live_unlock_transition_receipts_cannot_be_deleted
    BEFORE DELETE ON unlock_transition_receipts
    FOR EACH ROW
    EXECUTE FUNCTION reject_live_unlock_transition_receipt_delete();

-- Pre-0041 binaries persisted successful expiring capability responses.  Take
-- an exclusive lock and temporarily disable only the ownership guard while
-- replacing those exact route-family responses with a bounded disposition.
-- No capability value is inspected, returned, or logged by this migration.
LOCK TABLE cap_internal_idempotency IN ACCESS EXCLUSIVE MODE;
ALTER TABLE cap_internal_idempotency
    DISABLE TRIGGER cap_internal_idempotency_owner_guard;

UPDATE cap_internal_idempotency
   SET response_status = 409,
       response_body = jsonb_build_object(
           'error', 'idempotency_recovery_required',
           'retryable', false,
           'disposition', 'reconcile_then_retry_with_new_key'
       ),
       updated_at = clock_timestamp()
 WHERE completed_at IS NOT NULL
   AND method = 'POST'
   AND response_status BETWEEN 200 AND 299
   AND (
       path ~ '^/internal/paas/orgs/[^/]+/apps/[^/]+/config-token$'
       OR path ~ '^/internal/paas/orgs/[^/]+/apps/[^/]+/signer/rotation-token$'
       OR path ~ '^/internal/paas/orgs/[^/]+/deployments/[0-9a-fA-F-]+/config-token$'
   );

ALTER TABLE cap_internal_idempotency
    ENABLE TRIGGER cap_internal_idempotency_owner_guard;
