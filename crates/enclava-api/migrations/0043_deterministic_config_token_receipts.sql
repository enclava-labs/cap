-- Replay PaaS config capabilities without persisting bearer tokens or TEE
-- endpoint metadata. The durable receipt consists only of the existing
-- request-derived operation_id, DB-authored created_at, and completed_at.

ALTER TABLE cap_internal_idempotency
    ADD COLUMN capability_receipt_version smallint,
    ADD COLUMN capability_resource_id uuid,
    ADD COLUMN capability_instance_id text;

ALTER TABLE cap_internal_idempotency
    DROP CONSTRAINT cap_internal_idempotency_recovery_kind_check,
    ADD CONSTRAINT cap_internal_idempotency_recovery_kind_check
        CHECK (
            recovery_kind IS NULL
            OR recovery_kind IN (
                'retry_safe',
                'deterministic_resource',
                'expiring_capability',
                'deterministic_expiring_capability',
                'fail_closed'
            )
        ),
    ADD CONSTRAINT cap_internal_idempotency_config_token_receipt_binding_check
        CHECK (
            recovery_kind IS DISTINCT FROM 'deterministic_expiring_capability'
            OR (
                capability_receipt_version = 1
                AND capability_resource_id IS NOT NULL
                AND capability_instance_id IS NOT NULL
                AND capability_instance_id <> ''
            )
        ),
    ADD CONSTRAINT cap_internal_idempotency_config_token_receipt_body_check
        CHECK (
            recovery_kind IS DISTINCT FROM 'deterministic_expiring_capability'
            OR response_body IS NULL
            OR (
                response_status = 409
                -- JSONB equality fixes the complete key set and value types.
                -- The timestamp values are the exact DB-authored whole-second
                -- UTC RFC3339 receipt times, so neither field is an arbitrary
                -- bearer sink.
                AND response_body = jsonb_build_object(
                    'error', 'idempotency_capability_expired',
                    'retryable', false,
                    'disposition', 'new_key_after_expiry',
                    'proof_version', 'deterministic_config_token_receipt_v1',
                    'capability_issued_at', to_char(
                        date_trunc('second', created_at) AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                    ),
                    'capability_expires_at', to_char(
                        (
                            date_trunc('second', created_at)
                            + interval '5 minutes'
                        ) AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                    )
                )
            )
        ),
    ADD CONSTRAINT cap_internal_idempotency_config_token_no_success_body_check
        CHECK (
            method <> 'POST'
            OR NOT (
                path ~ '^/internal/paas/orgs/[^/]+/apps/[^/]+/config-token$'
                OR path ~ '^/internal/paas/orgs/[^/]+/deployments/[0-9a-fA-F-]+/config-token$'
            )
            OR response_status IS NULL
            OR response_status NOT BETWEEN 200 AND 299
        ) NOT VALID;

-- Migration 0041 replaced pre-receipt capability responses with safe bounded
-- tombstones. Enrich only the two config-token route families with a
-- conservative DB-authored recovery proof. This timestamp is the old
-- six-minute lease deadline, not the signed five-minute JWT expiry.
LOCK TABLE cap_internal_idempotency IN ACCESS EXCLUSIVE MODE;
ALTER TABLE cap_internal_idempotency
    DISABLE TRIGGER cap_internal_idempotency_owner_guard;

UPDATE cap_internal_idempotency
   SET response_status = 409,
       response_body = jsonb_build_object(
           'error', 'idempotency_capability_expired',
           'retryable', false,
           'disposition', 'new_key_after_expiry',
           'proof_version', 'legacy_expiring_capability_lease_v1',
           'recovery_after', GREATEST(
               COALESCE(
                   lease_expires_at,
                   date_trunc('second', created_at) + interval '6 minutes'
               ),
               date_trunc('second', created_at) + interval '6 minutes'
           )
       ),
       updated_at = clock_timestamp()
 WHERE (recovery_kind IS NULL OR recovery_kind = 'expiring_capability')
   AND completed_at IS NOT NULL
   AND method = 'POST'
   AND (
       response_status BETWEEN 200 AND 299
       OR response_body->>'error' = 'idempotency_recovery_required'
   )
   AND (
       path ~ '^/internal/paas/orgs/[^/]+/apps/[^/]+/config-token$'
       OR path ~ '^/internal/paas/orgs/[^/]+/deployments/[0-9a-fA-F-]+/config-token$'
   );

ALTER TABLE cap_internal_idempotency
    VALIDATE CONSTRAINT cap_internal_idempotency_config_token_no_success_body_check;

ALTER TABLE cap_internal_idempotency
    ENABLE TRIGGER cap_internal_idempotency_owner_guard;

COMMENT ON CONSTRAINT cap_internal_idempotency_config_token_receipt_body_check
    ON cap_internal_idempotency IS
    'Deterministic config-token receipts never persist a successful bearer or TEE endpoint response; only non-2xx terminal proof bodies are allowed.';
