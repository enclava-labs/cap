-- Crash-safe ownership and route-specific recovery metadata for the PaaS
-- internal idempotency ledger.  Existing rows remain readable during a
-- rolling upgrade; new handlers claim them before completing a response.

ALTER TABLE cap_internal_idempotency
    ADD COLUMN reservation_token uuid,
    ADD COLUMN operation_id uuid,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN recovery_kind text,
    ADD COLUMN attempt_count integer NOT NULL DEFAULT 0;

ALTER TABLE cap_internal_idempotency
    ADD CONSTRAINT cap_internal_idempotency_recovery_kind_check
        CHECK (
            recovery_kind IS NULL
            OR recovery_kind IN (
                'retry_safe',
                'deterministic_resource',
                'expiring_capability',
                'fail_closed'
            )
        ),
    ADD CONSTRAINT cap_internal_idempotency_attempt_count_check
        CHECK (attempt_count >= 0),
    ADD CONSTRAINT cap_internal_idempotency_operation_owner_check
        CHECK (reservation_token IS NULL OR operation_id IS NOT NULL);

CREATE INDEX idx_cap_internal_idempotency_incomplete_lease
    ON cap_internal_idempotency (lease_expires_at, updated_at)
    WHERE completed_at IS NULL;

-- Preprod can contain abandoned pre-lease rows whose upstream outbox work no
-- longer exists.  They cannot be recovered safely without route-specific
-- identity, and no future retry is guaranteed to visit them.  Close only rows
-- that predate this ownership model and have been quiet beyond the same
-- 30-minute legacy grace period used by the API.  The response is deliberately
-- bounded: it contains no key, path, hash, or request payload.  A random UUID
-- fences any pre-upgrade handler that later wakes up; terminal rows never use
-- operation_id for resource adoption.
WITH stale_legacy AS MATERIALIZED (
    SELECT idempotency_key,
           gen_random_uuid() AS terminal_token
     FROM cap_internal_idempotency
     WHERE completed_at IS NULL
       AND reservation_token IS NULL
       AND operation_id IS NULL
       AND recovery_kind IS NULL
       AND updated_at <= clock_timestamp() - interval '30 minutes'
     FOR UPDATE
)
UPDATE cap_internal_idempotency AS ledger
   SET reservation_token = stale_legacy.terminal_token,
       operation_id = stale_legacy.terminal_token,
       lease_expires_at = NULL,
       recovery_kind = 'fail_closed',
       response_status = 409,
       response_body = jsonb_build_object(
           'error', 'idempotency_recovery_required',
           'retryable', false,
           'disposition', 'reconcile_then_retry_with_new_key'
       ),
       completed_at = clock_timestamp(),
       updated_at = clock_timestamp(),
       attempt_count = attempt_count + 1
  FROM stale_legacy
 WHERE ledger.idempotency_key = stale_legacy.idempotency_key;

-- A pre-upgrade handler completes by idempotency key alone.  Once a new
-- handler has claimed a row, reject that stale write at the database boundary
-- unless the connection proves the current reservation token.  Legacy rows
-- with no token remain writable by old handlers until they are reclaimed.
CREATE FUNCTION enforce_cap_internal_idempotency_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    configured_token text;
BEGIN
    IF OLD.reservation_token IS NOT NULL
       AND (
           NEW.response_status IS DISTINCT FROM OLD.response_status
           OR NEW.response_body IS DISTINCT FROM OLD.response_body
           OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
       )
    THEN
        configured_token := current_setting(
            'enclava.idempotency_reservation_token',
            true
        );
        IF configured_token IS NULL
           OR configured_token <> OLD.reservation_token::text
        THEN
            RAISE EXCEPTION 'idempotency reservation owner changed'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER cap_internal_idempotency_owner_guard
BEFORE UPDATE OF response_status, response_body, completed_at
ON cap_internal_idempotency
FOR EACH ROW
EXECUTE FUNCTION enforce_cap_internal_idempotency_owner();

COMMENT ON COLUMN cap_internal_idempotency.operation_id IS
    'Stable request-derived identity used to adopt an exact resource after response loss; migration terminal tombstones use their fencing token instead.';
COMMENT ON COLUMN cap_internal_idempotency.reservation_token IS
    'Current completion owner; response writes are compare-and-swap guarded.';
COMMENT ON COLUMN cap_internal_idempotency.lease_expires_at IS
    'PostgreSQL-authored recovery deadline, renewed by the current handler while it owns the reservation.';
