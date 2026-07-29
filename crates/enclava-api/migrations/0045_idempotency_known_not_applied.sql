ALTER TABLE cap_internal_idempotency
    ADD COLUMN known_not_applied boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT cap_internal_idempotency_known_not_applied_check
        CHECK (
            NOT known_not_applied
            OR (
                completed_at IS NULL
                AND response_status IS NULL
                AND response_body IS NULL
                AND reservation_token IS NOT NULL
                AND operation_id IS NOT NULL
                AND lease_expires_at IS NOT NULL
            )
        );

COMMENT ON COLUMN cap_internal_idempotency.known_not_applied IS
    'The current reservation ended before applying an effect and may be reclaimed by the exact bound request under any recovery policy.';
