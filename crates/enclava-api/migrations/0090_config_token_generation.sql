-- Config tokens are app-scoped. A superseded deploy's still-valid token can
-- overwrite a later deploy's customer config, including SSH authorized keys,
-- because the TEE only checks instance_id. Persist the apply-job generation
-- the receipt was minted for so replay regenerates the same fenced token and
-- cannot upgrade into a later generation. NULL preserves pre-fence receipts.
ALTER TABLE cap_internal_idempotency
    ADD COLUMN capability_config_generation bigint;

ALTER TABLE cap_internal_idempotency
    ADD CONSTRAINT cap_internal_idempotency_config_generation_nonnegative
        CHECK (
            capability_config_generation IS NULL
            OR capability_config_generation >= 0
        );
