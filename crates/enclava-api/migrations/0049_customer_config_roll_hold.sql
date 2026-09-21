-- A template redeploy can roll the workload before the CLI finishes writing
-- customer config into the still-running TEE. PaaS never stores those values,
-- so the apply job stays in setup_pending until an explicit release. An
-- expired hold fails the deployment without applying, leaving the previous
-- workload in place.

DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT con.conname
      INTO constraint_name
      FROM pg_constraint AS con
      JOIN pg_class AS rel ON rel.oid = con.conrelid
     WHERE rel.relname = 'deployment_apply_jobs'
       AND con.contype = 'c'
       AND pg_get_constraintdef(con.oid) ILIKE '%deployment_superseded%';
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'deployment_apply_jobs last_error_code check not found';
    END IF;
    EXECUTE format(
        'ALTER TABLE deployment_apply_jobs DROP CONSTRAINT %I',
        constraint_name
    );
END $$;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check
    CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_superseded',
            'customer_config_hold_expired'
        )
    );

ALTER TABLE deployment_apply_jobs
    ADD COLUMN customer_config_hold boolean NOT NULL DEFAULT false,
    ADD COLUMN customer_config_hold_until timestamptz,
    ADD COLUMN customer_config_released_at timestamptz,
    ADD CONSTRAINT deployment_apply_jobs_customer_config_hold_check
        CHECK (
            (
                NOT customer_config_hold
                AND customer_config_hold_until IS NULL
                AND customer_config_released_at IS NULL
            )
            OR (
                customer_config_hold
                AND customer_config_hold_until IS NOT NULL
            )
        );

CREATE INDEX idx_deployment_apply_jobs_customer_config_hold
    ON deployment_apply_jobs (customer_config_hold_until)
    WHERE customer_config_hold
      AND customer_config_released_at IS NULL
      AND state = 'setup_pending';
