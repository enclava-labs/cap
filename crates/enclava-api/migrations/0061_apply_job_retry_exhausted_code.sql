-- #231: terminalize requeue-without-terminal exhaustion.
--
-- The apply-job requeue loop now publishes a terminal failure once a job's
-- retries outlive every legitimate retry window (rollout budget + grace for
-- nonterminal observations, the contention horizon for transient errors).
-- Persist that exhaustion with its own bounded, operator-visible
-- classification so the job row carries why it stopped retrying. Widens the
-- 0060 constraint in place; every previously legal value stays legal.
ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT deployment_apply_jobs_last_error_code_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_superseded',
            'customer_config_hold_expired',
            'deployment_retry_exhausted'
        )
    );
