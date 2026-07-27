-- A terminal rollout failure still has one authoritative side effect left:
-- publish the newly-enqueued KBS revocation and then release the exact
-- deployment mutation fences. Keep that tail as durable job work so a process
-- exit or transient Trustee failure cannot strand an infinite namespace/KBS
-- fence behind a job that already says completed.

ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT IF EXISTS deployment_apply_jobs_state_check,
    DROP CONSTRAINT IF EXISTS deployment_apply_jobs_check1,
    DROP CONSTRAINT IF EXISTS deployment_apply_jobs_lock_state_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_state_check
    CHECK (state IN (
        'setup_pending', 'setting_up',
        'cleanup_pending', 'cleaning_up',
        'pending', 'running',
        'rollout_cleanup_pending', 'rollout_cleaning_up',
        'completed', 'failed'
    )),
    ADD CONSTRAINT deployment_apply_jobs_lock_state_check
    CHECK (
        (
            state IN (
                'setting_up', 'cleaning_up', 'running',
                'rollout_cleaning_up'
            )
            AND lock_token IS NOT NULL
        )
        OR (
            state IN (
                'setup_pending', 'cleanup_pending', 'pending',
                'rollout_cleanup_pending', 'completed', 'failed'
            )
            AND lock_token IS NULL
        )
    );

DROP INDEX idx_deployment_apply_jobs_dispatch;

CREATE INDEX idx_deployment_apply_jobs_dispatch
    ON deployment_apply_jobs
       (payload_version, state, next_attempt_at, locked_until, created_at)
    WHERE state IN (
        'setup_pending', 'setting_up', 'cleanup_pending', 'cleaning_up',
        'pending', 'running',
        'rollout_cleanup_pending', 'rollout_cleaning_up'
    );

-- Recover terminal rollout failures committed by the previous binary between
-- publishing the failed deployment and releasing its retained mutation
-- fences. Apply errors use job.state='failed', so completed+failed identifies
-- the fully observed rollout path whose remaining KBS revocation is safe to
-- retry. A previous binary may already have released only its KBS fence before
-- crashing; cleanup loads and releases that exact retained provider subset,
-- and treats the absent KBS owner as proof that Trustee reconciliation already
-- completed.
UPDATE deployment_apply_jobs AS job
   SET state = 'rollout_cleanup_pending',
       next_attempt_at = clock_timestamp(),
       last_error_code = NULL,
       updated_at = clock_timestamp()
  FROM deployments AS deployment
 WHERE deployment.id = job.deployment_id
   AND deployment.status = 'failed'::deploy_status_enum
   AND job.state = 'completed'
   AND EXISTS (
       SELECT 1
         FROM app_mutation_leases AS mutation
        WHERE mutation.app_id = job.app_id
          AND mutation.operation_kind = 'deployment_apply'
          AND mutation.operation_id = job.deployment_id
          AND mutation.owner_token IS NOT NULL
   );
