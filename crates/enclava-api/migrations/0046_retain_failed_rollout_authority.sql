-- Failed-rollout cleanup is the sole authority allowed to publish the pending
-- KBS revocation (when its KBS fence is still present) and release its exact
-- retained app/provider mutation subset. Preserve backfilled migration-0045
-- owners indefinitely so generic KBS/edge startup reconcilers cannot reclaim
-- a finite provider fence first.

-- A restore-generation advance retires cleanup jobs from the restored
-- authority with a distinct bounded operator code. Migration 0038's original
-- inline constraint predates runtime authority, so extend it before startup
-- can rotate the first restored generation. DROP+ADD keeps this migration's
-- executable upgrade regression idempotent.
ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT IF EXISTS deployment_apply_jobs_last_error_code_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check
    CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_superseded',
            'runtime_authority_rotated'
        )
    );

UPDATE app_mutation_leases AS mutation
   SET reclaim_after = 'infinity'::timestamptz,
       updated_at = clock_timestamp()
  FROM deployment_apply_jobs AS job
 WHERE job.state IN ('rollout_cleanup_pending', 'rollout_cleaning_up')
   AND mutation.app_id = job.app_id
   AND mutation.operation_kind = 'deployment_apply'
   AND mutation.operation_id = job.deployment_id
   AND mutation.owner_token IS NOT NULL;

UPDATE external_resource_mutation_leases AS resource
   SET reclaim_after = 'infinity'::timestamptz,
       updated_at = clock_timestamp()
  FROM deployment_apply_jobs AS job,
       app_mutation_leases AS mutation
 WHERE job.state IN ('rollout_cleanup_pending', 'rollout_cleaning_up')
   AND mutation.app_id = job.app_id
   AND mutation.operation_kind = 'deployment_apply'
   AND mutation.operation_id = job.deployment_id
   AND mutation.owner_token IS NOT NULL
   AND resource.owner_token = mutation.owner_token
   AND resource.operation_kind = mutation.operation_kind
   AND resource.operation_id = mutation.operation_id;
