-- Failed-rollout cleanup is the sole authority allowed to publish the pending
-- KBS revocation and release its exact app/provider mutation set. Preserve
-- backfilled migration-0045 owners indefinitely so generic KBS/edge startup
-- reconcilers cannot reclaim a finite provider fence first.

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
