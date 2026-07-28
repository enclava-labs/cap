-- A deployment worker poisons its Kubernetes namespace fence before the first
-- request because a timed-out request may still complete. If the worker dies,
-- preserve the normal 360-second late-response quarantine measured from its
-- expired mutation lease, but do not leave the exact operation fenced at
-- infinity forever. This covers both terminal failures and retryable durable
-- jobs left behind by an interrupted worker.
UPDATE external_resource_mutation_leases AS resource
   SET reclaim_after = resource.locked_until + interval '360 seconds'
  FROM app_mutation_leases AS app,
       deployment_apply_jobs AS job,
       deployments AS deployment
 WHERE app.operation_kind = 'deployment_apply'
   AND app.operation_id = job.deployment_id
   AND app.owner_token IS NOT NULL
   AND job.app_id = app.app_id
   AND deployment.id = job.deployment_id
   AND deployment.app_id = job.app_id
   AND deployment.org_id = job.org_id
   AND app.locked_until <= clock_timestamp()
   AND (
       (
           job.state IN ('completed', 'failed')
           AND deployment.status = 'failed'::deploy_status_enum
       )
       OR (
           job.state IN ('pending', 'running')
           AND deployment.status IN (
               'pending'::deploy_status_enum,
               'applying'::deploy_status_enum,
               'watching'::deploy_status_enum
           )
           AND (
               job.lock_token IS NULL
               OR job.locked_until <= clock_timestamp()
           )
       )
   )
   AND resource.resource_scope = 'kubernetes_namespace'
   AND resource.owner_token = app.owner_token
   AND resource.operation_kind = app.operation_kind
   AND resource.operation_id = app.operation_id
   AND resource.reclaim_after = 'infinity'::timestamptz;
