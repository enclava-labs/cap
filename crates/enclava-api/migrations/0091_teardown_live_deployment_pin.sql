-- The owned ordinal-0 pod teardown will hit, named by its controller
-- ownerReference and enclava.dev/deployment-id label (#235).
--
-- The deleting selector otherwise keeps only the newest completed job and
-- the newest later publication. That drops an intermediate publication whose
-- pod is still Ready, so the Service can ask that pod to erase its seed
-- without policy authority. One server-written row per app (replicas is 1)
-- admits that named publication without stacking every historical generation
-- into the shared byte budget. Client-supplied labels are not a write path.
CREATE TABLE teardown_live_deployment_pins (
    app_id uuid PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    deployment_id uuid NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
