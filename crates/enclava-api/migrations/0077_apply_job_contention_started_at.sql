-- Anchor the contention horizon at the first transient apply requeue, not
-- when the deployment was accepted. Existing pending jobs start a fresh
-- horizon on their next contention requeue.
ALTER TABLE deployment_apply_jobs
    ADD COLUMN contention_started_at timestamptz;
