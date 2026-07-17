-- Durable handoff between deployment acceptance and manifest application.
--
-- A deployment and its immutable apply payload are committed together.  The
-- API process claims work with a renewable lease, so a process exit at any
-- point after commit leaves work that another process can safely reclaim.
-- Block old replicas from inserting or advancing deployments between the
-- compatibility preflight and deferred-trigger installation.
LOCK TABLE deployments IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workload_artifacts IN SHARE ROW EXCLUSIVE MODE;

-- One signed artifact row is authoritative for an app deployment. Refuse to
-- guess which pre-existing duplicate is correct; operators must reconcile it
-- before retrying this migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM workload_artifacts
         GROUP BY app_id, deploy_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'workload_artifacts contains duplicate (app_id, deploy_id) bindings';
    END IF;
END
$$;

ALTER TABLE workload_artifacts
    ADD CONSTRAINT workload_artifacts_app_deploy_unique UNIQUE (app_id, deploy_id);

CREATE TABLE deployment_apply_jobs (
    deployment_id uuid PRIMARY KEY REFERENCES deployments(id) ON DELETE CASCADE,
    payload       jsonb NOT NULL,
    state         text NOT NULL
                  CHECK (state IN (
                      'setting_up', 'cleanup_pending', 'cleaning_up',
                      'pending', 'running', 'completed', 'failed'
                  )),
    lock_token    uuid,
    locked_until  timestamptz,
    attempts      integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error_code text CHECK (
        last_error_code IS NULL
        OR last_error_code IN ('deployment_setup_failed', 'deployment_apply_failed')
    ),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK ((lock_token IS NULL) = (locked_until IS NULL)),
    CHECK (
        (state IN ('setting_up', 'cleaning_up', 'running') AND lock_token IS NOT NULL)
        OR (
            state IN ('cleanup_pending', 'pending', 'completed', 'failed')
            AND lock_token IS NULL
        )
    )
);

CREATE INDEX idx_deployment_apply_jobs_dispatch
    ON deployment_apply_jobs (state, next_attempt_at, locked_until, created_at)
    WHERE state IN (
        'setting_up', 'cleanup_pending', 'cleaning_up', 'pending', 'running'
    );

-- An immutable apply payload cannot be reconstructed safely from a deployment
-- row. Fail the migration rather than silently backfilling incomplete work.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM deployments AS deployment
         WHERE deployment.status IN ('pending', 'applying', 'watching')
           AND NOT EXISTS (
               SELECT 1
                 FROM deployment_apply_jobs AS job
                WHERE job.deployment_id = deployment.id
           )
    ) THEN
        RAISE EXCEPTION
            'nonterminal deployments without durable apply jobs must be reconciled';
    END IF;
END
$$;

CREATE FUNCTION require_nonterminal_deployment_apply_job()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Read the canonical row at deferred execution time. This permits a row
    -- inserted pending and terminalized in one transaction without a job.
    IF EXISTS (
        SELECT 1
          FROM deployments AS deployment
         WHERE deployment.id = NEW.id
           AND deployment.status IN ('pending', 'applying', 'watching')
           AND NOT EXISTS (
               SELECT 1
                 FROM deployment_apply_jobs AS job
                WHERE job.deployment_id = deployment.id
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'nonterminal deployment requires a durable apply job';
    END IF;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER deployments_require_apply_job
AFTER INSERT OR UPDATE OF status ON deployments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION require_nonterminal_deployment_apply_job();
