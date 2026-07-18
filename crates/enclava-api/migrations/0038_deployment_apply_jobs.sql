-- Durable handoff between deployment acceptance and manifest application.
--
-- The job row is the canonical immutable apply snapshot. A deployment, its
-- accepted app/runtime payload, and its relational identity/artifact bindings
-- are committed together. Workers use renewable database leases, so a process
-- exit after commit leaves work that another process can safely reclaim.
--
-- Rolling upgrade contract: consumers must understand payload N and N-1
-- before producers emit N. Claims filter on relational payload_version, so a
-- future payload remains recoverable and unmodified until compatible workers
-- are deployed; it is never guessed at or terminalized by an older worker.
--
-- Block old replicas from inserting or advancing deployments between the
-- compatibility preflight and deferred-trigger installation.
LOCK TABLE deployments IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE workload_artifacts IN SHARE ROW EXCLUSIVE MODE;

-- Composite identities let every job and artifact bind app/org ownership with
-- a real foreign key instead of trusting duplicated JSON identifiers.
ALTER TABLE deployments
    ADD CONSTRAINT deployments_id_app_org_unique UNIQUE (id, app_id, org_id),
    ADD CONSTRAINT deployments_id_app_unique UNIQUE (id, app_id);

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

    IF EXISTS (
        SELECT 1
          FROM workload_artifacts AS artifact
          LEFT JOIN deployments AS deployment
            ON deployment.id = artifact.deploy_id
           AND deployment.app_id = artifact.app_id
         WHERE deployment.id IS NULL
    ) THEN
        RAISE EXCEPTION
            'workload_artifacts contains rows without a matching app deployment';
    END IF;
END
$$;

ALTER TABLE workload_artifacts
    ADD CONSTRAINT workload_artifacts_app_deploy_unique
        UNIQUE (app_id, deploy_id),
    ADD CONSTRAINT workload_artifacts_app_deploy_hash_unique
        UNIQUE (app_id, deploy_id, descriptor_core_hash),
    ADD CONSTRAINT workload_artifacts_deploy_hash_unique
        UNIQUE (deploy_id, descriptor_core_hash),
    ADD CONSTRAINT workload_artifacts_deployment_app_fk
        FOREIGN KEY (deploy_id, app_id)
        REFERENCES deployments(id, app_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION reject_workload_artifact_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'workload artifacts are immutable';
END
$$;

CREATE TRIGGER workload_artifacts_are_immutable
BEFORE UPDATE ON workload_artifacts
FOR EACH ROW
EXECUTE FUNCTION reject_workload_artifact_update();

CREATE FUNCTION reject_live_workload_artifact_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- A direct artifact delete must never sever the canonical signed
    -- deployment snapshot. The deployment FK cascade runs after the parent
    -- row is gone, so deployment deletion still removes its artifacts.
    IF EXISTS (
        SELECT 1
          FROM deployments
         WHERE id = OLD.deploy_id
           AND app_id = OLD.app_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'live deployment workload artifacts cannot be deleted';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER live_workload_artifacts_cannot_be_deleted
BEFORE DELETE ON workload_artifacts
FOR EACH ROW
EXECUTE FUNCTION reject_live_workload_artifact_delete();

CREATE TABLE deployment_apply_jobs (
    deployment_id uuid PRIMARY KEY,
    generation    bigint GENERATED ALWAYS AS IDENTITY UNIQUE NOT NULL,
    app_id        uuid NOT NULL,
    org_id        uuid NOT NULL,
    source_deployment_id uuid NOT NULL,
    payload_version integer NOT NULL CHECK (payload_version > 0),
    payload       jsonb NOT NULL,
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    cleanup_app_on_setup_failure boolean NOT NULL,
    signed_required boolean NOT NULL,
    artifact_deployment_id uuid,
    artifact_descriptor_core_hash bytea,
    log_encryption jsonb,
    state         text NOT NULL
                  CHECK (state IN (
                      'setup_pending', 'setting_up',
                      'cleanup_pending', 'cleaning_up',
                      'pending', 'running', 'completed', 'failed'
                  )),
    lock_token    uuid,
    locked_until  timestamptz,
    attempts      integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error_code text CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_superseded'
        )
    ),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT deployment_apply_jobs_deployment_identity_fk
        FOREIGN KEY (deployment_id, app_id, org_id)
        REFERENCES deployments(id, app_id, org_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT deployment_apply_jobs_source_identity_fk
        FOREIGN KEY (source_deployment_id, app_id, org_id)
        REFERENCES deployments(id, app_id, org_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT deployment_apply_jobs_artifact_binding_fk
        FOREIGN KEY (artifact_deployment_id, artifact_descriptor_core_hash)
        REFERENCES workload_artifacts(deploy_id, descriptor_core_hash)
        MATCH FULL
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((lock_token IS NULL) = (locked_until IS NULL)),
    CHECK (
        (state IN ('setting_up', 'cleaning_up', 'running') AND lock_token IS NOT NULL)
        OR (
            state IN (
                'setup_pending', 'cleanup_pending', 'pending', 'completed', 'failed'
            )
            AND lock_token IS NULL
        )
    ),
    CHECK (
        cleanup_app_on_setup_failure
        OR state NOT IN ('cleanup_pending', 'cleaning_up')
    ),
    CHECK (
        NOT signed_required
        OR artifact_deployment_id IS NOT NULL
    ),
    CHECK (
        artifact_deployment_id IS NULL
        OR artifact_deployment_id = source_deployment_id
    ),
    CHECK (
        (payload->>'version')::integer IS NOT DISTINCT FROM payload_version
    ),
    CHECK (
        payload->'log_encryption' IS NOT DISTINCT FROM
        COALESCE(log_encryption, 'null'::jsonb)
    )
);

CREATE INDEX idx_deployment_apply_jobs_dispatch
    ON deployment_apply_jobs
       (payload_version, state, next_attempt_at, locked_until, created_at)
    WHERE state IN (
        'setup_pending', 'setting_up', 'cleanup_pending', 'cleaning_up',
        'pending', 'running'
    );

CREATE INDEX idx_deployment_apply_jobs_source
    ON deployment_apply_jobs (source_deployment_id);

CREATE INDEX idx_deployment_apply_jobs_app_generation
    ON deployment_apply_jobs (app_id, generation DESC);

CREATE INDEX idx_deployment_apply_jobs_artifact
    ON deployment_apply_jobs
       (artifact_deployment_id, artifact_descriptor_core_hash)
    WHERE artifact_deployment_id IS NOT NULL;

CREATE FUNCTION reject_deployment_apply_job_snapshot_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        OLD.deployment_id,
        OLD.generation,
        OLD.app_id,
        OLD.org_id,
        OLD.source_deployment_id,
        OLD.payload_version,
        OLD.payload,
        OLD.payload_sha256,
        OLD.cleanup_app_on_setup_failure,
        OLD.signed_required,
        OLD.artifact_deployment_id,
        OLD.artifact_descriptor_core_hash,
        OLD.log_encryption
    ) IS DISTINCT FROM ROW(
        NEW.deployment_id,
        NEW.generation,
        NEW.app_id,
        NEW.org_id,
        NEW.source_deployment_id,
        NEW.payload_version,
        NEW.payload,
        NEW.payload_sha256,
        NEW.cleanup_app_on_setup_failure,
        NEW.signed_required,
        NEW.artifact_deployment_id,
        NEW.artifact_descriptor_core_hash,
        NEW.log_encryption
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'deployment apply job snapshot is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER deployment_apply_job_snapshot_is_immutable
BEFORE UPDATE ON deployment_apply_jobs
FOR EACH ROW
EXECUTE FUNCTION reject_deployment_apply_job_snapshot_update();

-- A deployment is itself an immutable accepted/source snapshot. Changing
-- identity, image, signed-artifact selection, or log-encryption metadata would
-- silently render different bytes even if a terminal job were later removed.
-- Setup-state and rollout-status transitions are intentionally still allowed.
CREATE FUNCTION preserve_referenced_deployment_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (
        OLD.app_id IS DISTINCT FROM NEW.app_id
        OR OLD.org_id IS DISTINCT FROM NEW.org_id
        OR OLD.image_digest IS DISTINCT FROM NEW.image_digest
        OR OLD.spec_snapshot->'image' IS DISTINCT FROM NEW.spec_snapshot->'image'
        OR OLD.spec_snapshot->'image_digest' IS DISTINCT FROM NEW.spec_snapshot->'image_digest'
        OR OLD.spec_snapshot->'signed_descriptor_core_hash'
            IS DISTINCT FROM NEW.spec_snapshot->'signed_descriptor_core_hash'
        OR OLD.spec_snapshot->'log_encryption'
            IS DISTINCT FROM NEW.spec_snapshot->'log_encryption'
        OR OLD.spec_snapshot->'workload_security_profile'
            IS DISTINCT FROM NEW.spec_snapshot->'workload_security_profile'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'referenced deployment apply snapshot is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER referenced_deployment_snapshot_is_immutable
BEFORE UPDATE ON deployments
FOR EACH ROW
EXECUTE FUNCTION preserve_referenced_deployment_snapshot();

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
                  AND job.state IN (
                      'setup_pending', 'setting_up', 'pending', 'running'
                  )
           )
    ) THEN
        RAISE EXCEPTION
            'nonterminal deployments without durable apply jobs must be reconciled';
    END IF;
END
$$;

CREATE FUNCTION require_nonterminal_deployment_apply_job_id(target_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    -- Read the canonical row at deferred execution time. This permits a row
    -- inserted pending and terminalized in one transaction without a job, and
    -- permits a parent deployment cascade after the deployment row disappears.
    IF EXISTS (
        SELECT 1
          FROM deployments AS deployment
         WHERE deployment.id = target_id
           AND deployment.status IN ('pending', 'applying', 'watching')
           AND NOT EXISTS (
               SELECT 1
                 FROM deployment_apply_jobs AS job
                WHERE job.deployment_id = deployment.id
                  AND job.state IN (
                      'setup_pending', 'setting_up', 'pending', 'running'
                  )
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'nonterminal deployment requires a durable apply job';
    END IF;
END
$$;

CREATE FUNCTION require_nonterminal_deployment_apply_job()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM require_nonterminal_deployment_apply_job_id(NEW.id);
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER deployments_require_apply_job
AFTER INSERT OR UPDATE OF status ON deployments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION require_nonterminal_deployment_apply_job();

CREATE FUNCTION preserve_job_for_nonterminal_deployment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM require_nonterminal_deployment_apply_job_id(OLD.deployment_id);
    RETURN NULL;
END
$$;

-- Cover the job side too: deleting/re-keying a job may not bypass the
-- deployment-side trigger. A cascaded parent delete is allowed because the
-- canonical deployment no longer exists at deferred execution time.
CREATE CONSTRAINT TRIGGER jobs_preserve_nonterminal_deployment
AFTER DELETE OR UPDATE OF deployment_id, state ON deployment_apply_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION preserve_job_for_nonterminal_deployment();
