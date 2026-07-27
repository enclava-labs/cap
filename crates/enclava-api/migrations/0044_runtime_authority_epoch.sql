-- Kubernetes objects can outlive the Postgres authority that assigned their
-- monotonic mutation generations. A retained generation is comparable only
-- inside the database lifetime that issued it. This epoch lets a freshly
-- initialized or restored authority replace retained runtime metadata instead
-- of treating an unrelated higher integer as newer intent forever.
CREATE TABLE cap_runtime_authority (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    authority_epoch uuid NOT NULL DEFAULT gen_random_uuid()
        CHECK (
            authority_epoch
                <> '00000000-0000-0000-0000-000000000000'::uuid
        ),
    -- This value is supplied from deployment state that is not part of a
    -- database backup. It must increase before restoring a backup. Startup
    -- rotates authority_epoch when the configured value advances and refuses
    -- to run when GitOps attempts to move it backwards.
    restore_generation bigint NOT NULL DEFAULT 0
        CHECK (restore_generation >= 0),
    epoch_established_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO cap_runtime_authority (singleton)
VALUES (true);

COMMENT ON TABLE cap_runtime_authority IS
    'Database-lifetime authority identity for generation metadata retained in external runtime objects.';

COMMENT ON COLUMN cap_runtime_authority.restore_generation IS
    'Out-of-database monotonic restore incarnation; increment in deployment state before every database restore.';
