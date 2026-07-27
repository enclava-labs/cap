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
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO cap_runtime_authority (singleton)
VALUES (true);

COMMENT ON TABLE cap_runtime_authority IS
    'Database-lifetime authority identity for generation metadata retained in external runtime objects.';
