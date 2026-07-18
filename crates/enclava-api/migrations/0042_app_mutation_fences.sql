-- A durable, renewable generation fence survives loss of the PostgreSQL
-- connection that owns an advisory app lane. External side effects may only
-- publish success or compensation while their generation/token remains the
-- current owner for the app.
CREATE TABLE app_mutation_leases (
    app_id uuid PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    generation bigint NOT NULL DEFAULT 0,
    owner_token uuid,
    operation_kind text,
    operation_id uuid,
    locked_until timestamptz,
    reclaim_after timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT app_mutation_leases_generation_positive CHECK (generation >= 0),
    CONSTRAINT app_mutation_leases_owner_shape CHECK (
        (owner_token IS NULL
            AND operation_kind IS NULL
            AND operation_id IS NULL
            AND locked_until IS NULL
            AND reclaim_after IS NULL)
        OR
        (owner_token IS NOT NULL
            AND operation_kind IS NOT NULL
            AND btrim(operation_kind) <> ''
            AND operation_id IS NOT NULL
            AND locked_until IS NOT NULL
            AND reclaim_after IS NOT NULL
            AND reclaim_after > locked_until)
    )
);

CREATE INDEX idx_app_mutation_leases_expiry
    ON app_mutation_leases(locked_until)
    WHERE owner_token IS NOT NULL;

-- Provider resources outlive an app row. Keeping these generation fences
-- independent of apps prevents a late response for a deleted app from
-- clobbering DNS/edge/KBS authority reused by a newly-created app.
CREATE TABLE external_resource_mutation_leases (
    resource_scope text NOT NULL,
    resource_key text NOT NULL,
    generation bigint NOT NULL DEFAULT 0,
    owner_token uuid,
    operation_kind text,
    operation_id uuid,
    locked_until timestamptz,
    reclaim_after timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (resource_scope, resource_key),
    CONSTRAINT external_resource_mutation_scope_not_blank
        CHECK (btrim(resource_scope) <> ''),
    CONSTRAINT external_resource_mutation_key_not_blank
        CHECK (btrim(resource_key) <> ''),
    CONSTRAINT external_resource_mutation_generation_positive CHECK (generation >= 0),
    CONSTRAINT external_resource_mutation_owner_shape CHECK (
        (owner_token IS NULL
            AND operation_kind IS NULL
            AND operation_id IS NULL
            AND locked_until IS NULL
            AND reclaim_after IS NULL)
        OR
        (owner_token IS NOT NULL
            AND operation_kind IS NOT NULL
            AND btrim(operation_kind) <> ''
            AND operation_id IS NOT NULL
            AND locked_until IS NOT NULL
            AND reclaim_after IS NOT NULL
            AND reclaim_after > locked_until)
    )
);

CREATE INDEX idx_external_resource_mutation_reclaim
    ON external_resource_mutation_leases(reclaim_after)
    WHERE owner_token IS NOT NULL;
