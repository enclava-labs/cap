-- CAP internal foundation for hosted PaaS integration.
--
-- CAP remains usable as a self-service core product, but PaaS-managed
-- organizations are explicitly marked and can only be mutated through
-- authenticated internal routes.

ALTER TABLE organizations
    ALTER COLUMN entitlement_class DROP DEFAULT,
    ALTER COLUMN entitlement_class TYPE text USING entitlement_class::text,
    ALTER COLUMN entitlement_class SET DEFAULT 'core';

ALTER TABLE organizations
    ADD CONSTRAINT organizations_entitlement_class_not_blank
        CHECK (length(btrim(entitlement_class)) > 0);

DROP TYPE entitlement_class_enum;

CREATE TABLE organization_management (
    org_id       uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    mode         text NOT NULL DEFAULT 'self_service'
                 CHECK (mode IN ('self_service', 'paas_managed')),
    paas_org_id  text UNIQUE,
    status       text NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended', 'deleted')),
    suspended_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (mode = 'self_service' AND paas_org_id IS NULL)
        OR (mode = 'paas_managed' AND paas_org_id IS NOT NULL)
    )
);

INSERT INTO organization_management (org_id, mode, status)
SELECT id, 'self_service', 'active'
  FROM organizations
ON CONFLICT (org_id) DO NOTHING;

CREATE TABLE paas_external_mappings (
    resource_type    text NOT NULL
                     CHECK (resource_type IN ('organization', 'user')),
    paas_external_id text NOT NULL,
    cap_id           uuid NOT NULL,
    org_id           uuid REFERENCES organizations(id) ON DELETE CASCADE,
    metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_type, paas_external_id),
    UNIQUE (resource_type, cap_id)
);

CREATE INDEX idx_paas_external_mappings_org
    ON paas_external_mappings (org_id);

CREATE TABLE cap_internal_idempotency (
    idempotency_key text PRIMARY KEY,
    method          text NOT NULL,
    path            text NOT NULL,
    request_hash    bytea NOT NULL,
    response_status int,
    response_body   jsonb,
    completed_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_entitlements (
    org_id         uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    version        bigint NOT NULL,
    deploy_allowed boolean NOT NULL,
    block_reason   text,
    limits         jsonb NOT NULL,
    source         text NOT NULL DEFAULT 'paas',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (version >= 0),
    CHECK (jsonb_typeof(limits) = 'object'),
    CHECK (deploy_allowed OR block_reason IS NOT NULL)
);

CREATE TABLE paas_membership_sync_state (
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    paas_user_id text NOT NULL,
    role         text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    version      bigint NOT NULL DEFAULT 0,
    active       boolean NOT NULL,
    synced_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    UNIQUE (org_id, paas_user_id)
);

