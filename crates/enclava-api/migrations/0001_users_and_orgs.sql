-- Custom enum types
CREATE TYPE entitlement_class_enum AS ENUM ('core');
CREATE TYPE provider_enum AS ENUM ('email', 'nostr');
CREATE TYPE role_enum AS ENUM ('owner', 'admin', 'member');

-- Organizations (tenant entity)
CREATE TABLE organizations (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    display_name text,
    entitlement_class entitlement_class_enum NOT NULL DEFAULT 'core',
    is_personal boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Users
CREATE TABLE users (
    id           uuid PRIMARY KEY,
    display_name text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Authentication identities (extensible providers)
CREATE TABLE user_identities (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        provider_enum NOT NULL,
    identifier      text NOT NULL,
    credential_hash text,
    is_primary      boolean NOT NULL DEFAULT false,
    verified_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, identifier)
);

CREATE INDEX idx_user_identities_user_id ON user_identities(user_id);

-- Org membership
CREATE TABLE memberships (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role       role_enum NOT NULL DEFAULT 'member',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id)
);

CREATE INDEX idx_memberships_org_id ON memberships(org_id);
