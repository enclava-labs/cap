-- API keys (scoped to org)
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by   uuid NOT NULL REFERENCES users(id),
    key_hash     text NOT NULL,
    key_prefix   text NOT NULL,
    name         text NOT NULL,
    scopes       text[] NOT NULL DEFAULT '{}',
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz
);

CREATE INDEX idx_api_keys_org_id ON api_keys(org_id);
CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);

-- Audit log (append-only)
CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    org_id     uuid REFERENCES organizations(id),
    app_id     uuid,
    user_id    uuid,
    action     text NOT NULL,
    detail     jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_org_id ON audit_log(org_id);
CREATE INDEX idx_audit_log_app_id ON audit_log(app_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);

-- Config metadata (key names only, values live on encrypted filesystem inside TEE)
CREATE TABLE config_metadata (
    id         uuid PRIMARY KEY,
    app_id     uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key_name   text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key_name)
);

CREATE INDEX idx_config_metadata_app_id ON config_metadata(app_id);
