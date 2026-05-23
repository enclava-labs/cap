CREATE TABLE device_login_sessions (
    id                         uuid PRIMARY KEY,
    device_code_hash           bytea NOT NULL UNIQUE,
    user_code_hash             bytea NOT NULL UNIQUE,
    verification_uri           text NOT NULL,
    verification_uri_complete  text NOT NULL,
    requested_org_name         text,
    status                     text NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    approved_user_id           uuid REFERENCES users(id) ON DELETE CASCADE,
    approved_org_id            uuid REFERENCES organizations(id) ON DELETE CASCADE,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    expires_at                 timestamptz NOT NULL,
    approved_at                timestamptz,
    denied_at                  timestamptz,
    last_polled_at             timestamptz
);

CREATE INDEX device_login_sessions_status_expires
    ON device_login_sessions (status, expires_at);
