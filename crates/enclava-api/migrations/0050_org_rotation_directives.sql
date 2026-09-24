-- Consume-once ledger for owner rotation directives (issue #120).
-- A rotation directive replayed while the (current -> replacement) pair is
-- still valid must be rejected by CAP even when the embedded signature keeps
-- verifying: store the digest of each accepted directive's signed bytes and
-- reject any later directive whose digest already exists for the org.
CREATE TABLE org_rotation_directives (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    directive_sha256 bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, directive_sha256)
);

CREATE INDEX org_rotation_directives_created_at
    ON org_rotation_directives(created_at);
