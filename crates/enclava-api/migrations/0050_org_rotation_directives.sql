-- Consume-once ledger for owner rotation directives (issue #120).
-- A rotation directive replayed while the (current -> replacement) pair is
-- still valid must be rejected by CAP even when the embedded signature keeps
-- verifying: store the digest of each accepted directive's signed bytes and
-- reject any later directive whose digest already exists for the org.
-- SECURITY: rows must never be deleted while directives for the org can
-- still verify; directive freshness is enforced by the API's signed_at
-- max-age check, not by purging this ledger. Do not add a reaper.
CREATE TABLE org_rotation_directives (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    directive_sha256 bytea NOT NULL CHECK (octet_length(directive_sha256) = 32),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, directive_sha256)
);
