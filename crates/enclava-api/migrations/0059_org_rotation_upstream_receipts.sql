-- Presentation order cannot prove execution. Expired recovery needs the exact
-- successful upstream owner version and timestamp; old intents cannot be backfilled.
CREATE TABLE org_rotation_upstream_receipts (
    org_id                 uuid NOT NULL,
    directive_sha256       bytea NOT NULL CHECK (octet_length(directive_sha256) = 32),
    keyring_sha256         bytea NOT NULL CHECK (octet_length(keyring_sha256) = 32),
    upstream_owner_version bigint NOT NULL CHECK (upstream_owner_version > 0),
    upstream_rotated_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, upstream_owner_version),
    FOREIGN KEY (org_id, directive_sha256, keyring_sha256)
        REFERENCES org_rotation_intents (org_id, directive_sha256, keyring_sha256)
        ON DELETE CASCADE
);
