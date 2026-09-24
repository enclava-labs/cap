-- Durable presentation record for owner-rotation attempts (PR #185 review).
-- Before any signing-service rotate-owner effect can happen, CAP records the
-- exact (directive digest, keyring payload digest) pair presented for a
-- new-version rotation in its own committed transaction. If the upstream
-- rotation succeeds but the CAP transaction rolls back, the signing service
-- is pinned to the replacement while no keyring version or ledger row
-- exists; the first-use signed_at max-age waiver for retrying that exact
-- request past the window is granted only when this row matches the retry
-- byte-for-byte (directive AND keyring body) -- a different directive or a
-- different keyring payload over the same (current -> replacement) pair
-- gets no waiver, so a captured directive cannot mint a version in the
-- drift state. Rows are presentation records, never purged.
CREATE TABLE org_rotation_intents (
    org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    directive_sha256 bytea NOT NULL CHECK (octet_length(directive_sha256) = 32),
    keyring_sha256   bytea NOT NULL CHECK (octet_length(keyring_sha256) = 32),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, directive_sha256, keyring_sha256)
);
