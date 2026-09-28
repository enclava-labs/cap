-- Durable presentation record for owner-rotation attempts (PR #185 review).
-- Before any signing-service rotate-owner effect can happen, CAP records the
-- exact (directive digest, keyring payload digest) pair presented for a
-- new-version rotation in its own committed transaction. This row is proof
-- of presentation only: it grants nothing. In particular the expired
-- first-use signed_at max-age waiver is NOT granted by an intent row (an
-- earlier design did that and let a captured, never-actioned presentation
-- mint a version); since 0059_org_rotation_upstream_receipts that waiver
-- requires a receipt minted from a response-validated rotate-owner call and
-- matched against the live upstream owner. Rows are never purged.
CREATE TABLE org_rotation_intents (
    org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    directive_sha256 bytea NOT NULL CHECK (octet_length(directive_sha256) = 32),
    keyring_sha256   bytea NOT NULL CHECK (octet_length(keyring_sha256) = 32),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, directive_sha256, keyring_sha256)
);
