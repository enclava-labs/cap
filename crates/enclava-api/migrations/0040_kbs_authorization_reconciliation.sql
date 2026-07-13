-- Durable reconciliation state. The terminal ledger intentionally survives
-- bundle retention cleanup so a restored KBS database cannot silently lose an
-- irreversible revocation that CAP had already confirmed and purged.
ALTER TABLE workload_artifact_authorizations
    ADD COLUMN last_reconciled_at timestamptz;

CREATE INDEX idx_workload_artifact_authorizations_reconcile
    ON workload_artifact_authorizations(last_reconciled_at, created_at)
    WHERE publication_state = 'active' AND terminally_revoked_at IS NULL;

CREATE TABLE kbs_authorization_tombstone_ledger (
    descriptor_core_hash bytea PRIMARY KEY,
    revocation_reason text NOT NULL,
    kbs_confirmed_at timestamptz,
    last_reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT kbs_authorization_tombstone_ledger_hash_len
        CHECK (octet_length(descriptor_core_hash) = 32),
    CONSTRAINT kbs_authorization_tombstone_ledger_reason_limit
        CHECK (length(btrim(revocation_reason)) > 0
            AND length(revocation_reason) <= 1024)
);

CREATE INDEX idx_kbs_authorization_tombstone_ledger_reconcile
    ON kbs_authorization_tombstone_ledger(last_reconciled_at, created_at);

CREATE TABLE org_owner_authorization_rotations (
    rotation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    old_owner_version bigint NOT NULL,
    old_owner_pubkey_sha256 bytea NOT NULL,
    replacement_owner_version bigint NOT NULL,
    grace_expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_owner_authorization_rotations_versions
        CHECK (old_owner_version > 0
            AND replacement_owner_version > old_owner_version),
    CONSTRAINT org_owner_authorization_rotations_hash_len
        CHECK (octet_length(old_owner_pubkey_sha256) = 32),
    UNIQUE (org_id, replacement_owner_version)
);

CREATE INDEX idx_org_owner_authorization_rotations_due
    ON org_owner_authorization_rotations(grace_expires_at)
    WHERE completed_at IS NULL;
