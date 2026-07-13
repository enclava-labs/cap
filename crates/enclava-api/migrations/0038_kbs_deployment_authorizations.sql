-- Receipt-mode storage foundation. Existing workload_artifacts rows remain
-- readable during the phased rollout; receipt-mode writers populate every new
-- bundle column. The maintenance cutover can make these columns NOT NULL after
-- legacy workloads are drained.
ALTER TABLE workload_artifacts
    ADD COLUMN namespace text,
    ADD COLUMN expected_init_data_hash bytea,
    ADD COLUMN org_keyring_envelope jsonb,
    ADD COLUMN bundle_schema_version text,
    ADD COLUMN artifact_bundle_digest bytea,
    ADD COLUMN terminally_revoked_at timestamptz,
    ADD COLUMN revocation_reason text,
    ADD CONSTRAINT workload_artifacts_expected_init_hash_len
        CHECK (expected_init_data_hash IS NULL OR octet_length(expected_init_data_hash) = 32),
    ADD CONSTRAINT workload_artifacts_bundle_digest_len
        CHECK (artifact_bundle_digest IS NULL OR octet_length(artifact_bundle_digest) = 32),
    ADD CONSTRAINT workload_artifacts_revocation_pair
        CHECK ((terminally_revoked_at IS NULL) = (revocation_reason IS NULL));

CREATE UNIQUE INDEX idx_workload_artifacts_bundle_digest
    ON workload_artifacts(artifact_bundle_digest)
    WHERE artifact_bundle_digest IS NOT NULL;

CREATE TABLE workload_artifact_authorizations (
    descriptor_core_hash bytea PRIMARY KEY
        REFERENCES workload_artifacts(descriptor_core_hash) ON DELETE RESTRICT,
    authorization_id uuid NOT NULL UNIQUE,
    receipt_resource_path text NOT NULL UNIQUE,
    authorization_bytes bytea NOT NULL,
    authorization_digest bytea NOT NULL UNIQUE,
    issuer_key_id text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz,
    publication_state text NOT NULL DEFAULT 'pending',
    published_at timestamptz,
    deactivated_at timestamptz,
    publication_digest bytea,
    terminally_revoked_at timestamptz,
    kbs_tombstoned_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workload_artifact_authorizations_descriptor_hash_len
        CHECK (octet_length(descriptor_core_hash) = 32),
    CONSTRAINT workload_artifact_authorizations_digest_len
        CHECK (octet_length(authorization_digest) = 32),
    CONSTRAINT workload_artifact_authorizations_publication_digest_len
        CHECK (publication_digest IS NULL OR octet_length(publication_digest) = 32),
    CONSTRAINT workload_artifact_authorizations_state
        CHECK (publication_state IN ('pending', 'active', 'inactive', 'tombstoned')),
    CONSTRAINT workload_artifact_authorizations_expiry
        CHECK (expires_at IS NULL OR expires_at > issued_at),
    CONSTRAINT workload_artifact_authorizations_tombstone_state
        CHECK (kbs_tombstoned_at IS NULL OR (
            publication_state = 'tombstoned' AND terminally_revoked_at IS NOT NULL
        )),
    CONSTRAINT workload_artifact_authorizations_receipt_path
        CHECK (receipt_resource_path ~ '^default/policy-receipts/[0-9a-f]{64}$'),
    CONSTRAINT workload_artifact_authorizations_body_limit
        CHECK (octet_length(authorization_bytes) <= 16384)
);

CREATE TABLE deployment_artifact_activations (
    management_deployment_id uuid PRIMARY KEY
        REFERENCES deployments(id) ON DELETE RESTRICT,
    descriptor_core_hash bytea NOT NULL
        REFERENCES workload_artifacts(descriptor_core_hash) ON DELETE RESTRICT,
    activation_state text NOT NULL DEFAULT 'pending_publication',
    activated_at timestamptz,
    deactivated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deployment_artifact_activations_hash_len
        CHECK (octet_length(descriptor_core_hash) = 32),
    CONSTRAINT deployment_artifact_activations_state
        CHECK (activation_state IN (
            'pending_publication', 'active', 'inactive', 'terminally_revoked'
        )),
    CONSTRAINT deployment_artifact_activations_active_timestamp
        CHECK (activation_state <> 'active' OR activated_at IS NOT NULL),
    CONSTRAINT deployment_artifact_activations_inactive_timestamp
        CHECK (activation_state NOT IN ('inactive', 'terminally_revoked')
            OR deactivated_at IS NOT NULL)
);

CREATE INDEX idx_deployment_artifact_activations_active_descriptor
    ON deployment_artifact_activations(descriptor_core_hash)
    WHERE activation_state = 'active';

CREATE TABLE kbs_authorization_outbox (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key text NOT NULL UNIQUE,
    descriptor_core_hash bytea NOT NULL
        REFERENCES workload_artifact_authorizations(descriptor_core_hash) ON DELETE RESTRICT,
    operation text NOT NULL,
    payload_digest bytea,
    payload_bytes bytea,
    state text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT kbs_authorization_outbox_hash_len
        CHECK (octet_length(descriptor_core_hash) = 32),
    CONSTRAINT kbs_authorization_outbox_operation
        CHECK (operation IN ('publish', 'deactivate', 'revoke')),
    CONSTRAINT kbs_authorization_outbox_state
        CHECK (state IN ('pending', 'processing', 'succeeded', 'failed')),
    CONSTRAINT kbs_authorization_outbox_attempt_count
        CHECK (attempt_count >= 0),
    CONSTRAINT kbs_authorization_outbox_publish_payload
        CHECK (
            (operation = 'publish' AND payload_digest IS NOT NULL
                AND octet_length(payload_digest) = 32 AND payload_bytes IS NOT NULL)
            OR
            (operation <> 'publish' AND payload_digest IS NULL AND payload_bytes IS NULL)
        )
);

CREATE INDEX idx_kbs_authorization_outbox_ready
    ON kbs_authorization_outbox(next_attempt_at, created_at)
    WHERE state IN ('pending', 'failed');
