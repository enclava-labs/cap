-- Signer-rotation tokens are bearer tokens with a 600s TTL. Bind each jti
-- to the exact rotation it authorized and mark it consumed inside the
-- rotation transaction, so a captured token cannot be replayed within its
-- validity window (issue #119).
CREATE TABLE consumed_signer_rotation_tokens (
    jti        text PRIMARY KEY,
    user_id    uuid NOT NULL,
    org_id     uuid NOT NULL,
    app_id     uuid NOT NULL,
    subject    text NOT NULL,
    issuer     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

-- Rotation must also withdraw KBS trust from the previous signer as soon as
-- the new identity is committed, not only at the next deployment. workload_
-- artifacts rows are immutable by trigger (0038), so revocation is recorded
-- in a side table keyed by descriptor hash; the signed-policy selector
-- refuses any artifact with a live withdrawal row.
CREATE TABLE withdrawn_signer_artifacts (
    descriptor_core_hash bytea PRIMARY KEY
        REFERENCES workload_artifacts(descriptor_core_hash) ON DELETE CASCADE,
    app_id       uuid NOT NULL,
    rotated_out_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_withdrawn_signer_artifacts_app
    ON withdrawn_signer_artifacts (app_id);

-- Backfill: an app whose current signer identity differs from an artifact's
-- signed descriptor identity has already been rotated; withdraw those
-- artifacts so the selector stops re-admitting them.
INSERT INTO withdrawn_signer_artifacts (
    descriptor_core_hash, app_id, rotated_out_at
)
SELECT artifact.descriptor_core_hash, artifact.app_id, now()
  FROM workload_artifacts AS artifact
  JOIN apps AS app ON app.id = artifact.app_id
 WHERE (
        app.signer_identity_subject IS NOT NULL
        OR app.signer_identity_issuer IS NOT NULL
   )
   AND (
        artifact.descriptor_payload -> 'signer_identity' ->> 'subject'
            IS DISTINCT FROM app.signer_identity_subject
        OR artifact.descriptor_payload -> 'signer_identity' ->> 'issuer'
            IS DISTINCT FROM app.signer_identity_issuer
   )
ON CONFLICT DO NOTHING;
