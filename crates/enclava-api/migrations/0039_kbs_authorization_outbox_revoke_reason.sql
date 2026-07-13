-- Terminal revocation changes CAP state before KBS is contacted. Persist the
-- operator reason with the retryable outbox event so reconciliation can finish
-- the irreversible KBS tombstone after an outage.
ALTER TABLE kbs_authorization_outbox
    ADD COLUMN operation_reason text;

ALTER TABLE kbs_authorization_outbox
    DROP CONSTRAINT kbs_authorization_outbox_publish_payload,
    ADD CONSTRAINT kbs_authorization_outbox_operation_payload CHECK (
        (operation = 'publish' AND payload_digest IS NOT NULL
            AND octet_length(payload_digest) = 32 AND payload_bytes IS NOT NULL
            AND operation_reason IS NULL)
        OR
        (operation = 'deactivate' AND payload_digest IS NULL
            AND payload_bytes IS NULL AND operation_reason IS NULL)
        OR
        (operation = 'revoke' AND payload_digest IS NULL
            AND payload_bytes IS NULL AND operation_reason IS NOT NULL)
    ),
    ADD CONSTRAINT kbs_authorization_outbox_reason_limit CHECK (
        operation_reason IS NULL OR (
            length(btrim(operation_reason)) > 0 AND length(operation_reason) <= 1024
        )
    );
