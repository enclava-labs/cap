-- BTCPay webhook idempotency / replay protection (Phase 0, item G).
-- event_id is the primary key so duplicate (delivery_id, event_id) tuples are rejected.
CREATE TABLE processed_webhooks (
    delivery_id text NOT NULL,
    event_id text PRIMARY KEY,
    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_processed_webhooks_delivery_id ON processed_webhooks(delivery_id);
