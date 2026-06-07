ALTER TABLE apps
ADD COLUMN egress_allowlist jsonb NOT NULL DEFAULT '[]'::jsonb;
