ALTER TABLE apps
ADD COLUMN egress_mode text NOT NULL DEFAULT 'restricted';

ALTER TABLE apps
ADD CONSTRAINT apps_egress_mode_check
CHECK (egress_mode IN ('restricted', 'public_internet'));
