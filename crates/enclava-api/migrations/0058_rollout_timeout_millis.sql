-- Keep the initial budget when live volume evidence changes during observation.
-- Existing generations retain their previous ten-minute budget.
ALTER TABLE deployments
    ADD COLUMN rollout_timeout_millis BIGINT NOT NULL DEFAULT 600000,
    ADD CONSTRAINT deployments_rollout_timeout_millis_positive
        CHECK (rollout_timeout_millis > 0);
