-- Anchor the cumulative rollout-observation window for durable apply jobs.
-- Once a deployment generation reaches 'watching', the first transition
-- records when observation began so restarted or resliced watchers cannot
-- extend the rollout deadline forever.
ALTER TABLE deployments
    ADD COLUMN observing_since TIMESTAMPTZ;
