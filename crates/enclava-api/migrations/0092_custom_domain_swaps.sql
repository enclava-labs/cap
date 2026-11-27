-- cap F1: make the one-custom-domain-per-app contract honest.
--
-- A pending swap records the OUTGOING domain. While a marker exists, the
-- desired HAProxy route set keeps serving the outgoing domain alongside the
-- row's (incoming) custom domain, so a replacement never opens a
-- zero-domain window: the row already carries the replacement, whose
-- certificate arrives with the workload restart that the verify schedules.
-- The swap settler deletes the marker once the workload rollout settles
-- (the serving certificate then carries the row's domain) and the HAProxy
-- reconciler removes the outgoing route on its next pass.
--
-- A table rather than a column: the apps row's custom_domain IS the
-- singular per-app slot the workload descriptor reads; the outgoing domain
-- is transient swap state that must not leak into that contract.
CREATE TABLE custom_domain_swaps (
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    outgoing_domain text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, outgoing_domain)
);
