-- Codex review on #243, P1 "fence narrowed scopes against older replicas":
-- the repository-scope epoch marker lived only as an annotation on the
-- managed Secret, so a scope-narrowing rollout that DELETED the secret left
-- older replicas (whose broader configuration still matches the repository)
-- with nothing to compare against — their deploy path's create-on-404 branch
-- and the sweep's repair pass recreated the platform PAT and reattached it
-- on the next deployment, silently undoing the narrowing.
--
-- This shared-DB fence records the newest TENANT_IMAGE_PULL_SCOPE_GENERATION
-- epoch that has made a pull-secret decision for a namespace. Replicas
-- running an older epoch defer all pull-secret writes in a fenced-newer
-- namespace (the newer policy owns it): they neither create nor refresh nor
-- delete there, and their workload admission stays closed until they are
-- upgraded — the same contract the on-secret annotation already documents
-- (DEPLOYMENT.md, TENANT_IMAGE_PULL_SCOPE_GENERATION), now durable outside
-- the deletable object. The epoch is monotonic per namespace (never lowered)
-- because a stale replica must never rewind a newer rollout's authority.
CREATE TABLE tenant_pull_secret_scope_fences (
    namespace text PRIMARY KEY,
    scope_epoch bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT tenant_pull_secret_scope_fences_epoch_nonnegative
        CHECK (scope_epoch >= 0),
    CONSTRAINT tenant_pull_secret_scope_fences_namespace_not_blank
        CHECK (btrim(namespace) <> '')
);

-- Codex review on #243, round 3, P1 "stop stale-scope replicas from
-- dispatching new namespaces" + P1 "fence pull-secret creation against
-- credential rollouts": the per-namespace fence above only protects
-- namespaces the NEWER replica has already swept. A namespace created
-- AFTER the newer replica's sweep has no fence row, so an older replica's
-- monotonic upsert succeeds with its lower epoch and it creates the pull
-- secret under its broader policy / stale credential. Symmetrically, the
-- credential epoch lived only on live Secret annotations, so a namespace
-- WITHOUT the configured-name Secret had no authority to reject a stale
-- token on the create-on-404 path.
--
-- This rollout-wide authority closes both holes: every deploy/sweep that
-- records a per-namespace fence also raises the fleet-wide maximum scope
-- and credential epochs, and a replica whose OWN epoch is below either
-- maximum defers ALL tenant pull-secret work (requeueable) — the same
-- closed-until-upgraded admission contract as the per-namespace fence,
-- now covering namespaces the newer rollout has not reached yet. Both
-- maxima are monotonic (never lowered): a stale replica must never rewind
-- a newer rollout's authority.
CREATE TABLE tenant_pull_secret_rollout_authority (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    max_scope_epoch bigint NOT NULL DEFAULT 0,
    max_credential_epoch bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT tenant_pull_secret_rollout_authority_single_row CHECK (id),
    CONSTRAINT tenant_pull_secret_rollout_authority_scope_nonnegative
        CHECK (max_scope_epoch >= 0),
    CONSTRAINT tenant_pull_secret_rollout_authority_credential_nonnegative
        CHECK (max_credential_epoch >= 0)
);
INSERT INTO tenant_pull_secret_rollout_authority (id) VALUES (true)
ON CONFLICT (id) DO NOTHING;
