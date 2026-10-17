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
