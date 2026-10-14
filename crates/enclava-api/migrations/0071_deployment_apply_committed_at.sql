-- Durable evidence that a deployment's Kubernetes generation reached the
-- apply stage. `manifest_hash` is stored at the 'applying' transition --
-- before KBS reconciliation and before the provider write -- so a newer
-- row carrying only a hash does NOT prove the cluster's desired generation
-- changed. `apply_committed_at` is stamped as the SSA apply call is
-- entered: conservative evidence that the cluster may hold this
-- generation's spec even when the client never observes the response (an
-- ambiguous timeout or connection error after Kubernetes accepted the
-- request), and never for failures that happen before the provider call
-- (KBS reconciliation, engine startup). A `deployment_apply_failed` row
-- with this marker therefore still owns the cluster's latest applied
-- generation -- including when the apply later fails in a post-apply step
-- (backend resolution, edge routes). `observing_since` (0047) is the
-- legacy equivalent for rows that reached 'watching'; the rollout settling
-- guard (`app_has_rollout_in_flight`) accepts either as supersession
-- evidence and ignores `manifest_hash` entirely.
ALTER TABLE deployments
    ADD COLUMN apply_committed_at timestamptz;
