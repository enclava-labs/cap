-- Durable proof that a deployment's Kubernetes manifests were actually
-- committed to the cluster. `manifest_hash` is stored at the 'applying'
-- transition -- before KBS reconciliation and before the provider write --
-- so a newer row carrying only a hash does NOT prove the cluster's desired
-- generation changed. `apply_committed_at` is stamped only after
-- `apply_all_with_tenant_image_pull_secret` (the SSA apply) returns, and
-- before any post-apply step (backend resolution, edge routes) can fail
-- the job, so a `deployment_apply_failed` row with this marker still owns
-- the cluster's latest applied generation. `observing_since` (0047) is the
-- legacy equivalent for rows that reached 'watching'; the rollout settling
-- guard (`app_has_rollout_in_flight`) accepts either as supersession
-- evidence and ignores `manifest_hash` entirely.
ALTER TABLE deployments
    ADD COLUMN apply_committed_at timestamptz;
