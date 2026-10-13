-- #124: the PVC ownership bound for adopted-namespace sweeps must be the
-- start of CAP's Kubernetes write window, not deployment acceptance time.
-- observing_since is only persisted AFTER a fully successful apply (the
-- watching transition), so it is NULL for exactly the partial applies the
-- cleanup compensates. apply_started_at is stamped when the deployment
-- enters 'applying' — immediately before the first Kubernetes write.
ALTER TABLE deployments
    ADD COLUMN apply_started_at timestamptz;

-- Legacy terminal rows: historical apply failures commonly retain
-- manifest_hash/observing_since evidence. Without the marker they would
-- make no_other_generation_owns_provider_state reject every later failed
-- generation of the app forever, with no path to ever mark them incomplete
-- (cleanup returns at that gate before any sweep runs). Backfill them into
-- the retryable state: exempt from the ownership gate's evidence clause,
-- evidence kept for the storage-size guard, cleared once any later sweep
-- of the app converges the namespace.
UPDATE deployments
   SET cleanup_sweep_incomplete = true
 WHERE status = 'failed'
   AND (manifest_hash IS NOT NULL OR observing_since IS NOT NULL);
