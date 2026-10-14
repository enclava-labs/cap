-- #124: the PVC ownership bound for adopted-namespace sweeps must be the
-- start of CAP's Kubernetes write window, not deployment acceptance time.
-- observing_since is only persisted AFTER a fully successful apply (the
-- watching transition), so it is NULL for exactly the partial applies the
-- cleanup compensates. apply_started_at is stamped when the deployment
-- enters 'applying' — immediately before the first Kubernetes write.
ALTER TABLE deployments
    ADD COLUMN apply_started_at timestamptz,
    ADD COLUMN sts_apply_started_at timestamptz,
    ADD COLUMN sts_uid text,
    ADD COLUMN sts_created_at timestamptz;

-- sts_apply_started_at is stamped immediately before the apply attempts
-- the StatefulSet step (the final apply phase): it is the earliest moment
-- a `<vct>-<sts>-<ordinal>` claim of this workload could come under CAP
-- lineage (the StatefulSet controller creates-or-adopts the ordinal-0
-- claims). The PVC sweep uses it as its temporal ownership bound, so a
-- tenant claim created after `apply_started_at` but before the StatefulSet
-- step can never be swept. NULL means the apply never reached the
-- StatefulSet step and its claim-name namespace was never CAP-touched.

-- Legacy terminal rows: historical apply failures commonly retain
-- manifest_hash evidence. Without the marker they would make
-- no_other_generation_owns_provider_state reject every later failed
-- generation of the app forever, with no path to ever mark them incomplete
-- (cleanup returns at that gate before any sweep runs). Backfill them into
-- the retryable state: exempt from the ownership gate's evidence clause,
-- evidence kept for the storage-size guard, cleared once any later sweep
-- of the app converges the namespace.
--
-- ONLY rows that never reached `watching`: a row with observing_since
-- completed its apply and may still back a LIVE workload (supersession
-- terminalizes watching rows to failed WITHOUT provider cleanup), so its
-- evidence must keep the ownership-gate veto — exempting it would let a
-- later failed apply delete the namespace under that workload. Rows with
-- manifest_hash only are partial applies: their provider state is exactly
-- what a later generation's compensating sweep converges.
--
-- Codex P1 (cutoff): the cutoff must be the time migration 0047 was
-- INSTALLED in this database — observing_since was added by 0047 (2026-09-14)
-- WITHOUT a backfill, so a NULL value only proves never-watched for rows
-- created after 0047 was installed in THIS database. An installation that
-- upgraded after the 0047 release date can hold failed rows created
-- between the release and its actual upgrade; those rows also have NULL
-- observing_since (their failure predates the column existing locally),
-- yet may back live historical workloads — marking them retryable would
-- let a later failed apply sweep a still-live workload and its PVCs.
-- Deriving the cutoff from _sqlx_migrations.installed_on (the ledger row
-- sqlx writes when 0047 ran HERE) keeps the guarantee database-local; the
-- COALESCE fallback keeps ledger-less databases on the conservative side
-- (nothing backfilled, every legacy row keeps the gate veto). Use the
-- database's recorded installation time for migration 0047, or avoid
-- backfilling rows whose lifecycle cannot be proven.
UPDATE deployments
   SET cleanup_sweep_incomplete = true
 WHERE status = 'failed'
   AND manifest_hash IS NOT NULL
   AND observing_since IS NULL
   AND created_at >= COALESCE(
        (SELECT installed_on FROM _sqlx_migrations WHERE version = 47 AND success),
        TIMESTAMPTZ '-infinity'
       );
