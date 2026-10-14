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
    ADD COLUMN sts_created_at timestamptz,
    ADD COLUMN sts_observed_deleted_at timestamptz;

-- sts_apply_started_at is stamped immediately before the apply attempts
-- the StatefulSet step (the final apply phase): it is the earliest moment
-- a `<vct>-<sts>-<ordinal>` claim of this workload could come under CAP
-- lineage (the StatefulSet controller creates-or-adopts the ordinal-0
-- claims). It is NEVER a deletion bound (it precedes the Kubernetes
-- write by an unbounded interval); its role is marking that the row
-- REACHED the sts step, so a sweep that finds no sts_created_at
-- provenance for it must fail closed on unproven claims.
--
-- sts_uid / sts_created_at / sts_observed_deleted_at record the PROVEN
-- lineage window of the StatefulSet this row's apply created: the
-- server-reported UID and creationTimestamp (from the apply response, or
-- a sweep's live observation), and the time a sweep stamped BEFORE
-- issuing the sts delete. A claim is deletable by a retry sweep (sts
-- gone) only on claim-specific evidence: a controller ownerReference
-- pinning the proven UID, or creation strictly INSIDE the closed window
-- [sts_created_at, sts_observed_deleted_at] — the creation time alone is
-- only a lower bound, and a tenant claim created after the sts deletion
-- must never be swept. NULL sts_observed_deleted_at = open window =
-- fail closed.

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
--
-- Codex P2 (apply timing, not row creation): `created_at >=` alone is the
-- ACCEPTANCE time, not when the deployment actually applied. A deployment
-- queued before the upgrade can first enter 'applying' and fail after 0047
-- was installed: its NULL observing_since reliably means it never reached
-- watching (its whole apply ran under observing_since-aware code), but its
-- earlier created_at excludes it from the cutoff — leaving it unmarked, so
-- no_other_generation_owns_provider_state rejects every later failure and
-- compensation is permanently disabled for that app. The OR-clause below
-- recovers exactly that population — but NOT by trusting the error code
-- (devin 🔴 round-6: a pre-0047 WATCHED row can also carry these codes: it
-- watched under pre-0047 code (no observing_since stamp), lost its lease,
-- and a later re-apply failed; marking THAT row would exempt a possibly
-- LIVE workload from the ownership gate). The sound positive signals:
--
--   * job.updated_at >= the 0047 install: the claim that terminal-published
--     ran after 0047 was installed HERE (a terminal publish always happens
--     inside its own claim; requeued claims never terminal-publish). This
--     excludes pre-install publishes of watched rows.
--   * job.attempts = 1: the job was claimed exactly once — a row that
--     reached watching and then failed through a later claim necessarily
--     has attempts >= 2 (the watch claim plus the failing claim). A single
--     claim that terminal-publishes an apply/setup failure cannot have
--     completed the watching transition first: after `watching` the flow
--     only produces rollout outcomes, whose sole non-requeueable error is
--     an app/org identity mismatch the schema's identity FKs make
--     unreachable. (The watch transition itself stamps observing_since,
--     which the outer WHERE already excludes.)
--
-- Together these prove the one and only claim ran post-install and failed
-- before watching — the queued-across-upgrade population. Residual
-- conservatism: rows that needed a transient-error requeue (attempts >= 2)
-- before terminal failure keep the gate veto; they stay safe, just
-- uncompensated until a future reconciliation pass. Superseded rows
-- ('deployment_superseded') and completed applies keep the veto entirely.
UPDATE deployments
   SET cleanup_sweep_incomplete = true
 WHERE status = 'failed'
   AND manifest_hash IS NOT NULL
   AND observing_since IS NULL
   AND (
        created_at >= COALESCE(
            (SELECT installed_on FROM _sqlx_migrations WHERE version = 47 AND success),
            TIMESTAMPTZ 'infinity'
        )
        OR EXISTS (
            SELECT 1 FROM deployment_apply_jobs AS job
             WHERE job.deployment_id = deployments.id
               AND job.attempts = 1
               AND job.updated_at >= COALESCE(
                    (SELECT installed_on FROM _sqlx_migrations WHERE version = 47 AND success),
                    TIMESTAMPTZ 'infinity'
               )
               AND job.last_error_code IN
                   ('deployment_apply_failed', 'deployment_setup_failed')
        )
   );
