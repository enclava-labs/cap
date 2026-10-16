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
-- lineage of the StatefulSet this row's apply created: the server-reported
-- UID and creationTimestamp (from the apply response, or a sweep's live
-- observation), and the time a sweep stamped BEFORE issuing the sts
-- delete. A claim is deletable by a retry sweep (sts gone) ONLY on the
-- claim-specific ownerReference proof — a controller ownerReference
-- pinning the proven UID (see `classify_claim_lineage`). Creation
-- timestamps NEVER authorize deletion (doc trap corrected: the classifier
-- no longer accepts creation inside the recorded window — a tenant can
-- create the predictable ownerless `<vct>-<sts>-<ordinal>` name at any
-- moment, and a claim created after the sts deletion must never be
-- swept); the window columns are kept for observability and retry
-- accounting. Unproven claims are retained and keep the sweep
-- incomplete.

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
--   * the terminal-publishing claim is the first claim that could have
--     watched. A claim that reaches watching publishes a rollout outcome
--     (`last_error_code` stays NULL, the job requeues or completes) and can
--     never terminal-publish `deployment_apply_failed`; a row can only have
--     watched through an EARLIER claim. So the proof is a claim count —
--     but counted in APPLY claims, not raw `attempts` (devin: `claim_job`
--     increments `attempts` for the DNS-setup claim too). A setup claim is
--     not watch-capable: a job leaves 'setup_pending'/'setting_up' for
--     'pending' only through `mark_setup_accepted`, and a setup failure
--     terminal-publishes `deployment_setup_failed` before any apply claim
--     exists. For a job that provably ran the setup state machine, the
--     second claim is therefore the FIRST apply claim: the ordinary
--     queued-across-upgrade deployment (setup claim + first apply claim
--     failing post-install). Ready-flow jobs — rollback (`trigger =
--     'rollback'`, `spec_snapshot ? 'rollback_to'`) and unlock
--     (`spec_snapshot ? 'unlock_mode'`, `unlock_transition_receipts`) —
--     insert their job straight into 'pending' via `insert_ready_job`, so
--     their two-claim rows are ambiguous with a watched apply followed by a
--     failed re-apply. Those flows keep the strict single-claim proof
--     (`attempts = 1`): a single claim that terminal-publishes an apply
--     failure cannot have completed the watching transition first (it would
--     have published a rollout outcome instead), and the watch transition
--     itself stamps observing_since, which the outer WHERE already excludes.
--
-- Together these prove the terminal-publishing claim ran post-install and
-- failed before watching — the queued-across-upgrade population. Residual
-- conservatism: ready-flow rows requeued before terminal failure, and
-- setup rows whose setup claim itself was re-claimed (attempts >= 3), keep
-- the gate veto; they stay safe, just uncompensated until a future
-- reconciliation pass. Superseded rows ('deployment_superseded') and
-- completed applies keep the veto entirely.
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
               AND job.updated_at >= COALESCE(
                    (SELECT installed_on FROM _sqlx_migrations WHERE version = 47 AND success),
                    TIMESTAMPTZ 'infinity'
               )
               AND job.last_error_code IN
                   ('deployment_apply_failed', 'deployment_setup_failed')
               AND (
                    -- Single-claim proof (ready flows included): the one
                    -- claim terminal-published the failure, so the row
                    -- never reached watching.
                    job.attempts = 1
                    OR (
                        -- Setup-flow proof: exactly the DNS-setup claim
                        -- plus the first apply claim. The setup claim
                        -- cannot watch, so the failing claim is the first
                        -- claim that could have. Rollback/unlock jobs
                        -- (insert_ready_job: no setup claim) are excluded:
                        -- their two-claim rows cannot be distinguished from
                        -- a watched apply followed by a failed re-apply.
                        job.attempts = 2
                        AND deployments.trigger <> 'rollback'
                        AND NOT (deployments.spec_snapshot ? 'rollback_to')
                        AND NOT (deployments.spec_snapshot ? 'unlock_mode')
                        AND NOT EXISTS (
                            SELECT 1 FROM unlock_transition_receipts AS receipt
                             WHERE receipt.deployment_id = deployments.id
                        )
                    )
               )
        )
   );
