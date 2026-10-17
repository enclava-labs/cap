-- Proof a generation applied its StatefulSet. setup_state='accepted' is
-- written before any workload spec, and manifest_hash is stored when apply
-- begins, still before the StatefulSet write. Neither shows that a later
-- generation replaced the serving spec.
--
-- observing_since is set only after apply_all returns, which includes the
-- StatefulSet apply, so it is a safe historical signal. Do not backfill from
-- manifest_hash or status: those are set before the StatefulSet write.
-- Generations applied by the previous replica are covered only if they
-- reached watching; a new replica records this column after StatefulSet apply.
ALTER TABLE deployments
    ADD COLUMN workload_spec_published_at TIMESTAMPTZ;

UPDATE deployments
   SET workload_spec_published_at = observing_since
 WHERE observing_since IS NOT NULL;
