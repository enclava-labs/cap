-- Record the confidential-teardown outcome on the surviving owner binding so
-- a later recreate of the same name (same binding key: the key is derived
-- from the tenant namespace and app name) can refuse when the previous
-- incarnation's owner seed may still exist in KBS.
--
-- Backfill: pre-0050 soft-deleted bindings have no recorded outcome. Reaching
-- row deletion required either a completed teardown (post-#151) or no
-- teardown requirement at all; the pre-#151 swallowed-failure cases are the
-- known stale-seed class handled by the manual runbook when they wedge. Treat
-- legacy rows as completed so recreate behavior is unchanged; every destroy
-- from this migration onward records its true outcome.
ALTER TABLE kbs_owner_bindings
    ADD COLUMN workload_teardown_completed_at TIMESTAMPTZ,
    ADD COLUMN workload_teardown_waived_at TIMESTAMPTZ;

UPDATE kbs_owner_bindings
   SET workload_teardown_completed_at = deleted_at
 WHERE deleted_at IS NOT NULL;
