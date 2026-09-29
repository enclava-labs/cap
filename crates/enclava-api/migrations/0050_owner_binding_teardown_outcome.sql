-- Tombstones for apps destroyed while their confidential workload teardown
-- never completed: the owner seed may still exist in KBS, and a fresh create
-- under the same binding key (the key is derived from the tenant namespace
-- and app name, so it is identical across incarnations of the same name)
-- would boot already-claimed.
--
-- The tombstone lives in its own table because kbs_owner_bindings cascades
-- away with the app row (migration 0006): a waiver recorded on the binding
-- row would be deleted in the same request that writes it. kbs_owner_seed_
-- waivers has no foreign keys by design - it must outlive the app.
--
-- No backfill is needed: only a destroy whose teardown never completed
-- writes a waiver row, and pre-0050 destroys reached row deletion only with
-- a completed teardown (post-#151) or no teardown requirement at all. The
-- pre-#151 swallowed-failure cases are the known stale-seed class handled
-- by the manual runbook when they wedge; absence of a waiver keeps their
-- recreate behavior unchanged.
CREATE TABLE kbs_owner_seed_waivers (
    binding_key   text PRIMARY KEY,
    app_id        uuid NOT NULL,
    org_name      text NOT NULL,
    app_name      text NOT NULL,
    waived_at     timestamptz NOT NULL DEFAULT now()
);
