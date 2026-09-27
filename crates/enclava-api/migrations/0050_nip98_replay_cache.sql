-- NIP-98 auth event replay guard (cap#116).
--
-- verify_nip98_event validated freshness, signature and tag bindings but
-- never recorded the event id, so a captured kind-27235 event could be
-- replayed against /auth/login or /auth/signup until its created_at left
-- the 60-second window.
--
-- This table is a short-lived replay cache. Rows are only useful to an
-- attacker (and to the guard) while the event is still inside the
-- freshness window; the reaper task deletes anything older than 15
-- minutes. Because the reaper only ticks hourly, an expired row can
-- survive up to one retention window plus one full tick interval before
-- the purge removes it, so the table is bounded by the login-event rate of
-- a ~75-minute window worst case (15-minute retention + up to 60 minutes
-- between reaper ticks), not 15. This is only a table-size bound: rows are
-- security-inert long before then, because the 60-second freshness check
-- rejects the event regardless of cache state.
CREATE TABLE IF NOT EXISTS nip98_replay_cache (
    event_id TEXT PRIMARY KEY,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
