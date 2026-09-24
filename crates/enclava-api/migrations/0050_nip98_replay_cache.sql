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
-- minutes, so the table is bounded by the login-event rate of a ~15-minute
-- window at steady state (and only a stale backlog between reaper ticks).
CREATE TABLE IF NOT EXISTS nip98_replay_cache (
    event_id TEXT PRIMARY KEY,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
