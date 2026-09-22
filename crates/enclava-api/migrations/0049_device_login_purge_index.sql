-- no-transaction
-- Built CONCURRENTLY (and therefore outside a transaction) so applying the
-- migration against a live table full of flood backlog does not take a lock
-- that blocks device-login INSERT/UPDATE/DELETE for the duration of the
-- index build. Note for a zero-downtime rollout: run this via cap_migrate
-- while at most one API revision is serving; a failed CONCURRENTLY build
-- leaves an INVALID index that must be dropped before retrying.
--
-- The device-login reaper purges with `WHERE expires_at < now() - interval
-- '24 hours'`, which cannot use the existing (status, expires_at) index
-- because it does not constrain the leading `status` column. Under the
-- sustained unauthenticated /auth/device/start traffic this reaper exists
-- to contain, that made every hourly purge a full-table scan followed by
-- one large DELETE transaction on each replica.
--
-- This expires_at-leading index serves the purge predicate directly.
CREATE INDEX CONCURRENTLY device_login_sessions_expires_purge
    ON device_login_sessions (expires_at);
