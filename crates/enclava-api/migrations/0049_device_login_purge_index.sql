-- The device-login reaper purges with `WHERE expires_at < now() - interval
-- '24 hours'`, which cannot use the existing (status, expires_at) index
-- because it does not constrain the leading `status` column. Under the
-- sustained unauthenticated /auth/device/start traffic this reaper exists
-- to contain, that made every hourly purge a full-table scan followed by
-- one large DELETE transaction on each replica.
--
-- This expires_at-leading index serves the purge predicate directly.
CREATE INDEX device_login_sessions_expires_purge
    ON device_login_sessions (expires_at);
