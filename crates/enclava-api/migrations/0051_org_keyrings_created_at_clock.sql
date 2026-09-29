-- org_keyrings.created_at must reflect the moment a version row is actually
-- inserted, not the start of the inserting transaction (issue #120 follow-up).
--
-- Keyring uploads and owner rotations queue on the shared signing-authority
-- lane (pg_advisory_xact_lock) before inserting the new version, so a
-- transaction-start timestamp (now() == transaction_timestamp()) can predate
-- the real insertion by the full lock wait -- and by the signing-service
-- round-trip on the rotation path. The owner-rotation directive
-- version-recency bound compares the directive's signed_at against the
-- current version's created_at; with a transaction-start default, a directive
-- captured after the uploading transaction began but before the version row
-- lands would pass that bound and be accepted as newer than the version it
-- predates. clock_timestamp() is the true statement wall-clock time and is
-- the correct insertion-time witness. Existing rows are committed audit
-- history and are not backfilled.
ALTER TABLE org_keyrings
    ALTER COLUMN created_at SET DEFAULT clock_timestamp();
