-- Migration watermark for org_keyrings.created_at reliability (PR #185
-- review, codex P2 follow-up to migration 0051).
--
-- 0051 changed the column DEFAULT to clock_timestamp(), but existing rows --
-- and any row whose INSERT statement ran under pre-migration code before
-- 0051 committed -- keep the legacy transaction-start semantics: created_at
-- can predate the row's real insertion by the full signing-authority lane
-- wait. A catalog default binds every insert the moment it commits (including
-- inserts by still-running old pods), and a migration cannot commit past an
-- in-flight INSERT: therefore every legacy-semantics row executed its INSERT
-- strictly before 0051 committed, i.e. before this migration runs.
--
-- rotate_org_owner floors the directive version-recency bound at
-- max(current version's created_at, this watermark): rows inserted after the
-- watermark carry exact clock_timestamp() witnesses, while rows created
-- before it are treated as legacy and compared against the watermark itself,
-- so a directive captured while a legacy upload/rotation sat queued on the
-- lane cannot be accepted as "newer than" the version it predates during
-- the post-rollout first-use window.
CREATE TABLE org_keyrings_created_at_watermark (
    singleton      boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    watermarked_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO org_keyrings_created_at_watermark (singleton) VALUES (true);
