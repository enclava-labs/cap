-- Quarantine recovery marker for 0061's payload-shape repair (#187 delta,
-- loop #37 item 5).  This table and its backfill used to live inline in this
-- branch's 0061; 0061 now carries the canonical bytes shared with #178/#185
-- and the divergent delta is re-seated here as an additive migration so all
-- three PRs converge on identical 0061 bytes.
--
-- Why the marker exists (unchanged reasoning): 0061's quarantine drops every
-- keyring row of an org whose CURRENT keyring was malformed, but the signing
-- service's owner registration for that org stays live.  Without a marker,
-- the replacement upload follows put_keyring's unrestricted first-version
-- path, which accepts any active org owner's registered key without calling
-- fence_successor_keyring_version -- that can either bypass the live owner's
-- cryptographic authorization or leave CAP pinned to a different owner than
-- the signing service, blocking future signing and rotation.  Record the
-- quarantine so the first-version path can require the replacement v1 signer
-- to match the live signing-service owner before restoring authority
-- (fence_quarantined_keyring_recovery in crates/enclava-api/src/routes/orgs.rs).
-- The marker row is consumed by the transaction that commits a keyring
-- version; a version that reaches the insert at all has passed the recovery
-- gate (or restored authority through the successor path).  Only the orgs
-- that lost EVERY row are marked: an org whose clean current version
-- survived keeps its authority and never takes the first-version path.
--
-- Backfill: 0061's quarantine state lives in a TEMP table it drops before
-- this migration can observe it, so the repair pass below reconstructs the
-- marked org set from the durable org_keyring_repairs archive 0061 leaves
-- behind: a quarantined org had ALL of its rows archived and has NO row
-- surviving in org_keyrings, while an org whose clean current version
-- survived the repair keeps its rows.  quarantined_latest_version is the
-- highest archived version -- for a quarantined org every version was
-- archived, so that maximum is exactly the pre-repair current version.
-- On a fresh database org_keyring_repairs is empty and the backfill is a
-- no-op; the end state therefore matches what the divergent 0061 produced
-- on both fresh and populated databases.  The IF NOT EXISTS / ON CONFLICT
-- guards keep this migration safe on databases that already carry the
-- marker table from #187's earlier divergent 0061.
--
-- Window capture (review finding): 0061 commits and releases ACCESS
-- EXCLUSIVE before this migration runs (0062..0084 sit in between, and the
-- documented rollout keeps a pre-0061 replica live).  That replica's
-- unrestricted first-version path inserts a replacement v1, and it can
-- then append a later version before this migration runs.  The backfill's
-- NOT EXISTS (org_keyrings) filter is the post-quarantine empty state.
-- Deleting only archive-colliding rows is not enough: an appended version
-- was never archived, so a "no unarchived live version" predicate treats
-- it as a clean survivor, leaves the colliding v1 in place, and the
-- backfill writes no marker.  Any live/archive version collision is
-- evidence the window captured the org.  Quarantine every live generation
-- of that org (the archived payload stays in org_keyring_repairs) before
-- the backfill, so the empty-state filter records the marker and the next
-- upload takes the fenced path.  A clean survivor has no collision: 0061
-- archives only rows it deletes, and the preserved current version stays
-- live and absent from the archive.
--
-- Divergent 0061 created the marker table but did not install an INSERT
-- fence. Old writers can therefore capture authority even with that table
-- present. A remaining marker proves recovery was never fenced: quarantine
-- every live generation for that org, including any archive collisions.
-- Conversely, a recovery through the new handler consumes its marker. With
-- the divergent table present, preserve marker-free rows even when v1
-- collides with the archive: that can be an already-authorized recovery.
LOCK TABLE org_keyrings, org_keyring_repairs IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    captured record;
BEGIN
    IF to_regclass('org_keyring_shape_recoveries') IS NULL THEN
        FOR captured IN
            DELETE FROM org_keyrings k
             WHERE EXISTS (
                   SELECT 1
                     FROM org_keyrings live
                     JOIN org_keyring_repairs archived
                       ON archived.org_id = live.org_id
                      AND archived.version = live.version
                    WHERE live.org_id = k.org_id
               )
             RETURNING k.org_id, k.version
        LOOP
            RAISE NOTICE 'migration 0085: quarantined live keyring v% for org % (a live version collides with org_keyring_repairs, so every live generation was removed); the displaced signer must restore authority through the fenced first-version path',
                captured.version, captured.org_id;
        END LOOP;
    ELSE
        -- Lock the existing markers too, so cleanup and trigger installation
        -- observe one stable recovery state throughout this migration.
        LOCK TABLE org_keyring_shape_recoveries IN ACCESS EXCLUSIVE MODE;
        FOR captured IN
            DELETE FROM org_keyrings k
             WHERE EXISTS (
                   SELECT 1 FROM org_keyring_shape_recoveries r
                    WHERE r.org_id = k.org_id
               )
             RETURNING k.org_id, k.version
        LOOP
            RAISE NOTICE 'migration 0085: quarantined live keyring v% for org % (recovery marker still present); the displaced signer must restore authority through the fenced first-version path',
                captured.version, captured.org_id;
        END LOOP;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS org_keyring_shape_recoveries (
    org_id                     uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    quarantined_latest_version bigint NOT NULL,
    recorded_at                timestamptz NOT NULL DEFAULT now()
);

INSERT INTO org_keyring_shape_recoveries (org_id, quarantined_latest_version)
SELECT r.org_id, max(r.version)
  FROM org_keyring_repairs r
 WHERE NOT EXISTS (
       SELECT 1 FROM org_keyrings k WHERE k.org_id = r.org_id
 )
 GROUP BY r.org_id
ON CONFLICT (org_id) DO NOTHING;

-- The repair above is not durable against the still-live old binary: the
-- moment this transaction commits, that binary can insert another v1, the
-- new binary sees a row and skips fence_quarantined_keyring_recovery, and a
-- later successor write would consume the marker.  Reject any keyring insert
-- while the marker remains.  The fenced path deletes the marker in the same
-- transaction before its insert, so a recovery that passed the signer check
-- is allowed and a failed insert rolls the marker back.  Old binaries do not
-- know to delete the marker, so their insert fails closed.
CREATE OR REPLACE FUNCTION org_keyrings_reject_unfenced_quarantine_recovery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM org_keyring_shape_recoveries r
         WHERE r.org_id = NEW.org_id
    ) THEN
        RAISE EXCEPTION 'quarantined keyring recovery requires the fenced signer check'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS org_keyrings_fence_quarantine_recovery ON org_keyrings;
CREATE TRIGGER org_keyrings_fence_quarantine_recovery
    BEFORE INSERT ON org_keyrings
    FOR EACH ROW
    EXECUTE FUNCTION org_keyrings_reject_unfenced_quarantine_recovery();
