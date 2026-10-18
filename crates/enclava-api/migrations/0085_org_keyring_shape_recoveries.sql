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
LOCK TABLE org_keyrings, org_keyring_repairs IN ACCESS EXCLUSIVE MODE;

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
