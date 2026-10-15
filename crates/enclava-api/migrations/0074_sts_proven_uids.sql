-- Codex P2: a reclaimed deployment can re-create its StatefulSet under a NEW
-- UID. 0072's sts_uid is first-writer-wins, so once the recreated set was
-- deleted its claims' ownerReference pinned an unknown UID and stayed
-- unproven — stranding the cleanup marker and the storage guard.
--
-- sts_proven_uids accumulates EVERY proven CAP-lineage StatefulSet UID
-- (idempotent append in persist_sts_provenance; the primary
-- sts_uid/sts_created_at record keeps first-writer-wins). Every uid in this
-- set entered through the gated is_cap_created_generation_leftover paths
-- (apply response / sweep pre-delete record), so a claim pinning one is
-- exactly a claim of a CAP-created StatefulSet incarnation — each UID here
-- is a PROVEN creation fact, never a temporal window that authorizes
-- deletion by itself.
ALTER TABLE deployments
    ADD COLUMN sts_proven_uids text[] NOT NULL DEFAULT '{}';

UPDATE deployments
   SET sts_proven_uids = ARRAY[sts_uid]
 WHERE sts_uid IS NOT NULL;
