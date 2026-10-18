-- Durable legacy-publication obligation marker + rotation sentinel (Codex
-- review findings on #187): a signer rotation must not confirm as published
-- while a previously rendered legacy Rego policy can keep authorizing the
-- rotated-out signer, and the rotation decision must serialize with an
-- in-flight legacy publication on a configured replica.
--
-- Two rows:
--   sentinel   -- locked FOR UPDATE by both the signer-rotation identity
--                 transaction and the legacy publication critical section
--                 (binding read through ConfigMap write), serializing the
--                 two against each other. Never updated.
--   obligation -- the marker itself, recorded_at IS NOT NULL meaning a
--                 signer-bearing legacy publication was owed at least
--                 once. Only the publisher writes it, as its own committed
--                 write taken while it holds the sentinel lock, so even a
--                 failed or lost publication keeps the evidence without
--                 deadlocking against the lock it holds.
CREATE TABLE legacy_publication_obligation (
    key         text PRIMARY KEY CHECK (key IN ('sentinel', 'obligation')),
    recorded_at timestamptz
);

INSERT INTO legacy_publication_obligation (key, recorded_at)
VALUES ('sentinel', NULL);

-- Conservative backfill: a binding row with a signer identity (including
-- soft-deleted rows, whose deletion does not un-publish anything) is
-- evidence that a signer-bearing legacy publication was owed before this
-- marker existed. Null-identity bindings pin no signer and record nothing.
INSERT INTO legacy_publication_obligation (key, recorded_at)
SELECT 'obligation',
       CASE
           WHEN EXISTS (
               SELECT 1 FROM kbs_tls_bindings
                WHERE signer_identity_subject IS NOT NULL
                  AND signer_identity_issuer IS NOT NULL
           )
           THEN now()
           ELSE NULL
       END;
