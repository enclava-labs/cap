-- Durable legacy-publication obligation marker + rotation sentinel (Codex
-- review finding on #187): a signer rotation must not confirm as published
-- while a previously rendered legacy Rego policy can keep authorizing the
-- rotated-out signer. A live kbs_tls_bindings row alone cannot prove
-- publication was ever required -- the binding is only the render source --
-- so an unconfigured replica needs durable evidence that a signer-bearing
-- legacy policy was actually rendered at least once before it may confirm a
-- rotation. recorded_at IS NOT NULL is that evidence.
--
-- The sentinel row is always present: both the legacy publication critical
-- section and the signer-rotation gates lock it FOR UPDATE (migration
-- comment and kbs.rs::lock_and_read_legacy_publication_obligation), which
-- serializes the rotation decision with an in-flight legacy publication.
-- An empty table cannot be locked, so exactly one row is kept.
CREATE TABLE legacy_publication_obligation (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    recorded_at timestamptz
);

-- Conservative backfill, on the same predicate the runtime marker uses: a
-- binding row that pins a signer (non-null subject and issuer) at upgrade
-- time -- including soft-deleted ones, because deleting a binding does not
-- un-publish the policy that already carried it -- means this install may
-- have published a signer-bearing legacy policy before the marker existed.
-- Recording the obligation makes those installs fail closed on
-- unconfigured rotation confirmation. A binding that never pinned a signer
-- cannot have authorized the rotated-out signer, so null-identity rows and
-- never-bound installs stay unmarked and keep rotating exactly as before.
INSERT INTO legacy_publication_obligation (singleton, recorded_at)
SELECT true,
       CASE
           WHEN EXISTS (
               SELECT 1
                 FROM kbs_tls_bindings
                WHERE signer_identity_subject IS NOT NULL
                  AND signer_identity_issuer IS NOT NULL
           )
           THEN now()
           ELSE NULL
       END;
