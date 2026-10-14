-- Durable legacy-publication obligation marker (Codex review finding on
-- #187): a signer rotation must not confirm as published while a previously
-- rendered legacy Rego policy can keep authorizing the rotated-out signer.
-- A live kbs_tls_bindings row alone cannot prove publication was ever
-- required -- the binding is only the render source -- so an unconfigured
-- replica needs durable evidence that a signer-bearing legacy policy was
-- actually rendered at least once before it may confirm a rotation.
CREATE TABLE legacy_publication_obligation (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- Conservative backfill: any binding row at upgrade time (including
-- soft-deleted ones -- deleting a binding does not un-publish the policy
-- that already carried it) means this install may have published a
-- signer-bearing legacy policy before the marker existed. Recording the
-- obligation makes those installs fail closed on unconfigured rotation
-- confirmation; a genuinely never-published install has no binding rows and
-- stays unmarked, so its rotations keep succeeding exactly as before.
INSERT INTO legacy_publication_obligation (singleton)
SELECT true
 WHERE EXISTS (SELECT 1 FROM kbs_tls_bindings);
