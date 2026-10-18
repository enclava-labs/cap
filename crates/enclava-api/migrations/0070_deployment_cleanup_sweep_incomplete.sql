-- #124: a failed apply whose adopted-namespace sweep could not complete
-- keeps its provider-state evidence (manifest_hash/observing_since) so the
-- storage-size guard stays armed — but that evidence must not block LATER
-- failed generations of the same app from running their own compensating
-- cleanup forever. The marker records "cleanup was attempted and left
-- leftovers": such rows are exempt from the ownership gate's evidence
-- clause, and the marker (plus evidence) is cleared once any later sweep
-- of the same app converges the namespace, because every swept object name
-- is shared across the app's generations.
ALTER TABLE deployments
    ADD COLUMN cleanup_sweep_incomplete boolean NOT NULL DEFAULT false;
