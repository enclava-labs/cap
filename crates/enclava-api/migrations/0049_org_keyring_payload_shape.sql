-- #130 follow-up: KBS candidate loading parses the latest keyring payload of
-- every org in a single query (load_signed_policy_candidates in
-- crates/enclava-api/src/kbs.rs). Until now the "payloads are always
-- well-formed JSON" invariant was enforced only by the put_keyring /
-- rotate_org_owner handlers; a malformed row inserted by a future backfill
-- script, manual psql fix, or new writer would abort candidate loading for
-- EVERY org simultaneously (reconciler errors, stale policy stays live in
-- Trustee). Enforce the shape at the database level instead: the payload must
-- be a JSON object whose "members" entry is an array -- exactly the shape the
-- selector CTE requires to never raise. Malformed payloads fail the INSERT
-- (the constraint raises on non-UTF-8 or invalid JSON), and the selector
-- itself still fails closed per org through the INNER JOIN.
ALTER TABLE org_keyrings
    ADD CONSTRAINT org_keyrings_payload_wellformed CHECK (
        jsonb_typeof(convert_from(keyring_payload, 'UTF8')::jsonb) = 'object'
        AND jsonb_typeof(
            convert_from(keyring_payload, 'UTF8')::jsonb -> 'members'
        ) = 'array'
    );
