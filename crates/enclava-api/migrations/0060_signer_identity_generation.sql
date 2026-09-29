-- PR #187 review follow-up ("Rotate-back falsely completes superseded
-- rotation"): a deferred signer publication checkpoint must be able to
-- distinguish "the identity event I committed is still the live one" from
-- "a later rotation happened to restore the same subject/issuer" (A -> B ->
-- C -> B). Subject/issuer equality alone cannot: the rotate-back
-- re-establishes the same pair through a NEW authority event, so the old
-- checkpoint would falsely finalize as a successful publication of its own
-- rotation. Persist a monotonic per-app generation bumped by the database on
-- every identity change -- mirroring 0052's apps_signer_rotation_withdrawal
-- trigger, so a replica still running old route code during a rolling
-- deploy is fenced identically -- capture it atomically with the commit,
-- and compare it alongside the checkpointed committed response before and
-- after publication.
ALTER TABLE apps
    ADD COLUMN signer_rotation_generation BIGINT NOT NULL DEFAULT 0;

CREATE FUNCTION bump_signer_identity_generation() RETURNS trigger
AS $$
BEGIN
    NEW.signer_rotation_generation := OLD.signer_rotation_generation + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER apps_signer_identity_generation
    BEFORE UPDATE OF signer_identity_subject, signer_identity_issuer ON apps
    FOR EACH ROW
    WHEN (
        OLD.signer_identity_subject IS DISTINCT FROM NEW.signer_identity_subject
        OR OLD.signer_identity_issuer IS DISTINCT FROM NEW.signer_identity_issuer
    )
    EXECUTE FUNCTION bump_signer_identity_generation();
