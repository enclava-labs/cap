-- cap#254: a successful create POST returns an exact UID, but a timed-out or
-- otherwise unresolved UID-pinned compensating DELETE used to only log that
-- UID. A mutating admission webhook can strip the creation stamp, and
-- failed-apply cleanup then correctly refuses to delete the unmarked object
-- by name. A crash loses the log. This table is the durable identity of that
-- object: kind, namespace/name, the POST-returned UID, and the failed
-- apply's deployment identity and generation.
--
-- Reconciliation may DELETE only the recorded UID, with a UID precondition.
-- A same-named replacement or a pre-existing adopted object is never deleted
-- by name. Rows are not deletion authority for anything except that UID.
-- No foreign key: dropping an app or deployment row must not drop the
-- obligation while the object may still exist. UIDs are cluster-unique.
CREATE TABLE unresolved_post_create_compensations (
    id BIGSERIAL PRIMARY KEY,
    app_id UUID NOT NULL,
    deployment_id UUID NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT,
    name TEXT NOT NULL,
    uid TEXT NOT NULL,
    mutation_generation BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    resolved_at TIMESTAMPTZ,
    resolve_reason TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_error TEXT,
    CONSTRAINT unresolved_post_create_compensations_uid_key UNIQUE (uid),
    CONSTRAINT unresolved_post_create_compensations_uid_nonempty CHECK (uid <> ''),
    CONSTRAINT unresolved_post_create_compensations_name_nonempty CHECK (name <> ''),
    CONSTRAINT unresolved_post_create_compensations_resolve_reason_check
        CHECK (
            resolve_reason IS NULL
            OR resolve_reason IN (
                'absent',
                'deleted',
                'stale_replacement',
                'later_generation'
            )
        )
);

CREATE INDEX unresolved_post_create_compensations_due_idx
    ON unresolved_post_create_compensations (next_attempt_at)
    WHERE resolved_at IS NULL;
