-- cap#272: creation-evidence provenance trusts client-selected field-manager
-- names. annotation_owned_by_manager / classify_generation_leftover treat a
-- managedFields entry whose manager string equals "enclava-platform" as CAP
-- provenance for RESOURCE_CREATED_BY_ANNOTATION, but Kubernetes neither
-- authenticates nor reserves field-manager strings: in an adopted namespace a
-- tenant can pre-create a target-shaped object carrying the creation
-- annotation and submit the write with fieldManager=enclava-platform,
-- producing an entry indistinguishable from CAP's own.
--
-- Creation is provable at exactly one moment: the create POST response
-- observed by this control plane. This table records (kind, name, uid) per
-- app for every object CAP's applies create; the failed-apply sweep and the
-- namespace teardown require the live object's UID to match a row here (or
-- the object to predate the compiled-in CREATION_LEDGER_CUTOVER — bounded
-- one-time migration trust) before creation evidence authorizes deletion.
--
-- Rows are append-only facts written by the apply path before it may
-- proceed; nothing ever updates or deletes them. app_id-scoped uniqueness:
-- the same UID re-observed by a retry of the same app must not duplicate.
CREATE TABLE resource_creation_ledger (
    id BIGSERIAL PRIMARY KEY,
    app_id UUID NOT NULL,
    deployment_id UUID,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT,
    uid TEXT NOT NULL,
    mutation_generation BIGINT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (app_id, uid)
);

CREATE INDEX resource_creation_ledger_app_name_idx
    ON resource_creation_ledger (app_id, name);
