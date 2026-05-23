ALTER TABLE apps
    ADD COLUMN source_provider text,
    ADD COLUMN source_repository text,
    ADD CONSTRAINT apps_source_provider_check
        CHECK (source_provider IS NULL OR source_provider IN ('github', 'gitlab')),
    ADD CONSTRAINT apps_source_pair_check
        CHECK (
            (source_provider IS NULL AND source_repository IS NULL)
            OR (source_provider IS NOT NULL AND source_repository IS NOT NULL)
        ),
    ADD CONSTRAINT apps_source_repository_not_blank_check
        CHECK (source_repository IS NULL OR length(btrim(source_repository)) > 0);

ALTER TABLE deployments
    ADD COLUMN org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN external_id text,
    ADD COLUMN source_provider text,
    ADD COLUMN source_repository text,
    ADD CONSTRAINT deployments_external_id_not_blank_check
        CHECK (external_id IS NULL OR length(btrim(external_id)) > 0),
    ADD CONSTRAINT deployments_source_provider_check
        CHECK (source_provider IS NULL OR source_provider IN ('github', 'gitlab')),
    ADD CONSTRAINT deployments_source_pair_check
        CHECK (
            (source_provider IS NULL AND source_repository IS NULL)
            OR (source_provider IS NOT NULL AND source_repository IS NOT NULL)
        ),
    ADD CONSTRAINT deployments_source_repository_not_blank_check
        CHECK (source_repository IS NULL OR length(btrim(source_repository)) > 0);

UPDATE deployments d
   SET org_id = a.org_id
  FROM apps a
 WHERE d.app_id = a.id
   AND d.org_id IS NULL;

ALTER TABLE deployments
    ALTER COLUMN org_id SET NOT NULL;

CREATE UNIQUE INDEX idx_deployments_org_external_id
    ON deployments (org_id, external_id)
    WHERE external_id IS NOT NULL;
