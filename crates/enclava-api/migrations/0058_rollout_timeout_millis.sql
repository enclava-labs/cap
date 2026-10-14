-- Add rollout_timeout_millis column with sensible defaults:
-- - Existing 'watching' rows backfilled with size-derived budget from their apply job.
--   The size-derived timeout was computed as base 600s + (total_mib / 16) seconds,
--   stored in the accepted job payload's rollout_timeout. We compute the same budget
--   at migration time using the manifest sizes stored in the deployment row.
-- - New rows get the base 600s budget; fresh volumes add their scan allowance later.
ALTER TABLE deployments
    ADD COLUMN rollout_timeout_millis BIGINT;

-- Backfill watching rows with their size-derived budget: base 10 min + 16 MiB/s scan rate.
-- The manifest sizes are stored as strings like "2Gi" in size_* columns.
-- Extract numeric value and unit, compute total MiB, then add to base 600s.
-- COALESCE handles NULL sizes as 0 (won't affect already-terminal rows anyway).
WITH size_calc AS (
    SELECT
        d.id,
        d.app_id,
        COALESCE(
            (regexp_match(d.size_app_data, '^(\d+)(\w+)$'))[1]::numeric *
            CASE (regexp_match(d.size_app_data, '^(\d+)(\w+)$'))[2]
                WHEN 'Ki' THEN 1.0/1024
                WHEN 'Mi' THEN 1
                WHEN 'Gi' THEN 1024
                WHEN 'Ti' THEN 1024*1024
                ELSE 1
            END +
            (regexp_match(d.size_tls_data, '^(\d+)(\w+)$'))[1]::numeric *
            CASE (regexp_match(d.size_tls_data, '^(\d+)(\w+)$'))[2]
                WHEN 'Ki' THEN 1.0/1024
                WHEN 'Mi' THEN 1
                WHEN 'Gi' THEN 1024
                WHEN 'Ti' THEN 1024*1024
                ELSE 1
            END,
            0
        ) AS total_mib
    FROM deployments d
    WHERE d.status = 'watching'::deploy_status_enum
)
UPDATE deployments d
SET rollout_timeout_millis = (
    600000 + -- base 10 minutes in ms
    (SELECT CAST(total_mib / 16.0 * 1000 AS BIGINT) FROM size_calc s WHERE s.id = d.id)
)
FROM size_calc s
WHERE d.id = s.id AND d.status = 'watching'::deploy_status_enum;

-- Set default for any remaining NULLs (new inserts, or rows that weren't watching)
UPDATE deployments SET rollout_timeout_millis = 600000 WHERE rollout_timeout_millis IS NULL;

-- Add NOT NULL constraint after all values are populated
ALTER TABLE deployments
    ALTER COLUMN rollout_timeout_millis SET NOT NULL,
    ADD CONSTRAINT deployments_rollout_timeout_millis_positive
        CHECK (rollout_timeout_millis > 0);
