-- One accepted-override floor per CAP database/environment, shared by replicas.
-- Seed the row so FOR UPDATE also serializes the first concurrent acceptance.
CREATE TABLE platform_release_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    platform_release_version TEXT,
    created_at TEXT,
    payload_sha256 TEXT,
    CONSTRAINT complete_release_mark CHECK (
        (platform_release_version IS NULL AND created_at IS NULL AND payload_sha256 IS NULL)
        OR (platform_release_version IS NOT NULL AND created_at IS NOT NULL AND payload_sha256 IS NOT NULL
            AND length(trim(platform_release_version)) > 0 AND payload_sha256 ~ '^[0-9a-f]{64}$')
    )
);
INSERT INTO platform_release_state (singleton) VALUES (TRUE);
