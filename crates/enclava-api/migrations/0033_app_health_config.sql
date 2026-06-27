ALTER TABLE apps
ADD COLUMN health_path text NOT NULL DEFAULT '/health',
ADD COLUMN health_interval_seconds int NOT NULL DEFAULT 30,
ADD COLUMN health_timeout_seconds int NOT NULL DEFAULT 5;
