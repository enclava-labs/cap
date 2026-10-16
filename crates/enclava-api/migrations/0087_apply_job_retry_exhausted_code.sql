-- #231: terminalize requeue-without-terminal exhaustion.
--
-- The apply-job requeue loop now publishes a terminal failure once a job's
-- retries outlive every legitimate retry window (rollout budget + grace for
-- nonterminal observations, the contention horizon for transient errors).
-- Persist that exhaustion with its own bounded, operator-visible
-- classification so the job row carries why it stopped retrying. Retain
-- the full bounded classification set from #220's 0073 (plus this code):
-- previously legal rows must stay legal when #220 has landed first. If #220
-- lands afterward, its migration must retain deployment_retry_exhausted.
ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT deployment_apply_jobs_last_error_code_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_superseded',
            'customer_config_hold_expired',
            'deployment_rollout_failed',
            'deployment_authority_changed',
            'deployment_validation_error',
            'kubernetes_api_error',
            'provider_write_timeout',
            'invalid_mutation_generation',
            'invalid_live_mutation_generation',
            'stale_mutation_generation',
            'provider_generation_not_applied',
            'missing_resource_identity',
            'resource_not_found',
            'mutation_conflict_exhausted',
            'namespace_not_ready',
            'rollout_timeout',
            'rollout_failed',
            'cleanup_failed',
            'manifest_generation_error',
            'serialization_error',
            'database_error',
            'no_containers',
            'image_parse_error',
            'image_digest_required',
            'deploy_runtime_not_configured',
            'kbs_policy_error',
            'signed_policy_budget_exceeded',
            'app_not_deployed',
            'edge_route_error',
            'mutation_fence_error',
            'dns_setup_error',
            'invalid_job_payload',
            'unsupported_job_payload_version',
            'artifact_invalid',
            'lease_lost',
            'apply_limiter_closed',
            'side_effect_admission_closed',
            'dns_not_configured',
            'dns_outside_managed_zone',
            'dns_hostname_in_use',
            'dns_provider_error',
            'dns_transport_error',
            'app_mutation_busy',
            'app_mutation_lease_lost',
            'app_mutation_unavailable',
            'volume_evidence_unavailable',
            'deployment_retry_exhausted'
        )
    );
