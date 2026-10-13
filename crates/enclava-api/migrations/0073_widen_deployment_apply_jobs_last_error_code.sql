-- #18: terminal apply failures now persist the bounded failure
-- classification (DeploymentJobError::code, e.g. `kbs_policy_error`)
-- instead of the constant 'deployment_apply_failed', so the real reason
-- (like a signed-policy budget rejection) survives to the public
-- projection. Widen the CHECK to the full bounded classification set.
-- Every value below is a bounded &'static str classification code —
-- never provider, Kubernetes, or runtime plaintext — and the list
-- mirrors PUBLIC_DEPLOYMENT_ERROR_CODES in src/routes/deployments.rs
-- (enforced by the public_error_codes_are_persistable_job_codes test).
ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT deployment_apply_jobs_last_error_code_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            -- control-plane codes
            'deployment_superseded',
            'deployment_setup_failed',
            'deployment_apply_failed',
            'deployment_rollout_failed',
            'deployment_authority_changed',
            'deployment_validation_error',
            -- provider/engine codes (ApplyError::public_code)
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
            -- deploy-level codes (DeployError::public_code)
            'database_error',
            'no_containers',
            'image_parse_error',
            'image_digest_required',
            'deploy_runtime_not_configured',
            'kbs_policy_error',
            'edge_route_error',
            'mutation_fence_error',
            -- job-level codes (DeploymentJobError::code)
            'dns_setup_error',
            'invalid_job_payload',
            'unsupported_job_payload_version',
            'artifact_invalid',
            'lease_lost',
            'apply_limiter_closed',
            'side_effect_admission_closed',
            -- DNS setup codes (dns_error_code)
            'dns_not_configured',
            'dns_outside_managed_zone',
            'dns_hostname_in_use',
            'dns_provider_error',
            'dns_transport_error',
            -- mutation-lease codes (MutationLeaseError)
            'app_mutation_busy',
            'app_mutation_lease_lost',
            'app_mutation_unavailable'
        )
    );
