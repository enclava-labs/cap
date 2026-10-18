-- #276: DeployError::public_code emits pull_secret_reconcile_deferred and
-- pull_secret_delete_conflict. Widen deployment_apply_jobs.last_error_code
-- so those bounded classifications can be persisted.
--
-- Pattern mirrors #220's 0082: drop the named CHECK, then add it back with
-- the full allowlist. Constraint name is deployment_apply_jobs_last_error_code_check
-- (0082's ALTER; on this branch 0060 creates that name — confirmed on the
-- gate DB: the live CHECK is the four 0060 codes).
--
-- The list is additive under every merge order this file can follow:
--   * main's 0060 allowlist (the four control-plane codes), and
--   * #220's 0082 / #260's 0076 allowlist (identical 51-code set; 0087 is
--     numbered after both, so it must not narrow a constraint they already
--     applied).
-- Previously legal rows stay legal. The two pull-secret codes are the only
-- additions beyond that union.
ALTER TABLE deployment_apply_jobs
    DROP CONSTRAINT deployment_apply_jobs_last_error_code_check;

ALTER TABLE deployment_apply_jobs
    ADD CONSTRAINT deployment_apply_jobs_last_error_code_check CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            -- control-plane codes (main 0060, retained)
            'deployment_superseded',
            'customer_config_hold_expired',
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
            -- engine codes inherited from main's P2 evidence work (0075)
            'creation_evidence_lost',
            'missing_resource_identity',
            'resource_not_found',
            'resource_vanished',
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
            'signed_policy_budget_exceeded',
            'app_not_deployed',
            'edge_route_error',
            'mutation_fence_error',
            -- cap#276: scoped pull-secret reconcile/delete classifications
            'pull_secret_reconcile_deferred',
            'pull_secret_delete_conflict',
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
            'app_mutation_unavailable',
            -- preflight volume-evidence codes (main; DeploymentJobError::code)
            'volume_evidence_unavailable',
            -- cap#260 (#231) terminal exhaustion code: 0076 and 0082 both
            -- require every later allowlist to retain it
            'deployment_retry_exhausted'
        )
    );
