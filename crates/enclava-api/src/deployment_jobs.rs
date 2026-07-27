//! Durable deployment setup and manifest-apply dispatch.
//!
//! Request handlers commit an immutable payload in `deployment_apply_jobs`
//! alongside the deployment row.  Workers use renewable database leases, so
//! process termination after commit cannot strand an accepted deployment in an
//! in-memory Tokio task.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

use crate::deploy::{
    ApplyDeploymentManifestsRequest, DeploymentApplySnapshot, DeploymentRolloutOutcome,
};
use crate::models::{App, DeployStatus};
use crate::state::AppState;
use enclava_engine::types::{AttestationConfig, LogEncryptionConfig};

pub const DEPLOYMENT_SETUP_STATE: &str = "setup_state";
pub const DEPLOYMENT_SETUP_DNS_PENDING: &str = "dns_pending";
pub const DEPLOYMENT_SETUP_CLEANUP_PENDING: &str = "cleanup_pending";
pub const DEPLOYMENT_SETUP_ACCEPTED: &str = "accepted";
pub const DEPLOYMENT_SETUP_FAILED: &str = "failed";
pub const DEPLOYMENT_SETUP_FAILED_MESSAGE: &str = "deployment_setup_failed";
const DEPLOYMENT_APPLY_FAILED_MESSAGE: &str = "deployment_apply_failed";
const JOB_PAYLOAD_VERSION: i32 = 1;
const MIN_SUPPORTED_JOB_PAYLOAD_VERSION: i32 = 1;
const MAX_SUPPORTED_JOB_PAYLOAD_VERSION: i32 = JOB_PAYLOAD_VERSION;
const LEASE_INTERVAL_SQL: &str = "90 seconds";
const SETUP_RECOVERY_DELAY_SQL: &str = "5 seconds";
const CLEANUP_RETRY_INTERVAL_SQL: &str = "30 seconds";
const APPLY_RETRY_INTERVAL_SQL: &str = "5 seconds";
const ROLLOUT_OBSERVATION_RETRY_INTERVAL_SQL: &str = "30 seconds";
const ROLLOUT_CLEANUP_HANDOFF_DELAY_SQL: &str = "1 second";
const ROLLOUT_CLEANUP_RETRY_INTERVAL_SQL: &str = "30 seconds";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_RENEW_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_SETUP_WORKERS: usize = 8;
const MAX_APPLY_WORKERS: usize = 32;

fn apply_worker_limit(configured_apply_concurrency: usize) -> usize {
    configured_apply_concurrency
        .max(1)
        .saturating_mul(4)
        .min(MAX_APPLY_WORKERS)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentApplyJobPayload {
    version: i32,
    pub app: App,
    pub snapshot: DeploymentApplySnapshot,
    pub attestation_config: Option<AttestationConfig>,
    pub api_signing_pubkey: String,
    pub api_url: String,
    pub artifact_deployment_id: Option<Uuid>,
    pub artifact_descriptor_core_hash: Option<[u8; 32]>,
    pub log_encryption: Option<LogEncryptionConfig>,
    /// A failed first generic deployment owns the newly inserted app and may
    /// delete it after all tracked DNS records have been removed.
    pub delete_app_on_setup_failure: bool,
}

impl DeploymentApplyJobPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: App,
        snapshot: DeploymentApplySnapshot,
        attestation_config: Option<AttestationConfig>,
        api_signing_pubkey: String,
        api_url: String,
        artifact_deployment_id: Option<Uuid>,
        artifact_descriptor_core_hash: Option<[u8; 32]>,
        log_encryption: Option<LogEncryptionConfig>,
        delete_app_on_setup_failure: bool,
    ) -> Self {
        Self {
            version: JOB_PAYLOAD_VERSION,
            app,
            snapshot,
            attestation_config,
            api_signing_pubkey,
            api_url,
            artifact_deployment_id,
            artifact_descriptor_core_hash,
            log_encryption,
            delete_app_on_setup_failure,
        }
    }

    fn validate_for_app(&self, app_id: Uuid, org_id: Uuid) -> Result<(), DeploymentJobError> {
        if self.version != JOB_PAYLOAD_VERSION {
            return Err(DeploymentJobError::InvalidPayload);
        }
        if self.app.id != app_id || self.app.org_id != org_id {
            return Err(DeploymentJobError::InvalidPayload);
        }
        if self.snapshot.containers.is_empty() {
            return Err(DeploymentJobError::InvalidPayload);
        }
        if self.artifact_deployment_id.is_some() != self.artifact_descriptor_core_hash.is_some() {
            return Err(DeploymentJobError::InvalidPayload);
        }
        if self
            .snapshot
            .containers
            .iter()
            .any(|container| container.app_id != self.app.id)
            || self.snapshot.resources.app_id != self.app.id
        {
            return Err(DeploymentJobError::InvalidPayload);
        }
        Ok(())
    }

    fn canonical_value_and_hash(
        &self,
    ) -> Result<(serde_json::Value, [u8; 32]), DeploymentJobError> {
        let value = canonicalize_json(
            serde_json::to_value(self).map_err(|_| DeploymentJobError::InvalidPayload)?,
        );
        Ok((value.clone(), canonical_payload_hash(&value)?))
    }
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonicalize_json(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar,
    }
}

fn canonical_payload_hash(value: &serde_json::Value) -> Result<[u8; 32], DeploymentJobError> {
    let canonical = canonicalize_json(value.clone());
    let bytes = serde_json::to_vec(&canonical).map_err(|_| DeploymentJobError::InvalidPayload)?;
    Ok(Sha256::digest(bytes).into())
}

#[derive(Debug, Clone)]
pub struct SetupJobLease {
    pub deployment_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct ClaimedJob {
    deployment_id: Uuid,
    app_id: Uuid,
    org_id: Uuid,
    source_deployment_id: Uuid,
    payload_version: i32,
    lock_token: Uuid,
    payload: serde_json::Value,
    payload_sha256: Vec<u8>,
    cleanup_app_on_setup_failure: bool,
    signed_required: bool,
    artifact_deployment_id: Option<Uuid>,
    artifact_descriptor_core_hash: Option<Vec<u8>>,
    log_encryption: Option<serde_json::Value>,
}

impl ClaimedJob {
    fn artifact_descriptor_core_hash(&self) -> Result<Option<[u8; 32]>, DeploymentJobError> {
        self.artifact_descriptor_core_hash
            .as_ref()
            .map(|bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeploymentJobError::InvalidPayload)
            })
            .transpose()
    }

    fn decode_payload(&self) -> Result<DeploymentApplyJobPayload, DeploymentJobError> {
        if !(MIN_SUPPORTED_JOB_PAYLOAD_VERSION..=MAX_SUPPORTED_JOB_PAYLOAD_VERSION)
            .contains(&self.payload_version)
        {
            return Err(DeploymentJobError::UnsupportedPayloadVersion);
        }
        let actual_hash = canonical_payload_hash(&self.payload)?;
        if actual_hash.as_slice() != self.payload_sha256.as_slice() {
            return Err(DeploymentJobError::InvalidPayload);
        }
        let payload: DeploymentApplyJobPayload = serde_json::from_value(self.payload.clone())
            .map_err(|_| DeploymentJobError::InvalidPayload)?;
        payload.validate_for_app(self.app_id, self.org_id)?;
        if payload.version != self.payload_version
            || payload.delete_app_on_setup_failure != self.cleanup_app_on_setup_failure
            || payload.artifact_deployment_id != self.artifact_deployment_id
            || payload.artifact_descriptor_core_hash != self.artifact_descriptor_core_hash()?
            || serde_json::to_value(&payload.log_encryption)
                .map_err(|_| DeploymentJobError::InvalidPayload)?
                != self
                    .log_encryption
                    .clone()
                    .unwrap_or(serde_json::Value::Null)
        {
            return Err(DeploymentJobError::InvalidPayload);
        }
        Ok(payload)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StoredDeploymentApplyAuthority {
    pub payload: DeploymentApplyJobPayload,
    pub source_deployment_id: Uuid,
    pub signed_required: bool,
    pub artifact_deployment_id: Option<Uuid>,
    pub artifact_descriptor_core_hash: Option<[u8; 32]>,
    pub payload_sha256: [u8; 32],
}

/// Load an accepted deployment's exact immutable worker snapshot. Rollback
/// uses this instead of reconstructing historical runtime state from the
/// partial human-facing deployment spec snapshot.
pub(crate) async fn load_stored_deployment_apply_authority(
    pool: &PgPool,
    deployment_id: Uuid,
    app_id: Uuid,
    org_id: Uuid,
) -> Result<StoredDeploymentApplyAuthority, DeploymentJobError> {
    let job = sqlx::query_as::<_, ClaimedJob>(
        "SELECT deployment_id, app_id, org_id, source_deployment_id,
                payload_version,
                COALESCE(lock_token, '00000000-0000-0000-0000-000000000000'::uuid)
                    AS lock_token,
                payload, payload_sha256, cleanup_app_on_setup_failure,
                signed_required, artifact_deployment_id,
                artifact_descriptor_core_hash, log_encryption
           FROM deployment_apply_jobs
          WHERE deployment_id = $1
            AND app_id = $2
            AND org_id = $3",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DeploymentJobError::InvalidPayload)?;
    let payload = job.decode_payload()?;
    validate_canonical_source_snapshot(pool, &job, &payload).await?;
    Ok(StoredDeploymentApplyAuthority {
        payload,
        source_deployment_id: job.source_deployment_id,
        signed_required: job.signed_required,
        artifact_deployment_id: job.artifact_deployment_id,
        artifact_descriptor_core_hash: job.artifact_descriptor_core_hash()?,
        payload_sha256: job
            .payload_sha256
            .as_slice()
            .try_into()
            .map_err(|_| DeploymentJobError::InvalidPayload)?,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentJobError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("DNS setup error: {0}")]
    Dns(#[from] crate::dns::DnsError),
    #[error("invalid durable deployment payload")]
    InvalidPayload,
    #[error("unsupported durable deployment payload version")]
    UnsupportedPayloadVersion,
    #[error("durable deployment setup failed")]
    SetupFailed,
    #[error("stored deployment artifact is unavailable or malformed")]
    Artifact,
    #[error("deployment job lease was lost")]
    LeaseLost,
    #[error("deployment authority changed before apply")]
    Authority,
    #[error("deployment apply failed: {0}")]
    Apply(#[from] crate::deploy::DeployError),
    #[error("KBS policy authority update failed: {0}")]
    Kbs(#[from] crate::kbs::KbsPolicyError),
    #[error("deployment apply limiter closed")]
    ApplyLimiterClosed,
    #[error("side-effect admission limiter closed")]
    SideEffectAdmissionClosed,
    #[error("durable application mutation fence failed: {0}")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
}

impl DeploymentJobError {
    /// Bounded operator-visible classification. Never log the Display source:
    /// provider, Kubernetes, and artifact failures can contain tenant text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Db(_) => "database_error",
            Self::Dns(_) => "dns_setup_error",
            Self::InvalidPayload => "invalid_job_payload",
            Self::UnsupportedPayloadVersion => "unsupported_job_payload_version",
            Self::SetupFailed => "deployment_setup_failed",
            Self::Artifact => "artifact_invalid",
            Self::LeaseLost => "lease_lost",
            Self::Authority => "deployment_authority_changed",
            Self::Apply(error) => error.public_code(),
            Self::Kbs(_) => "kbs_policy_error",
            Self::ApplyLimiterClosed => "apply_limiter_closed",
            Self::SideEffectAdmissionClosed => "side_effect_admission_closed",
            Self::Mutation(error) => match error {
                crate::mutation_leases::MutationLeaseError::Busy => "app_mutation_busy",
                crate::mutation_leases::MutationLeaseError::Lost => "app_mutation_lease_lost",
                crate::mutation_leases::MutationLeaseError::AppUnavailable => {
                    "app_mutation_unavailable"
                }
                crate::mutation_leases::MutationLeaseError::AdmissionClosed => {
                    "side_effect_admission_closed"
                }
                crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority => {
                    "stale_runtime_authority"
                }
                crate::mutation_leases::MutationLeaseError::Database(_) => "database_error",
            },
        }
    }

    fn should_requeue_without_terminal_failure(&self) -> bool {
        matches!(
            self,
            Self::Db(_)
                | Self::LeaseLost
                | Self::ApplyLimiterClosed
                | Self::SideEffectAdmissionClosed
                | Self::Mutation(_)
        )
    }
}

fn dns_error_code(error: &crate::dns::DnsError) -> &'static str {
    match error {
        crate::dns::DnsError::NotConfigured => "dns_not_configured",
        crate::dns::DnsError::OutsideManagedZone(_) => "dns_outside_managed_zone",
        crate::dns::DnsError::HostnameInUse { .. } => "dns_hostname_in_use",
        crate::dns::DnsError::Cloudflare(_) => "dns_provider_error",
        crate::dns::DnsError::Http(_) => "dns_transport_error",
        crate::dns::DnsError::Db(_) => "database_error",
    }
}

/// Insert an unowned setup job in the same transaction as the deployment.
///
/// A request cannot safely own a lease until its transaction commits: the
/// transaction timestamp may be arbitrarily old and the worker cannot renew a
/// row that is not visible yet. The request claims this handle after commit,
/// immediately renews it with `clock_timestamp()`, and only then performs DNS
/// side effects.
pub async fn insert_setup_job(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    source_deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
    signed_required: bool,
) -> Result<SetupJobLease, DeploymentJobError> {
    let (app_id, org_id) =
        sqlx::query_as::<_, (Uuid, Uuid)>("SELECT app_id, org_id FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(DeploymentJobError::InvalidPayload)?;
    payload.validate_for_app(app_id, org_id)?;
    let (payload_value, payload_sha256) = payload.canonical_value_and_hash()?;
    let log_encryption = payload
        .log_encryption
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| DeploymentJobError::InvalidPayload)?;
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (
             deployment_id, app_id, org_id, source_deployment_id,
             payload_version, payload, payload_sha256,
             cleanup_app_on_setup_failure, signed_required,
             artifact_deployment_id, artifact_descriptor_core_hash,
             log_encryption, state, next_attempt_at
         )
         VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
             'setup_pending', clock_timestamp() + $13::interval
         )",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(org_id)
    .bind(source_deployment_id)
    .bind(JOB_PAYLOAD_VERSION)
    .bind(payload_value)
    .bind(payload_sha256.to_vec())
    .bind(payload.delete_app_on_setup_failure)
    .bind(signed_required)
    .bind(payload.artifact_deployment_id)
    .bind(
        payload
            .artifact_descriptor_core_hash
            .map(|hash| hash.to_vec()),
    )
    .bind(log_encryption)
    .bind(SETUP_RECOVERY_DELAY_SQL)
    .execute(&mut **tx)
    .await?;
    Ok(SetupJobLease { deployment_id })
}

/// Insert a job whose setup was already satisfied (for example rollback).
pub async fn insert_ready_job(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    source_deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
    signed_required: bool,
) -> Result<(), DeploymentJobError> {
    let (app_id, org_id) =
        sqlx::query_as::<_, (Uuid, Uuid)>("SELECT app_id, org_id FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(DeploymentJobError::InvalidPayload)?;
    payload.validate_for_app(app_id, org_id)?;
    let (payload_value, payload_sha256) = payload.canonical_value_and_hash()?;
    let log_encryption = payload
        .log_encryption
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| DeploymentJobError::InvalidPayload)?;
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (
             deployment_id, app_id, org_id, source_deployment_id,
             payload_version, payload, payload_sha256,
             cleanup_app_on_setup_failure, signed_required,
             artifact_deployment_id, artifact_descriptor_core_hash,
             log_encryption, state
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending')",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(org_id)
    .bind(source_deployment_id)
    .bind(JOB_PAYLOAD_VERSION)
    .bind(payload_value)
    .bind(payload_sha256.to_vec())
    .bind(payload.delete_app_on_setup_failure)
    .bind(signed_required)
    .bind(payload.artifact_deployment_id)
    .bind(
        payload
            .artifact_descriptor_core_hash
            .map(|hash| hash.to_vec()),
    )
    .bind(log_encryption)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Finish the DNS setup owned by a request handler or a recovery worker.
pub async fn process_setup_job(
    state: &AppState,
    lease: SetupJobLease,
) -> Result<(), DeploymentJobError> {
    if let Some(job) = claim_job(
        &state.db,
        "setup_pending",
        "setting_up",
        Some(lease.deployment_id),
    )
    .await?
    {
        return process_claimed_setup_job(state, job).await;
    }

    // A dispatcher may have claimed the durable row in the small interval
    // between request commit and this call. Never return a false 500 or start
    // duplicate DNS work. Observe that owner; if its lease expires, reclaim by
    // ID, otherwise return once setup reaches an accepted/terminal state.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2 * 90 + 5);
    loop {
        let row = sqlx::query_as::<_, (String, bool)>(
            "SELECT state,
                    COALESCE(locked_until < clock_timestamp(), false)
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(lease.deployment_id)
        .fetch_optional(&state.db)
        .await?;
        match row {
            Some((job_state, _))
                if matches!(job_state.as_str(), "pending" | "running" | "completed") =>
            {
                return Ok(());
            }
            Some((job_state, _))
                if matches!(
                    job_state.as_str(),
                    "failed" | "cleanup_pending" | "cleaning_up"
                ) =>
            {
                return Err(DeploymentJobError::SetupFailed);
            }
            Some((job_state, expired))
                if job_state == "setup_pending" || (job_state == "setting_up" && expired) =>
            {
                if let Some(job) = claim_job(
                    &state.db,
                    "setup_pending",
                    "setting_up",
                    Some(lease.deployment_id),
                )
                .await?
                {
                    return process_claimed_setup_job(state, job).await;
                }
            }
            Some(_) => {}
            None => return Err(DeploymentJobError::SetupFailed),
        }
        if tokio::time::Instant::now() >= deadline {
            // The job remains durable and owned. Returning success here means
            // "accepted for asynchronous setup", not that DNS succeeded.
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Hold the app generation lane across an external setup/cleanup side effect.
/// No application or child row is locked while the external provider writes
/// its own CAP bookkeeping, avoiding a self-deadlock. The relational lease,
/// deployment generation and durable deleting phase are rechecked only after
/// the advisory lane has been acquired.
async fn acquire_job_side_effect_lane(
    state: &AppState,
    job: &ClaimedJob,
    expected_state: &'static str,
    expected_app_resources: Option<&App>,
) -> Result<Transaction<'static, Postgres>, DeploymentJobError> {
    let mut lane = state.db.begin().await?;
    crate::deploy::lock_app_deployment_lane(&mut lane, job.app_id).await?;
    let current: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM deployment_apply_jobs AS apply_job
               JOIN deployments AS deployment
                 ON deployment.id = apply_job.deployment_id
                AND deployment.app_id = apply_job.app_id
                AND deployment.org_id = apply_job.org_id
               JOIN apps AS app
                 ON app.id = apply_job.app_id
                AND app.org_id = apply_job.org_id
              WHERE apply_job.deployment_id = $1
                AND apply_job.app_id = $2
                AND apply_job.org_id = $3
                AND apply_job.state = $4
                AND apply_job.lock_token = $5
                AND app.status <> 'deleting'::app_status_enum
         )",
    )
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(expected_state)
    .bind(job.lock_token)
    .fetch_one(&mut *lane)
    .await?;
    if !current {
        return Err(DeploymentJobError::LeaseLost);
    }
    if let Some(expected) = expected_app_resources {
        let current_resources: Option<(String, Option<String>, Option<String>, String)> =
            sqlx::query_as(
                "SELECT domain, tee_domain, custom_domain, namespace
                   FROM apps
                  WHERE id = $1 AND org_id = $2",
            )
            .bind(job.app_id)
            .bind(job.org_id)
            .fetch_optional(&mut *lane)
            .await?;
        if current_resources
            != Some((
                expected.domain.clone(),
                expected.tee_domain.clone(),
                expected.custom_domain.clone(),
                expected.namespace.clone(),
            ))
        {
            return Err(DeploymentJobError::Authority);
        }
    }
    Ok(lane)
}

async fn process_claimed_setup_job(
    state: &AppState,
    job: ClaimedJob,
) -> Result<(), DeploymentJobError> {
    let payload = match job.decode_payload() {
        Ok(payload) => payload,
        Err(error @ DeploymentJobError::InvalidPayload) => {
            fail_unreadable_job(&state.db, &job, "setting_up").await;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let mut resources = vec![
        crate::mutation_leases::ResourceFence::dns(&payload.app.domain),
        crate::mutation_leases::ResourceFence::dns(
            payload
                .app
                .tee_domain
                .as_deref()
                .unwrap_or(&payload.app.domain),
        ),
        crate::mutation_leases::ResourceFence::kbs_policy(),
    ];
    if let Some(custom_domain) = payload.app.custom_domain.as_deref() {
        resources.push(crate::mutation_leases::ResourceFence::dns(custom_domain));
    }
    let mut mutation = match crate::mutation_leases::claim(
        state,
        job.app_id,
        "deployment_setup",
        job.deployment_id,
        false,
        resources,
    )
    .await
    {
        Ok(mutation) => mutation,
        Err(error) => {
            requeue_setup_job(&state.db, &job, DeploymentJobError::from(error).code()).await?;
            return Ok(());
        }
    };
    if state.dns.is_some() {
        mutation
            .arm_resource_scope_until_reconciled("dns_hostname")
            .await?;
    }
    let mut side_effect_lane =
        match acquire_job_side_effect_lane(state, &job, "setting_up", Some(&payload.app)).await {
            Ok(lane) => lane,
            Err(error) => {
                if matches!(error, DeploymentJobError::Authority) {
                    mark_setup_failed(&state.db, &job).await?;
                    reconcile_pending_kbs_with_mutation(state, &mutation).await?;
                }
                mutation.finish().await?;
                return Err(error);
            }
        };

    let setup = async {
        let tee_domain = payload
            .app
            .tee_domain
            .as_deref()
            .unwrap_or(&payload.app.domain);
        crate::dns::ensure_dns_pair(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            job.app_id,
            &payload.app.domain,
            tee_domain,
        )
        .await?;
        if let Some(custom_domain) = payload.app.custom_domain.as_ref() {
            crate::dns::record_custom_domain(&state.db, job.app_id, custom_domain).await?;
        }
        Ok::<(), crate::dns::DnsError>(())
    };

    let outcome = mutation
        .guard_provider_in_tx(
            &mut side_effect_lane,
            with_lease_heartbeat(
                &state.db,
                state.runtime_authority,
                job.deployment_id,
                job.lock_token,
                "setting_up",
                setup,
            ),
        )
        .await??;
    match outcome {
        Ok(()) => {
            mark_setup_accepted_in_tx(&mut side_effect_lane, job.deployment_id, job.lock_token)
                .await?;
            mutation.finish_in_tx(&mut side_effect_lane).await?;
            side_effect_lane.commit().await?;
            Ok(())
        }
        Err(error) => {
            mutation.assert_current_in_tx(&mut side_effect_lane).await?;
            mark_setup_failed_in_tx(&mut side_effect_lane, &job).await?;
            side_effect_lane.commit().await?;
            if reconcile_pending_kbs_with_mutation(state, &mutation)
                .await
                .is_ok()
            {
                // DNS may have accepted the failed request, so retain its
                // app/hostname quarantine while unblocking KBS revocation.
                release_kbs_resource(&state.db, &mut mutation).await?;
            }
            mutation
                .retain_resource_scope_until_reconciled("dns_hostname")
                .await?;
            Err(DeploymentJobError::Dns(error))
        }
    }
}

async fn requeue_setup_job(
    pool: &PgPool,
    job: &ClaimedJob,
    _reason: &'static str,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'setup_pending',
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = clock_timestamp() + $1::interval,
                last_error_code = NULL,
                updated_at = clock_timestamp()
          WHERE deployment_id = $2
            AND app_id = $3
            AND org_id = $4
            AND state = 'setting_up'
            AND lock_token = $5",
    )
    .bind(SETUP_RECOVERY_DELAY_SQL)
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.lock_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

#[cfg(test)]
async fn mark_setup_accepted(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    mark_setup_accepted_in_tx(&mut tx, deployment_id, lock_token).await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_setup_accepted_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let deployment = sqlx::query(
        "UPDATE deployments
            SET spec_snapshot = jsonb_set(
                spec_snapshot,
                '{setup_state}',
                '\"accepted\"'::jsonb,
                true
            )
          WHERE id = $1
            AND spec_snapshot->>'setup_state' = $2",
    )
    .bind(deployment_id)
    .bind(DEPLOYMENT_SETUP_DNS_PENDING)
    .execute(&mut **tx)
    .await?;
    if deployment.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let job = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'pending',
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = NULL,
                updated_at = clock_timestamp()
          WHERE deployment_id = $1
            AND state = 'setting_up'
            AND lock_token = $2",
    )
    .bind(deployment_id)
    .bind(lock_token)
    .execute(&mut **tx)
    .await?;
    if job.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn mark_setup_failed(pool: &PgPool, claimed: &ClaimedJob) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    crate::deploy::lock_app_deployment_lane(&mut tx, claimed.app_id).await?;
    mark_setup_failed_in_tx(&mut tx, claimed).await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_setup_failed_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    claimed: &ClaimedJob,
) -> Result<(), DeploymentJobError> {
    let next_setup_state = if claimed.cleanup_app_on_setup_failure {
        DEPLOYMENT_SETUP_CLEANUP_PENDING
    } else {
        DEPLOYMENT_SETUP_FAILED
    };
    let next_job_state = if claimed.cleanup_app_on_setup_failure {
        "cleanup_pending"
    } else {
        "failed"
    };
    let job = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = $1,
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = clock_timestamp(),
                last_error_code = $2,
                updated_at = clock_timestamp()
          WHERE deployment_id = $3
            AND app_id = $4
            AND org_id = $5
            AND state = 'setting_up'
            AND lock_token = $6",
    )
    .bind(next_job_state)
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(claimed.deployment_id)
    .bind(claimed.app_id)
    .bind(claimed.org_id)
    .bind(claimed.lock_token)
    .execute(&mut **tx)
    .await?;
    if job.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let deployment = sqlx::query(
        "UPDATE deployments
            SET status = 'failed'::deploy_status_enum,
                spec_snapshot = jsonb_set(
                    spec_snapshot,
                    '{setup_state}',
                    to_jsonb($3::text),
                    true
                ),
                error_message = $1,
                completed_at = clock_timestamp()
          WHERE id = $2
            AND app_id = $4
            AND org_id = $5",
    )
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(claimed.deployment_id)
    .bind(next_setup_state)
    .bind(claimed.app_id)
    .bind(claimed.org_id)
    .execute(&mut **tx)
    .await?;
    if deployment.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    if claimed.cleanup_app_on_setup_failure {
        sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1 AND org_id = $2",
        )
        .bind(claimed.app_id)
        .bind(claimed.org_id)
        .execute(&mut **tx)
        .await?;
    }
    crate::kbs::enqueue_signed_policy_revocation_if_active(tx).await?;
    Ok(())
}

async fn attempt_setup_cleanup(
    state: &AppState,
    app_id: Uuid,
    org_id: Uuid,
    expected_managed_pair: Option<(&str, &str)>,
) -> bool {
    if let Err(error) = crate::dns::delete_all_dns_records_for_app(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app_id,
    )
    .await
    {
        tracing::error!(
            app_id = %app_id,
            error_code = dns_error_code(&error),
            "failed to clean up DNS after deployment setup failure"
        );
        return false;
    }
    if let Some((app_host, tee_host)) = expected_managed_pair
        && let Err(error) = crate::dns::delete_managed_dns_pair_by_hostname(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            app_id,
            app_host,
            tee_host,
        )
        .await
    {
        tracing::error!(
            app_id = %app_id,
            error_code = dns_error_code(&error),
            "failed to reconcile provider DNS after setup response loss"
        );
        return false;
    }

    let records_remain = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM dns_records WHERE app_id = $1)",
    )
    .bind(app_id)
    .fetch_one(&state.db)
    .await
    {
        Ok(remaining) => remaining,
        Err(_error) => {
            tracing::error!(
                app_id = %app_id,
                error_code = "database_error",
                "failed to verify DNS cleanup after deployment setup failure"
            );
            return false;
        }
    };
    if records_remain {
        tracing::error!(
            app_id = %app_id,
            "DNS cleanup left tracked records; retaining app for reconciliation"
        );
        return false;
    }

    let _ = org_id;
    true
}

async fn process_cleanup_job(state: &AppState, job: ClaimedJob) {
    if !job.cleanup_app_on_setup_failure {
        tracing::error!(
            deployment_id = %job.deployment_id,
            error_code = "invalid_job_payload",
            "refused cleanup job without relational cleanup ownership"
        );
        return;
    }
    let expected_app = job.decode_payload().ok().map(|payload| payload.app);
    let hostnames = match sqlx::query_scalar::<_, String>(
        "SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname",
    )
    .bind(job.app_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(hostnames) => hostnames,
        Err(_) => {
            let _ = release_cleanup_for_retry(&state.db, job.deployment_id, job.lock_token).await;
            return;
        }
    };
    let mut resources: Vec<_> = hostnames
        .iter()
        .map(|hostname| crate::mutation_leases::ResourceFence::dns(hostname))
        .collect();
    if let Some(app) = expected_app.as_ref() {
        resources.push(crate::mutation_leases::ResourceFence::dns(&app.domain));
        resources.push(crate::mutation_leases::ResourceFence::dns(
            app.tee_domain.as_deref().unwrap_or(&app.domain),
        ));
        if let Some(custom_domain) = app.custom_domain.as_deref() {
            resources.push(crate::mutation_leases::ResourceFence::dns(custom_domain));
        }
    }
    let mut mutation = match crate::mutation_leases::claim(
        state,
        job.app_id,
        "deployment_cleanup",
        job.deployment_id,
        true,
        resources,
    )
    .await
    {
        Ok(mutation) => mutation,
        Err(error) => {
            let _ = release_cleanup_for_retry(&state.db, job.deployment_id, job.lock_token).await;
            tracing::info!(
                deployment_id = %job.deployment_id,
                error_code = DeploymentJobError::from(error).code(),
                "deferred durable deployment cleanup behind mutation fence"
            );
            return;
        }
    };
    if state.dns.is_some()
        && mutation
            .arm_resource_scope_until_reconciled("dns_hostname")
            .await
            .is_err()
    {
        let _ = release_cleanup_for_retry(&state.db, job.deployment_id, job.lock_token).await;
        return;
    }
    let mut side_effect_lane =
        match acquire_job_side_effect_lane(state, &job, "cleaning_up", None).await {
            Ok(lane) => lane,
            Err(error) => {
                let _ = mutation.finish().await;
                tracing::info!(
                    deployment_id = %job.deployment_id,
                    error_code = error.code(),
                    "skipped stale durable deployment cleanup"
                );
                return;
            }
        };
    let current_hostnames = match sqlx::query_scalar::<_, String>(
        "SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname",
    )
    .bind(job.app_id)
    .fetch_all(&mut *side_effect_lane)
    .await
    {
        Ok(hostnames) => hostnames,
        Err(_) => return,
    };
    if current_hostnames != hostnames {
        if mutation.finish_in_tx(&mut side_effect_lane).await.is_ok()
            && release_cleanup_for_retry_in_tx(
                &mut side_effect_lane,
                job.deployment_id,
                job.lock_token,
            )
            .await
            .is_ok()
        {
            let _ = side_effect_lane.commit().await;
        }
        return;
    }
    let outcome = mutation
        .guard_provider_in_tx(
            &mut side_effect_lane,
            with_lease_heartbeat(
                &state.db,
                state.runtime_authority,
                job.deployment_id,
                job.lock_token,
                "cleaning_up",
                attempt_setup_cleanup(
                    state,
                    job.app_id,
                    job.org_id,
                    expected_app.as_ref().map(|app| {
                        (
                            app.domain.as_str(),
                            app.tee_domain.as_deref().unwrap_or(&app.domain),
                        )
                    }),
                ),
            ),
        )
        .await;
    match outcome {
        Ok(Ok(true)) => {
            if sqlx::query("SAVEPOINT cleanup_app_delete")
                .execute(&mut *side_effect_lane)
                .await
                .is_err()
                || mutation.finish_in_tx(&mut side_effect_lane).await.is_err()
            {
                return;
            }
            let app_delete = sqlx::query("DELETE FROM apps WHERE id = $1 AND org_id = $2")
                .bind(job.app_id)
                .bind(job.org_id)
                .execute(&mut *side_effect_lane)
                .await;
            if app_delete.is_err() {
                if sqlx::query("ROLLBACK TO SAVEPOINT cleanup_app_delete")
                    .execute(&mut *side_effect_lane)
                    .await
                    .is_err()
                    || sqlx::query("RELEASE SAVEPOINT cleanup_app_delete")
                        .execute(&mut *side_effect_lane)
                        .await
                        .is_err()
                    || mutation.finish_in_tx(&mut side_effect_lane).await.is_err()
                    || release_cleanup_for_retry_in_tx(
                        &mut side_effect_lane,
                        job.deployment_id,
                        job.lock_token,
                    )
                    .await
                    .is_err()
                {
                    return;
                }
            } else if sqlx::query("RELEASE SAVEPOINT cleanup_app_delete")
                .execute(&mut *side_effect_lane)
                .await
                .is_err()
            {
                return;
            }
        }
        Ok(Ok(false)) => {
            if mutation
                .assert_current_in_tx(&mut side_effect_lane)
                .await
                .is_err()
            {
                return;
            }
            if mutation
                .retain_resource_scope_until_reconciled_in_tx(&mut side_effect_lane, "dns_hostname")
                .await
                .is_err()
            {
                return;
            }
            if let Err(error) = release_cleanup_for_retry_in_tx(
                &mut side_effect_lane,
                job.deployment_id,
                job.lock_token,
            )
            .await
            {
                tracing::error!(deployment_id = %job.deployment_id, error_code = error.code(), "failed to schedule durable deployment cleanup retry");
                return;
            }
        }
        Ok(Err(error)) => {
            tracing::error!(deployment_id = %job.deployment_id, error_code = error.code(), "durable deployment cleanup lost its lease");
            return;
        }
        Err(_) => {
            tracing::error!(deployment_id = %job.deployment_id, error_code = "app_mutation_lease_lost", "durable deployment cleanup lost provider mutation authority");
            return;
        }
    }
    if side_effect_lane.commit().await.is_err() {
        tracing::error!(
            deployment_id = %job.deployment_id,
            error_code = "database_error",
            "failed to publish durable deployment cleanup"
        );
    }
}

async fn release_cleanup_for_retry(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    release_cleanup_for_retry_in_tx(&mut tx, deployment_id, lock_token).await?;
    tx.commit().await?;
    Ok(())
}

async fn release_cleanup_for_retry_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'cleanup_pending',
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = clock_timestamp() + $1::interval,
                last_error_code = $2,
                updated_at = clock_timestamp()
          WHERE deployment_id = $3
            AND state = 'cleaning_up'
            AND lock_token = $4",
    )
    .bind(CLEANUP_RETRY_INTERVAL_SQL)
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(deployment_id)
    .bind(lock_token)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

/// Start the durable dispatcher after migrations and runtime configuration
/// have loaded.  Every API replica may run this loop; `FOR UPDATE SKIP LOCKED`
/// and lease tokens ensure that only one owns a job at a time.
pub fn spawn_deployment_dispatcher(state: AppState) {
    let setup_worker_slots = Arc::new(tokio::sync::Semaphore::new(MAX_SETUP_WORKERS));
    let configured_apply_workers =
        apply_worker_limit(state.deployment_apply_permits.available_permits());
    let apply_worker_slots = Arc::new(tokio::sync::Semaphore::new(configured_apply_workers));
    tokio::spawn(async move {
        loop {
            let mut found_work = false;

            if let Ok(worker_slot) = setup_worker_slots.clone().try_acquire_owned() {
                match claim_setup_job(&state.db).await {
                    Ok(Some(job)) => {
                        found_work = true;
                        let worker_state = state.clone();
                        tokio::spawn(async move {
                            let _worker_slot = worker_slot;
                            let deployment_id = job.deployment_id;
                            if let Err(error) = process_claimed_setup_job(&worker_state, job).await
                            {
                                tracing::error!(
                                    deployment_id = %deployment_id,
                                    error_code = error.code(),
                                    "durable deployment DNS setup failed"
                                );
                            }
                        });
                    }
                    Ok(None) => match claim_cleanup_job(&state.db).await {
                        Ok(Some(job)) => {
                            found_work = true;
                            let worker_state = state.clone();
                            tokio::spawn(async move {
                                let _worker_slot = worker_slot;
                                process_cleanup_job(&worker_state, job).await;
                            });
                        }
                        Ok(None) => drop(worker_slot),
                        Err(error) => {
                            drop(worker_slot);
                            tracing::error!(
                                error_code = error.code(),
                                "failed to claim durable deployment cleanup job"
                            );
                        }
                    },
                    Err(error) => {
                        drop(worker_slot);
                        tracing::error!(
                            error_code = error.code(),
                            "failed to claim durable deployment setup job"
                        );
                    }
                }
            }

            if let Ok(worker_slot) = apply_worker_slots.clone().try_acquire_owned() {
                match claim_rollout_cleanup_job(&state.db).await {
                    Ok(Some(job)) => {
                        found_work = true;
                        let worker_state = state.clone();
                        tokio::spawn(async move {
                            process_rollout_cleanup_job(worker_state, job, worker_slot).await;
                        });
                    }
                    Ok(None) => match claim_apply_job(&state.db).await {
                        Ok(Some(job)) => {
                            found_work = true;
                            let worker_state = state.clone();
                            tokio::spawn(async move {
                                process_apply_job(worker_state, job, worker_slot).await;
                            });
                        }
                        Ok(None) => drop(worker_slot),
                        Err(error) => {
                            drop(worker_slot);
                            tracing::error!(
                                error_code = error.code(),
                                "failed to claim durable deployment apply job"
                            );
                        }
                    },
                    Err(error) => {
                        drop(worker_slot);
                        tracing::error!(
                            error_code = error.code(),
                            "failed to claim durable failed-rollout cleanup job"
                        );
                    }
                }
            }

            if found_work {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(IDLE_POLL_INTERVAL).await;
            }
        }
    });
}

/// Finish retained failed-rollout authority before a generic startup
/// reconciler is allowed to claim any of its provider fences.
///
/// Migration 0045 can turn a terminal job from an older binary into
/// `rollout_cleanup_pending`, and migration 0046 preserves its exact app and
/// provider mutation rows indefinitely. Running a generic reconciler before
/// that exact cleanup would either block startup forever or, on an installation
/// that has not yet applied 0046, reclaim a finite global fence and make exact
/// cleanup impossible.
///
/// This startup path intentionally claims no setup or apply work. It waits for
/// an already-claimed cleanup job to finish or become reclaimable, drains every
/// retained cleanup in creation order, and fails closed on a provider error.
pub async fn reconcile_failed_rollout_cleanup_at_startup(
    state: &AppState,
) -> Result<(), DeploymentJobError> {
    loop {
        let Some((deployment_id, payload_version)) = oldest_rollout_cleanup_job(&state.db).await?
        else {
            return Ok(());
        };
        if !(MIN_SUPPORTED_JOB_PAYLOAD_VERSION..=MAX_SUPPORTED_JOB_PAYLOAD_VERSION)
            .contains(&payload_version)
        {
            return Err(DeploymentJobError::UnsupportedPayloadVersion);
        }
        let Some(job) = claim_job(
            &state.db,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await?
        else {
            // Another startup or a surviving dispatcher still owns this exact
            // job. Keep provider reconciliation behind it until it either
            // completes or its durable job lease expires.
            tokio::time::sleep(IDLE_POLL_INTERVAL).await;
            continue;
        };

        if let Err(error) = execute_rollout_cleanup_job(state, &job).await {
            let error_code = error.code();
            requeue_rollout_cleanup_job(&state.db, &job, error_code).await?;
            return Err(error);
        }
    }
}

async fn oldest_rollout_cleanup_job(
    pool: &PgPool,
) -> Result<Option<(Uuid, i32)>, DeploymentJobError> {
    sqlx::query_as(
        "SELECT deployment_id, payload_version
           FROM deployment_apply_jobs
          WHERE state IN ('rollout_cleanup_pending', 'rollout_cleaning_up')
          ORDER BY created_at, deployment_id
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(DeploymentJobError::from)
}

async fn claim_setup_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "setup_pending", "setting_up", None).await
}

async fn claim_apply_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "pending", "running", None).await
}

async fn claim_rollout_cleanup_job(
    pool: &PgPool,
) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "rollout_cleanup_pending", "rollout_cleaning_up", None).await
}

async fn claim_cleanup_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "cleanup_pending", "cleaning_up", None).await
}

async fn claim_job(
    pool: &PgPool,
    ready_state: &str,
    claimed_state: &str,
    only_deployment_id: Option<Uuid>,
) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    let lock_token = Uuid::new_v4();
    let job = sqlx::query_as::<_, ClaimedJob>(
        "WITH candidate AS (
             SELECT deployment_id
               FROM deployment_apply_jobs
              WHERE payload_version BETWEEN $4 AND $5
                AND (
                    (
                        state = $1
                        AND (
                            $7::uuid IS NOT NULL
                            OR next_attempt_at <= clock_timestamp()
                        )
                    )
                    OR (state = $2 AND locked_until < clock_timestamp())
                )
                AND ($7::uuid IS NULL OR deployment_id = $7)
              ORDER BY created_at, deployment_id
              FOR UPDATE SKIP LOCKED
              LIMIT 1
         )
         UPDATE deployment_apply_jobs AS job
            SET state = $2,
                lock_token = $3,
                locked_until = clock_timestamp() + $6::interval,
                attempts = attempts + 1,
                updated_at = clock_timestamp()
           FROM candidate
          WHERE job.deployment_id = candidate.deployment_id
         RETURNING job.deployment_id, job.app_id, job.org_id,
                   job.source_deployment_id, job.payload_version,
                   job.lock_token, job.payload, job.payload_sha256,
                   job.cleanup_app_on_setup_failure, job.signed_required,
                   job.artifact_deployment_id,
                   job.artifact_descriptor_core_hash, job.log_encryption",
    )
    .bind(ready_state)
    .bind(claimed_state)
    .bind(lock_token)
    .bind(MIN_SUPPORTED_JOB_PAYLOAD_VERSION)
    .bind(MAX_SUPPORTED_JOB_PAYLOAD_VERSION)
    .bind(LEASE_INTERVAL_SQL)
    .bind(only_deployment_id)
    .fetch_optional(pool)
    .await?;
    Ok(job)
}

async fn process_rollout_cleanup_job(
    state: AppState,
    job: ClaimedJob,
    _worker_slot: tokio::sync::OwnedSemaphorePermit,
) {
    let deployment_id = job.deployment_id;
    match execute_rollout_cleanup_job(&state, &job).await {
        Ok(()) => {}
        Err(error) => {
            if let Err(requeue_error) =
                requeue_rollout_cleanup_job(&state.db, &job, error.code()).await
            {
                tracing::error!(
                    deployment_id = %deployment_id,
                    error_code = requeue_error.code(),
                    "failed to requeue durable failed-rollout cleanup"
                );
            } else {
                tracing::warn!(
                    deployment_id = %deployment_id,
                    error_code = error.code(),
                    "failed-rollout cleanup remains durably pending"
                );
            }
        }
    }
}

async fn execute_rollout_cleanup_job(
    state: &AppState,
    job: &ClaimedJob,
) -> Result<(), DeploymentJobError> {
    let payload = job.decode_payload()?;
    with_lease_heartbeat(
        &state.db,
        state.runtime_authority,
        job.deployment_id,
        job.lock_token,
        "rollout_cleaning_up",
        reconcile_failed_rollout_cleanup(state, job, &payload),
    )
    .await?
}

async fn reconcile_failed_rollout_cleanup(
    state: &AppState,
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
) -> Result<(), DeploymentJobError> {
    let _admission = state
        .admit_side_effect()
        .await
        .map_err(|_| DeploymentJobError::SideEffectAdmissionClosed)?;
    let expected_resources = deployment_apply_resource_fences(payload);

    // Validate both the live process incarnation and the exact retained
    // deployment mutation before touching Trustee. Migration 0045 can recover
    // a previous binary after it already reconciled and released only the KBS
    // fence, so accept the exact retained subset but never an unrelated
    // resource. This also rejects a stale pre-restore replica that happened to
    // claim the durable cleanup row.
    let mut preflight = state.db.begin().await?;
    if !state
        .runtime_authority
        .is_current_in_tx(&mut preflight)
        .await?
    {
        return Err(crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority.into());
    }
    crate::deploy::lock_app_deployment_lane(&mut preflight, job.app_id).await?;
    lock_owned_rollout_cleanup_job(&mut preflight, job).await?;
    let retained_resources = crate::mutation_leases::reconciliation_owner_resources_in_tx(
        &mut preflight,
        job.app_id,
        "deployment_apply",
        job.deployment_id,
    )
    .await?;
    if retained_resources
        .iter()
        .any(|resource| !expected_resources.contains(resource))
    {
        return Err(crate::mutation_leases::MutationLeaseError::Lost.into());
    }
    let kbs_retained =
        retained_resources.contains(&crate::mutation_leases::ResourceFence::kbs_policy());
    preflight.commit().await?;

    // A missing KBS fence means the pre-upgrade worker already completed this
    // job's Trustee reconciliation before crashing. When KBS is not configured
    // the atomic completion path below must additionally prove that no global
    // signed-policy generation remains pending before releasing any authority.
    if kbs_retained && let Some(kbs_policy) = state.kbs_policy.as_ref() {
        crate::mutation_leases::guard_provider_with_runtime_authority(
            &state.db,
            state.runtime_authority,
            crate::kbs::reconcile_pending_signed_policy_artifacts(
                &state.db,
                Some(kbs_policy),
                state.runtime_authority,
            ),
        )
        .await??;
    }

    complete_reconciled_rollout_cleanup(
        &state.db,
        state.runtime_authority,
        job,
        &retained_resources,
        state.kbs_policy.is_none(),
    )
    .await
}

async fn complete_reconciled_rollout_cleanup(
    pool: &PgPool,
    runtime_authority: crate::runtime_authority::RuntimeAuthority,
    job: &ClaimedJob,
    expected_resources: &[crate::mutation_leases::ResourceFence],
    require_no_pending_signed_policy: bool,
) -> Result<(), DeploymentJobError> {
    // Clearing the retained provider generations and marking the durable job
    // complete are one transaction. A crash on either side leaves both for a
    // future worker to retry.
    let mut tx = pool.begin().await?;
    if !runtime_authority.is_current_in_tx(&mut tx).await? {
        return Err(crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority.into());
    }
    crate::deploy::lock_app_deployment_lane(&mut tx, job.app_id).await?;
    lock_owned_rollout_cleanup_job(&mut tx, job).await?;
    if require_no_pending_signed_policy {
        crate::kbs::require_no_pending_signed_policy_in_tx(&mut tx).await?;
    }
    crate::mutation_leases::release_reconciled_operation_in_tx(
        &mut tx,
        job.app_id,
        "deployment_apply",
        job.deployment_id,
        expected_resources,
    )
    .await?;
    let completed = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'completed',
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = NULL,
                updated_at = clock_timestamp()
          WHERE deployment_id = $1
            AND app_id = $2
            AND org_id = $3
            AND state = 'rollout_cleaning_up'
            AND lock_token = $4",
    )
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.lock_token)
    .execute(&mut *tx)
    .await?;
    if completed.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    tx.commit().await?;
    Ok(())
}

async fn lock_owned_rollout_cleanup_job(
    tx: &mut Transaction<'_, Postgres>,
    job: &ClaimedJob,
) -> Result<(), DeploymentJobError> {
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM deployment_apply_jobs
              WHERE deployment_id = $1
                AND app_id = $2
                AND org_id = $3
                AND state = 'rollout_cleaning_up'
                AND lock_token = $4
              FOR UPDATE
         )",
    )
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.lock_token)
    .fetch_one(&mut **tx)
    .await?;
    if !owned {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn requeue_rollout_cleanup_job(
    pool: &PgPool,
    job: &ClaimedJob,
    _reason: &'static str,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'rollout_cleanup_pending',
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = clock_timestamp() + $1::interval,
                last_error_code = $2,
                updated_at = clock_timestamp()
          WHERE deployment_id = $3
            AND app_id = $4
            AND org_id = $5
            AND state = 'rollout_cleaning_up'
            AND lock_token = $6",
    )
    .bind(ROLLOUT_CLEANUP_RETRY_INTERVAL_SQL)
    .bind(DEPLOYMENT_APPLY_FAILED_MESSAGE)
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.lock_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn process_apply_job(
    state: AppState,
    job: ClaimedJob,
    _worker_slot: tokio::sync::OwnedSemaphorePermit,
) {
    let deployment_id = job.deployment_id;
    let lock_token = job.lock_token;
    let payload = match job.decode_payload() {
        Ok(payload) => payload,
        Err(DeploymentJobError::InvalidPayload) => {
            fail_unreadable_job(&state.db, &job, "running").await;
            return;
        }
        Err(_) => return,
    };

    let result = with_lease_heartbeat(
        &state.db,
        state.runtime_authority,
        deployment_id,
        lock_token,
        "running",
        apply_claimed_job(&state, &job, &payload),
    )
    .await;

    match result {
        Ok(Ok(JobApplyOutcome::Applied(outcome, mut mutation))) => {
            let publication = publish_rollout_outcome_with_mutation(
                &state.db,
                &job,
                &outcome,
                Some(&mut mutation),
            )
            .await;
            if let Err(error) = publication {
                tracing::error!(
                    deployment_id = %deployment_id,
                    error_code = error.code(),
                    "failed to publish durable deployment rollout outcome"
                );
            }
        }
        Ok(Ok(JobApplyOutcome::AlreadyTerminal)) => {
            if let Err(error) =
                finish_job(&state.db, deployment_id, lock_token, "completed", None).await
            {
                tracing::error!(
                    deployment_id = %deployment_id,
                    error_code = error.code(),
                    "failed to complete terminal durable deployment job"
                );
            }
        }
        Ok(Ok(JobApplyOutcome::ApplyFailed(error, mut mutation))) => {
            fail_apply_job_with_mutation(&state, &job, &error, Some(&mut mutation)).await;
        }
        Ok(Err(error)) if error.should_requeue_without_terminal_failure() => {
            if let Err(requeue_error) = requeue_apply_job(&state.db, &job, error.code()).await {
                tracing::error!(
                    deployment_id = %deployment_id,
                    error_code = requeue_error.code(),
                    "failed to requeue durable deployment after transient contention"
                );
            }
        }
        Ok(Err(error)) => {
            fail_apply_job(&state, &job, &error).await;
        }
        Err(error) => {
            tracing::error!(
                deployment_id = %deployment_id,
                error_code = error.code(),
                "durable deployment job lost its lease"
            );
        }
    }
}

async fn requeue_apply_job(
    pool: &PgPool,
    job: &ClaimedJob,
    _reason: &'static str,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'pending',
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = clock_timestamp() + $1::interval,
                last_error_code = NULL,
                updated_at = clock_timestamp()
          WHERE deployment_id = $2
            AND app_id = $3
            AND org_id = $4
            AND state = 'running'
            AND lock_token = $5",
    )
    .bind(APPLY_RETRY_INTERVAL_SQL)
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.lock_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn fail_unreadable_job(pool: &PgPool, claimed: &ClaimedJob, claimed_state: &str) {
    let setup_phase = claimed_state == "setting_up";
    let failure_code = if setup_phase {
        DEPLOYMENT_SETUP_FAILED_MESSAGE
    } else {
        DEPLOYMENT_APPLY_FAILED_MESSAGE
    };
    // Mandatory first-app cleanup is relational. Even completely malformed
    // JSON remains recoverable: quarantine setup, then let cleanup use app_id.
    let cleanup_pending = setup_phase && claimed.cleanup_app_on_setup_failure;
    let next_job_state = if cleanup_pending {
        "cleanup_pending"
    } else {
        "failed"
    };
    let next_setup_state = if cleanup_pending {
        DEPLOYMENT_SETUP_CLEANUP_PENDING
    } else {
        DEPLOYMENT_SETUP_FAILED
    };
    let result: Result<(), DeploymentJobError> = async {
        let mut tx = pool.begin().await?;
        // Canonical publication order: advisory app lane, durable job row,
        // deployment row, then app row.  Every acceptance/deletion/rollback
        // writer uses the same outer lane, preventing row-lock inversion.
        crate::deploy::lock_app_deployment_lane(&mut tx, claimed.app_id).await?;
        let job = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = $1,
                    lock_token = NULL,
                    locked_until = NULL,
                    next_attempt_at = CASE
                        WHEN $1 = 'cleanup_pending' THEN clock_timestamp()
                        ELSE next_attempt_at
                    END,
                    last_error_code = $2,
                    updated_at = clock_timestamp()
              WHERE deployment_id = $3
                AND app_id = $4
                AND org_id = $5
                AND state = $6
                AND lock_token = $7",
        )
        .bind(next_job_state)
        .bind(failure_code)
        .bind(claimed.deployment_id)
        .bind(claimed.app_id)
        .bind(claimed.org_id)
        .bind(claimed_state)
        .bind(claimed.lock_token)
        .execute(&mut *tx)
        .await?;
        if job.rows_affected() != 1 {
            return Err(DeploymentJobError::LeaseLost);
        }
        sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    spec_snapshot = CASE
                        WHEN $1 = 'setting_up' THEN jsonb_set(
                            spec_snapshot,
                            '{setup_state}',
                            to_jsonb($4::text),
                            true
                        )
                        ELSE spec_snapshot
                    END,
                    error_message = $2,
                    completed_at = clock_timestamp()
              WHERE id = $3
                AND app_id = $5
                AND org_id = $6",
        )
        .bind(claimed_state)
        .bind(failure_code)
        .bind(claimed.deployment_id)
        .bind(next_setup_state)
        .bind(claimed.app_id)
        .bind(claimed.org_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE apps AS app
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
               FROM deployments AS deployment
              WHERE deployment.id = $1
                AND app.id = $2
                AND app.org_id = $3
                AND deployment.id = (
                    SELECT latest.deployment_id
                      FROM deployment_apply_jobs AS latest
                     WHERE latest.app_id = deployment.app_id
                     ORDER BY latest.generation DESC
                     LIMIT 1
                )",
        )
        .bind(claimed.deployment_id)
        .bind(claimed.app_id)
        .bind(claimed.org_id)
        .execute(&mut *tx)
        .await?;
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx).await?;
        tx.commit().await?;
        Ok::<(), DeploymentJobError>(())
    }
    .await;

    if result.is_err() {
        tracing::error!(
            deployment_id = %claimed.deployment_id,
            error_code = "database_error",
            "failed to quarantine malformed durable deployment job"
        );
    } else {
        tracing::error!(
            deployment_id = %claimed.deployment_id,
            error_code = "invalid_job_payload",
            "quarantined malformed durable deployment job"
        );
    }
}

#[derive(Debug)]
enum JobApplyOutcome {
    Applied(
        DeploymentRolloutOutcome,
        crate::mutation_leases::AppMutationLease,
    ),
    ApplyFailed(DeploymentJobError, crate::mutation_leases::AppMutationLease),
    AlreadyTerminal,
}

async fn apply_claimed_job(
    state: &AppState,
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
) -> Result<JobApplyOutcome, DeploymentJobError> {
    payload.validate_for_app(job.app_id, job.org_id)?;
    let primary_image_digest = validate_canonical_source_snapshot(&state.db, job, payload).await?;
    if deployment_is_terminal(&state.db, job.deployment_id).await? {
        return Ok(JobApplyOutcome::AlreadyTerminal);
    }

    // Preflight before queueing on the semaphore, then repeat after capacity is
    // granted. The latest org keyring can change while this future waits.
    validate_apply_artifacts(state, job, payload, &primary_image_digest).await?;

    let Some((apply_permit, mut mutation, mut authority_lane, validated)) =
        acquire_apply_permit_and_revalidate(state, job, payload).await?
    else {
        return Ok(JobApplyOutcome::AlreadyTerminal);
    };

    let edge_config_generation = mutation
        .resource_generation(&crate::mutation_leases::ResourceFence::edge_config())
        .ok_or(crate::mutation_leases::MutationLeaseError::Lost)?;
    let kubernetes_mutation_generation = mutation
        .resource_generation(&crate::mutation_leases::ResourceFence::new(
            "kubernetes_namespace",
            &payload.app.namespace,
        ))
        .ok_or(crate::mutation_leases::MutationLeaseError::Lost)?;
    let rollout = mutation
        .guard_provider_in_tx(
            &mut authority_lane,
            crate::deploy::apply_deployment_manifests(
                ApplyDeploymentManifestsRequest {
                    pool: state.db.clone(),
                    runtime_authority: state.runtime_authority,
                    app: payload.app.clone(),
                    snapshot: payload.snapshot.clone(),
                    // The operation deployment remains distinct from the historical
                    // source/artifact deployment used by rollback signatures. Manifests
                    // and encrypted log frame metadata report this new operation ID.
                    deployment_id: job.deployment_id,
                    attestation_config: payload.attestation_config.clone(),
                    kbs_policy_config: state.kbs_policy.clone(),
                    edge_config_generation,
                    kubernetes_mutation_generation,
                    api_signing_pubkey: payload.api_signing_pubkey.clone(),
                    api_url: payload.api_url.clone(),
                    workload_artifact_binding: validated.workload_artifact_binding,
                    signed_policy_artifact: validated.signed_policy_artifact,
                    local_workload_artifacts_json: validated.local_workload_artifacts_json,
                    local_trustee_policy_json: validated.local_trustee_policy_json,
                    log_encryption: payload.log_encryption.clone(),
                },
                &mutation,
            ),
        )
        .await?;
    drop(apply_permit);
    let rollout = match rollout {
        Ok(rollout) => rollout,
        Err(error) => {
            authority_lane.commit().await?;
            return Ok(JobApplyOutcome::ApplyFailed(error.into(), mutation));
        }
    };
    let Some(rollout) = rollout else {
        mutation.finish_in_tx(&mut authority_lane).await?;
        authority_lane.commit().await?;
        return Ok(JobApplyOutcome::AlreadyTerminal);
    };
    authority_lane.commit().await?;
    let outcome = mutation.guard_provider(rollout.watch()).await?;
    Ok(JobApplyOutcome::Applied(outcome, mutation))
}

async fn acquire_apply_permit_and_revalidate(
    state: &AppState,
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
) -> Result<
    Option<(
        tokio::sync::OwnedSemaphorePermit,
        crate::mutation_leases::AppMutationLease,
        Transaction<'static, Postgres>,
        ValidatedApplyArtifacts,
    )>,
    DeploymentJobError,
> {
    let apply_permit = state
        .deployment_apply_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| DeploymentJobError::ApplyLimiterClosed)?;
    // Keep the apply-specific queue outside durable mutation admission. The
    // mutation claim acquires exactly one shared permit before any connection.
    let resources = deployment_apply_resource_fences(payload);
    let mut mutation = crate::mutation_leases::claim(
        state,
        job.app_id,
        "deployment_apply",
        job.deployment_id,
        false,
        resources,
    )
    .await?;

    // Revalidate every mutable authority immediately before external side
    // effects while holding the global authority order. Keyring rotation,
    // entitlement revocation, app mutation, deletion and generation
    // supersession all take one of these lanes and therefore cannot commit
    // between validation and manifest/KBS application.
    let mut authority_lane = state.db.begin().await?;
    crate::entitlements::lock_org_entitlement_lane(&mut authority_lane, job.org_id).await?;
    crate::signing_service::lock_org_signing_authority_lane(&mut authority_lane, job.org_id)
        .await?;
    crate::deploy::lock_app_deployment_lane(&mut authority_lane, job.app_id).await?;
    let validation: Result<Option<ValidatedApplyArtifacts>, DeploymentJobError> = async {
        let current_job: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                   FROM deployment_apply_jobs
                  WHERE deployment_id = $1
                    AND app_id = $2
                    AND org_id = $3
                    AND state = 'running'
                    AND lock_token = $4
             )",
        )
        .bind(job.deployment_id)
        .bind(job.app_id)
        .bind(job.org_id)
        .bind(job.lock_token)
        .fetch_one(&mut *authority_lane)
        .await?;
        if !current_job
            || !crate::deploy::deployment_is_active_for_apply(
                &mut authority_lane,
                job.app_id,
                job.deployment_id,
            )
            .await?
        {
            return Ok(None);
        }

        let expected_authority = crate::deploy::ExistingAppAuthoritySnapshot::new(
            payload.app.updated_at,
            payload.snapshot.containers.clone(),
            payload.snapshot.resources.clone(),
        );
        if !crate::deploy::verify_existing_app_authority(
            &mut authority_lane,
            job.app_id,
            &expected_authority,
        )
        .await?
        {
            return Err(DeploymentJobError::Authority);
        }
        crate::routes::deployments::enforce_authoritative_entitlement(
            &mut authority_lane,
            job.org_id,
            &payload.snapshot.resources,
            false,
        )
        .await
        .map_err(|_| DeploymentJobError::Authority)?;
        let primary_image_digest =
            validate_canonical_source_snapshot(&state.db, job, payload).await?;
        validate_apply_artifacts(state, job, payload, &primary_image_digest)
            .await
            .map(Some)
    }
    .await;
    let validated = match validation {
        Ok(Some(validated)) => validated,
        Ok(None) => {
            mutation.finish_in_tx(&mut authority_lane).await?;
            authority_lane.commit().await?;
            drop(apply_permit);
            return Ok(None);
        }
        Err(error) => {
            // No provider future has been polled yet, so releasing this claim
            // is safe and avoids quarantining KBS/namespace resources for a
            // stale job or deterministic authority rejection.
            mutation.finish_in_tx(&mut authority_lane).await?;
            authority_lane.commit().await?;
            drop(apply_permit);
            return Err(error);
        }
    };
    Ok(Some((apply_permit, mutation, authority_lane, validated)))
}

fn deployment_apply_resource_fences(
    payload: &DeploymentApplyJobPayload,
) -> Vec<crate::mutation_leases::ResourceFence> {
    let mut resources = vec![
        crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &payload.app.namespace),
        crate::mutation_leases::ResourceFence::kbs_policy(),
        crate::mutation_leases::ResourceFence::edge_config(),
        crate::mutation_leases::ResourceFence::edge(&payload.app.domain),
    ];
    if let Some(tee_domain) = payload.app.tee_domain.as_deref() {
        resources.push(crate::mutation_leases::ResourceFence::edge(tee_domain));
    }
    if let Some(custom_domain) = payload.app.custom_domain.as_deref() {
        resources.push(crate::mutation_leases::ResourceFence::edge(custom_domain));
    }
    resources.sort();
    resources.dedup();
    resources
}

#[derive(Debug)]
struct ValidatedApplyArtifacts {
    workload_artifact_binding: Option<enclava_engine::types::WorkloadArtifactBinding>,
    signed_policy_artifact: Option<crate::signing_service::SignedPolicyArtifact>,
    local_workload_artifacts_json: Option<String>,
    local_trustee_policy_json: Option<String>,
}

async fn validate_apply_artifacts(
    state: &AppState,
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
    primary_image_digest: &str,
) -> Result<ValidatedApplyArtifacts, DeploymentJobError> {
    let currently_signed_required = crate::routes::deployments::customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    );
    if (job.signed_required || currently_signed_required) && job.artifact_deployment_id.is_none() {
        return Err(DeploymentJobError::Artifact);
    }

    let (Some(artifact_deployment_id), Some(expected_descriptor_core_hash)) = (
        job.artifact_deployment_id,
        job.artifact_descriptor_core_hash()?,
    ) else {
        return Ok(ValidatedApplyArtifacts {
            workload_artifact_binding: None,
            signed_policy_artifact: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
        });
    };
    let loaded = crate::signing_service::load_workload_artifacts_exact(
        &state.db,
        job.app_id,
        artifact_deployment_id,
        expected_descriptor_core_hash,
    )
    .await
    .map_err(|_| DeploymentJobError::Artifact)?
    .ok_or(DeploymentJobError::Artifact)?;
    if loaded.descriptor.org_id != job.org_id
        || loaded.descriptor.app_id != job.app_id
        || loaded.descriptor.deploy_id != artifact_deployment_id
        || artifact_deployment_id != job.source_deployment_id
    {
        return Err(DeploymentJobError::Artifact);
    }
    let signing_service_pubkey_hex = state
        .attestation
        .as_ref()
        .and_then(|config| config.signing_service_pubkey_hex.as_deref())
        .ok_or(DeploymentJobError::Artifact)?;
    loaded
        .validate_stored_authority(
            &state.db,
            &payload.app,
            primary_image_digest,
            &payload.api_signing_pubkey,
            signing_service_pubkey_hex,
        )
        .await
        .map_err(|_| DeploymentJobError::Artifact)?;
    validate_signed_render(job, payload, &loaded)?;
    Ok(ValidatedApplyArtifacts {
        workload_artifact_binding: Some(loaded.binding),
        signed_policy_artifact: Some(loaded.signed_policy_artifact),
        local_workload_artifacts_json: Some(loaded.workload_artifacts_json),
        local_trustee_policy_json: Some(loaded.trustee_policy_json),
    })
}

fn snapshot_signed_hash(
    spec_snapshot: &serde_json::Value,
) -> Result<Option<[u8; 32]>, DeploymentJobError> {
    match spec_snapshot.get("signed_descriptor_core_hash") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(hash)) => hex::decode(hash)
            .map_err(|_| DeploymentJobError::InvalidPayload)?
            .try_into()
            .map(Some)
            .map_err(|_: Vec<u8>| DeploymentJobError::InvalidPayload),
        Some(_) => Err(DeploymentJobError::InvalidPayload),
    }
}

fn snapshot_log_encryption(spec_snapshot: &serde_json::Value) -> serde_json::Value {
    spec_snapshot
        .get("log_encryption")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

async fn validate_canonical_source_snapshot(
    pool: &PgPool,
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
) -> Result<String, DeploymentJobError> {
    let operation = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, serde_json::Value)>(
        "SELECT app_id, org_id, image_digest, spec_snapshot
           FROM deployments WHERE id = $1",
    )
    .bind(job.deployment_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    let source = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, serde_json::Value)>(
        "SELECT app_id, org_id, image_digest, spec_snapshot
           FROM deployments WHERE id = $1",
    )
    .bind(job.source_deployment_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if (operation.0, operation.1) != (job.app_id, job.org_id)
        || (source.0, source.1) != (job.app_id, job.org_id)
        || payload.app.id != job.app_id
        || payload.app.org_id != job.org_id
    {
        return Err(DeploymentJobError::InvalidPayload);
    }

    let primary = payload
        .snapshot
        .containers
        .iter()
        .find(|container| container.is_primary)
        .ok_or(DeploymentJobError::InvalidPayload)?;
    let primary_digest = primary
        .image_digest
        .clone()
        .ok_or(DeploymentJobError::InvalidPayload)?;
    if operation.2.as_deref() != Some(primary_digest.as_str())
        || source.2.as_deref() != Some(primary_digest.as_str())
    {
        return Err(DeploymentJobError::InvalidPayload);
    }

    let accepted_log_encryption = serde_json::to_value(&payload.log_encryption)
        .map_err(|_| DeploymentJobError::InvalidPayload)?;
    if snapshot_log_encryption(&operation.3) != accepted_log_encryption
        || snapshot_log_encryption(&source.3) != accepted_log_encryption
    {
        return Err(DeploymentJobError::InvalidPayload);
    }

    let operation_hash = snapshot_signed_hash(&operation.3)?;
    let source_hash = snapshot_signed_hash(&source.3)?;
    match (
        job.artifact_deployment_id,
        job.artifact_descriptor_core_hash()?,
    ) {
        (Some(artifact_deployment_id), Some(expected_hash)) => {
            if artifact_deployment_id != job.source_deployment_id
                || operation_hash != Some(expected_hash)
                || source_hash != Some(expected_hash)
            {
                return Err(DeploymentJobError::Artifact);
            }
        }
        (None, None) if operation_hash.is_none() && source_hash.is_none() => {}
        _ => return Err(DeploymentJobError::Artifact),
    }
    Ok(primary_digest)
}

fn validate_signed_render(
    job: &ClaimedJob,
    payload: &DeploymentApplyJobPayload,
    loaded: &crate::signing_service::LoadedWorkloadArtifacts,
) -> Result<(), DeploymentJobError> {
    let attestation = payload
        .attestation_config
        .as_ref()
        .ok_or(DeploymentJobError::Artifact)?;
    let mut app_spec = crate::deploy::build_confidential_app_from_rows(
        &payload.app,
        job.deployment_id,
        attestation,
        &payload.api_signing_pubkey,
        &payload.api_url,
        &payload.snapshot.containers,
        &payload.snapshot.resources,
    )
    .map_err(|_| DeploymentJobError::Artifact)?;
    app_spec.workload_artifact_binding = Some(loaded.binding.clone());
    app_spec.log_encryption = payload.log_encryption.clone();
    crate::routes::deployments::select_local_signed_artifact_delivery(&mut app_spec.attestation);
    let policy_sha256: [u8; 32] = hex::decode(&loaded.signed_policy_artifact.agent_policy_sha256)
        .map_err(|_| DeploymentJobError::Artifact)?
        .try_into()
        .map_err(|_: Vec<u8>| DeploymentJobError::Artifact)?;
    app_spec.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
        policy_text: loaded.signed_policy_artifact.agent_policy_text.clone(),
        policy_sha256,
        genpolicy_version_pin: loaded
            .signed_policy_artifact
            .metadata
            .genpolicy_version_pin
            .clone(),
    });
    let (_encoded, cc_init_data_hash) =
        enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
    loaded
        .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
        .map_err(|_| DeploymentJobError::Artifact)
}

async fn deployment_is_terminal(
    pool: &PgPool,
    deployment_id: Uuid,
) -> Result<bool, DeploymentJobError> {
    let status =
        sqlx::query_scalar::<_, DeployStatus>("SELECT status FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .fetch_optional(pool)
            .await?
            .ok_or(DeploymentJobError::LeaseLost)?;
    Ok(matches!(
        status,
        DeployStatus::Healthy | DeployStatus::Failed | DeployStatus::RolledBack
    ))
}

async fn fail_apply_job(state: &AppState, job: &ClaimedJob, error: &DeploymentJobError) {
    fail_apply_job_with_mutation(state, job, error, None).await;
}

async fn reconcile_pending_kbs_with_mutation(
    state: &AppState,
    mutation: &crate::mutation_leases::AppMutationLease,
) -> Result<(), DeploymentJobError> {
    mutation
        .guard_provider(crate::kbs::reconcile_pending_signed_policy_artifacts(
            &state.db,
            state.kbs_policy.as_ref(),
            state.runtime_authority,
        ))
        .await??;
    Ok(())
}

async fn release_kbs_resource(
    pool: &PgPool,
    mutation: &mut crate::mutation_leases::AppMutationLease,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    crate::deploy::lock_app_deployment_lane(&mut tx, mutation.app_id()).await?;
    mutation
        .release_resource_in_tx(
            &mut tx,
            &crate::mutation_leases::ResourceFence::kbs_policy(),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn fail_apply_job_with_mutation(
    state: &AppState,
    job: &ClaimedJob,
    error: &DeploymentJobError,
    mut mutation: Option<&mut crate::mutation_leases::AppMutationLease>,
) {
    let published =
        match publish_apply_failure_with_mutation(&state.db, job, mutation.as_deref_mut()).await {
            Ok(()) => true,
            Err(db_error) => {
                tracing::error!(
                    deployment_id = %job.deployment_id,
                    error_code = db_error.code(),
                    "failed to atomically publish durable deployment failure"
                );
                false
            }
        };
    if published && let Some(mutation) = mutation {
        if reconcile_pending_kbs_with_mutation(state, mutation)
            .await
            .is_ok()
        {
            if let Err(release_error) = release_kbs_resource(&state.db, mutation).await {
                tracing::error!(
                    deployment_id = %job.deployment_id,
                    error_code = release_error.code(),
                    "failed to release reconciled global KBS mutation fence"
                );
            }
        } else {
            tracing::error!(
                deployment_id = %job.deployment_id,
                error_code = "kbs_policy_reconciliation_failed",
                "terminal deployment revocation remains durably pending"
            );
        }
    }
    tracing::error!(
        app_id = %job.app_id,
        deployment_id = %job.deployment_id,
        error_code = error.code(),
        "durable deployment apply failed"
    );
}

async fn lock_owned_running_job(
    tx: &mut Transaction<'_, Postgres>,
    job: &ClaimedJob,
) -> Result<(), DeploymentJobError> {
    let owned = sqlx::query_scalar::<_, Uuid>(
        "SELECT deployment_id
           FROM deployment_apply_jobs
          WHERE deployment_id = $1
            AND state = 'running'
            AND lock_token = $2
            AND app_id = $3
            AND org_id = $4
          FOR UPDATE",
    )
    .bind(job.deployment_id)
    .bind(job.lock_token)
    .bind(job.app_id)
    .bind(job.org_id)
    .fetch_optional(&mut **tx)
    .await?;
    if owned.is_none() {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn publish_rollout_outcome_with_mutation(
    pool: &PgPool,
    job: &ClaimedJob,
    outcome: &DeploymentRolloutOutcome,
    mutation: Option<&mut crate::mutation_leases::AppMutationLease>,
) -> Result<(), DeploymentJobError> {
    let failed = outcome.deploy_status == "failed";
    if failed && mutation.is_none() {
        return Err(crate::mutation_leases::MutationLeaseError::Lost.into());
    }
    let mut tx = pool.begin().await?;
    // Canonical order shared with acceptance/delete/rollback/unlock:
    // app advisory lane -> job row -> deployment row -> app row.
    crate::deploy::lock_app_deployment_lane(&mut tx, job.app_id).await?;
    lock_owned_running_job(&mut tx, job).await?;
    let deployment = sqlx::query_as::<_, (Uuid, Uuid, DeployStatus, Option<String>)>(
        "SELECT app_id, org_id, status, manifest_hash
           FROM deployments
          WHERE id = $1
          FOR UPDATE",
    )
    .bind(job.deployment_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if deployment.0 != job.app_id || deployment.1 != job.org_id {
        return Err(DeploymentJobError::InvalidPayload);
    }
    if deployment.2 != DeployStatus::Watching
        || deployment.3.as_deref() != Some(outcome.manifest_hash.as_str())
    {
        return Err(DeploymentJobError::LeaseLost);
    }

    let deployment_result = sqlx::query(
        "UPDATE deployments
            SET status = $1::deploy_status_enum,
                error_message = $2,
                completed_at = CASE WHEN $3 THEN clock_timestamp() ELSE completed_at END
          WHERE id = $4
            AND app_id = $5
            AND org_id = $6
            AND status = 'watching'::deploy_status_enum
            AND manifest_hash = $7",
    )
    .bind(outcome.deploy_status)
    .bind(outcome.error_code)
    .bind(outcome.terminal)
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(&outcome.manifest_hash)
    .execute(&mut *tx)
    .await?;
    if deployment_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    // A nonterminal watch result is a worker projection, not a mutation of
    // accepted app authority. Keep updated_at stable so the immutable payload
    // remains valid when this same job is claimed for its observation retry.
    let app_result = sqlx::query(
        "UPDATE apps
            SET status = $1::app_status_enum,
                updated_at = CASE
                    WHEN $2 THEN clock_timestamp()
                    ELSE updated_at
                END
          WHERE id = $3
            AND org_id = $4
            AND status <> 'deleting'::app_status_enum
            AND $5 = (
                SELECT latest.deployment_id
                  FROM deployment_apply_jobs AS latest
                 WHERE latest.app_id = $3
                 ORDER BY latest.generation DESC
                 LIMIT 1
            )",
    )
    .bind(outcome.app_status)
    .bind(outcome.terminal)
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.deployment_id)
    .execute(&mut *tx)
    .await?;
    if app_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let job_result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = CASE
                    WHEN $1 AND $2 THEN 'rollout_cleanup_pending'
                    WHEN $1 THEN 'completed'
                    ELSE 'pending'
                END,
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = CASE
                    WHEN $1 AND $2
                        THEN clock_timestamp() + $3::interval
                    WHEN $1 THEN next_attempt_at
                    ELSE clock_timestamp() + $4::interval
                END,
                last_error_code = NULL,
                updated_at = clock_timestamp()
          WHERE deployment_id = $5
            AND state = 'running'
            AND lock_token = $6",
    )
    .bind(outcome.terminal)
    .bind(failed)
    .bind(ROLLOUT_CLEANUP_HANDOFF_DELAY_SQL)
    .bind(ROLLOUT_OBSERVATION_RETRY_INTERVAL_SQL)
    .bind(job.deployment_id)
    .bind(job.lock_token)
    .execute(&mut *tx)
    .await?;
    if job_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    if failed {
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx).await?;
    }
    if let Some(mutation) = mutation {
        if failed {
            // Make the durable cleanup job the only authority that can release
            // this exact app/provider generation set. In particular, generic
            // KBS and edge reconcilers must never steal the retained global
            // fences merely because a process-level quarantine elapsed.
            mutation.retain_all_until_reconciled_in_tx(&mut tx).await?;
        } else {
            mutation.finish_in_tx(&mut tx).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
async fn publish_rollout_outcome(
    pool: &PgPool,
    job: &ClaimedJob,
    outcome: &DeploymentRolloutOutcome,
) -> Result<(), DeploymentJobError> {
    publish_rollout_outcome_with_mutation(pool, job, outcome, None).await
}

async fn publish_apply_failure_with_mutation(
    pool: &PgPool,
    job: &ClaimedJob,
    mutation: Option<&mut crate::mutation_leases::AppMutationLease>,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    crate::deploy::lock_app_deployment_lane(&mut tx, job.app_id).await?;
    lock_owned_running_job(&mut tx, job).await?;
    let deployment = sqlx::query_as::<_, (Uuid, Uuid, DeployStatus)>(
        "SELECT app_id, org_id, status
           FROM deployments
          WHERE id = $1
          FOR UPDATE",
    )
    .bind(job.deployment_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if deployment.0 != job.app_id || deployment.1 != job.org_id {
        return Err(DeploymentJobError::InvalidPayload);
    }
    if matches!(
        deployment.2,
        DeployStatus::Healthy | DeployStatus::Failed | DeployStatus::RolledBack
    ) {
        return Err(DeploymentJobError::LeaseLost);
    }

    let deployment_result = sqlx::query(
        "UPDATE deployments
            SET status = 'failed'::deploy_status_enum,
                error_message = $1,
                completed_at = clock_timestamp()
          WHERE id = $2
            AND app_id = $3
            AND org_id = $4
            AND status IN ('pending', 'applying', 'watching')",
    )
    .bind(DEPLOYMENT_APPLY_FAILED_MESSAGE)
    .bind(job.deployment_id)
    .bind(job.app_id)
    .bind(job.org_id)
    .execute(&mut *tx)
    .await?;
    if deployment_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let app_result = sqlx::query(
        "UPDATE apps
            SET status = 'failed'::app_status_enum,
                updated_at = clock_timestamp()
          WHERE id = $1
            AND org_id = $2
            AND status <> 'deleting'::app_status_enum
            AND $3 = (
                SELECT latest.deployment_id
                  FROM deployment_apply_jobs AS latest
                 WHERE latest.app_id = $1
                 ORDER BY latest.generation DESC
                 LIMIT 1
            )",
    )
    .bind(job.app_id)
    .bind(job.org_id)
    .bind(job.deployment_id)
    .execute(&mut *tx)
    .await?;
    if app_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let job_result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'failed',
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = $1,
                updated_at = clock_timestamp()
          WHERE deployment_id = $2
            AND state = 'running'
            AND lock_token = $3",
    )
    .bind(DEPLOYMENT_APPLY_FAILED_MESSAGE)
    .bind(job.deployment_id)
    .bind(job.lock_token)
    .execute(&mut *tx)
    .await?;
    if job_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx).await?;
    if let Some(mutation) = mutation {
        // A deploy error can follow partial Kubernetes/KBS publication or a
        // local timeout. Fence the terminal DB publication, but deliberately
        // retain the provider generations through their reclaim quarantine so
        // a late response cannot clobber the next accepted generation.
        mutation.assert_current_in_tx(&mut tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
async fn publish_apply_failure(pool: &PgPool, job: &ClaimedJob) -> Result<(), DeploymentJobError> {
    publish_apply_failure_with_mutation(pool, job, None).await
}

async fn finish_job(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &str,
    last_error_code: Option<&str>,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = $1,
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = $2,
                updated_at = clock_timestamp()
          WHERE deployment_id = $3
            AND state = 'running'
            AND lock_token = $4",
    )
    .bind(state)
    .bind(last_error_code)
    .bind(deployment_id)
    .bind(lock_token)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

fn with_lease_heartbeat<'a, F, T>(
    pool: &'a PgPool,
    runtime_authority: crate::runtime_authority::RuntimeAuthority,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &'a str,
    future: F,
) -> impl Future<Output = Result<T, DeploymentJobError>> + 'a
where
    F: Future<Output = T> + 'a,
{
    let mut future = Box::pin(future);
    async move {
        // Renew immediately after the claim transaction commits and before the
        // future is first polled. `clock_timestamp()` is wall-clock time even in a
        // long transaction; `now()` would reuse the transaction start timestamp.
        renew_job_lease_bounded(pool, runtime_authority, deployment_id, lock_token, state).await?;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
            HEARTBEAT_INTERVAL,
        );
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                output = &mut future => return Ok(output),
                _ = heartbeat.tick() => {
                    renew_job_lease_bounded(
                        pool,
                        runtime_authority,
                        deployment_id,
                        lock_token,
                        state,
                    )
                    .await?;
                }
            }
        }
    }
}

async fn renew_job_lease_bounded(
    pool: &PgPool,
    runtime_authority: crate::runtime_authority::RuntimeAuthority,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &str,
) -> Result<(), DeploymentJobError> {
    tokio::time::timeout(
        HEARTBEAT_RENEW_TIMEOUT,
        renew_job_lease(pool, runtime_authority, deployment_id, lock_token, state),
    )
    .await
    .map_err(|_| DeploymentJobError::LeaseLost)?
}

async fn renew_job_lease(
    pool: &PgPool,
    runtime_authority: crate::runtime_authority::RuntimeAuthority,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &str,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    if !runtime_authority.is_current_in_tx(&mut tx).await? {
        return Err(crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority.into());
    }
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET locked_until = clock_timestamp() + $1::interval,
                updated_at = clock_timestamp()
          WHERE deployment_id = $2
            AND state = $3
            AND lock_token = $4",
    )
    .bind(LEASE_INTERVAL_SQL)
    .bind(deployment_id)
    .bind(state)
    .bind(lock_token)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use ed25519_dalek::{Signer, SigningKey};
    use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
    use enclava_common::descriptor::{
        Capabilities, DeploymentDescriptor, OciRuntimeSpec, Resources, SecurityContext, Sidecars,
        SignerIdentity, descriptor_canonical_bytes, descriptor_core_hash,
    };
    use enclava_engine::manifest::containers::ENCLAVA_WAIT_EXEC_PATH;
    use enclava_engine::types::{GeneratedAgentPolicy, WorkloadArtifactBinding};
    use sqlx::types::Json;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn lease_heartbeat_does_not_duplicate_large_future_state() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://stack-size.invalid/enclava")
            .expect("lazy pool does not connect");
        let payload = [0_u8; 32 * 1024];
        let operation = async move {
            std::future::pending::<()>().await;
            std::hint::black_box(payload);
        };
        let operation_size = std::mem::size_of_val(&operation);
        assert!(
            operation_size >= payload.len(),
            "size canary must retain its {}-byte payload, got {operation_size}",
            payload.len()
        );
        let heartbeat = with_lease_heartbeat(
            &pool,
            crate::runtime_authority::TEST_RUNTIME_AUTHORITY,
            Uuid::nil(),
            Uuid::nil(),
            "running",
            operation,
        );
        let heartbeat_size = std::mem::size_of_val(&heartbeat);

        fn assert_send<T: Send>(_: &T) {}
        assert_send(&heartbeat);

        assert!(
            heartbeat_size <= 8 * 1024,
            "lease heartbeat amplified future state from {operation_size} to {heartbeat_size} bytes"
        );
    }

    async fn database_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect deployment job test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate deployment job test database");
        pool
    }

    #[tokio::test]
    async fn stale_runtime_authority_rejects_job_heartbeat_before_polling_cleanup() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let claimed = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup job for stale heartbeat")
            .expect("setup job exists");
        let deadline_before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT locked_until
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load deadline before stale heartbeat");

        let mut stale_authority = crate::runtime_authority::TEST_RUNTIME_AUTHORITY;
        stale_authority.epoch = Uuid::new_v4();
        let provider_polled = Arc::new(AtomicBool::new(false));
        let mark_polled = provider_polled.clone();
        let error = with_lease_heartbeat(
            &pool,
            stale_authority,
            deployment_id,
            claimed.lock_token,
            "setting_up",
            async move {
                mark_polled.store(true, Ordering::SeqCst);
            },
        )
        .await
        .expect_err("stale cleanup heartbeat must fail before provider work");
        assert!(matches!(
            error,
            DeploymentJobError::Mutation(
                crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority
            )
        ));
        assert!(!provider_polled.load(Ordering::SeqCst));
        let deadline_after: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT locked_until
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load deadline after stale heartbeat");
        assert_eq!(deadline_after, deadline_before);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete stale heartbeat fixture");
    }

    fn test_app(org_id: Uuid, app_id: Uuid) -> App {
        let now = chrono::Utc::now();
        let suffix = app_id.simple().to_string();
        App {
            id: app_id,
            org_id,
            name: format!("durable-{}", &suffix[..12]),
            namespace: format!("cap-durable-{}", &suffix[..12]),
            instance_id: format!("durable-{suffix}"),
            tenant_id: suffix[..8].to_string(),
            service_account: format!("cap-durable-{}-sa", &suffix[..12]),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: crate::models::UnlockMode::Auto,
            domain: format!("durable-{}.enclava.dev", &suffix[..12]),
            tee_domain: Some(format!("durable-{}.tee.enclava.dev", &suffix[..12])),
            custom_domain: None,
            status: crate::models::AppStatus::Creating,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    fn test_payload(app: &App) -> DeploymentApplyJobPayload {
        DeploymentApplyJobPayload::new(
            app.clone(),
            DeploymentApplySnapshot::new(
                vec![crate::models::AppContainer {
                    id: Uuid::new_v4(),
                    app_id: app.id,
                    name: "web".to_string(),
                    image_ref: "ghcr.io/acme/app".to_string(),
                    image_digest: Some(format!("sha256:{}", "aa".repeat(32))),
                    port: None,
                    command: None,
                    storage_paths: None,
                    workload_security_profile: Some("restricted".to_string()),
                    is_primary: true,
                }],
                crate::models::AppResources {
                    app_id: app.id,
                    cpu_limit: "1".to_string(),
                    memory_limit: "1Gi".to_string(),
                    app_data_size: "5Gi".to_string(),
                    tls_data_size: "2Gi".to_string(),
                },
            ),
            None,
            "api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        )
    }

    async fn insert_job_fixture(
        pool: &PgPool,
    ) -> (App, Uuid, SetupJobLease, DeploymentApplyJobPayload) {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let mut app = test_app(org_id, app_id);
        let mut payload = test_payload(&app);
        let mut tx = pool.begin().await.expect("begin deployment job fixture");
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("durable-{org_id}"))
        .bind(&org_id.simple().to_string()[..8])
        .execute(&mut *tx)
        .await
        .expect("insert deployment job organization");
        sqlx::query(
            "INSERT INTO apps (
                id, org_id, name, namespace, instance_id, tenant_id,
                service_account, bootstrap_owner_pubkey_hash,
                tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                status, egress_allowlist, egress_mode, created_at, updated_at
             )
             VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum,
                $11, $12, $13::app_status_enum, $14, $15, $16, $17
             )",
        )
        .bind(app.id)
        .bind(app.org_id)
        .bind(&app.name)
        .bind(&app.namespace)
        .bind(&app.instance_id)
        .bind(&app.tenant_id)
        .bind(&app.service_account)
        .bind(&app.bootstrap_owner_pubkey_hash)
        .bind(&app.tenant_instance_identity_hash)
        .bind(app.unlock_mode)
        .bind(&app.domain)
        .bind(app.tee_domain.as_deref())
        .bind(app.status)
        .bind(&app.egress_allowlist)
        .bind(&app.egress_mode)
        .bind(app.created_at)
        .bind(app.updated_at)
        .execute(&mut *tx)
        .await
        .expect("insert deployment job app");
        app = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
            .bind(app.id)
            .fetch_one(&mut *tx)
            .await
            .expect("reload exact deployment job app");
        payload.app = app.clone();
        for container in &payload.snapshot.containers {
            sqlx::query(
                "INSERT INTO app_containers (
                     id, app_id, name, image_ref, image_digest, port, command,
                     storage_paths, workload_security_profile, is_primary
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(container.id)
            .bind(container.app_id)
            .bind(&container.name)
            .bind(&container.image_ref)
            .bind(container.image_digest.as_deref())
            .bind(container.port)
            .bind(container.command.as_deref())
            .bind(container.storage_paths.as_ref())
            .bind(container.workload_security_profile.as_deref())
            .bind(container.is_primary)
            .execute(&mut *tx)
            .await
            .expect("insert deployment job container");
        }
        sqlx::query(
            "INSERT INTO app_resources (
                 app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(payload.snapshot.resources.app_id)
        .bind(&payload.snapshot.resources.cpu_limit)
        .bind(&payload.snapshot.resources.memory_limit)
        .bind(&payload.snapshot.resources.app_data_size)
        .bind(&payload.snapshot.resources.tls_data_size)
        .execute(&mut *tx)
        .await
        .expect("insert deployment job resources");
        let image_digest = format!("sha256:{}", "aa".repeat(32));
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, spec_snapshot, image_digest
             ) VALUES ($1, $2, $3, 'api', $4, $5)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(serde_json::json!({
            "setup_state": DEPLOYMENT_SETUP_DNS_PENDING,
            "image": "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "image_digest": &image_digest,
            "signed_descriptor_core_hash": null,
            "log_encryption": null,
        }))
        .bind(&image_digest)
        .execute(&mut *tx)
        .await
        .expect("insert deployment job deployment");
        let lease = insert_setup_job(&mut tx, deployment_id, deployment_id, &payload, false)
            .await
            .expect("insert setup job");
        tx.commit().await.expect("commit deployment job fixture");
        (app, deployment_id, lease, payload)
    }

    async fn replace_job_with_raw_payload(
        pool: &PgPool,
        deployment_id: Uuid,
        payload: serde_json::Value,
        payload_version: i32,
        cleanup_app_on_setup_failure: bool,
        state: &str,
    ) {
        let payload_sha256 = canonical_payload_hash(&payload).expect("hash raw job payload");
        let log_encryption = payload
            .get("log_encryption")
            .filter(|value| !value.is_null())
            .cloned();
        let mut tx = pool.begin().await.expect("begin raw job replacement");
        sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
            .bind(deployment_id)
            .execute(&mut *tx)
            .await
            .expect("delete original job in replacement transaction");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state
             )
             SELECT id, app_id, org_id, id, $2, $3, $4, $5, false,
                    NULL, NULL, $6, $7
               FROM deployments
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(payload_version)
        .bind(payload)
        .bind(payload_sha256.to_vec())
        .bind(cleanup_app_on_setup_failure)
        .bind(log_encryption)
        .bind(state)
        .execute(&mut *tx)
        .await
        .expect("insert raw replacement job");
        tx.commit().await.expect("commit raw job replacement");
    }

    async fn recreate_test_deployment_with_signed_hash(
        tx: &mut Transaction<'_, Postgres>,
        deployment_id: Uuid,
        descriptor_hash: [u8; 32],
    ) {
        let (org_id, app_id, mut spec_snapshot, image_digest): (
            Uuid,
            Uuid,
            serde_json::Value,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT org_id, app_id, spec_snapshot, image_digest
               FROM deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&mut **tx)
        .await
        .expect("load deployment before signed test recreation");
        sqlx::query("DELETE FROM deployments WHERE id = $1")
            .bind(deployment_id)
            .execute(&mut **tx)
            .await
            .expect("delete unsigned deployment before signed test recreation");
        spec_snapshot["signed_descriptor_core_hash"] =
            serde_json::json!(hex::encode(descriptor_hash));
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, status, spec_snapshot, image_digest
             ) VALUES (
                 $1, $2, $3, 'api'::trigger_enum, 'pending'::deploy_status_enum, $4, $5
             )",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(spec_snapshot)
        .bind(image_digest)
        .execute(&mut **tx)
        .await
        .expect("recreate canonical signed test deployment");
    }

    async fn replace_job_with_fake_signed_binding(
        pool: &PgPool,
        deployment_id: Uuid,
        mut payload: DeploymentApplyJobPayload,
    ) -> [u8; 32] {
        let descriptor_hash = [0x5a; 32];
        payload.artifact_deployment_id = Some(deployment_id);
        payload.artifact_descriptor_core_hash = Some(descriptor_hash);
        let (payload_value, payload_sha256) = payload
            .canonical_value_and_hash()
            .expect("hash fake signed payload");
        let mut tx = pool.begin().await.expect("begin fake signed replacement");
        recreate_test_deployment_with_signed_hash(&mut tx, deployment_id, descriptor_hash).await;
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             )
             SELECT $2, app_id, id,
                    jsonb_build_object('app_id', app_id, 'deploy_id', id),
                    $3, 'fake-key', '{}'::jsonb, $4, '{}'::jsonb
               FROM deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(descriptor_hash.to_vec())
        .bind(vec![0_u8; 64])
        .bind(vec![0_u8; 64])
        .execute(&mut *tx)
        .await
        .expect("insert fake signed artifact binding");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state
             )
             SELECT id, app_id, org_id, id, $2, $3, $4, false, true,
                    id, $5, NULL, 'setup_pending'
               FROM deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(JOB_PAYLOAD_VERSION)
        .bind(payload_value)
        .bind(payload_sha256.to_vec())
        .bind(descriptor_hash.to_vec())
        .execute(&mut *tx)
        .await
        .expect("insert fake signed job");
        tx.commit().await.expect("commit fake signed replacement");
        descriptor_hash
    }

    struct TestKeyringAuthority {
        owner_key: SigningKey,
        user_id: Uuid,
        signing_key_id: Uuid,
        member_added_at: chrono::DateTime<chrono::Utc>,
    }

    fn signed_test_keyring(
        org_id: Uuid,
        authority: &TestKeyringAuthority,
        version: u64,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let pubkey = authority.owner_key.verifying_key().to_bytes();
        let added_at = authority.member_added_at.to_rfc3339();
        let member_hash = ce_v1_hash(&[
            ("user_id", authority.user_id.as_bytes().as_slice()),
            ("pubkey", pubkey.as_slice()),
            ("role", b"owner"),
            ("added_at", added_at.as_bytes()),
        ]);
        let user_id_label = authority.user_id.to_string();
        let members_hash = ce_v1_hash(&[(user_id_label.as_str(), member_hash.as_slice())]);
        let version_bytes = version.to_be_bytes();
        let updated_at_text = updated_at.to_rfc3339();
        let canonical = ce_v1_bytes(&[
            ("purpose", b"enclava-org-keyring-v1"),
            ("org_id", org_id.as_bytes().as_slice()),
            ("version", &version_bytes),
            ("members", &members_hash),
            ("updated_at", updated_at_text.as_bytes()),
        ]);
        let signature = authority.owner_key.sign(&canonical).to_bytes().to_vec();
        let keyring = serde_json::json!({
            "org_id": org_id,
            "version": version,
            "members": [{
                "user_id": authority.user_id,
                "pubkey": hex::encode(pubkey),
                "role": "owner",
                "added_at": authority.member_added_at,
            }],
            "updated_at": updated_at,
        });
        let envelope = serde_json::json!({
            "keyring": keyring,
            "signature": hex::encode(&signature),
            "signing_pubkey": hex::encode(pubkey),
        });
        (keyring, envelope, signature)
    }

    async fn insert_test_keyring_version(
        pool: &PgPool,
        org_id: Uuid,
        authority: &TestKeyringAuthority,
        version: u64,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        let (keyring, envelope, signature) =
            signed_test_keyring(org_id, authority, version, updated_at);
        sqlx::query(
            "INSERT INTO org_keyrings (
                 org_id, version, keyring_payload, signature, signing_key_id
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(version as i64)
        .bind(serde_json::to_vec(&keyring).expect("serialize test keyring"))
        .bind(signature)
        .bind(authority.signing_key_id)
        .execute(pool)
        .await
        .expect("insert test keyring version");
        envelope
    }

    async fn replace_job_with_valid_signed_binding(
        pool: &PgPool,
        deployment_id: Uuid,
        mut payload: DeploymentApplyJobPayload,
        state: &mut AppState,
    ) -> (DeploymentApplyJobPayload, TestKeyringAuthority) {
        let owner_key = SigningKey::from_bytes(&[0x41; 32]);
        let platform_key = SigningKey::from_bytes(&[0x52; 32]);
        payload.app.signer_identity_subject = Some(
            "https://github.com/acme/app/.github/workflows/deploy.yml@refs/heads/main".to_string(),
        );
        payload.app.signer_identity_issuer =
            Some("https://token.actions.githubusercontent.com".to_string());
        payload.app.signer_identity_set_at = Some(chrono::Utc::now());
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = $2,
                    signer_identity_issuer = $3,
                    signer_identity_set_at = $4
              WHERE id = $1",
        )
        .bind(payload.app.id)
        .bind(payload.app.signer_identity_subject.as_deref())
        .bind(payload.app.signer_identity_issuer.as_deref())
        .bind(payload.app.signer_identity_set_at)
        .execute(pool)
        .await
        .expect("record signed fixture identity");
        let user_id = Uuid::new_v4();
        let signing_key_id = Uuid::new_v4();
        let member_added_at = chrono::Utc::now();
        let authority = TestKeyringAuthority {
            owner_key,
            user_id,
            signing_key_id,
            member_added_at,
        };
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'durable signer')")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("insert durable signer user");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner'::role_enum)",
        )
        .bind(user_id)
        .bind(payload.app.org_id)
        .execute(pool)
        .await
        .expect("insert durable signer membership");
        sqlx::query(
            "INSERT INTO user_signing_keys (id, user_id, pubkey)
             VALUES ($1, $2, $3)",
        )
        .bind(signing_key_id)
        .bind(user_id)
        .bind(authority.owner_key.verifying_key().to_bytes().to_vec())
        .execute(pool)
        .await
        .expect("insert durable signer key");
        let keyring_envelope =
            insert_test_keyring_version(pool, payload.app.org_id, &authority, 1, member_added_at)
                .await;

        let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());
        state
            .attestation
            .as_mut()
            .expect("signed fixture attestation")
            .signing_service_pubkey_hex = Some(platform_pubkey_hex.clone());
        state.require_customer_signed_policy_artifact = true;
        payload.attestation_config = state.attestation.clone();

        let image_digest = payload.snapshot.containers[0]
            .image_digest
            .clone()
            .expect("signed fixture image digest");
        let agent_policy_text =
            "package agent_policy\n\ndefault CreateContainerRequest := true\n".to_string();
        let rego_text = "package policy\n\ndefault allow := false\n".to_string();
        let agent_policy_hash: [u8; 32] = Sha256::digest(agent_policy_text.as_bytes()).into();
        let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
        let mut descriptor = DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: payload.app.org_id,
            org_slug: payload.app.tenant_id.clone(),
            app_id: payload.app.id,
            app_name: payload.app.name.clone(),
            deploy_id: deployment_id,
            created_at: chrono::Utc::now(),
            nonce: [0x13; 32],
            app_domain: payload.app.domain.clone(),
            tee_domain: payload
                .app
                .tee_domain
                .clone()
                .unwrap_or_else(|| payload.app.domain.clone()),
            custom_domains: payload.app.custom_domain.clone().into_iter().collect(),
            namespace: payload.app.namespace.clone(),
            service_account: payload.app.service_account.clone(),
            identity_hash: hex::decode(&payload.app.tenant_instance_identity_hash)
                .expect("decode fixture identity hash")
                .try_into()
                .expect("fixture identity hash length"),
            image_ref: format!("ghcr.io/acme/app@{image_digest}"),
            image_digest: image_digest.clone(),
            signer_identity: SignerIdentity {
                subject: payload
                    .app
                    .signer_identity_subject
                    .clone()
                    .unwrap_or_default(),
                issuer: payload
                    .app
                    .signer_identity_issuer
                    .clone()
                    .unwrap_or_default(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec![ENCLAVA_WAIT_EXEC_PATH.to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![],
                ports: vec![],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: format!("sha256:{}", "11".repeat(32)),
                caddy_digest: format!("sha256:{}", "22".repeat(32)),
            },
            api_signing_pubkey: payload.api_signing_pubkey.clone(),
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: format!("default/{}-owner", payload.app.namespace),
            unlock_mode: "auto".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "cap-test".to_string(),
            expected_agent_policy_hash: agent_policy_hash,
            expected_cc_init_data_hash: [0; 32],
            expected_kbs_policy_hash: rego_hash,
        };
        let descriptor_hash = descriptor_core_hash(&descriptor);
        // Decode through the production adapter so the runtime binding uses
        // the exact CE-v1 keyring fingerprint implementation.
        let provisional_descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": "00".repeat(64),
            "signing_key_id": "durable-owner",
            "signing_pubkey": hex::encode(authority.owner_key.verifying_key().to_bytes()),
        })
        .to_string();
        let provisional = crate::signing_service::decode_optional_blobs(
            Some(provisional_descriptor_blob),
            Some(keyring_envelope.to_string()),
        )
        .expect("decode provisional signed fixture")
        .expect("provisional signed fixture exists");
        let binding = provisional.binding();
        assert_eq!(binding.descriptor_core_hash, descriptor_hash);

        let mut app_spec = crate::deploy::build_confidential_app_from_rows(
            &payload.app,
            deployment_id,
            payload
                .attestation_config
                .as_ref()
                .expect("signed fixture payload attestation"),
            &payload.api_signing_pubkey,
            &payload.api_url,
            &payload.snapshot.containers,
            &payload.snapshot.resources,
        )
        .expect("build signed fixture runtime");
        app_spec.workload_artifact_binding = Some(WorkloadArtifactBinding {
            descriptor_core_hash: binding.descriptor_core_hash,
            descriptor_signing_pubkey: binding.descriptor_signing_pubkey,
            org_keyring_fingerprint: binding.org_keyring_fingerprint,
        });
        crate::routes::deployments::select_local_signed_artifact_delivery(
            &mut app_spec.attestation,
        );
        app_spec.generated_agent_policy = Some(GeneratedAgentPolicy {
            policy_text: agent_policy_text.clone(),
            policy_sha256: agent_policy_hash,
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
        });
        let (_, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        descriptor.expected_cc_init_data_hash = hex::decode(cc_init_data_hash)
            .expect("decode signed fixture cc-init hash")
            .try_into()
            .expect("signed fixture cc-init hash length");

        let descriptor_signature = authority
            .owner_key
            .sign(&descriptor_canonical_bytes(&descriptor));
        let descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": hex::encode(descriptor_signature.to_bytes()),
            "signing_key_id": "durable-owner",
            "signing_pubkey": hex::encode(authority.owner_key.verifying_key().to_bytes()),
        })
        .to_string();
        let artifacts = crate::signing_service::decode_optional_blobs(
            Some(descriptor_blob),
            Some(keyring_envelope.to_string()),
        )
        .expect("decode signed fixture")
        .expect("signed fixture exists");
        artifacts
            .validate_customer_authority(pool)
            .await
            .expect("validate initial signed fixture authority");

        let metadata = crate::signing_service::PolicyMetadata {
            app_id: payload.app.id.to_string(),
            deploy_id: deployment_id.to_string(),
            descriptor_core_hash: hex::encode(artifacts.descriptor_core_hash),
            descriptor_signing_pubkey: hex::encode(artifacts.descriptor_signing_pubkey),
            platform_release_version: artifacts.descriptor.platform_release_version.clone(),
            policy_template_id: artifacts.descriptor.policy_template_id.clone(),
            policy_template_sha256: hex::encode(artifacts.descriptor.policy_template_sha256),
            agent_policy_sha256: hex::encode(agent_policy_hash),
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            signed_at: "2026-07-17T00:00:00+00:00".to_string(),
            key_id: "durable-policy-key".to_string(),
        };
        let metadata_hash = ce_v1_hash(&[
            ("app_id", payload.app.id.as_bytes().as_slice()),
            ("deploy_id", deployment_id.as_bytes().as_slice()),
            ("descriptor_core_hash", &artifacts.descriptor_core_hash),
            (
                "descriptor_signing_pubkey",
                &artifacts.descriptor_signing_pubkey,
            ),
            (
                "platform_release_version",
                metadata.platform_release_version.as_bytes(),
            ),
            ("policy_template_id", metadata.policy_template_id.as_bytes()),
            (
                "policy_template_sha256",
                &artifacts.descriptor.policy_template_sha256,
            ),
            ("agent_policy_sha256", &agent_policy_hash),
            (
                "genpolicy_version_pin",
                metadata.genpolicy_version_pin.as_bytes(),
            ),
            ("signed_at", metadata.signed_at.as_bytes()),
            ("key_id", metadata.key_id.as_bytes()),
        ]);
        let signing_input = ce_v1_bytes(&[
            ("purpose", b"enclava-policy-artifact-v1"),
            ("metadata", &metadata_hash),
            ("rego_sha256", &rego_hash),
        ]);
        let mut signed_policy_artifact = crate::signing_service::SignedPolicyArtifact {
            metadata,
            rego_text,
            rego_sha256: hex::encode(rego_hash),
            agent_policy_text,
            agent_policy_sha256: hex::encode(agent_policy_hash),
            signature: hex::encode(platform_key.sign(&signing_input).to_bytes()),
            verify_pubkey_b64: B64.encode(platform_key.verifying_key().to_bytes()),
            org_keyring: None,
        };
        artifacts
            .validate_signed_artifact(&signed_policy_artifact, &platform_pubkey_hex)
            .expect("validate signed fixture policy");
        artifacts
            .attach_customer_authority(&mut signed_policy_artifact)
            .expect("attach signed fixture authority");

        payload.artifact_deployment_id = Some(deployment_id);
        payload.artifact_descriptor_core_hash = Some(artifacts.descriptor_core_hash);
        let mut tx = pool.begin().await.expect("begin valid signed replacement");
        recreate_test_deployment_with_signed_hash(
            &mut tx,
            deployment_id,
            artifacts.descriptor_core_hash,
        )
        .await;
        crate::signing_service::persist_workload_artifacts(
            &mut *tx,
            payload.app.id,
            deployment_id,
            &artifacts,
            &signed_policy_artifact,
        )
        .await
        .expect("persist valid signed fixture");
        insert_setup_job(&mut tx, deployment_id, deployment_id, &payload, true)
            .await
            .expect("insert valid signed durable job");
        tx.commit()
            .await
            .expect("commit valid signed durable replacement");
        (payload, authority)
    }

    #[test]
    fn durable_payload_rejects_cross_app_rows() {
        let now = chrono::Utc::now();
        let app_id = Uuid::new_v4();
        let app = App {
            id: app_id,
            org_id: Uuid::new_v4(),
            name: "durable-app".to_string(),
            namespace: "cap-durable-app".to_string(),
            instance_id: "durable-instance".to_string(),
            tenant_id: "deadbeef".to_string(),
            service_account: "cap-durable-app-sa".to_string(),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: crate::models::UnlockMode::Auto,
            domain: "durable-app.deadbeef.enclava.dev".to_string(),
            tee_domain: Some("durable-app.deadbeef.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: crate::models::AppStatus::Creating,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: now,
            updated_at: now,
        };
        let payload = DeploymentApplyJobPayload::new(
            app,
            DeploymentApplySnapshot::new(
                vec![crate::models::AppContainer {
                    id: Uuid::new_v4(),
                    app_id: Uuid::new_v4(),
                    name: "web".to_string(),
                    image_ref: "ghcr.io/acme/app".to_string(),
                    image_digest: Some(format!("sha256:{}", "aa".repeat(32))),
                    port: None,
                    command: None,
                    storage_paths: None,
                    workload_security_profile: Some("restricted".to_string()),
                    is_primary: true,
                }],
                crate::models::AppResources {
                    app_id,
                    cpu_limit: "1".to_string(),
                    memory_limit: "1Gi".to_string(),
                    app_data_size: "5Gi".to_string(),
                    tls_data_size: "2Gi".to_string(),
                },
            ),
            None,
            "api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        );

        assert!(matches!(
            payload.validate_for_app(payload.app.id, payload.app.org_id),
            Err(DeploymentJobError::InvalidPayload)
        ));
    }

    #[test]
    fn durable_payload_hash_binds_the_full_runtime_snapshot() {
        let app = test_app(Uuid::new_v4(), Uuid::new_v4());
        let payload = test_payload(&app);
        let (mut value, accepted_hash) = payload
            .canonical_value_and_hash()
            .expect("hash accepted runtime payload");
        value["snapshot"]["resources"]["cpu_limit"] = serde_json::json!("64");
        let claimed = ClaimedJob {
            deployment_id: Uuid::new_v4(),
            app_id: app.id,
            org_id: app.org_id,
            source_deployment_id: Uuid::new_v4(),
            payload_version: JOB_PAYLOAD_VERSION,
            lock_token: Uuid::new_v4(),
            payload: value,
            payload_sha256: accepted_hash.to_vec(),
            cleanup_app_on_setup_failure: false,
            signed_required: false,
            artifact_deployment_id: None,
            artifact_descriptor_core_hash: None,
            log_encryption: None,
        };

        assert!(matches!(
            claimed.decode_payload(),
            Err(DeploymentJobError::InvalidPayload)
        ));
    }

    #[test]
    fn deployment_worker_backlog_is_bounded() {
        assert_eq!(apply_worker_limit(0), 4);
        assert_eq!(apply_worker_limit(1), 4);
        assert_eq!(apply_worker_limit(4), 16);
        assert_eq!(apply_worker_limit(usize::MAX), MAX_APPLY_WORKERS);
    }

    #[tokio::test]
    async fn expired_setup_and_apply_leases_recover_after_restart() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let original_setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim initial setup")
            .expect("initial setup job exists");

        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire setup lease");
        let recovered_setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim expired setup")
            .expect("expired setup job exists");
        assert_ne!(recovered_setup.lock_token, original_setup.lock_token);

        mark_setup_accepted(&pool, deployment_id, recovered_setup.lock_token)
            .await
            .expect("atomically accept recovered setup");
        let (setup_state, job_state): (String, String) = sqlx::query_as(
            "SELECT d.spec_snapshot->>'setup_state', j.state
               FROM deployments d
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load accepted recovered setup");
        assert_eq!(setup_state, DEPLOYMENT_SETUP_ACCEPTED);
        assert_eq!(job_state, "pending");

        let first_apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim ready apply")
            .expect("ready apply job exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate apply worker crash");
        let recovered_apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("reclaim crashed apply")
            .expect("crashed apply job exists");
        assert_ne!(recovered_apply.lock_token, first_apply.lock_token);
        let recovered_payload = recovered_apply
            .decode_payload()
            .expect("decode recovered payload");
        assert_eq!(recovered_payload.app.id, app.id);

        let attempts: i32 = sqlx::query_scalar(
            "SELECT attempts FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load recovered attempt count");
        assert_eq!(attempts, 4);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment job fixture");
    }

    #[tokio::test]
    async fn expired_watching_lease_is_reclaimed_and_publishes_terminal_result() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let first_apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim first apply")
            .expect("apply exists");
        let manifest_hash = "reclaimed-watching-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage worker crash during watch");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire watching worker lease");
        let recovered = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("reclaim watching apply")
            .expect("watching apply is reclaimable");
        assert_ne!(recovered.lock_token, first_apply.lock_token);

        let mut lane = pool.begin().await.expect("begin reclaimed app lane");
        crate::deploy::lock_app_deployment_lane(&mut lane, app.id)
            .await
            .expect("lock reclaimed app lane");
        assert!(
            crate::deploy::deployment_is_active_for_apply(&mut lane, app.id, deployment_id,)
                .await
                .expect("check reclaimed watching generation"),
            "watching remains an active, idempotently re-applicable generation"
        );
        lane.rollback().await.expect("release reclaimed app lane");

        publish_rollout_outcome(
            &pool,
            &recovered,
            &DeploymentRolloutOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_code: None,
                terminal: true,
                manifest_hash: manifest_hash.to_string(),
            },
        )
        .await
        .expect("publish recovered rollout result");
        let (deployment_status, app_status, job_state): (String, String, String) = sqlx::query_as(
            "SELECT deployment.status::text, app.status::text, job.state
                   FROM deployments AS deployment
                   JOIN apps AS app ON app.id = deployment.app_id
                   JOIN deployment_apply_jobs AS job
                     ON job.deployment_id = deployment.id
                  WHERE deployment.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load recovered terminal state");
        assert_eq!(deployment_status, "healthy");
        assert_eq!(app_status, "running");
        assert_eq!(job_state, "completed");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete watching recovery fixture");
    }

    #[tokio::test]
    async fn failed_rollout_cleanup_survives_retry_and_worker_crash_before_atomic_release() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);

        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim failed-rollout setup")
            .expect("failed-rollout setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept failed-rollout setup");
        let apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim failed rollout apply")
            .expect("failed rollout apply exists");
        let expected_resources = deployment_apply_resource_fences(&payload);
        let mut mutation = crate::mutation_leases::claim(
            &state,
            app.id,
            "deployment_apply",
            deployment_id,
            false,
            expected_resources.clone(),
        )
        .await
        .expect("claim failed rollout mutation");
        mutation
            .arm_resource_scope_until_reconciled("kubernetes_namespace")
            .await
            .expect("retain namespace until terminal cleanup");

        let manifest_hash = "failed-rollout-cleanup-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage failed rollout watcher");
        publish_rollout_outcome_with_mutation(
            &pool,
            &apply,
            &DeploymentRolloutOutcome {
                deploy_status: "failed",
                app_status: "failed",
                error_code: Some("rollout_failed"),
                terminal: true,
                manifest_hash: manifest_hash.to_string(),
            },
            Some(&mut mutation),
        )
        .await
        .expect("publish failed rollout into durable cleanup");
        drop(mutation);

        let (published_app_retained, published_resources_retained): (bool, i64) = sqlx::query_as(
            "SELECT mutation.reclaim_after = 'infinity'::timestamptz,
                        (
                            SELECT count(*)
                              FROM external_resource_mutation_leases AS resource
                             WHERE resource.owner_token = mutation.owner_token
                               AND resource.operation_kind = mutation.operation_kind
                               AND resource.operation_id = mutation.operation_id
                               AND resource.reclaim_after = 'infinity'::timestamptz
                        )
                   FROM app_mutation_leases AS mutation
                  WHERE mutation.app_id = $1
                    AND mutation.operation_kind = 'deployment_apply'
                    AND mutation.operation_id = $2",
        )
        .bind(app.id)
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load newly retained failed-rollout authority");
        assert!(published_app_retained);
        assert_eq!(
            published_resources_retained,
            expected_resources.len() as i64
        );

        // Simulate the finite owner rows left by a pre-0046 binary and execute
        // the idempotent backfill itself. This validates the real upgrade SQL,
        // not merely the new publication path.
        sqlx::query(
            "UPDATE app_mutation_leases
                SET reclaim_after = clock_timestamp() + interval '5 minutes'
              WHERE app_id = $1",
        )
        .bind(app.id)
        .execute(&pool)
        .await
        .expect("simulate finite pre-0046 app authority");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET reclaim_after = clock_timestamp() + interval '5 minutes'
              WHERE operation_kind = 'deployment_apply'
                AND operation_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate finite pre-0046 provider authority");
        sqlx::raw_sql(include_str!(
            "../migrations/0046_retain_failed_rollout_authority.sql"
        ))
        .execute(&pool)
        .await
        .expect("run failed-rollout authority retention backfill");

        let (job_state, deployment_status, app_status, app_retained, retained_resources): (
            String,
            DeployStatus,
            crate::models::AppStatus,
            bool,
            i64,
        ) = sqlx::query_as(
            "SELECT job.state, deployment.status, app.status,
                    mutation.reclaim_after = 'infinity'::timestamptz,
                    (
                        SELECT count(*)
                          FROM external_resource_mutation_leases AS resource
                         WHERE resource.owner_token = mutation.owner_token
                           AND resource.operation_kind = mutation.operation_kind
                           AND resource.operation_id = mutation.operation_id
                           AND resource.reclaim_after = 'infinity'::timestamptz
                    )
               FROM deployment_apply_jobs AS job
               JOIN deployments AS deployment ON deployment.id = job.deployment_id
               JOIN apps AS app ON app.id = job.app_id
               JOIN app_mutation_leases AS mutation
                 ON mutation.app_id = job.app_id
                AND mutation.operation_kind = 'deployment_apply'
                AND mutation.operation_id = job.deployment_id
              WHERE job.deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load pending failed-rollout cleanup");
        assert_eq!(job_state, "rollout_cleanup_pending");
        assert_eq!(deployment_status, DeployStatus::Failed);
        assert_eq!(app_status, crate::models::AppStatus::Failed);
        assert!(app_retained);
        assert_eq!(retained_resources, expected_resources.len() as i64);

        let generic_reconcile = match crate::mutation_leases::claim_resources(
            &state,
            "kbs_policy_reconcile",
            Uuid::new_v4(),
            vec![crate::mutation_leases::ResourceFence::kbs_policy()],
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("generic KBS reconciliation must not steal cleanup authority"),
        };
        assert!(matches!(
            generic_reconcile,
            crate::mutation_leases::MutationLeaseError::Busy
        ));

        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make first failed-rollout cleanup due");
        let crashed = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("claim first failed-rollout cleanup")
        .expect("first failed-rollout cleanup exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate failed-rollout cleanup worker crash");
        let retry = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("reclaim crashed failed-rollout cleanup")
        .expect("crashed failed-rollout cleanup is reclaimable");
        assert_ne!(retry.lock_token, crashed.lock_token);

        let mut stale_authority = crate::runtime_authority::TEST_RUNTIME_AUTHORITY;
        stale_authority.epoch = Uuid::new_v4();
        let stale_authority_error = complete_reconciled_rollout_cleanup(
            &pool,
            stale_authority,
            &retry,
            &expected_resources,
            false,
        )
        .await
        .expect_err("pre-restore cleanup authority cannot release retained provider fences");
        assert!(matches!(
            stale_authority_error,
            DeploymentJobError::Mutation(
                crate::mutation_leases::MutationLeaseError::StaleRuntimeAuthority
            )
        ));

        let stale_error = complete_reconciled_rollout_cleanup(
            &pool,
            crate::runtime_authority::TEST_RUNTIME_AUTHORITY,
            &crashed,
            &expected_resources,
            false,
        )
        .await
        .expect_err("stale cleanup owner cannot release provider fences");
        assert!(matches!(stale_error, DeploymentJobError::LeaseLost));
        let still_owned: i64 = sqlx::query_scalar(
            "SELECT count(*)
               FROM external_resource_mutation_leases
              WHERE operation_kind = 'deployment_apply'
                AND operation_id = $1
                AND owner_token IS NOT NULL",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("count fences after stale cleanup attempt");
        assert_eq!(still_owned, expected_resources.len() as i64);

        requeue_rollout_cleanup_job(&pool, &retry, "kbs_policy_error")
            .await
            .expect("transient Trustee failure requeues cleanup");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make retried failed-rollout cleanup due");
        let recovered = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("claim retried failed-rollout cleanup")
        .expect("retried failed-rollout cleanup exists");
        execute_rollout_cleanup_job(&state, &recovered)
            .await
            .expect("standalone cleanup skips absent Trustee and releases full retained set");

        let (final_job_state, remaining_app_owner, remaining_resource_owners): (String, i64, i64) =
            sqlx::query_as(
                "SELECT job.state,
                    (SELECT count(*) FROM app_mutation_leases
                      WHERE app_id = job.app_id AND owner_token IS NOT NULL),
                    (SELECT count(*) FROM external_resource_mutation_leases
                      WHERE operation_kind = 'deployment_apply'
                        AND operation_id = job.deployment_id
                        AND owner_token IS NOT NULL)
               FROM deployment_apply_jobs AS job
              WHERE job.deployment_id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("load completed failed-rollout cleanup");
        assert_eq!(final_job_state, "completed");
        assert_eq!(remaining_app_owner, 0);
        assert_eq!(remaining_resource_owners, 0);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete failed-rollout cleanup fixture");
    }

    #[tokio::test]
    async fn missing_kbs_config_retains_cleanup_until_signed_generation_is_applied() {
        #[derive(sqlx::FromRow)]
        struct ReconciliationSnapshot {
            desired_generation: i64,
            configmap_generation: i64,
            applied_generation: i64,
            configmap_policy_sha256: Option<Vec<u8>>,
            applied_policy_sha256: Option<Vec<u8>>,
            configmap_resource_version: Option<String>,
        }

        let pool = database_test_pool().await;
        let original_reconciliation: ReconciliationSnapshot = sqlx::query_as(
            "SELECT desired_generation, configmap_generation, applied_generation,
                    configmap_policy_sha256, applied_policy_sha256,
                    configmap_resource_version
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .expect("load original signed-policy reconciliation");
        let applied_hash = vec![0x5a_u8; 32];
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 1,
                    configmap_generation = 1,
                    applied_generation = 1,
                    configmap_policy_sha256 = $1,
                    applied_policy_sha256 = $1,
                    configmap_resource_version = 'pre-missing-config-test',
                    updated_at = clock_timestamp()
              WHERE singleton",
        )
        .bind(&applied_hash)
        .execute(&pool)
        .await
        .expect("establish previously applied signed-policy authority");

        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.kbs_policy = None;

        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim missing-config setup")
            .expect("missing-config setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept missing-config setup");
        let apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim missing-config apply")
            .expect("missing-config apply exists");
        let expected_resources = deployment_apply_resource_fences(&payload);
        let mut mutation = crate::mutation_leases::claim(
            &state,
            app.id,
            "deployment_apply",
            deployment_id,
            false,
            expected_resources.clone(),
        )
        .await
        .expect("claim missing-config mutation");
        let manifest_hash = "missing-kbs-config-failed-rollout";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage missing-config rollout watcher");
        publish_rollout_outcome_with_mutation(
            &pool,
            &apply,
            &DeploymentRolloutOutcome {
                deploy_status: "failed",
                app_status: "failed",
                error_code: Some("rollout_failed"),
                terminal: true,
                manifest_hash: manifest_hash.to_string(),
            },
            Some(&mut mutation),
        )
        .await
        .expect("publish pending signed-policy revocation");
        drop(mutation);

        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make missing-config cleanup due");
        let cleanup = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("claim missing-config cleanup")
        .expect("missing-config cleanup exists");
        let error = execute_rollout_cleanup_job(&state, &cleanup)
            .await
            .expect_err("pending signed-policy generation must fail closed without KBS config");
        assert!(matches!(
            error,
            DeploymentJobError::Kbs(crate::kbs::KbsPolicyError::NotConfigured)
        ));
        requeue_rollout_cleanup_job(&pool, &cleanup, error.code())
            .await
            .expect("requeue missing-config cleanup");

        let (
            pending_state,
            desired_generation,
            applied_generation,
            retained_app_owners,
            retained_resource_owners,
        ): (String, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT job.state,
                    reconciliation.desired_generation,
                    reconciliation.applied_generation,
                    (
                        SELECT count(*)
                          FROM app_mutation_leases
                         WHERE app_id = job.app_id
                           AND owner_token IS NOT NULL
                    ),
                    (
                        SELECT count(*)
                          FROM external_resource_mutation_leases
                         WHERE operation_kind = 'deployment_apply'
                           AND operation_id = job.deployment_id
                           AND owner_token IS NOT NULL
                    )
               FROM deployment_apply_jobs AS job
               CROSS JOIN kbs_signed_policy_reconciliation AS reconciliation
              WHERE job.deployment_id = $1
                AND reconciliation.singleton",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load fail-closed missing-config state");
        assert_eq!(pending_state, "rollout_cleanup_pending");
        assert_eq!(desired_generation, 2);
        assert_eq!(applied_generation, 1);
        assert_eq!(retained_app_owners, 1);
        assert_eq!(retained_resource_owners, expected_resources.len() as i64);

        let reconciled_hash = vec![0x6b_u8; 32];
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET configmap_generation = desired_generation,
                    applied_generation = desired_generation,
                    configmap_policy_sha256 = $1,
                    applied_policy_sha256 = $1,
                    configmap_resource_version = 'reconciled-missing-config-test',
                    updated_at = clock_timestamp()
              WHERE singleton",
        )
        .bind(&reconciled_hash)
        .execute(&pool)
        .await
        .expect("simulate externally completed signed-policy reconciliation");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make reconciled cleanup due");
        let reconciled = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("claim reconciled cleanup")
        .expect("reconciled cleanup exists");
        execute_rollout_cleanup_job(&state, &reconciled)
            .await
            .expect("current signed generation permits no-provider authority release");
        let completed: (String, i64, i64) = sqlx::query_as(
            "SELECT job.state,
                    (
                        SELECT count(*)
                          FROM app_mutation_leases
                         WHERE app_id = job.app_id
                           AND owner_token IS NOT NULL
                    ),
                    (
                        SELECT count(*)
                          FROM external_resource_mutation_leases
                         WHERE operation_kind = 'deployment_apply'
                           AND operation_id = job.deployment_id
                           AND owner_token IS NOT NULL
                    )
               FROM deployment_apply_jobs AS job
              WHERE job.deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load completed no-provider cleanup");
        assert_eq!(completed, ("completed".to_string(), 0, 0));

        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = $1,
                    configmap_generation = $2,
                    applied_generation = $3,
                    configmap_policy_sha256 = $4,
                    applied_policy_sha256 = $5,
                    configmap_resource_version = $6,
                    updated_at = clock_timestamp()
              WHERE singleton",
        )
        .bind(original_reconciliation.desired_generation)
        .bind(original_reconciliation.configmap_generation)
        .bind(original_reconciliation.applied_generation)
        .bind(original_reconciliation.configmap_policy_sha256)
        .bind(original_reconciliation.applied_policy_sha256)
        .bind(original_reconciliation.configmap_resource_version)
        .execute(&pool)
        .await
        .expect("restore original signed-policy reconciliation");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete missing-config cleanup fixture");
    }

    #[tokio::test]
    async fn restore_rotation_completes_cleanup_with_allowed_error_code() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    error_message = 'restore-rotation-test',
                    completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make restore rotation deployment terminal");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'rollout_cleanup_pending',
                    next_attempt_at = clock_timestamp(),
                    updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("stage retained cleanup before restore rotation");

        let mut tx = pool.begin().await.expect("begin restore rotation test");
        let rotated = crate::runtime_authority::establish_epoch_with(
            &mut tx,
            crate::runtime_authority::TEST_RUNTIME_AUTHORITY.restore_generation + 1,
        )
        .await
        .expect("restore rotation retires retained cleanup");
        assert_eq!(
            rotated.restore_generation,
            crate::runtime_authority::TEST_RUNTIME_AUTHORITY.restore_generation + 1
        );
        let retired: (String, Option<String>) = sqlx::query_as(
            "SELECT state, last_error_code
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&mut *tx)
        .await
        .expect("load restore-retired cleanup");
        assert_eq!(
            retired,
            (
                "completed".to_string(),
                Some("runtime_authority_rotated".to_string()),
            )
        );
        tx.rollback().await.expect("rollback restore rotation test");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete restore rotation fixture");
    }

    #[tokio::test]
    async fn migration_cleanup_accepts_previously_released_kbs_subset_in_standalone_mode() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.kbs_policy = None;

        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim migration-subset setup")
            .expect("migration-subset setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept migration-subset setup");
        let apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim migration-subset apply")
            .expect("migration-subset apply exists");
        let expected_resources = deployment_apply_resource_fences(&payload);
        let mut mutation = crate::mutation_leases::claim(
            &state,
            app.id,
            "deployment_apply",
            deployment_id,
            false,
            expected_resources.clone(),
        )
        .await
        .expect("claim migration-subset mutation");
        mutation
            .arm_resource_scope_until_reconciled("kubernetes_namespace")
            .await
            .expect("retain migration-subset namespace");

        let manifest_hash = "migration-partial-owner-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage migration-subset rollout watcher");
        publish_rollout_outcome_with_mutation(
            &pool,
            &apply,
            &DeploymentRolloutOutcome {
                deploy_status: "failed",
                app_status: "failed",
                error_code: Some("rollout_failed"),
                terminal: true,
                manifest_hash: manifest_hash.to_string(),
            },
            Some(&mut mutation),
        )
        .await
        .expect("publish migration-subset failed rollout");
        drop(mutation);

        // Reconstruct the previous-binary crash window: the terminal job was
        // already completed and successful Trustee reconciliation released
        // only the KBS fence, leaving the app and remaining provider subset.
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'completed',
                    next_attempt_at = clock_timestamp(),
                    updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate pre-0045 completed rollout job");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE resource_scope = 'kbs_policy'
                AND resource_key = 'global'
                AND operation_kind = 'deployment_apply'
                AND operation_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate pre-upgrade KBS-only release");
        sqlx::query(
            "UPDATE app_mutation_leases
                SET reclaim_after = clock_timestamp() + interval '10 minutes'
              WHERE app_id = $1",
        )
        .bind(app.id)
        .execute(&pool)
        .await
        .expect("make pre-upgrade app owner finite");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET reclaim_after = clock_timestamp() + interval '10 minutes'
              WHERE operation_kind = 'deployment_apply'
                AND operation_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make pre-upgrade provider subset finite");

        sqlx::raw_sql(include_str!(
            "../migrations/0045_failed_rollout_cleanup_jobs.sql"
        ))
        .execute(&pool)
        .await
        .expect("run real migration-0045 partial-owner backfill");
        sqlx::raw_sql(include_str!(
            "../migrations/0046_retain_failed_rollout_authority.sql"
        ))
        .execute(&pool)
        .await
        .expect("run real migration-0046 subset retention");

        let (job_state, retained_resources, retained_kbs): (String, i64, i64) = sqlx::query_as(
            "SELECT job.state,
                        (
                            SELECT count(*)
                              FROM external_resource_mutation_leases AS resource
                             WHERE resource.operation_kind = 'deployment_apply'
                               AND resource.operation_id = job.deployment_id
                               AND resource.owner_token IS NOT NULL
                               AND resource.reclaim_after = 'infinity'::timestamptz
                        ),
                        (
                            SELECT count(*)
                              FROM external_resource_mutation_leases AS resource
                             WHERE resource.resource_scope = 'kbs_policy'
                               AND resource.resource_key = 'global'
                               AND resource.owner_token IS NOT NULL
                        )
                   FROM deployment_apply_jobs AS job
                  WHERE job.deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load migrated partial cleanup authority");
        assert_eq!(job_state, "rollout_cleanup_pending");
        assert_eq!(retained_resources, expected_resources.len() as i64 - 1);
        assert_eq!(retained_kbs, 0);

        let cleanup = claim_job(
            &pool,
            "rollout_cleanup_pending",
            "rollout_cleaning_up",
            Some(deployment_id),
        )
        .await
        .expect("claim migrated partial cleanup")
        .expect("migrated partial cleanup exists");
        execute_rollout_cleanup_job(&state, &cleanup)
            .await
            .expect("standalone cleanup releases exact retained subset without Trustee");

        let (final_state, app_owners, provider_owners): (String, i64, i64) = sqlx::query_as(
            "SELECT job.state,
                    (
                        SELECT count(*)
                          FROM app_mutation_leases
                         WHERE app_id = job.app_id
                           AND owner_token IS NOT NULL
                    ),
                    (
                        SELECT count(*)
                          FROM external_resource_mutation_leases
                         WHERE operation_kind = 'deployment_apply'
                           AND operation_id = job.deployment_id
                           AND owner_token IS NOT NULL
                    )
               FROM deployment_apply_jobs AS job
              WHERE job.deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load completed partial cleanup");
        assert_eq!(final_state, "completed");
        assert_eq!(app_owners, 0);
        assert_eq!(provider_owners, 0);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete partial cleanup fixture");
    }

    #[tokio::test]
    async fn nonterminal_password_rollout_preserves_authority_for_delayed_retry() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim apply")
            .expect("apply exists");
        let manifest_hash = "password-create-watching-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage password rollout observation");

        publish_rollout_outcome(
            &pool,
            &apply,
            &DeploymentRolloutOutcome {
                deploy_status: "watching",
                app_status: "creating",
                error_code: None,
                terminal: false,
                manifest_hash: manifest_hash.to_string(),
            },
        )
        .await
        .expect("publish nonterminal observation atomically");

        let (deployment_status, app_status, app_updated_at, job_state, token, delayed): (
            String,
            String,
            chrono::DateTime<chrono::Utc>,
            String,
            Option<Uuid>,
            bool,
        ) = sqlx::query_as(
            "SELECT deployment.status::text, app.status::text, app.updated_at,
                    job.state, job.lock_token,
                    job.next_attempt_at > clock_timestamp()
               FROM deployments AS deployment
               JOIN apps AS app ON app.id = deployment.app_id
               JOIN deployment_apply_jobs AS job
                 ON job.deployment_id = deployment.id
              WHERE deployment.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load nonterminal durable observation");
        assert_eq!(deployment_status, "watching");
        assert_eq!(app_status, "creating");
        assert_eq!(app_updated_at, payload.app.updated_at);
        assert_eq!(job_state, "pending");
        assert!(token.is_none());
        assert!(delayed);

        let retry = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim observation retry")
            .expect("observation retry exists");
        let retry_payload = retry.decode_payload().expect("decode observation retry");
        let expected_authority = crate::deploy::ExistingAppAuthoritySnapshot::new(
            retry_payload.app.updated_at,
            retry_payload.snapshot.containers,
            retry_payload.snapshot.resources,
        );
        let mut authority_lane = pool.begin().await.expect("begin retry authority check");
        crate::deploy::lock_app_deployment_lane(&mut authority_lane, app.id)
            .await
            .expect("lock retry app lane");
        assert!(
            crate::deploy::verify_existing_app_authority(
                &mut authority_lane,
                app.id,
                &expected_authority,
            )
            .await
            .expect("verify retry authority"),
            "nonterminal observation must preserve its immutable app authority"
        );
        authority_lane
            .rollback()
            .await
            .expect("release retry authority lane");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete nonterminal observation fixture");
    }

    #[tokio::test]
    async fn superseded_watching_lease_cannot_publish_after_reclaim_window() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let apply = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim apply")
            .expect("apply exists");
        let manifest_hash = "superseded-watching-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum,
                    manifest_hash = $2
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(manifest_hash)
        .execute(&pool)
        .await
        .expect("stage watching generation");
        let mut supersede = pool.begin().await.expect("begin supersession");
        crate::deploy::lock_app_deployment_lane(&mut supersede, app.id)
            .await
            .expect("lock supersession app lane");
        crate::deploy::supersede_incomplete_deployments(&mut supersede, app.id)
            .await
            .expect("supersede watching generation");
        supersede.commit().await.expect("commit supersession");

        let error = publish_rollout_outcome(
            &pool,
            &apply,
            &DeploymentRolloutOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_code: None,
                terminal: true,
                manifest_hash: manifest_hash.to_string(),
            },
        )
        .await
        .expect_err("superseded watcher publication must be fenced");
        assert!(matches!(error, DeploymentJobError::LeaseLost));
        let (deployment_status, deployment_error, job_state, job_error): (
            String,
            Option<String>,
            String,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT deployment.status::text, deployment.error_message,
                    job.state, job.last_error_code
               FROM deployments AS deployment
               JOIN deployment_apply_jobs AS job
                 ON job.deployment_id = deployment.id
              WHERE deployment.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load superseded watching state");
        assert_eq!(deployment_status, "failed");
        assert_eq!(deployment_error.as_deref(), Some("deployment_superseded"));
        assert_eq!(job_state, "failed");
        assert_eq!(job_error.as_deref(), Some("deployment_superseded"));

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete superseded watching fixture");
    }

    #[tokio::test]
    async fn stale_setup_token_cannot_publish_false_acceptance() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");

        let error = mark_setup_accepted(&pool, deployment_id, Uuid::new_v4())
            .await
            .expect_err("stale setup owner rejected");
        assert!(matches!(error, DeploymentJobError::LeaseLost));
        let (setup_state, job_state, lock_token): (String, String, Uuid) = sqlx::query_as(
            "SELECT d.spec_snapshot->>'setup_state', j.state, j.lock_token
               FROM deployments d
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load rejected setup transition");
        assert_eq!(setup_state, DEPLOYMENT_SETUP_DNS_PENDING);
        assert_eq!(job_state, "setting_up");
        assert_eq!(lock_token, setup.lock_token);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment job fixture");
    }

    #[tokio::test]
    async fn existing_app_setup_failure_is_terminal_without_cleanup_marker() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");

        mark_setup_failed(&pool, &setup)
            .await
            .expect("persist existing-app setup failure");

        let (setup_state, job_state, lock_token, locked_until, app_status): (
            String,
            String,
            Option<Uuid>,
            Option<chrono::DateTime<chrono::Utc>>,
            String,
        ) = sqlx::query_as(
            "SELECT d.spec_snapshot->>'setup_state',
                    j.state,
                    j.lock_token,
                    j.locked_until,
                    a.status::text
               FROM deployments d
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
               JOIN apps a ON a.id = d.app_id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load existing-app setup failure");

        assert_eq!(setup_state, DEPLOYMENT_SETUP_FAILED);
        assert_eq!(job_state, "failed");
        assert!(lock_token.is_none());
        assert!(locked_until.is_none());
        assert_eq!(app_status, "creating");
        assert_ne!(setup_state, DEPLOYMENT_SETUP_DNS_PENDING);
        assert_ne!(setup_state, DEPLOYMENT_SETUP_CLEANUP_PENDING);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment job fixture");
    }

    #[tokio::test]
    async fn deferred_gate_rejects_old_style_insert_and_accepts_same_tx_job() {
        let pool = database_test_pool().await;
        let (app, _deployment_id, _setup_lease, payload) = insert_job_fixture(&pool).await;

        let old_style_id = Uuid::new_v4();
        let mut old_tx = pool.begin().await.expect("begin old-style deployment");
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot)
             VALUES ($1, $2, $3, 'api', $4)",
        )
        .bind(old_style_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(serde_json::json!({"setup_state": DEPLOYMENT_SETUP_ACCEPTED}))
        .execute(&mut *old_tx)
        .await
        .expect("deferred trigger permits statement");
        let error = old_tx
            .commit()
            .await
            .expect_err("commit without durable job must fail");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let new_style_id = Uuid::new_v4();
        let mut new_tx = pool.begin().await.expect("begin new-style deployment");
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot)
             VALUES ($1, $2, $3, 'api', $4)",
        )
        .bind(new_style_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(serde_json::json!({"setup_state": DEPLOYMENT_SETUP_ACCEPTED}))
        .execute(&mut *new_tx)
        .await
        .expect("insert new-style deployment");
        insert_ready_job(&mut new_tx, new_style_id, new_style_id, &payload, false)
            .await
            .expect("insert same-transaction durable job");
        new_tx
            .commit()
            .await
            .expect("same-transaction durable job satisfies gate");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment gate fixture");
    }

    #[tokio::test]
    async fn unsupported_future_payload_version_waits_for_compatible_worker() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let mut future_payload = serde_json::to_value(payload).expect("serialize future payload");
        future_payload["version"] = serde_json::json!(JOB_PAYLOAD_VERSION + 1);
        replace_job_with_raw_payload(
            &pool,
            deployment_id,
            future_payload,
            JOB_PAYLOAD_VERSION + 1,
            false,
            "setup_pending",
        )
        .await;

        let claimed = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("future payload claim query");
        assert!(claimed.is_none());
        let (setup_state, job_state, lock_token, attempts): (String, String, Option<Uuid>, i32) =
            sqlx::query_as(
                "SELECT d.spec_snapshot->>'setup_state', j.state, j.lock_token, j.attempts
                   FROM deployments d
                   JOIN deployment_apply_jobs j ON j.deployment_id = d.id
                  WHERE d.id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("load future-version job");
        assert_eq!(setup_state, DEPLOYMENT_SETUP_DNS_PENDING);
        assert_eq!(job_state, "setup_pending");
        assert!(lock_token.is_none());
        assert_eq!(attempts, 0);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete malformed payload fixture");
    }

    #[tokio::test]
    async fn unsupported_cleanup_payload_fails_startup_without_claiming() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    error_message = 'future-cleanup-payload',
                    completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make future cleanup deployment terminal");
        let mut future_payload = serde_json::to_value(payload).expect("serialize future payload");
        future_payload["version"] = serde_json::json!(JOB_PAYLOAD_VERSION + 1);
        replace_job_with_raw_payload(
            &pool,
            deployment_id,
            future_payload,
            JOB_PAYLOAD_VERSION + 1,
            false,
            "rollout_cleanup_pending",
        )
        .await;

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        let error = reconcile_failed_rollout_cleanup_at_startup(&state)
            .await
            .expect_err("unsupported cleanup payload must refuse startup explicitly");
        assert!(matches!(
            error,
            DeploymentJobError::UnsupportedPayloadVersion
        ));
        let (state, lock_token, attempts): (String, Option<Uuid>, i32) = sqlx::query_as(
            "SELECT state, lock_token, attempts
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load unsupported cleanup after startup refusal");
        assert_eq!(state, "rollout_cleanup_pending");
        assert!(lock_token.is_none());
        assert_eq!(attempts, 0);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete unsupported cleanup fixture");
    }

    #[tokio::test]
    async fn cross_app_and_empty_setup_payloads_are_quarantined_not_reclaimed() {
        let pool = database_test_pool().await;
        for cross_app in [false, true] {
            let (app, deployment_id, setup_handle, payload) = insert_job_fixture(&pool).await;
            let mut malformed = serde_json::to_value(payload).expect("serialize payload");
            if cross_app {
                malformed["snapshot"]["containers"][0]["app_id"] =
                    serde_json::json!(Uuid::new_v4());
            } else {
                malformed["snapshot"]["containers"] = serde_json::json!([]);
            }
            replace_job_with_raw_payload(
                &pool,
                deployment_id,
                malformed,
                JOB_PAYLOAD_VERSION,
                false,
                "setup_pending",
            )
            .await;

            let mut state = crate::test_support::lazy_state();
            state.db = pool.clone();
            let error = process_setup_job(&state, setup_handle)
                .await
                .expect_err("semantically invalid setup rejected");
            assert!(matches!(error, DeploymentJobError::InvalidPayload));
            let (setup_state, job_state, lock_token): (String, String, Option<Uuid>) =
                sqlx::query_as(
                    "SELECT d.spec_snapshot->>'setup_state', j.state, j.lock_token
                       FROM deployments d
                       JOIN deployment_apply_jobs j ON j.deployment_id = d.id
                      WHERE d.id = $1",
                )
                .bind(deployment_id)
                .fetch_one(&pool)
                .await
                .expect("load semantically quarantined setup");
            assert_eq!(setup_state, DEPLOYMENT_SETUP_FAILED);
            assert_eq!(job_state, "failed");
            assert!(lock_token.is_none());

            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(app.org_id)
                .execute(&pool)
                .await
                .expect("delete semantic payload fixture");
        }
    }

    #[tokio::test]
    async fn semantic_apply_payload_failure_is_token_conditionally_quarantined() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let mut malformed = serde_json::to_value(payload).expect("serialize payload");
        malformed["snapshot"]["containers"] = serde_json::json!([]);
        replace_job_with_raw_payload(
            &pool,
            deployment_id,
            malformed,
            JOB_PAYLOAD_VERSION,
            false,
            "pending",
        )
        .await;
        let claimed = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim invalid apply")
            .expect("invalid apply job exists");
        let worker_slot = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .expect("acquire test worker slot");
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        process_apply_job(state, claimed, worker_slot).await;

        let (deploy_status, app_status, job_state, lock_token): (
            String,
            String,
            String,
            Option<Uuid>,
        ) = sqlx::query_as(
            "SELECT d.status::text, a.status::text, j.state, j.lock_token
               FROM deployments d
               JOIN apps a ON a.id = d.app_id
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load quarantined apply");
        assert_eq!(deploy_status, "failed");
        assert_eq!(app_status, "failed");
        assert_eq!(job_state, "failed");
        assert!(lock_token.is_none());

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete invalid apply fixture");
    }

    #[tokio::test]
    async fn setup_handoff_is_unowned_until_request_claim_and_dispatcher_honors_delay() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let (state, token, lease, recovery_delayed): (
            String,
            Option<Uuid>,
            Option<chrono::DateTime<chrono::Utc>>,
            bool,
        ) = sqlx::query_as(
            "SELECT state, lock_token, locked_until,
                    next_attempt_at > clock_timestamp()
               FROM deployment_apply_jobs
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load committed setup handoff");
        assert_eq!(state, "setup_pending");
        assert!(token.is_none());
        assert!(lease.is_none());
        assert!(recovery_delayed);
        assert!(
            claim_setup_job(&pool)
                .await
                .expect("dispatcher claim query")
                .is_none()
        );

        let request_claim = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("request claim query")
            .expect("request bypasses recovery delay");
        renew_job_lease(
            &pool,
            crate::runtime_authority::TEST_RUNTIME_AUTHORITY,
            deployment_id,
            request_claim.lock_token,
            "setting_up",
        )
        .await
        .expect("request renews setup lease");
        let lease_is_live: bool = sqlx::query_scalar(
            "SELECT locked_until > clock_timestamp()
               FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load renewed request lease");
        assert!(lease_is_live);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete setup handoff fixture");
    }

    #[tokio::test]
    async fn dispatcher_winner_is_observed_without_duplicate_request_setup() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_handle, _payload) = insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make recovery setup due");
        let dispatcher = claim_setup_job(&pool)
            .await
            .expect("dispatcher claim")
            .expect("dispatcher wins setup");
        mark_setup_accepted(&pool, deployment_id, dispatcher.lock_token)
            .await
            .expect("dispatcher accepts setup");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        process_setup_job(&state, setup_handle)
            .await
            .expect("request observes dispatcher acceptance");
        let attempts: i32 = sqlx::query_scalar(
            "SELECT attempts FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load dispatcher attempts");
        assert_eq!(attempts, 1, "request must not claim or duplicate DNS setup");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete dispatcher-winner fixture");
    }

    #[tokio::test]
    async fn request_owned_dns_failure_preserves_typed_error_mapping() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_handle, _payload) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.dns = Some(crate::dns::DnsConfig {
            cloudflare_api_token: "unused-test-token".to_string(),
            cloudflare_api_base_url: "http://127.0.0.1:1".to_string(),
            cloudflare_zone_id: Some("unused-test-zone".to_string()),
            cloudflare_zone_name: "outside.example.test".to_string(),
            target: "127.0.0.1".to_string(),
            required: true,
        });
        let error = process_setup_job(&state, setup_handle)
            .await
            .expect_err("out-of-zone DNS fails setup");
        assert!(matches!(
            error,
            DeploymentJobError::Dns(crate::dns::DnsError::OutsideManagedZone(_))
        ));

        let (owner_token, app_generation): (Uuid, i64) = sqlx::query_as(
            "SELECT owner_token, generation
               FROM app_mutation_leases
              WHERE app_id = $1
                AND operation_kind = 'deployment_setup'
                AND operation_id = $2",
        )
        .bind(app.id)
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load exact failed setup mutation owner");
        let owned_resources: Vec<(String, String, i64, bool)> = sqlx::query_as(
            "SELECT resource_scope,
                    resource_key,
                    generation,
                    reclaim_after = 'infinity'::timestamptz
               FROM external_resource_mutation_leases
              WHERE owner_token = $1
                AND operation_kind = 'deployment_setup'
                AND operation_id = $2
              ORDER BY resource_scope, resource_key",
        )
        .bind(owner_token)
        .bind(deployment_id)
        .fetch_all(&pool)
        .await
        .expect("load failed setup provider ownership");
        assert!(
            owned_resources
                .iter()
                .any(|(scope, _, _, poisoned)| { scope == "dns_hostname" && *poisoned }),
            "failed setup must retain an infinite DNS ambiguity fence"
        );

        // OutsideManagedZone is rejected before an HTTP request is sent, so
        // this test knows no detached provider write exists. Clear only the
        // exact operation/token/generation it just observed; never weaken the
        // production fail-closed path or any later owner.
        let mut cleanup = pool.begin().await.expect("begin exact test-owner cleanup");
        for (scope, key, generation, _) in &owned_resources {
            let cleared = sqlx::query(
                "UPDATE external_resource_mutation_leases
                    SET owner_token = NULL,
                        operation_kind = NULL,
                        operation_id = NULL,
                        locked_until = NULL,
                        reclaim_after = NULL,
                        updated_at = clock_timestamp()
                  WHERE resource_scope = $1
                    AND resource_key = $2
                    AND generation = $3
                    AND owner_token = $4
                    AND operation_kind = 'deployment_setup'
                    AND operation_id = $5",
            )
            .bind(scope)
            .bind(key)
            .bind(generation)
            .bind(owner_token)
            .bind(deployment_id)
            .execute(&mut *cleanup)
            .await
            .expect("clear exact failed setup resource owner");
            assert_eq!(cleared.rows_affected(), 1);
        }
        let cleared_app = sqlx::query(
            "UPDATE app_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE app_id = $1
                AND generation = $2
                AND owner_token = $3
                AND operation_kind = 'deployment_setup'
                AND operation_id = $4
                AND NOT EXISTS (
                    SELECT 1 FROM external_resource_mutation_leases
                     WHERE owner_token = $3
                )",
        )
        .bind(app.id)
        .bind(app_generation)
        .bind(owner_token)
        .bind(deployment_id)
        .execute(&mut *cleanup)
        .await
        .expect("clear exact failed setup app owner");
        assert_eq!(cleared_app.rows_affected(), 1);
        cleanup
            .commit()
            .await
            .expect("commit exact test-owner cleanup");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete DNS failure fixture");
    }

    #[tokio::test]
    async fn signed_job_and_artifact_snapshots_cannot_be_downgraded_or_mutated() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let descriptor_hash =
            replace_job_with_fake_signed_binding(&pool, deployment_id, payload).await;

        let downgrade_error = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET signed_required = false,
                    artifact_deployment_id = NULL,
                    artifact_descriptor_core_hash = NULL
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect_err("signed durable job cannot be downgraded");
        assert_eq!(
            downgrade_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let payload_error = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET payload = jsonb_set(payload, '{api_url}', to_jsonb('https://changed.test'::text))
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect_err("accepted runtime payload cannot be mutated");
        assert_eq!(
            payload_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let deployment_error = sqlx::query(
            "UPDATE deployments
                SET spec_snapshot = jsonb_set(
                    spec_snapshot,
                    '{signed_descriptor_core_hash}',
                    'null'::jsonb,
                    true
                )
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect_err("canonical signed deployment binding cannot be cleared");
        assert_eq!(
            deployment_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let mut delete_then_downgrade = pool
            .begin()
            .await
            .expect("begin delete-then-downgrade attempt");
        sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
            .bind(deployment_id)
            .execute(&mut *delete_then_downgrade)
            .await
            .expect("job-side invariant is deferred inside bypass attempt");
        let delete_then_downgrade_error = sqlx::query(
            "UPDATE deployments
                SET spec_snapshot = jsonb_set(
                    spec_snapshot,
                    '{signed_descriptor_core_hash}',
                    'null'::jsonb,
                    true
                )
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(&mut *delete_then_downgrade)
        .await
        .expect_err("deleting the job cannot bypass deployment snapshot immutability");
        assert_eq!(
            delete_then_downgrade_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        delete_then_downgrade
            .rollback()
            .await
            .expect("rollback delete-then-downgrade attempt");

        let artifact_update_error = sqlx::query(
            "UPDATE workload_artifacts
                SET descriptor_signing_key_id = 'changed'
              WHERE deploy_id = $1 AND descriptor_core_hash = $2",
        )
        .bind(deployment_id)
        .bind(descriptor_hash.to_vec())
        .execute(&pool)
        .await
        .expect_err("stored signed artifact cannot be mutated");
        assert_eq!(
            artifact_update_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let artifact_delete_error = sqlx::query(
            "DELETE FROM workload_artifacts
              WHERE deploy_id = $1 AND descriptor_core_hash = $2",
        )
        .bind(deployment_id)
        .bind(descriptor_hash.to_vec())
        .execute(&pool)
        .await
        .expect_err("referenced signed artifact cannot be deleted");
        assert_eq!(
            artifact_delete_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23503")
        );

        let mut delete_then_remove_artifact = pool
            .begin()
            .await
            .expect("begin delete-then-remove-artifact attempt");
        sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
            .bind(deployment_id)
            .execute(&mut *delete_then_remove_artifact)
            .await
            .expect("delete job before direct artifact removal attempt");
        let live_artifact_delete_error = sqlx::query(
            "DELETE FROM workload_artifacts
              WHERE deploy_id = $1 AND descriptor_core_hash = $2",
        )
        .bind(deployment_id)
        .bind(descriptor_hash.to_vec())
        .execute(&mut *delete_then_remove_artifact)
        .await
        .expect_err("live deployment retains artifact even after job deletion");
        assert_eq!(
            live_artifact_delete_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23503")
        );
        delete_then_remove_artifact
            .rollback()
            .await
            .expect("rollback direct artifact removal attempt");

        let job_delete_error =
            sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
                .bind(deployment_id)
                .execute(&pool)
                .await
                .expect_err("nonterminal signed deployment cannot lose its durable job");
        assert_eq!(
            job_delete_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete signed immutability fixture");
    }

    #[tokio::test]
    async fn permit_wait_revalidates_latest_keyring_before_rendering() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, payload) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.deployment_apply_permits = Arc::new(tokio::sync::Semaphore::new(1));
        let (payload, authority) =
            replace_job_with_valid_signed_binding(&pool, deployment_id, payload, &mut state).await;

        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim signed setup")
            .expect("signed setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept signed setup");
        let job = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim signed apply")
            .expect("signed apply exists");
        let decoded = job.decode_payload().expect("decode signed durable payload");
        assert_eq!(
            decoded.artifact_descriptor_core_hash,
            payload.artifact_descriptor_core_hash
        );
        let primary_image_digest = validate_canonical_source_snapshot(&pool, &job, &decoded)
            .await
            .expect("validate signed canonical snapshot before wait");
        validate_apply_artifacts(&state, &job, &decoded, &primary_image_digest)
            .await
            .expect("signed authority passes before permit wait");

        let blocker = state
            .deployment_apply_permits
            .clone()
            .acquire_owned()
            .await
            .expect("hold only apply permit");
        let state = Arc::new(state);
        let waiter_state = Arc::clone(&state);
        let waiter = tokio::spawn(async move {
            acquire_apply_permit_and_revalidate(&waiter_state, &job, &decoded).await
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "apply must wait behind held permit");

        insert_test_keyring_version(
            &pool,
            app.org_id,
            &authority,
            2,
            authority.member_added_at + chrono::Duration::seconds(1),
        )
        .await;
        drop(blocker);

        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("post-permit validation completes")
            .expect("post-permit validation task joins");
        assert!(
            matches!(result, Err(DeploymentJobError::Artifact)),
            "rotated keyring must reject the queued apply, got {result:?}"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete keyring revalidation fixture");
    }

    #[tokio::test]
    async fn cross_app_kbs_fence_contention_requeues_without_terminal_failure() {
        let pool = database_test_pool().await;
        let (holder_app, _, _, _) = insert_job_fixture(&pool).await;
        let (queued_app, queued_deployment, _, _) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = Arc::new(tokio::sync::Semaphore::new(2));
        state.deployment_apply_permits = Arc::new(tokio::sync::Semaphore::new(2));
        state.require_customer_signed_policy_artifact = false;
        state.attestation = None;

        let holder = crate::mutation_leases::claim(
            &state,
            holder_app.id,
            "other_app_kbs_publish",
            Uuid::new_v4(),
            false,
            vec![crate::mutation_leases::ResourceFence::kbs_policy()],
        )
        .await
        .expect("hold global KBS generation for another app");

        let setup = claim_job(
            &pool,
            "setup_pending",
            "setting_up",
            Some(queued_deployment),
        )
        .await
        .expect("claim queued setup")
        .expect("queued setup exists");
        mark_setup_accepted(&pool, queued_deployment, setup.lock_token)
            .await
            .expect("accept queued setup without provider side effect");
        let apply = claim_job(&pool, "pending", "running", Some(queued_deployment))
            .await
            .expect("claim queued apply")
            .expect("queued apply exists");
        let worker_slot = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .expect("acquire test worker slot");
        tokio::spawn(process_apply_job(state.clone(), apply, worker_slot))
            .await
            .expect("KBS contention worker task joins");

        let (job_state, token, deployment_status, app_status): (
            String,
            Option<Uuid>,
            DeployStatus,
            crate::models::AppStatus,
        ) = sqlx::query_as(
            "SELECT job.state, job.lock_token, deployment.status, app.status
               FROM deployment_apply_jobs AS job
               JOIN deployments AS deployment ON deployment.id = job.deployment_id
               JOIN apps AS app ON app.id = job.app_id
              WHERE job.deployment_id = $1",
        )
        .bind(queued_deployment)
        .fetch_one(&pool)
        .await
        .expect("read requeued deployment");
        assert_eq!(job_state, "pending");
        assert!(token.is_none());
        assert_eq!(deployment_status, DeployStatus::Pending);
        assert_ne!(app_status, crate::models::AppStatus::Failed);

        holder.finish().await.expect("release global KBS fence");
        let retry = crate::mutation_leases::claim(
            &state,
            queued_app.id,
            "retried_kbs_publish",
            queued_deployment,
            false,
            vec![crate::mutation_leases::ResourceFence::kbs_policy()],
        )
        .await
        .expect("retry can claim KBS generation after release");
        retry.finish().await.expect("release retry claim");
        for org_id in [holder_app.org_id, queued_app.org_id] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .expect("clean KBS contention fixture");
        }
    }

    #[tokio::test]
    async fn stale_apply_releases_pre_provider_app_and_resource_claims() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _, _) = insert_job_fixture(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = Arc::new(tokio::sync::Semaphore::new(2));
        state.deployment_apply_permits = Arc::new(tokio::sync::Semaphore::new(1));
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim stale setup")
            .expect("stale setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept stale setup");
        let job = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim stale apply")
            .expect("stale apply exists");
        let payload = job.decode_payload().expect("decode stale apply payload");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET lock_token = $2,
                    locked_until = clock_timestamp() + interval '90 seconds'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("make apply owner stale before final lane validation");

        let result = acquire_apply_permit_and_revalidate(&state, &job, &payload)
            .await
            .expect("stale validation returns cleanly");
        assert!(result.is_none());
        let app_owned: bool = sqlx::query_scalar(
            "SELECT owner_token IS NOT NULL FROM app_mutation_leases WHERE app_id = $1",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("read released app claim");
        assert!(!app_owned);
        let owned_resources: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE owner_token IS NOT NULL
                AND (
                    (resource_scope = 'kbs_policy' AND resource_key = 'global')
                    OR (resource_scope = 'kubernetes_namespace' AND resource_key = $1)
                )",
        )
        .bind(&app.namespace)
        .fetch_one(&pool)
        .await
        .expect("read released provider claims");
        assert_eq!(owned_resources, 0);
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("clean stale apply fixture");
    }

    #[tokio::test]
    async fn shared_dns_fence_contention_requeues_setup_without_failure() {
        let pool = database_test_pool().await;
        let (holder_app, _, _, _) = insert_job_fixture(&pool).await;
        let (queued_app, queued_deployment, _, _) = insert_job_fixture(&pool).await;
        let shared_hostname = queued_app.domain.clone();

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.side_effect_admission = Arc::new(tokio::sync::Semaphore::new(2));
        let holder = crate::mutation_leases::claim(
            &state,
            holder_app.id,
            "other_setup_dns",
            Uuid::new_v4(),
            false,
            vec![crate::mutation_leases::ResourceFence::dns(&shared_hostname)],
        )
        .await
        .expect("hold shared DNS generation");
        let queued = claim_job(
            &pool,
            "setup_pending",
            "setting_up",
            Some(queued_deployment),
        )
        .await
        .expect("claim contended setup")
        .expect("contended setup exists");
        process_claimed_setup_job(&state, queued)
            .await
            .expect("contention is an accepted durable retry");
        let (job_state, lock_token, deployment_status): (String, Option<Uuid>, DeployStatus) =
            sqlx::query_as(
                "SELECT job.state, job.lock_token, deployment.status
                   FROM deployment_apply_jobs AS job
                   JOIN deployments AS deployment ON deployment.id = job.deployment_id
                  WHERE job.deployment_id = $1",
            )
            .bind(queued_deployment)
            .fetch_one(&pool)
            .await
            .expect("read requeued setup");
        assert_eq!(job_state, "setup_pending");
        assert!(lock_token.is_none());
        assert_eq!(deployment_status, DeployStatus::Pending);
        holder
            .finish()
            .await
            .expect("release shared DNS generation");
        for org_id in [holder_app.org_id, queued_app.org_id] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .expect("clean DNS contention fixture");
        }
    }

    #[tokio::test]
    async fn supersession_rejects_unexpired_mutator_and_accepts_expired_owner() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _, _) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim supersession setup")
            .expect("supersession setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept supersession setup");
        let _running = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim supersession apply")
            .expect("supersession apply exists");

        let mut blocked = pool.begin().await.expect("begin blocked supersession");
        crate::deploy::lock_app_deployment_lane(&mut blocked, app.id)
            .await
            .expect("lock blocked supersession lane");
        assert!(matches!(
            crate::deploy::supersede_incomplete_deployments(&mut blocked, app.id).await,
            Err(crate::deploy::SupersedeDeploymentError::Busy)
        ));
        blocked
            .rollback()
            .await
            .expect("rollback blocked supersession");

        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire mutating owner");
        let mut reclaim = pool.begin().await.expect("begin expired supersession");
        crate::deploy::lock_app_deployment_lane(&mut reclaim, app.id)
            .await
            .expect("lock expired supersession lane");
        assert_eq!(
            crate::deploy::supersede_incomplete_deployments(&mut reclaim, app.id)
                .await
                .expect("supersede expired owner"),
            1
        );
        reclaim.commit().await.expect("commit expired supersession");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("clean supersession fixture");
    }

    #[tokio::test]
    async fn malformed_cleanup_owned_payload_remains_reconcilable_by_relational_app_id() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_handle, mut payload) = insert_job_fixture(&pool).await;
        payload.delete_app_on_setup_failure = true;
        let mut malformed = serde_json::to_value(payload).expect("serialize cleanup payload");
        malformed["snapshot"]["containers"] = serde_json::json!([]);
        replace_job_with_raw_payload(
            &pool,
            deployment_id,
            malformed,
            JOB_PAYLOAD_VERSION,
            true,
            "setup_pending",
        )
        .await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let error = process_setup_job(&state, setup_handle)
            .await
            .expect_err("malformed mandatory setup is quarantined");
        assert!(matches!(error, DeploymentJobError::InvalidPayload));
        let cleanup = claim_job(&pool, "cleanup_pending", "cleaning_up", Some(deployment_id))
            .await
            .expect("claim malformed cleanup")
            .expect("malformed cleanup remains recoverable");
        process_cleanup_job(&state, cleanup).await;
        let app_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1)")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("verify relational cleanup");
        assert!(!app_exists);
    }

    #[tokio::test]
    async fn database_rejects_false_cleanup_state_and_terminal_job_stranding() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let cleanup_error = sqlx::query(
            "UPDATE deployment_apply_jobs SET state = 'cleanup_pending'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect_err("false cleanup ownership cannot enter cleanup state");
        assert_eq!(
            cleanup_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let mut stranded = pool.begin().await.expect("begin stranded terminal job");
        sqlx::query(
            "UPDATE deployment_apply_jobs SET state = 'failed'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&mut *stranded)
        .await
        .expect("terminal job transition is deferred");
        let stranded_error = stranded
            .commit()
            .await
            .expect_err("nonterminal deployment cannot retain terminal job");
        assert_eq!(
            stranded_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );

        let mut atomic = pool
            .begin()
            .await
            .expect("begin atomic terminal transition");
        sqlx::query("UPDATE deployments SET status = 'failed'::deploy_status_enum WHERE id = $1")
            .bind(deployment_id)
            .execute(&mut *atomic)
            .await
            .expect("terminalize deployment");
        sqlx::query("UPDATE deployment_apply_jobs SET state = 'failed' WHERE deployment_id = $1")
            .bind(deployment_id)
            .execute(&mut *atomic)
            .await
            .expect("terminalize job");
        atomic
            .commit()
            .await
            .expect("atomic deployment/job terminalization passes invariant");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete terminal invariant fixture");
    }

    #[tokio::test]
    async fn database_rejects_payload_without_relational_version_match() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let mut tx = pool
            .begin()
            .await
            .expect("begin missing-version replacement");
        sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
            .bind(deployment_id)
            .execute(&mut *tx)
            .await
            .expect("delete versioned job inside replacement transaction");
        let error = sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state
             )
             SELECT id, app_id, org_id, id, 1, '{}'::jsonb, $2,
                    false, false, NULL, NULL, NULL, 'setup_pending'
               FROM deployments WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(vec![0_u8; 32])
        .execute(&mut *tx)
        .await
        .expect_err("missing JSON version cannot satisfy relational version check");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        tx.rollback()
            .await
            .expect("rollback missing-version replacement");

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete missing-version fixture");
    }

    #[tokio::test]
    async fn artifact_binding_is_unique_and_exact_hash_mismatch_is_absent() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_lease, _payload) = insert_job_fixture(&pool).await;
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test', '{}'::jsonb, $5, '{}'::jsonb)",
        )
        .bind(vec![1_u8; 32])
        .bind(app.id)
        .bind(deployment_id)
        .bind(Vec::<u8>::new())
        .bind(Vec::<u8>::new())
        .execute(&pool)
        .await
        .expect("insert authoritative artifact row");

        let duplicate_error = sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'other', '{}'::jsonb, $5, '{}'::jsonb)",
        )
        .bind(vec![2_u8; 32])
        .bind(app.id)
        .bind(deployment_id)
        .bind(Vec::<u8>::new())
        .bind(Vec::<u8>::new())
        .execute(&pool)
        .await
        .expect_err("duplicate app/deployment artifact binding rejected");
        assert_eq!(
            duplicate_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505")
        );

        let mismatched = crate::signing_service::load_workload_artifacts_exact(
            &pool,
            app.id,
            deployment_id,
            [3_u8; 32],
        )
        .await
        .expect("query exact mismatched binding");
        assert!(mismatched.is_none());

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete artifact binding fixture");
    }

    #[tokio::test]
    async fn deployment_identity_must_match_durable_payload() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_lease, mut payload) = insert_job_fixture(&pool).await;
        let claimed = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        payload.app.org_id = Uuid::new_v4();
        let error = validate_canonical_source_snapshot(&pool, &claimed, &payload)
            .await
            .expect_err("mismatched payload organization rejected");
        assert!(matches!(error, DeploymentJobError::InvalidPayload));

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment identity fixture");
    }

    #[tokio::test]
    async fn stale_apply_token_cannot_publish_rollout_success() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let stale = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim apply")
            .expect("apply job exists");
        let manifest_hash = "stale-success-manifest";
        sqlx::query(
            "UPDATE deployments
                SET status = 'watching'::deploy_status_enum, manifest_hash = $1
              WHERE id = $2",
        )
        .bind(manifest_hash)
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("prepare watching deployment");
        sqlx::query(
            "UPDATE deployment_apply_jobs SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire stale owner");
        let current = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("reclaim apply")
            .expect("reclaimed job exists");
        let outcome = DeploymentRolloutOutcome {
            deploy_status: "healthy",
            app_status: "running",
            error_code: None,
            terminal: true,
            manifest_hash: manifest_hash.to_string(),
        };

        let error = publish_rollout_outcome(&pool, &stale, &outcome)
            .await
            .expect_err("stale success publisher rejected");
        assert!(matches!(error, DeploymentJobError::LeaseLost));
        let (deploy_status, app_status, job_state, token): (String, String, String, Uuid) =
            sqlx::query_as(
                "SELECT d.status::text, a.status::text, j.state, j.lock_token
                   FROM deployments d
                   JOIN apps a ON a.id = d.app_id
                   JOIN deployment_apply_jobs j ON j.deployment_id = d.id
                  WHERE d.id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("load state after stale success");
        assert_eq!(deploy_status, "watching");
        assert_eq!(app_status, "creating");
        assert_eq!(job_state, "running");
        assert_eq!(token, current.lock_token);

        publish_rollout_outcome(&pool, &current, &outcome)
            .await
            .expect("current owner publishes success");
        let (deploy_status, app_status, job_state): (String, String, String) = sqlx::query_as(
            "SELECT d.status::text, a.status::text, j.state
               FROM deployments d
               JOIN apps a ON a.id = d.app_id
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load published success");
        assert_eq!(
            (
                deploy_status.as_str(),
                app_status.as_str(),
                job_state.as_str()
            ),
            ("healthy", "running", "completed")
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete stale success fixture");
    }

    #[tokio::test]
    async fn stale_apply_token_cannot_publish_failure() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, _payload) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim setup")
            .expect("setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept setup");
        let stale = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim apply")
            .expect("apply job exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire stale owner");
        let current = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("reclaim apply")
            .expect("reclaimed job exists");

        let error = publish_apply_failure(&pool, &stale)
            .await
            .expect_err("stale failure publisher rejected");
        assert!(matches!(error, DeploymentJobError::LeaseLost));
        let (deploy_status, app_status, job_state, token): (String, String, String, Uuid) =
            sqlx::query_as(
                "SELECT d.status::text, a.status::text, j.state, j.lock_token
                   FROM deployments d
                   JOIN apps a ON a.id = d.app_id
                   JOIN deployment_apply_jobs j ON j.deployment_id = d.id
                  WHERE d.id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("load state after stale failure");
        assert_eq!(deploy_status, "pending");
        assert_eq!(app_status, "creating");
        assert_eq!(job_state, "running");
        assert_eq!(token, current.lock_token);

        publish_apply_failure(&pool, &current)
            .await
            .expect("current owner publishes failure");
        let (deploy_status, app_status, job_state): (String, String, String) = sqlx::query_as(
            "SELECT d.status::text, a.status::text, j.state
               FROM deployments d
               JOIN apps a ON a.id = d.app_id
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load published failure");
        assert_eq!(
            (
                deploy_status.as_str(),
                app_status.as_str(),
                job_state.as_str()
            ),
            ("failed", "failed", "failed")
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete stale failure fixture");
    }

    #[tokio::test]
    async fn publisher_and_acceptance_share_app_then_job_lock_order() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _, _) = insert_job_fixture(&pool).await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim lock-order setup")
            .expect("lock-order setup exists");
        mark_setup_accepted(&pool, deployment_id, setup.lock_token)
            .await
            .expect("accept lock-order setup");
        let job = claim_job(&pool, "pending", "running", Some(deployment_id))
            .await
            .expect("claim lock-order apply")
            .expect("lock-order apply exists");

        let mut acceptance = pool.begin().await.expect("begin acceptance barrier");
        crate::deploy::lock_app_deployment_lane(&mut acceptance, app.id)
            .await
            .expect("acceptance owns outer app lane");
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let publisher_barrier = barrier.clone();
        let publisher_pool = pool.clone();
        let publisher = tokio::spawn(async move {
            publisher_barrier.wait().await;
            publish_apply_failure(&publisher_pool, &job).await
        });
        barrier.wait().await;
        // Give the publisher a scheduling turn. In the former inverse order it
        // acquired the job row here and then waited on our app lane.
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query(
                "SELECT deployment_id FROM deployment_apply_jobs
                  WHERE deployment_id = $1 FOR UPDATE",
            )
            .bind(deployment_id)
            .execute(&mut *acceptance),
        )
        .await
        .expect("app-lane owner is never blocked behind inverse job lock")
        .expect("acceptance locks job row");
        acceptance
            .commit()
            .await
            .expect("release acceptance barrier");

        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .expect("publisher completes without deadlock")
            .expect("publisher task joins")
            .expect("publisher commits after canonical lane wait");
        let (deployment_status, app_status): (DeployStatus, crate::models::AppStatus) =
            sqlx::query_as(
                "SELECT deployment.status, app.status
                   FROM deployments AS deployment
                   JOIN apps AS app ON app.id = deployment.app_id
                  WHERE deployment.id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&pool)
            .await
            .expect("read lock-order publication");
        assert_eq!(deployment_status, DeployStatus::Failed);
        assert_eq!(app_status, crate::models::AppStatus::Failed);
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("clean lock-order fixture");
    }

    #[tokio::test]
    async fn cleanup_is_reclaimed_after_crash_and_retried_after_transient_failure() {
        let pool = database_test_pool().await;
        let (app, deployment_id, _setup_handle, mut payload) = insert_job_fixture(&pool).await;
        payload.delete_app_on_setup_failure = true;
        replace_job_with_raw_payload(
            &pool,
            deployment_id,
            serde_json::to_value(&payload).expect("serialize cleanup payload"),
            JOB_PAYLOAD_VERSION,
            true,
            "setup_pending",
        )
        .await;
        let setup = claim_job(&pool, "setup_pending", "setting_up", Some(deployment_id))
            .await
            .expect("claim cleanup-owned setup")
            .expect("cleanup-owned setup exists");

        mark_setup_failed(&pool, &setup)
            .await
            .expect("persist cleanup-pending setup failure");
        let (setup_state, initial_state): (String, String) = sqlx::query_as(
            "SELECT d.spec_snapshot->>'setup_state', j.state
               FROM deployments d
               JOIN deployment_apply_jobs j ON j.deployment_id = d.id
              WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load initial cleanup state");
        assert_eq!(setup_state, DEPLOYMENT_SETUP_CLEANUP_PENDING);
        assert_eq!(initial_state, "cleanup_pending");

        // Claim cleanup and simulate process exit immediately afterward.
        let first_cleanup = claim_job(&pool, "cleanup_pending", "cleaning_up", Some(deployment_id))
            .await
            .expect("claim initial cleanup")
            .expect("initial cleanup exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire crashed cleanup lease");
        let claimed = claim_job(&pool, "cleanup_pending", "cleaning_up", Some(deployment_id))
            .await
            .expect("claim crashed cleanup")
            .expect("crashed cleanup exists");
        assert_ne!(claimed.lock_token, first_cleanup.lock_token);

        let suffix = app.id.simple().to_string();
        let function_name = format!("cap_test_block_cleanup_{suffix}");
        let trigger_name = format!("cap_test_block_cleanup_trigger_{suffix}");
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               IF OLD.id = '{}'::uuid THEN
                 RAISE EXCEPTION 'forced app cleanup failure';
               END IF;
               RETURN OLD;
             END
             $$",
            app.id
        ))
        .execute(&pool)
        .await
        .expect("create cleanup failure function");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE DELETE ON apps
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .expect("create cleanup failure trigger");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        process_cleanup_job(&state, claimed).await;
        let retry_state: String =
            sqlx::query_scalar("SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1")
                .bind(deployment_id)
                .fetch_one(&pool)
                .await
                .expect("load scheduled cleanup retry");
        assert_eq!(retry_state, "cleanup_pending");

        sqlx::query(&format!("DROP TRIGGER {trigger_name} ON apps"))
            .execute(&pool)
            .await
            .expect("drop cleanup failure trigger");
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .expect("drop cleanup failure function");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET next_attempt_at = clock_timestamp() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make cleanup retry due");
        let retry = claim_job(&pool, "cleanup_pending", "cleaning_up", Some(deployment_id))
            .await
            .expect("claim cleanup retry")
            .expect("cleanup retry exists");
        process_cleanup_job(&state, retry).await;

        let app_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1)")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("verify app cleanup");
        let job_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM deployment_apply_jobs WHERE deployment_id = $1)",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("verify job cleanup");
        assert!(!app_exists);
        assert!(!job_exists);
    }
}
