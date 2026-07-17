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
use sqlx::types::Json;
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
const JOB_PAYLOAD_VERSION: u32 = 1;
const LEASE_INTERVAL_SQL: &str = "90 seconds";
const CLEANUP_RETRY_INTERVAL_SQL: &str = "30 seconds";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
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
    version: u32,
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

    fn validate(&self) -> Result<(), DeploymentJobError> {
        if self.version != JOB_PAYLOAD_VERSION {
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
}

#[derive(Debug, Clone)]
pub struct SetupJobLease {
    pub deployment_id: Uuid,
    pub lock_token: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct ClaimedJob {
    deployment_id: Uuid,
    lock_token: Uuid,
    payload: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentJobError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("DNS setup error: {0}")]
    Dns(#[from] crate::dns::DnsError),
    #[error("invalid durable deployment payload")]
    InvalidPayload,
    #[error("stored deployment artifact is unavailable or malformed")]
    Artifact,
    #[error("deployment job lease was lost")]
    LeaseLost,
    #[error("deployment apply failed: {0}")]
    Apply(#[from] crate::deploy::DeployError),
    #[error("deployment apply limiter closed")]
    ApplyLimiterClosed,
}

impl DeploymentJobError {
    /// Bounded operator-visible classification. Never log the Display source:
    /// provider, Kubernetes, and artifact failures can contain tenant text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Db(_) => "database_error",
            Self::Dns(_) => "dns_setup_error",
            Self::InvalidPayload => "invalid_job_payload",
            Self::Artifact => "artifact_invalid",
            Self::LeaseLost => "lease_lost",
            Self::Apply(_) => "deployment_apply_error",
            Self::ApplyLimiterClosed => "apply_limiter_closed",
        }
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

/// Insert a setup-owned job in the same transaction as the deployment.
///
/// The returned token belongs to the request handler.  If that process exits,
/// another API replica can reclaim the lease after `locked_until`.
pub async fn insert_setup_job(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
) -> Result<SetupJobLease, DeploymentJobError> {
    payload.validate()?;
    let lock_token = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (
             deployment_id, payload, state, lock_token, locked_until
         )
         VALUES ($1, $2, 'setting_up', $3, now() + $4::interval)",
    )
    .bind(deployment_id)
    .bind(Json(payload))
    .bind(lock_token)
    .bind(LEASE_INTERVAL_SQL)
    .execute(&mut **tx)
    .await?;
    Ok(SetupJobLease {
        deployment_id,
        lock_token,
    })
}

/// Insert a job whose setup was already satisfied (for example rollback).
pub async fn insert_ready_job(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
) -> Result<(), DeploymentJobError> {
    payload.validate()?;
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (deployment_id, payload, state)
         VALUES ($1, $2, 'pending')",
    )
    .bind(deployment_id)
    .bind(Json(payload))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Finish the DNS setup owned by a request handler or a recovery worker.
pub async fn process_setup_job(
    state: &AppState,
    lease: SetupJobLease,
) -> Result<(), DeploymentJobError> {
    let payload = match load_leased_payload(
        &state.db,
        lease.deployment_id,
        lease.lock_token,
        "setting_up",
    )
    .await
    {
        Ok(payload) => payload,
        Err(error @ DeploymentJobError::InvalidPayload) => {
            fail_unreadable_job(
                &state.db,
                lease.deployment_id,
                lease.lock_token,
                "setting_up",
            )
            .await;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = payload.validate() {
        fail_unreadable_job(
            &state.db,
            lease.deployment_id,
            lease.lock_token,
            "setting_up",
        )
        .await;
        return Err(error);
    }

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
            payload.app.id,
            &payload.app.domain,
            tee_domain,
        )
        .await?;
        if let Some(custom_domain) = payload.app.custom_domain.as_ref() {
            crate::dns::record_custom_domain(&state.db, payload.app.id, custom_domain).await?;
        }
        Ok::<(), crate::dns::DnsError>(())
    };

    match with_lease_heartbeat(
        &state.db,
        lease.deployment_id,
        lease.lock_token,
        "setting_up",
        setup,
    )
    .await?
    {
        Ok(()) => mark_setup_accepted(&state.db, lease.deployment_id, lease.lock_token).await,
        Err(error) => {
            mark_setup_failed(
                &state.db,
                &payload.app,
                lease.deployment_id,
                lease.lock_token,
                payload.delete_app_on_setup_failure,
            )
            .await?;
            if payload.delete_app_on_setup_failure {
                process_cleanup_job(
                    state,
                    lease.deployment_id,
                    lease.lock_token,
                    payload.clone(),
                )
                .await;
            }
            Err(DeploymentJobError::Dns(error))
        }
    }
}

async fn load_leased_payload(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &str,
) -> Result<DeploymentApplyJobPayload, DeploymentJobError> {
    let payload = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload
           FROM deployment_apply_jobs
          WHERE deployment_id = $1
            AND lock_token = $2
            AND state = $3",
    )
    .bind(deployment_id)
    .bind(lock_token)
    .bind(state)
    .fetch_optional(pool)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    serde_json::from_value(payload).map_err(|_| DeploymentJobError::InvalidPayload)
}

async fn mark_setup_accepted(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
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
                updated_at = now()
          WHERE deployment_id = $1
            AND state = 'setting_up'
            AND lock_token = $2",
    )
    .bind(deployment_id)
    .bind(lock_token)
    .execute(&mut *tx)
    .await?;
    if job.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    tx.commit().await?;
    Ok(())
}

async fn mark_setup_failed(
    pool: &PgPool,
    app: &App,
    deployment_id: Uuid,
    lock_token: Uuid,
    mark_app_failed: bool,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    let next_setup_state = if mark_app_failed {
        DEPLOYMENT_SETUP_CLEANUP_PENDING
    } else {
        DEPLOYMENT_SETUP_FAILED
    };
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
                completed_at = now()
          WHERE id = $2",
    )
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(deployment_id)
    .bind(next_setup_state)
    .execute(&mut *tx)
    .await?;
    if deployment.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let next_job_state = if mark_app_failed {
        "cleaning_up"
    } else {
        "failed"
    };
    let job = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = $1,
                lock_token = CASE WHEN $1 = 'cleaning_up' THEN lock_token ELSE NULL END,
                locked_until = CASE
                    WHEN $1 = 'cleaning_up' THEN now() + $5::interval
                    ELSE NULL
                END,
                last_error_code = $4,
                updated_at = now()
          WHERE deployment_id = $2
            AND state = 'setting_up'
            AND lock_token = $3",
    )
    .bind(next_job_state)
    .bind(deployment_id)
    .bind(lock_token)
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(LEASE_INTERVAL_SQL)
    .execute(&mut *tx)
    .await?;
    if job.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    if mark_app_failed {
        sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = now()
              WHERE id = $1",
        )
        .bind(app.id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn attempt_setup_cleanup(state: &AppState, payload: &DeploymentApplyJobPayload) -> bool {
    if !payload.delete_app_on_setup_failure {
        return true;
    }
    let app = &payload.app;
    if let Err(error) = crate::dns::delete_all_dns_records_for_app(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
    )
    .await
    {
        tracing::error!(
            app_id = %app.id,
            error_code = dns_error_code(&error),
            "failed to clean up DNS after deployment setup failure"
        );
        return false;
    }

    let records_remain = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM dns_records WHERE app_id = $1)",
    )
    .bind(app.id)
    .fetch_one(&state.db)
    .await
    {
        Ok(remaining) => remaining,
        Err(_error) => {
            tracing::error!(
                app_id = %app.id,
                error_code = "database_error",
                "failed to verify DNS cleanup after deployment setup failure"
            );
            return false;
        }
    };
    if records_remain {
        tracing::error!(
            app_id = %app.id,
            "DNS cleanup left tracked records; retaining app for reconciliation"
        );
        return false;
    }

    if let Err(_error) = sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(
            app_id = %app.id,
            error_code = "database_error",
            "failed to compensate first generic deployment after setup failure"
        );
        return false;
    }
    true
}

async fn process_cleanup_job(
    state: &AppState,
    deployment_id: Uuid,
    lock_token: Uuid,
    payload: DeploymentApplyJobPayload,
) {
    let outcome = with_lease_heartbeat(
        &state.db,
        deployment_id,
        lock_token,
        "cleaning_up",
        attempt_setup_cleanup(state, &payload),
    )
    .await;
    match outcome {
        Ok(true) => {
            // Deleting the first-deployment app cascades the deployment and
            // job rows. If another cleanup owner already completed it, there
            // is likewise nothing left to publish.
        }
        Ok(false) => {
            if let Err(error) =
                release_cleanup_for_retry(&state.db, deployment_id, lock_token).await
            {
                tracing::error!(
                    deployment_id = %deployment_id,
                    error_code = error.code(),
                    "failed to schedule durable deployment cleanup retry"
                );
            }
        }
        Err(error) => tracing::error!(
            deployment_id = %deployment_id,
            error_code = error.code(),
            "durable deployment cleanup lost its lease"
        ),
    }
}

async fn release_cleanup_for_retry(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'cleanup_pending',
                lock_token = NULL,
                locked_until = NULL,
                next_attempt_at = now() + $1::interval,
                last_error_code = $2,
                updated_at = now()
          WHERE deployment_id = $3
            AND state = 'cleaning_up'
            AND lock_token = $4",
    )
    .bind(CLEANUP_RETRY_INTERVAL_SQL)
    .bind(DEPLOYMENT_SETUP_FAILED_MESSAGE)
    .bind(deployment_id)
    .bind(lock_token)
    .execute(pool)
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
                match claim_expired_setup_job(&state.db).await {
                    Ok(Some(job)) => {
                        found_work = true;
                        let worker_state = state.clone();
                        tokio::spawn(async move {
                            let _worker_slot = worker_slot;
                            let deployment_id = job.deployment_id;
                            if let Err(error) = process_setup_job(
                                &worker_state,
                                SetupJobLease {
                                    deployment_id,
                                    lock_token: job.lock_token,
                                },
                            )
                            .await
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
                                process_claimed_cleanup_job(worker_state, job).await;
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
                match claim_apply_job(&state.db).await {
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

async fn claim_expired_setup_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "setting_up", "setting_up", true, None).await
}

async fn claim_apply_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "pending", "running", false, None).await
}

async fn claim_cleanup_job(pool: &PgPool) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    claim_job(pool, "cleanup_pending", "cleaning_up", false, None).await
}

async fn claim_job(
    pool: &PgPool,
    ready_state: &str,
    claimed_state: &str,
    expired_only: bool,
    only_deployment_id: Option<Uuid>,
) -> Result<Option<ClaimedJob>, DeploymentJobError> {
    let lock_token = Uuid::new_v4();
    let job = sqlx::query_as::<_, ClaimedJob>(
        "WITH candidate AS (
             SELECT deployment_id
               FROM deployment_apply_jobs
              WHERE (
                    (state = $1 AND NOT $4)
                    OR (state = $2 AND locked_until < now())
                    OR (state = $1 AND $4 AND locked_until < now())
              )
                AND next_attempt_at <= now()
                AND ($6::uuid IS NULL OR deployment_id = $6)
              ORDER BY created_at, deployment_id
              FOR UPDATE SKIP LOCKED
              LIMIT 1
         )
         UPDATE deployment_apply_jobs AS job
            SET state = $2,
                lock_token = $3,
                locked_until = now() + $5::interval,
                attempts = attempts + 1,
                updated_at = now()
           FROM candidate
          WHERE job.deployment_id = candidate.deployment_id
         RETURNING job.deployment_id, job.lock_token, job.payload",
    )
    .bind(ready_state)
    .bind(claimed_state)
    .bind(lock_token)
    .bind(expired_only)
    .bind(LEASE_INTERVAL_SQL)
    .bind(only_deployment_id)
    .fetch_optional(pool)
    .await?;
    Ok(job)
}

async fn process_claimed_cleanup_job(state: AppState, job: ClaimedJob) {
    let deployment_id = job.deployment_id;
    let lock_token = job.lock_token;
    let payload = match serde_json::from_value::<DeploymentApplyJobPayload>(job.payload) {
        Ok(payload) if payload.validate().is_ok() => payload,
        Ok(_) | Err(_) => {
            fail_unreadable_job(&state.db, deployment_id, lock_token, "cleaning_up").await;
            return;
        }
    };
    process_cleanup_job(&state, deployment_id, lock_token, payload).await;
}

async fn process_apply_job(
    state: AppState,
    job: ClaimedJob,
    _worker_slot: tokio::sync::OwnedSemaphorePermit,
) {
    let deployment_id = job.deployment_id;
    let lock_token = job.lock_token;
    let payload = match serde_json::from_value::<DeploymentApplyJobPayload>(job.payload) {
        Ok(payload) if payload.validate().is_ok() => payload,
        Ok(_) | Err(_) => {
            fail_unreadable_job(&state.db, deployment_id, lock_token, "running").await;
            return;
        }
    };

    let result = with_lease_heartbeat(
        &state.db,
        deployment_id,
        lock_token,
        "running",
        apply_claimed_job(&state, deployment_id, &payload),
    )
    .await;

    match result {
        Ok(Ok(JobApplyOutcome::Applied(outcome))) => {
            if let Err(error) =
                publish_rollout_outcome(&state.db, deployment_id, lock_token, &payload, &outcome)
                    .await
            {
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
        Ok(Err(error)) => {
            fail_apply_job(&state, deployment_id, lock_token, &payload.app, &error).await;
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

async fn fail_unreadable_job(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    claimed_state: &str,
) {
    let setup_phase = matches!(claimed_state, "setting_up" | "cleaning_up");
    let failure_code = if setup_phase {
        DEPLOYMENT_SETUP_FAILED_MESSAGE
    } else {
        DEPLOYMENT_APPLY_FAILED_MESSAGE
    };
    let result = async {
        let mut tx = pool.begin().await?;
        let job = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'failed',
                    lock_token = NULL,
                    locked_until = NULL,
                    last_error_code = $1,
                    updated_at = now()
              WHERE deployment_id = $2
                AND state = $3
                AND lock_token = $4",
        )
        .bind(failure_code)
        .bind(deployment_id)
        .bind(claimed_state)
        .bind(lock_token)
        .execute(&mut *tx)
        .await?;
        if job.rows_affected() != 1 {
            return Err(sqlx::Error::RowNotFound);
        }
        sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    spec_snapshot = CASE
                        WHEN $1 IN ('setting_up', 'cleaning_up') THEN jsonb_set(
                            spec_snapshot,
                            '{setup_state}',
                            '\"failed\"'::jsonb,
                            true
                        )
                        ELSE spec_snapshot
                    END,
                    error_message = $2,
                    completed_at = now()
              WHERE id = $3",
        )
        .bind(claimed_state)
        .bind(failure_code)
        .bind(deployment_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE apps AS app
                SET status = 'failed'::app_status_enum,
                    updated_at = now()
               FROM deployments AS deployment
              WHERE deployment.id = $1
                AND app.id = deployment.app_id
                AND deployment.id = (
                    SELECT latest.id
                      FROM deployments AS latest
                     WHERE latest.app_id = deployment.app_id
                     ORDER BY latest.created_at DESC, latest.id DESC
                     LIMIT 1
                )",
        )
        .bind(deployment_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }
    .await;

    if result.is_err() {
        tracing::error!(
            deployment_id = %deployment_id,
            error_code = "database_error",
            "failed to quarantine malformed durable deployment job"
        );
    } else {
        tracing::error!(
            deployment_id = %deployment_id,
            error_code = "invalid_job_payload",
            "quarantined malformed durable deployment job"
        );
    }
}

#[derive(Debug, Clone)]
enum JobApplyOutcome {
    Applied(DeploymentRolloutOutcome),
    AlreadyTerminal,
}

async fn apply_claimed_job(
    state: &AppState,
    deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
) -> Result<JobApplyOutcome, DeploymentJobError> {
    payload.validate()?;
    validate_deployment_identity(&state.db, deployment_id, payload).await?;
    if deployment_is_terminal(&state.db, deployment_id).await? {
        return Ok(JobApplyOutcome::AlreadyTerminal);
    }

    let (
        workload_artifact_binding,
        signed_policy_artifact,
        local_workload_artifacts_json,
        local_trustee_policy_json,
    ) = if let (Some(artifact_deployment_id), Some(expected_descriptor_core_hash)) = (
        payload.artifact_deployment_id,
        payload.artifact_descriptor_core_hash,
    ) {
        let loaded = crate::signing_service::load_workload_artifacts_exact(
            &state.db,
            payload.app.id,
            artifact_deployment_id,
            expected_descriptor_core_hash,
        )
        .await
        .map_err(|_| DeploymentJobError::Artifact)?
        .ok_or(DeploymentJobError::Artifact)?;
        if loaded.descriptor.org_id != payload.app.org_id {
            return Err(DeploymentJobError::Artifact);
        }
        (
            Some(loaded.binding),
            Some(loaded.signed_policy_artifact),
            Some(loaded.workload_artifacts_json),
            Some(loaded.trustee_policy_json),
        )
    } else {
        (None, None, None, None)
    };

    let apply_permit = state
        .deployment_apply_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| DeploymentJobError::ApplyLimiterClosed)?;

    // A newer accepted deployment may have superseded this row while it was
    // waiting for apply capacity.  Never render a terminal/superseded job.
    if deployment_is_terminal(&state.db, deployment_id).await? {
        drop(apply_permit);
        return Ok(JobApplyOutcome::AlreadyTerminal);
    }
    validate_deployment_identity(&state.db, deployment_id, payload).await?;

    let rollout = crate::deploy::apply_deployment_manifests(ApplyDeploymentManifestsRequest {
        pool: state.db.clone(),
        app: payload.app.clone(),
        snapshot: payload.snapshot.clone(),
        deployment_id,
        attestation_config: payload.attestation_config.clone(),
        kbs_policy_config: state.kbs_policy.clone(),
        api_signing_pubkey: payload.api_signing_pubkey.clone(),
        api_url: payload.api_url.clone(),
        workload_artifact_binding,
        signed_policy_artifact,
        local_workload_artifacts_json,
        local_trustee_policy_json,
        log_encryption: payload.log_encryption.clone(),
    })
    .await?;
    drop(apply_permit);
    Ok(JobApplyOutcome::Applied(rollout.watch().await))
}

async fn validate_deployment_identity(
    pool: &PgPool,
    deployment_id: Uuid,
    payload: &DeploymentApplyJobPayload,
) -> Result<(), DeploymentJobError> {
    let identity = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "SELECT app_id, org_id FROM deployments WHERE id = $1",
    )
    .bind(deployment_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if identity != (payload.app.id, Some(payload.app.org_id)) {
        return Err(DeploymentJobError::InvalidPayload);
    }
    Ok(())
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

async fn fail_apply_job(
    state: &AppState,
    deployment_id: Uuid,
    lock_token: Uuid,
    app: &App,
    error: &DeploymentJobError,
) {
    if let Err(db_error) = publish_apply_failure(&state.db, deployment_id, lock_token, app).await {
        tracing::error!(
            deployment_id = %deployment_id,
            error_code = db_error.code(),
            "failed to atomically publish durable deployment failure"
        );
    }
    tracing::error!(
        app_id = %app.id,
        deployment_id = %deployment_id,
        error_code = error.code(),
        "durable deployment apply failed"
    );
}

async fn lock_owned_running_job(
    tx: &mut Transaction<'_, Postgres>,
    deployment_id: Uuid,
    lock_token: Uuid,
) -> Result<(), DeploymentJobError> {
    let owned = sqlx::query_scalar::<_, Uuid>(
        "SELECT deployment_id
           FROM deployment_apply_jobs
          WHERE deployment_id = $1
            AND state = 'running'
            AND lock_token = $2
          FOR UPDATE",
    )
    .bind(deployment_id)
    .bind(lock_token)
    .fetch_optional(&mut **tx)
    .await?;
    if owned.is_none() {
        return Err(DeploymentJobError::LeaseLost);
    }
    Ok(())
}

async fn publish_rollout_outcome(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    payload: &DeploymentApplyJobPayload,
    outcome: &DeploymentRolloutOutcome,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    // The lease row is always checked and locked before any tenant-visible
    // deployment or app state can be changed.
    lock_owned_running_job(&mut tx, deployment_id, lock_token).await?;
    let deployment = sqlx::query_as::<_, (Uuid, Option<Uuid>, DeployStatus, Option<String>)>(
        "SELECT app_id, org_id, status, manifest_hash
           FROM deployments
          WHERE id = $1
          FOR UPDATE",
    )
    .bind(deployment_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if deployment.0 != payload.app.id || deployment.1 != Some(payload.app.org_id) {
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
                completed_at = CASE WHEN $3 THEN now() ELSE completed_at END
          WHERE id = $4
            AND app_id = $5
            AND org_id = $6
            AND status = 'watching'::deploy_status_enum
            AND manifest_hash = $7",
    )
    .bind(outcome.deploy_status)
    .bind(outcome.error_code)
    .bind(outcome.terminal)
    .bind(deployment_id)
    .bind(payload.app.id)
    .bind(payload.app.org_id)
    .bind(&outcome.manifest_hash)
    .execute(&mut *tx)
    .await?;
    if deployment_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let app_result = sqlx::query(
        "UPDATE apps
            SET status = $1::app_status_enum,
                updated_at = now()
          WHERE id = $2 AND org_id = $3",
    )
    .bind(outcome.app_status)
    .bind(payload.app.id)
    .bind(payload.app.org_id)
    .execute(&mut *tx)
    .await?;
    if app_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let job_result = sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'completed',
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = NULL,
                updated_at = now()
          WHERE deployment_id = $1
            AND state = 'running'
            AND lock_token = $2",
    )
    .bind(deployment_id)
    .bind(lock_token)
    .execute(&mut *tx)
    .await?;
    if job_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    tx.commit().await?;
    Ok(())
}

async fn publish_apply_failure(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    app: &App,
) -> Result<(), DeploymentJobError> {
    let mut tx = pool.begin().await?;
    lock_owned_running_job(&mut tx, deployment_id, lock_token).await?;
    let deployment = sqlx::query_as::<_, (Uuid, Option<Uuid>, DeployStatus)>(
        "SELECT app_id, org_id, status
           FROM deployments
          WHERE id = $1
          FOR UPDATE",
    )
    .bind(deployment_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DeploymentJobError::LeaseLost)?;
    if deployment.0 != app.id || deployment.1 != Some(app.org_id) {
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
                completed_at = now()
          WHERE id = $2
            AND app_id = $3
            AND org_id = $4
            AND status IN ('pending', 'applying', 'watching')",
    )
    .bind(DEPLOYMENT_APPLY_FAILED_MESSAGE)
    .bind(deployment_id)
    .bind(app.id)
    .bind(app.org_id)
    .execute(&mut *tx)
    .await?;
    if deployment_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    let app_result = sqlx::query(
        "UPDATE apps
            SET status = 'failed'::app_status_enum,
                updated_at = now()
          WHERE id = $1 AND org_id = $2",
    )
    .bind(app.id)
    .bind(app.org_id)
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
                updated_at = now()
          WHERE deployment_id = $2
            AND state = 'running'
            AND lock_token = $3",
    )
    .bind(DEPLOYMENT_APPLY_FAILED_MESSAGE)
    .bind(deployment_id)
    .bind(lock_token)
    .execute(&mut *tx)
    .await?;
    if job_result.rows_affected() != 1 {
        return Err(DeploymentJobError::LeaseLost);
    }
    tx.commit().await?;
    Ok(())
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
                updated_at = now()
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

async fn with_lease_heartbeat<F, T>(
    pool: &PgPool,
    deployment_id: Uuid,
    lock_token: Uuid,
    state: &str,
    future: F,
) -> Result<T, DeploymentJobError>
where
    F: Future<Output = T>,
{
    tokio::pin!(future);
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;

    loop {
        tokio::select! {
            output = &mut future => return Ok(output),
            _ = heartbeat.tick() => {
                let result = sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET locked_until = now() + $1::interval,
                            updated_at = now()
                      WHERE deployment_id = $2
                        AND state = $3
                        AND lock_token = $4",
                )
                .bind(LEASE_INTERVAL_SQL)
                .bind(deployment_id)
                .bind(state)
                .bind(lock_token)
                .execute(pool)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(DeploymentJobError::LeaseLost);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let app = test_app(org_id, app_id);
        let payload = test_payload(&app);
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
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot)
             VALUES ($1, $2, $3, 'api', $4)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(serde_json::json!({
            "setup_state": DEPLOYMENT_SETUP_DNS_PENDING,
            "image": "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }))
        .execute(&mut *tx)
        .await
        .expect("insert deployment job deployment");
        let lease = insert_setup_job(&mut tx, deployment_id, &payload)
            .await
            .expect("insert setup job");
        tx.commit().await.expect("commit deployment job fixture");
        (app, deployment_id, lease, payload)
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
            payload.validate(),
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
        let (app, deployment_id, original_setup_lease, _payload) = insert_job_fixture(&pool).await;

        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire setup lease");
        let recovered_setup =
            claim_job(&pool, "setting_up", "setting_up", true, Some(deployment_id))
                .await
                .expect("claim expired setup")
                .expect("expired setup job exists");
        assert_ne!(recovered_setup.lock_token, original_setup_lease.lock_token);

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

        let first_apply = claim_job(&pool, "pending", "running", false, Some(deployment_id))
            .await
            .expect("claim ready apply")
            .expect("ready apply job exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("simulate apply worker crash");
        let recovered_apply = claim_job(&pool, "pending", "running", false, Some(deployment_id))
            .await
            .expect("reclaim crashed apply")
            .expect("crashed apply job exists");
        assert_ne!(recovered_apply.lock_token, first_apply.lock_token);
        let recovered_payload: DeploymentApplyJobPayload =
            serde_json::from_value(recovered_apply.payload).expect("decode recovered payload");
        assert_eq!(recovered_payload.app.id, app.id);

        let attempts: i32 = sqlx::query_scalar(
            "SELECT attempts FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load recovered attempt count");
        assert_eq!(attempts, 3);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment job fixture");
    }

    #[tokio::test]
    async fn stale_setup_token_cannot_publish_false_acceptance() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;

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
        assert_eq!(lock_token, setup_lease.lock_token);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete deployment job fixture");
    }

    #[tokio::test]
    async fn existing_app_setup_failure_is_terminal_without_cleanup_marker() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;

        mark_setup_failed(&pool, &app, deployment_id, setup_lease.lock_token, false)
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
        insert_ready_job(&mut new_tx, new_style_id, &payload)
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
    async fn semantic_setup_payload_failure_is_quarantined_once() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET payload = jsonb_set(payload, '{version}', '999'::jsonb)
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("corrupt durable payload version");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let error = process_setup_job(&state, setup_lease)
            .await
            .expect_err("invalid semantic payload rejected");
        assert!(matches!(error, DeploymentJobError::InvalidPayload));
        let (setup_state, job_state, lock_token): (String, String, Option<Uuid>) = sqlx::query_as(
            "SELECT d.spec_snapshot->>'setup_state', j.state, j.lock_token
                   FROM deployments d
                   JOIN deployment_apply_jobs j ON j.deployment_id = d.id
                  WHERE d.id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load quarantined job");
        assert_eq!(setup_state, DEPLOYMENT_SETUP_FAILED);
        assert_eq!(job_state, "failed");
        assert!(lock_token.is_none());

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("delete malformed payload fixture");
    }

    #[tokio::test]
    async fn cross_app_and_empty_setup_payloads_are_quarantined_not_reclaimed() {
        let pool = database_test_pool().await;
        for cross_app in [false, true] {
            let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;
            if cross_app {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET payload = jsonb_set(
                            payload,
                            '{snapshot,containers,0,app_id}',
                            to_jsonb($2::text)
                        )
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .bind(Uuid::new_v4().to_string())
                .execute(&pool)
                .await
                .expect("cross-bind durable payload container");
            } else {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET payload = jsonb_set(
                            payload,
                            '{snapshot,containers}',
                            '[]'::jsonb
                        )
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .execute(&pool)
                .await
                .expect("empty durable payload containers");
            }

            let mut state = crate::test_support::lazy_state();
            state.db = pool.clone();
            let error = process_setup_job(&state, setup_lease)
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
        let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;
        mark_setup_accepted(&pool, deployment_id, setup_lease.lock_token)
            .await
            .expect("accept setup");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET payload = jsonb_set(payload, '{snapshot,containers}', '[]'::jsonb)
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("empty apply payload containers");
        let claimed = claim_job(&pool, "pending", "running", false, Some(deployment_id))
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
        payload.app.org_id = Uuid::new_v4();
        let error = validate_deployment_identity(&pool, deployment_id, &payload)
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
        let (app, deployment_id, setup_lease, payload) = insert_job_fixture(&pool).await;
        mark_setup_accepted(&pool, deployment_id, setup_lease.lock_token)
            .await
            .expect("accept setup");
        let stale = claim_job(&pool, "pending", "running", false, Some(deployment_id))
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
            "UPDATE deployment_apply_jobs SET locked_until = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire stale owner");
        let current = claim_job(&pool, "pending", "running", false, Some(deployment_id))
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

        let error =
            publish_rollout_outcome(&pool, deployment_id, stale.lock_token, &payload, &outcome)
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

        publish_rollout_outcome(&pool, deployment_id, current.lock_token, &payload, &outcome)
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
        let (app, deployment_id, setup_lease, _payload) = insert_job_fixture(&pool).await;
        mark_setup_accepted(&pool, deployment_id, setup_lease.lock_token)
            .await
            .expect("accept setup");
        let stale = claim_job(&pool, "pending", "running", false, Some(deployment_id))
            .await
            .expect("claim apply")
            .expect("apply job exists");
        sqlx::query(
            "UPDATE deployment_apply_jobs SET locked_until = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire stale owner");
        let current = claim_job(&pool, "pending", "running", false, Some(deployment_id))
            .await
            .expect("reclaim apply")
            .expect("reclaimed job exists");

        let error = publish_apply_failure(&pool, deployment_id, stale.lock_token, &app)
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

        publish_apply_failure(&pool, deployment_id, current.lock_token, &app)
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
    async fn cleanup_is_reclaimed_after_crash_and_retried_after_transient_failure() {
        let pool = database_test_pool().await;
        let (app, deployment_id, setup_lease, mut payload) = insert_job_fixture(&pool).await;
        payload.delete_app_on_setup_failure = true;
        sqlx::query("UPDATE deployment_apply_jobs SET payload = $1 WHERE deployment_id = $2")
            .bind(Json(&payload))
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("enable cleanup for fixture");

        mark_setup_failed(&pool, &app, deployment_id, setup_lease.lock_token, true)
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
        assert_eq!(initial_state, "cleaning_up");

        // Simulate process exit immediately after the durable failure commit.
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET locked_until = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("expire crashed cleanup lease");
        let claimed = claim_job(
            &pool,
            "cleanup_pending",
            "cleaning_up",
            false,
            Some(deployment_id),
        )
        .await
        .expect("claim crashed cleanup")
        .expect("crashed cleanup exists");

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
        process_claimed_cleanup_job(state.clone(), claimed).await;
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
                SET next_attempt_at = now() - interval '1 second'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("make cleanup retry due");
        let retry = claim_job(
            &pool,
            "cleanup_pending",
            "cleaning_up",
            false,
            Some(deployment_id),
        )
        .await
        .expect("claim cleanup retry")
        .expect("cleanup retry exists");
        process_claimed_cleanup_job(state, retry).await;

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
