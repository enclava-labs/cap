//! Owner-facing lifecycle diagnosis for the active deployment (#90).
//!
//! Tenants have no Kubernetes credentials, no node access, and no platform
//! database visibility — those are correct confidential-computing trust
//! boundaries. This module is the safe replacement for the `kubectl
//! describe` / controller-log diagnosis an operator would otherwise
//! perform: it projects what the platform already knows durably (the
//! deployment, its apply job, and the app mutation lease) into a stable,
//! redacted phase / condition / reason contract that the CLI and hosted
//! console can render identically.
//!
//! Contract rules:
//! - Every string is a fixed, redacted token — no provider, Kubernetes,
//!   tenant, or database text is copied through.
//! - Absent rows degrade to `phase: "unknown"`; projection never fails.
//! - No secrets, node names, raw attestation evidence, or lease tokens.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::App;

/// A single durable step the active deployment is working through.
///
/// The job state machine is `setup_pending -> setting_up -> pending ->
/// running -> completed | failed` with `cleanup_pending -> cleaning_up`
/// for first-deploy rollback; `watching` deployments have already applied
/// their manifests and are observing rollout health.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    Queued,
    SettingUp,
    Applying,
    Watching,
    Healthy,
    Failed,
    Cancelled,
    Unknown,
}

impl DeploymentPhase {
    fn from_job_state(job_state: &str, deployment_status: &str, setup_state: Option<&str>) -> Self {
        match job_state {
            "setup_pending" => Self::Queued,
            "setting_up" => Self::SettingUp,
            "cleanup_pending" | "cleaning_up" => Self::SettingUp,
            "pending" => Self::Queued,
            // A `running` job spans manifest apply AND rollout watch; the
            // deployment row carries the exact sub-phase.
            "running" => match deployment_status {
                "watching" => Self::Watching,
                "applying" | "pending" => Self::Applying,
                _ => Self::Unknown,
            },
            "completed" => Self::Healthy,
            "failed" => Self::Failed,
            _ => {
                // The payload's setup marker survives into apply; a job
                // without an in-flight state is classified by it.
                match setup_state {
                    Some("dns_pending") | Some("cleanup_pending") | Some("failed") => Self::Failed,
                    _ => Self::Unknown,
                }
            }
        }
    }
}

/// Whether the phase is advancing, deliberately parked on an external
/// dependency, blocked by another operation's mutation lease, or terminal.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCondition {
    Progressing,
    WaitingExternal,
    BlockedByOperation,
    Stalled,
    Terminal,
    Unknown,
}

/// Stable, redacted reason codes. These are a public contract consumed by
/// the CLI and the hosted console: add new codes, never rename old ones.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentReason {
    DnsSetupPending,
    DeploymentSetupFailed,
    DeploymentApplyFailed,
    DeploymentSuperseded,
    LeaseExpiredRetryScheduled,
    MutationLeaseHeldByOperation,
    AppDeleting,
    NoApplyJobRecorded,
}

/// One row of the owner-facing lifecycle timeline: the durable facts behind
/// "when will it retry or fail terminally".
#[derive(Debug, Serialize)]
pub struct DeploymentDiagnostics {
    /// Normalized lifecycle phase of the active deployment.
    pub phase: DeploymentPhase,
    /// Progress classification for the current phase.
    pub condition: DeploymentCondition,
    /// Stable, redacted reason code for a non-progressing condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<DeploymentReason>,
    /// The deployment this projection describes.
    pub deployment_id: Uuid,
    /// Deployment creation time (phase start anchor).
    pub started_at: DateTime<Utc>,
    /// Last durable activity: job lease renewal, state change, or retry
    /// scheduling. Absent only when the job row is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_progress_at: Option<DateTime<Utc>>,
    /// Apply-attempt count for this job, including failed ones.
    pub attempts: i32,
    /// When the dispatcher will next pick the job up. Absent while a worker
    /// holds the lease or after a terminal state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Lease expiry when another operation owns the app mutation lease
    /// (including this deployment's own worker, whose renewals make the
    /// wait observable instead of opaque).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<DateTime<Utc>>,
    /// The operation that owns the app mutation lease, when one does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_operation: Option<String>,
    /// Cumulative rollout-observation anchor (`watching` deployments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observing_since: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct DiagnosticsRow {
    deployment_id: Option<Uuid>,
    deployment_status: String,
    setup_state: Option<String>,
    created_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    observing_since: Option<DateTime<Utc>>,
    job_state: Option<String>,
    job_updated_at: Option<DateTime<Utc>>,
    next_attempt_at: Option<DateTime<Utc>>,
    attempts: Option<i32>,
    job_locked_until: Option<DateTime<Utc>>,
    job_lock_token: Option<Uuid>,
    last_error_code: Option<String>,
    lease_locked_until: Option<DateTime<Utc>>,
    lease_operation_kind: Option<String>,
    app_deleting: bool,
}

/// Load the durable facts for the app's newest deployment and project them.
/// Never fails: missing rows produce `phase: unknown` diagnostics so the
/// endpoint stays available exactly when diagnosis is hardest.
pub(crate) async fn deployment_diagnostics(
    pool: &PgPool,
    app: &App,
) -> Result<DeploymentDiagnostics, sqlx::Error> {
    let row = sqlx::query_as::<_, DiagnosticsRow>(
        // sqlx::FromRow matches by column name: every qualified or computed
        // column MUST carry an explicit alias equal to the struct field.
        "SELECT deployment.id AS deployment_id,
                deployment.status::text AS deployment_status,
                deployment.spec_snapshot->>'setup_state' AS setup_state,
                deployment.created_at,
                deployment.completed_at,
                deployment.observing_since,
                job.state AS job_state,
                job.updated_at AS job_updated_at,
                job.next_attempt_at,
                job.attempts,
                job.locked_until AS job_locked_until,
                job.lock_token AS job_lock_token,
                job.last_error_code,
                lease.locked_until AS lease_locked_until,
                lease.operation_kind AS lease_operation_kind,
                app_row.status = 'deleting'::app_status_enum AS app_deleting
           FROM apps AS app_row
           LEFT JOIN LATERAL (
               SELECT * FROM deployments
                WHERE app_id = app_row.id
                ORDER BY created_at DESC, id DESC
                LIMIT 1
           ) AS deployment ON true
           LEFT JOIN deployment_apply_jobs AS job
                  ON job.deployment_id = deployment.id
           LEFT JOIN LATERAL (
               SELECT locked_until, operation_kind
                 FROM app_mutation_leases
                WHERE app_id = app_row.id
                  AND owner_token IS NOT NULL
                  AND reclaim_after > clock_timestamp()
                LIMIT 1
           ) AS lease ON true
          WHERE app_row.id = $1",
    )
    .bind(app.id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(DeploymentDiagnostics {
            phase: DeploymentPhase::Unknown,
            condition: DeploymentCondition::Unknown,
            reason: None,
            deployment_id: app.id,
            started_at: app.created_at,
            last_progress_at: None,
            attempts: 0,
            next_retry_at: None,
            blocked_until: None,
            blocking_operation: None,
            observing_since: None,
        });
    };
    Ok(project_diagnostics(row))
}

fn project_diagnostics(row: DiagnosticsRow) -> DeploymentDiagnostics {
    let deployment_id = row.deployment_id.unwrap_or_else(Uuid::new_v4);
    let started_at = row.created_at.unwrap_or_else(Utc::now);
    if row.app_deleting {
        return DeploymentDiagnostics {
            phase: DeploymentPhase::Cancelled,
            condition: DeploymentCondition::Terminal,
            reason: Some(DeploymentReason::AppDeleting),
            deployment_id,
            started_at,
            last_progress_at: row.job_updated_at.or(row.completed_at),
            attempts: row.attempts.unwrap_or(0),
            next_retry_at: None,
            blocked_until: None,
            blocking_operation: None,
            observing_since: row.observing_since,
        };
    }

    // No job row: either a pre-migration deployment or one whose job was
    // never created. The deployment status alone still classifies the
    // generation for the owner.
    let (phase, reason) = match (&row.job_state, row.setup_state.as_deref()) {
        (Some(job_state), _) => (
            DeploymentPhase::from_job_state(
                job_state,
                &row.deployment_status,
                row.setup_state.as_deref(),
            ),
            reason_for_job_state(job_state, &row),
        ),
        (None, Some(setup_state)) => {
            // No job row: a terminal deployment row still classifies the
            // generation for the owner.
            let phase = match row.deployment_status.as_str() {
                "failed" => {
                    if setup_state == "cancel" {
                        DeploymentPhase::Cancelled
                    } else {
                        DeploymentPhase::Failed
                    }
                }
                "healthy" => DeploymentPhase::Healthy,
                _ => DeploymentPhase::Unknown,
            };
            (
                phase,
                match setup_state {
                    "dns_pending" | "cleanup_pending" => Some(DeploymentReason::DnsSetupPending),
                    "failed" => Some(DeploymentReason::DeploymentSetupFailed),
                    _ => None,
                },
            )
        }
        (None, None) => (
            DeploymentPhase::Unknown,
            Some(DeploymentReason::NoApplyJobRecorded),
        ),
    };

    let attempts = row.attempts.unwrap_or(0);
    let worker_holds_lease = row.job_lock_token.is_some();
    let now = Utc::now();

    // The dispatcher retries a job whose lease expired while state remains
    // in flight; otherwise a non-terminal state with no live worker is
    // stale until the reconciler bounds it.
    let condition = match phase {
        DeploymentPhase::Healthy | DeploymentPhase::Failed | DeploymentPhase::Cancelled => {
            DeploymentCondition::Terminal
        }
        DeploymentPhase::Unknown => DeploymentCondition::Unknown,
        DeploymentPhase::Queued | DeploymentPhase::SettingUp | DeploymentPhase::Watching => {
            if worker_holds_lease && row.job_locked_until.is_some_and(|until| until > now) {
                DeploymentCondition::Progressing
            } else if row
                .next_attempt_at
                .is_some_and(|attempt_at| attempt_at > now)
            {
                DeploymentCondition::WaitingExternal
            } else {
                DeploymentCondition::Stalled
            }
        }
        DeploymentPhase::Applying => DeploymentCondition::Progressing,
    };

    // Refined reasons for non-progressing non-terminal jobs: a scheduled
    // retry is the dispatcher's lease-expiry recovery; a stall with a live
    // foreign lease is blocked on that operation.
    let reason = match condition {
        DeploymentCondition::WaitingExternal => {
            reason.or(Some(DeploymentReason::LeaseExpiredRetryScheduled))
        }
        DeploymentCondition::Stalled
            if row.lease_operation_kind.is_some()
                && row.lease_locked_until.is_some_and(|until| until > now) =>
        {
            Some(DeploymentReason::MutationLeaseHeldByOperation)
        }
        _ => reason,
    };

    let next_retry_at = match phase {
        DeploymentPhase::Queued | DeploymentPhase::SettingUp | DeploymentPhase::Watching => {
            row.next_attempt_at.filter(|attempt_at| attempt_at > &now)
        }
        _ => None,
    };

    DeploymentDiagnostics {
        phase,
        condition,
        reason,
        deployment_id,
        started_at,
        last_progress_at: row.job_updated_at.or(row.completed_at),
        attempts,
        next_retry_at,
        blocked_until: row.lease_locked_until.filter(|until| until > &now),
        blocking_operation: row.lease_operation_kind.filter(|_| {
            condition == DeploymentCondition::WaitingExternal
                || condition == DeploymentCondition::Stalled
        }),
        observing_since: row
            .observing_since
            .filter(|_| row.deployment_status == "watching"),
    }
}

/// Reason codes for non-progressing non-terminal jobs. Ordering matters:
/// the terminal classifications embedded in `last_error_code` win over
/// requeue bookkeeping.
fn reason_for_job_state(job_state: &str, row: &DiagnosticsRow) -> Option<DeploymentReason> {
    if matches!(job_state, "completed" | "failed" | "running") {
        return row.last_error_code.as_deref().and_then(error_code_reason);
    }
    match job_state {
        "setup_pending" | "setting_up" => match row.setup_state.as_deref() {
            Some("failed") => Some(DeploymentReason::DeploymentSetupFailed),
            _ => None,
        },
        _ => None,
    }
}

fn error_code_reason(code: &str) -> Option<DeploymentReason> {
    match code {
        "deployment_setup_failed" => Some(DeploymentReason::DeploymentSetupFailed),
        "deployment_apply_failed" => Some(DeploymentReason::DeploymentApplyFailed),
        "deployment_superseded" => Some(DeploymentReason::DeploymentSuperseded),
        _ => None,
    }
}

/// GET /apps/{name}/deployment/diagnostics -- owner-facing lifecycle
/// projection for the active deployment (#90). Authenticated, read-only,
/// and redacted by construction: every field is a durable database fact or
/// a fixed token.
pub async fn get_deployment_diagnostics(
    auth: AuthContext,
    State(state): State<crate::state::AppState>,
    axum::extract::Path(app_name): axum::extract::Path<String>,
) -> Result<Json<DeploymentDiagnostics>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "database error" })),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "app not found" })),
        ))?;

    let diagnostics = deployment_diagnostics(&state.db, &app).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "database error" })),
        )
    })?;

    Ok(Json(diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        deployment_status: &str,
        job_state: Option<&str>,
        setup_state: Option<&str>,
    ) -> DiagnosticsRow {
        DiagnosticsRow {
            deployment_id: Some(Uuid::new_v4()),
            deployment_status: deployment_status.to_string(),
            setup_state: setup_state.map(str::to_string),
            created_at: Some(Utc::now() - chrono::Duration::minutes(14)),
            completed_at: None,
            observing_since: None,
            job_state: job_state.map(str::to_string),
            job_updated_at: Some(Utc::now() - chrono::Duration::minutes(13)),
            next_attempt_at: None,
            attempts: Some(4),
            job_locked_until: Some(Utc::now() + chrono::Duration::seconds(90)),
            job_lock_token: Some(Uuid::new_v4()),
            last_error_code: None,
            lease_locked_until: None,
            lease_operation_kind: None,
            app_deleting: false,
        }
    }

    #[test]
    fn running_job_with_live_lease_is_progressing() {
        let diagnostics = project_diagnostics(row("applying", Some("running"), None));
        assert_eq!(diagnostics.phase, DeploymentPhase::Applying);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert_eq!(diagnostics.reason, None);
        assert_eq!(diagnostics.attempts, 4);
    }

    #[test]
    fn running_job_on_watching_deployment_is_watching() {
        let diagnostics = project_diagnostics(row("watching", Some("running"), None));
        assert_eq!(diagnostics.phase, DeploymentPhase::Watching);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
    }

    #[test]
    fn expired_lease_with_scheduled_retry_is_waiting_external() {
        let mut input = row("applying", Some("pending"), None);
        // Worker died mid-apply: state still `pending` for the retry query
        // but the lease expired and a retry is scheduled.
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(5));
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.phase, DeploymentPhase::Queued);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::LeaseExpiredRetryScheduled)
        );
        assert!(diagnostics.next_retry_at.is_some());
    }

    #[test]
    fn expired_lease_without_retry_is_stalled() {
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.condition, DeploymentCondition::Stalled);
        assert_eq!(diagnostics.reason, None);
    }

    #[test]
    fn failed_job_is_terminal_with_redacted_reason() {
        let mut input = row("failed", Some("failed"), None);
        input.last_error_code = Some("deployment_apply_failed".to_string());
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentApplyFailed)
        );
        assert_eq!(diagnostics.next_retry_at, None);
    }

    #[test]
    fn deleting_app_cancels_the_active_deployment() {
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.phase, DeploymentPhase::Cancelled);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::AppDeleting));
    }

    #[test]
    fn missing_job_classifies_by_setup_state() {
        let diagnostics = project_diagnostics(row("pending", None, Some("dns_pending")));
        assert_eq!(diagnostics.phase, DeploymentPhase::Unknown);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::DnsSetupPending));
    }

    #[test]
    fn missing_job_without_setup_state_reports_no_job() {
        let diagnostics = project_diagnostics(row("applying", None, None));
        assert_eq!(diagnostics.phase, DeploymentPhase::Unknown);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::NoApplyJobRecorded)
        );
    }

    #[test]
    fn live_foreign_lease_is_reported_as_blocking() {
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(5));
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("app_delete")
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn snapshot_setup_states_are_terminal_classifications() {
        let diagnostics = project_diagnostics(row("failed", None, Some("failed")));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentSetupFailed)
        );
    }

    #[test]
    fn cancel_setup_state_is_cancelled() {
        let diagnostics = project_diagnostics(row("failed", None, Some("cancel")));
        assert_eq!(diagnostics.phase, DeploymentPhase::Cancelled);
    }

    #[test]
    fn progress_fields_are_never_leaked_for_foreign_lease_only() {
        // A foreign lease without a retry anchor must not invent timing.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(input);
        assert_eq!(diagnostics.condition, DeploymentCondition::Stalled);
        assert!(diagnostics.next_retry_at.is_none());
        assert!(diagnostics.blocked_until.is_some());
    }
}
