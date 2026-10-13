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
//!   tenant, or database text is copied through. `blocking_operation` is
//!   allowlisted to the known mutation-lease operation kinds.
//! - Absent rows degrade to `phase: "unknown"` with a null deployment id;
//!   the projection never fabricates identity or timing.
//! - No secrets, node names, raw attestation evidence, or lease tokens.
//!
//! Durable state machine being projected (see deployment_jobs.rs):
//! - Job: `setup_pending -> setting_up -> pending -> running ->
//!   completed | failed`, with `cleanup_pending -> cleaning_up` for
//!   first-deploy rollback. A worker holds `lock_token`/`locked_until`
//!   while `setting_up`/`cleaning_up`/`running`.
//! - A rollout watch runs in ~90s slices: between slices the job returns
//!   to `pending` with `next_attempt_at = now + 30s` while the deployment
//!   stays `watching` (observing_since anchors the cumulative deadline).
//!   `pending` + deployment `watching` is therefore steady-state watch
//!   progress, NOT a lease-expiry retry.
//! - A terminal rollout outcome publishes job `completed` (last_error_code
//!   cleared) with deployment status `healthy` OR `failed` — the
//!   deployment row, not the job row, distinguishes success.
//! - Setup failure leaves job `cleanup_pending`/`cleaning_up` (rollback)
//!   with `last_error_code = deployment_setup_failed` and deployment
//!   `failed`.

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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    Queued,
    SettingUp,
    Applying,
    Watching,
    Healthy,
    Failed,
    /// The deployment was ended by app deletion or supersession, not by
    /// its own outcome.
    Cancelled,
    /// Durable rows missing or not classifiable.
    Unknown,
}

/// Whether the phase is advancing, deliberately waiting on the platform
/// dispatcher or an external dependency, blocked by another operation's
/// mutation lease, stalled with nothing scheduled, or terminal.
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
    DeploymentRolloutFailed,
    DeploymentSuperseded,
    /// The app mutation lease is held by another operation, including the
    /// post-expiry reclaim quarantine window.
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
    /// The deployment this projection describes. Null when no deployment
    /// row exists for the app.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<Uuid>,
    /// Deployment creation time (phase start anchor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// Last durable activity: job lease renewal, state change, or retry
    /// scheduling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_progress_at: Option<DateTime<Utc>>,
    /// Apply-attempt count for this job, including failed ones.
    pub attempts: i32,
    /// When the dispatcher will next pick the job up. Absent while a worker
    /// holds the lease, after a terminal state, or when nothing is due.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Deadline after which the app mutation lane admits a new claim
    /// (holder lock expiry, or the lost-owner reclaim quarantine after it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<DateTime<Utc>>,
    /// The operation that owns the app mutation lease, when one does.
    /// Allowlisted fixed token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_operation: Option<String>,
    /// Cumulative rollout-observation anchor (`watching` deployments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observing_since: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct DiagnosticsRow {
    deployment_id: Option<Uuid>,
    deployment_status: Option<String>,
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
    lease_reclaim_after: Option<DateTime<Utc>>,
    lease_operation_kind: Option<String>,
    app_deleting: bool,
}

/// Mutation-lease `operation_kind` values that may appear on the public
/// contract. A future caller putting anything else in the column must NOT
/// leak free text to owners; unknown kinds degrade to a fixed token.
const KNOWN_OPERATION_KINDS: &[&str] = &[
    "app_create_dns",
    "app_delete",
    "app_desired_state",
    "custom_domain_set",
    "custom_domain_remove",
    "deployment",
    "deployment_apply",
    "deployment_setup",
    "deployment_cleanup",
];

fn public_operation_kind(kind: Option<&str>) -> Option<&'static str> {
    match kind {
        Some(kind) => KNOWN_OPERATION_KINDS
            .iter()
            .find(|known| **known == kind)
            .copied()
            .or(Some("other_operation")),
        None => None,
    }
}

/// Load the durable facts for the app's newest deployment and project them.
/// Never fails on absent data: missing rows produce `phase: unknown`
/// diagnostics with a null deployment id, so the endpoint stays available
/// exactly when diagnosis is hardest.
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
                lease.reclaim_after AS lease_reclaim_after,
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
               SELECT locked_until, reclaim_after, operation_kind
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
    Ok(project_diagnostics(row))
}

/// Effective app-mutation-lane admission deadline, mirroring the 409
/// `retry_after` semantics (apps.rs `lease_retry_after_seconds`): a live
/// holder blocks until its renewable lock expiry; once the lock has lapsed
/// the row blocks until `reclaim_after` (lost-owner quarantine).
fn lease_admission_deadline(
    locked_until: Option<DateTime<Utc>>,
    reclaim_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match (locked_until, reclaim_after) {
        (Some(locked_until), _) if locked_until > now => Some(locked_until),
        (_, Some(reclaim_after)) if reclaim_after > now => Some(reclaim_after),
        _ => None,
    }
}

fn unknown_diagnostics() -> DeploymentDiagnostics {
    DeploymentDiagnostics {
        phase: DeploymentPhase::Unknown,
        condition: DeploymentCondition::Unknown,
        reason: None,
        deployment_id: None,
        started_at: None,
        last_progress_at: None,
        attempts: 0,
        next_retry_at: None,
        blocked_until: None,
        blocking_operation: None,
        observing_since: None,
    }
}

fn project_diagnostics(row: Option<DiagnosticsRow>) -> DeploymentDiagnostics {
    let Some(row) = row else {
        return unknown_diagnostics();
    };
    let now = Utc::now();

    // A foreign mutation lease blocks the app lane regardless of deployment
    // state. Quantify it the same way the 409 conflict body does.
    let blocking_operation = public_operation_kind(row.lease_operation_kind.as_deref());
    let blocked_until =
        lease_admission_deadline(row.lease_locked_until, row.lease_reclaim_after, now)
            .filter(|_| blocking_operation.is_some());

    let base = DeploymentDiagnostics {
        deployment_id: row.deployment_id,
        started_at: row.created_at,
        last_progress_at: row.job_updated_at.or(row.completed_at),
        attempts: row.attempts.unwrap_or(0),
        observing_since: row
            .observing_since
            .filter(|_| row.deployment_status.as_deref() == Some("watching")),
        blocked_until,
        blocking_operation: blocking_operation.map(str::to_string),
        ..unknown_diagnostics()
    };

    // An app being destroyed owns the lifecycle; the deployment underneath
    // is being torn down, not advanced.
    if row.app_deleting {
        return DeploymentDiagnostics {
            phase: DeploymentPhase::Cancelled,
            condition: DeploymentCondition::Terminal,
            reason: Some(DeploymentReason::AppDeleting),
            next_retry_at: None,
            ..base
        };
    }

    let Some(deployment_status) = row.deployment_status.as_deref() else {
        // App exists with no deployment row at all (created, never
        // deployed): a durable fact, not an error.
        return DeploymentDiagnostics {
            reason: Some(DeploymentReason::NoApplyJobRecorded),
            ..base
        };
    };

    let phase = classify_phase(deployment_status, row.job_state.as_deref(), &row);
    let reason = classify_reason(deployment_status, row.job_state.as_deref(), &row);
    let (condition, next_retry_at) = classify_condition_and_retry(phase, &row, now);
    let reason = match condition {
        DeploymentCondition::BlockedByOperation => {
            Some(DeploymentReason::MutationLeaseHeldByOperation)
        }
        _ => reason,
    };

    DeploymentDiagnostics {
        phase,
        condition,
        reason,
        next_retry_at,
        ..base
    }
}

/// The deployment row is the sub-phase authority; the job row carries the
/// worker/dispatcher view. Both are needed: `pending` + deployment
/// `watching` is a watch slice gap, while `pending` + `applying` is a
/// queued apply; `completed` + deployment `failed` is a terminal rollout
/// failure, not health.
fn classify_phase(
    deployment_status: &str,
    job_state: Option<&str>,
    row: &DiagnosticsRow,
) -> DeploymentPhase {
    match (deployment_status, job_state) {
        // Terminal rollout publishes clear the job error code; the
        // deployment row alone distinguishes success from failure.
        ("failed", _) => match row.setup_state.as_deref() {
            Some("cancel") => DeploymentPhase::Cancelled,
            _ => DeploymentPhase::Failed,
        },
        ("healthy", _) => DeploymentPhase::Healthy,
        // Watch slices release the job to `pending` between observations;
        // a setup-state job under a watching deployment is still in setup.
        ("watching", Some("setup_pending" | "setting_up")) | ("watching", None) => {
            DeploymentPhase::SettingUp
        }
        ("watching", _) => DeploymentPhase::Watching,
        ("applying", Some("setup_pending" | "setting_up")) => DeploymentPhase::SettingUp,
        ("applying", _) => DeploymentPhase::Applying,
        ("pending", _) => DeploymentPhase::Queued,
        _ => DeploymentPhase::Unknown,
    }
}

/// Redacted reason for a non-progressing or terminal classification.
fn classify_reason(
    deployment_status: &str,
    job_state: Option<&str>,
    row: &DiagnosticsRow,
) -> Option<DeploymentReason> {
    // Terminal classifications win: they are the durable outcome. A
    // terminal rollout failure publishes job `completed` with the error
    // code cleared, so `deployment_rollout_failed` is the fallback.
    if deployment_status == "failed" {
        return match row.setup_state.as_deref() {
            Some("cancel") => Some(DeploymentReason::DeploymentSuperseded),
            _ => row
                .last_error_code
                .as_deref()
                .and_then(error_code_reason)
                .or(Some(DeploymentReason::DeploymentRolloutFailed)),
        };
    }
    if deployment_status == "healthy" {
        return None;
    }
    match job_state {
        // No job row: the deployment's setup marker still classifies it.
        None => match row.setup_state.as_deref() {
            Some("dns_pending") | Some("cleanup_pending") => {
                Some(DeploymentReason::DnsSetupPending)
            }
            Some("failed") => Some(DeploymentReason::DeploymentSetupFailed),
            _ => None,
        },
        Some("setup_pending") => match row.setup_state.as_deref() {
            Some("dns_pending") => Some(DeploymentReason::DnsSetupPending),
            _ => None,
        },
        // Cleanup rollback after a first-deploy setup failure.
        Some("cleanup_pending") | Some("cleaning_up") => {
            Some(DeploymentReason::DeploymentSetupFailed)
        }
        Some("setting_up") => match row.setup_state.as_deref() {
            Some("failed") => Some(DeploymentReason::DeploymentSetupFailed),
            _ => None,
        },
        _ => None,
    }
}

/// Condition and retry timing from the worker/dispatcher state.
fn classify_condition_and_retry(
    phase: DeploymentPhase,
    row: &DiagnosticsRow,
    now: DateTime<Utc>,
) -> (DeploymentCondition, Option<DateTime<Utc>>) {
    match phase {
        DeploymentPhase::Healthy | DeploymentPhase::Failed | DeploymentPhase::Cancelled => {
            (DeploymentCondition::Terminal, None)
        }
        DeploymentPhase::Unknown => (DeploymentCondition::Unknown, None),
        DeploymentPhase::Queued => match row.next_attempt_at.filter(|a| a > &now) {
            // Submitted but not yet due (backoff after a lost worker).
            Some(attempt_at) => (DeploymentCondition::WaitingExternal, Some(attempt_at)),
            // Due now: waits only for the dispatcher's idle poll, which is
            // normal dispatch latency, not a stall.
            None => (DeploymentCondition::Progressing, None),
        },
        DeploymentPhase::SettingUp | DeploymentPhase::Applying | DeploymentPhase::Watching => {
            let worker_live = row.job_lock_token.is_some()
                && row.job_locked_until.is_some_and(|until| until > now);
            if worker_live {
                // A worker holds the job: lease renewals are durable
                // progress evidence even when the phase looks static.
                (DeploymentCondition::Progressing, None)
            } else if let Some(attempt_at) = row.next_attempt_at.filter(|a| a > &now) {
                // Dispatch scheduled but not yet due. For a `watching`
                // deployment this is the steady state between observation
                // slices — deliberate pacing, not a fault.
                (DeploymentCondition::WaitingExternal, Some(attempt_at))
            } else if blocked_by_lease(row, now) {
                (DeploymentCondition::BlockedByOperation, None)
            } else {
                // Eligible now or overdue with no worker and no schedule:
                // the reconciler bounds this, do not invent timing.
                (DeploymentCondition::Stalled, None)
            }
        }
    }
}

fn blocked_by_lease(row: &DiagnosticsRow, now: DateTime<Utc>) -> bool {
    row.lease_operation_kind.is_some()
        && lease_admission_deadline(row.lease_locked_until, row.lease_reclaim_after, now).is_some()
}

fn error_code_reason(code: &str) -> Option<DeploymentReason> {
    match code {
        "deployment_setup_failed" => Some(DeploymentReason::DeploymentSetupFailed),
        "deployment_apply_failed" => Some(DeploymentReason::DeploymentApplyFailed),
        "deployment_superseded" => Some(DeploymentReason::DeploymentSuperseded),
        "deployment_rollout_failed" => Some(DeploymentReason::DeploymentRolloutFailed),
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
            deployment_status: Some(deployment_status.to_string()),
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
            lease_reclaim_after: None,
            lease_operation_kind: None,
            app_deleting: false,
        }
    }

    #[test]
    fn running_job_with_live_lease_is_progressing() {
        let diagnostics = project_diagnostics(Some(row("applying", Some("running"), None)));
        assert_eq!(diagnostics.phase, DeploymentPhase::Applying);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert_eq!(diagnostics.reason, None);
        assert_eq!(diagnostics.attempts, 4);
    }

    #[test]
    fn running_job_on_watching_deployment_is_watching() {
        let diagnostics = project_diagnostics(Some(row("watching", Some("running"), None)));
        assert_eq!(diagnostics.phase, DeploymentPhase::Watching);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
    }

    #[test]
    fn watch_slice_gap_is_watching_waiting_external_not_lease_expired() {
        // Steady state between 90s observation slices: job released to
        // `pending` with a 30s retry while the deployment stays `watching`.
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(25));
        input.observing_since = Some(Utc::now() - chrono::Duration::minutes(3));
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Watching);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        // Deliberate watch pacing carries no fault reason.
        assert_eq!(diagnostics.reason, None);
        assert!(diagnostics.next_retry_at.is_some());
        assert!(diagnostics.observing_since.is_some());
    }

    #[test]
    fn terminal_rollout_failure_is_failed_even_when_job_completed() {
        // publish_rollout_outcome clears last_error_code and completes the
        // job on a terminal watch outcome; the deployment row is `failed`.
        let mut input = row("failed", Some("completed"), None);
        input.last_error_code = None;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentRolloutFailed)
        );
    }

    #[test]
    fn terminal_setup_failure_keeps_its_reason_over_completed_job() {
        let mut input = row("failed", Some("completed"), None);
        input.last_error_code = Some("deployment_setup_failed".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentSetupFailed)
        );
    }

    #[test]
    fn setup_cleanup_states_are_failed_setup_not_setting_up() {
        // First-deploy rollback: job cleanup_pending with deployment failed.
        let mut input = row("failed", Some("cleanup_pending"), Some("cleanup_pending"));
        input.last_error_code = Some("deployment_setup_failed".to_string());
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(30));
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentSetupFailed)
        );
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
    }

    #[test]
    fn failed_job_is_terminal_with_redacted_reason() {
        let mut input = row("failed", Some("failed"), None);
        input.last_error_code = Some("deployment_apply_failed".to_string());
        let diagnostics = project_diagnostics(Some(input));
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
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Cancelled);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::AppDeleting));
    }

    #[test]
    fn app_without_deployments_is_unknown_with_null_identity() {
        // No deployment row at all: never fabricate an id or a timestamp.
        let mut input = row("creating", None, None);
        input.deployment_id = None;
        input.deployment_status = None;
        input.created_at = None;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Unknown);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::NoApplyJobRecorded)
        );
        assert!(diagnostics.deployment_id.is_none());
        assert!(diagnostics.started_at.is_none());
    }

    #[test]
    fn missing_app_row_is_unknown_with_null_identity() {
        let diagnostics = project_diagnostics(None);
        assert_eq!(diagnostics.phase, DeploymentPhase::Unknown);
        assert!(diagnostics.deployment_id.is_none());
        assert!(diagnostics.started_at.is_none());
        assert_eq!(diagnostics.attempts, 0);
    }

    #[test]
    fn queued_job_not_yet_due_is_waiting_external() {
        let mut input = row("pending", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(5));
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Queued);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert_eq!(diagnostics.reason, None);
        assert!(diagnostics.next_retry_at.is_some());
    }

    #[test]
    fn queued_job_eligible_now_is_progressing_not_stalled() {
        // A due job waits only for the dispatcher's idle poll; that is not
        // a stall and must not tell the owner to contact support.
        let mut input = row("pending", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() - chrono::Duration::seconds(2));
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Queued);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert!(diagnostics.next_retry_at.is_none());
    }

    #[test]
    fn live_foreign_lease_is_blocked_by_operation() {
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(3));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::MutationLeaseHeldByOperation)
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("app_delete")
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn lapsed_lock_in_reclaim_quarantine_still_blocks() {
        // After the holder's lock expires the row still blocks the lane
        // until reclaim_after; the projection must not drop the window.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::seconds(30));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::MutationLeaseHeldByOperation)
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn unknown_operation_kind_degrades_to_fixed_token() {
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(3));
        input.lease_operation_kind = Some("future free text".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("other_operation")
        );
    }

    #[test]
    fn expired_lease_without_retry_or_lease_blocker_is_stalled() {
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.condition, DeploymentCondition::Stalled);
        assert_eq!(diagnostics.reason, None);
    }

    #[test]
    fn cancel_setup_state_is_cancelled() {
        let diagnostics = project_diagnostics(Some(row("failed", None, Some("cancel"))));
        assert_eq!(diagnostics.phase, DeploymentPhase::Cancelled);
    }

    #[test]
    fn missing_job_classifies_by_deployment_status() {
        let diagnostics = project_diagnostics(Some(row("pending", None, Some("dns_pending"))));
        assert_eq!(diagnostics.phase, DeploymentPhase::Queued);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::DnsSetupPending));
    }
}
