//! Owner-facing lifecycle diagnosis for the active deployment (#90).
//!
//! Tenants have no Kubernetes credentials, no node access, and no platform
//! database visibility — those are correct confidential-computing trust
//! boundaries. This module is the safe replacement for the `kubectl
//! describe` / controller-log diagnosis an operator would otherwise
//! perform: it projects what the platform already knows durably (the
//! deployment, its apply job, the app mutation lease, and the namespace
//! resource fence) into a stable, redacted phase / condition / reason
//! contract that the CLI and hosted console can render identically.
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
//! - A job is CLAIMABLE when it is `pending`/`setup_pending`/
//!   `cleanup_pending` with `next_attempt_at <= now`, or `running`/
//!   `setting_up`/`cleaning_up` with an expired lock (claim predicate in
//!   deployment_jobs.rs). Claimable means the dispatcher will pick it up
//!   as soon as an apply slot is free — with `CAP_MAX_CONCURRENT_APPLIES`
//!   default 1 that wait is the normal multi-app steady state, so a
//!   claimable job is ALWAYS progressing, never stalled.
//! - A terminal rollout outcome publishes job `completed` (last_error_code
//!   cleared) with deployment status `healthy` OR `failed` — the
//!   deployment row, not the job row, distinguishes success; the durable
//!   `deployments.error_message` token carries the public error code.
//! - Setup failure leaves job `cleanup_pending`/`cleaning_up` (rollback,
//!   retried on a 30s schedule) with `last_error_code =
//!   deployment_setup_failed` and deployment `failed`: the failure is
//!   durable but cleanup may still be running, so the condition is NOT
//!   terminal while a cleanup job is scheduled or held.
//! - The deployment's own mutation-lease kinds (`deployment`,
//!   `deployment_setup`, `deployment_cleanup`) and its own namespace
//!   fence (`deployment_apply` with this deployment's operation ID) are
//!   this deployment's lane while its job worker lock is live: never a
//!   foreign blocker. Once that worker lock expires the abandoned lease
//!   still gates `mutation_leases::claim` until `reclaim_after` (the
//!   claim predicate has no same-operation special case), so it becomes
//!   a visible recovery blocker. Foreign kinds (`app_delete`,
//!   `app_desired_state`, `custom_domain_*`, `app_create_dns`) and a
//!   poisoned/armed `kubernetes_namespace` resource fence DO block: a
//!   redeploy would 409 on them.

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
    /// The deployment was ended by supersession, not by its own outcome.
    Cancelled,
    /// The deployment was rolled back to a previous version.
    RolledBack,
    /// The app is being destroyed; the deployment underneath is being torn
    /// down and no deployment action is available until deletion finishes.
    Destroying,
    /// Durable rows missing or not classifiable.
    Unknown,
}

/// Whether the phase is advancing, deliberately waiting on the platform
/// dispatcher or an external dependency, blocked by another operation's
/// mutation lease or an external resource fence, stalled with nothing
/// scheduled, or terminal.
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
    /// A foreign operation holds the app mutation lease (including the
    /// post-expiry reclaim quarantine window) or the namespace resource
    /// fence is armed.
    MutationLeaseHeldByOperation,
    /// The app deletion was interrupted by a poisoned resource fence that
    /// must be cleared manually (namespace finalizers, orphaned resources).
    AppDeletionBlockedByPoisonedFence,
    /// The app deletion was abandoned (lease expired) while waiting on a
    /// foreign finite fence — no background worker will resume it.
    AppDeletionAbandonedWaitingOnForeignFence,
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
    /// Absent while only this deployment's own lease kinds are held, and
    /// for a poisoned fence with no automatic release time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<DateTime<Utc>>,
    /// The operation that owns the app mutation lane, when a FOREIGN
    /// operation or fence does. Allowlisted fixed token.
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
    /// Fixed public error token persisted on the publish path
    /// (`deployments.error_message`); never provider text.
    deployment_error_message: Option<String>,
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
    lease_operation_id: Option<Uuid>,
    fence_locked_until: Option<DateTime<Utc>>,
    /// `reclaim_after` of the namespace fence with `infinity` already
    /// NULLed in SQL: a poisoned fence carries no automatic release time.
    fence_reclaim_after: Option<DateTime<Utc>>,
    fence_operation_kind: Option<String>,
    fence_operation_id: Option<Uuid>,
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

/// Operation kinds on the app mutation lease that belong to THIS
/// deployment's own lane. They are held by this deployment's worker, so
/// they are never a foreign blocker and never populate the blocked/
/// holder fields while the deployment progresses.
const OWN_OPERATION_KINDS: &[&str] = &[
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

/// An "own" operation is one whose `operation_kind` is a deployment-lane kind
/// AND whose `operation_id` matches this deployment's ID. A previous
/// deployment's lease with the same kind but different ID blocks the lane.
fn is_own_operation(
    kind: Option<&str>,
    operation_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
) -> bool {
    kind.is_some_and(|kind| {
        OWN_OPERATION_KINDS.contains(&kind)
            && operation_id.is_some_and(|op_id| deployment_id.is_some_and(|dep_id| op_id == dep_id))
    })
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
                deployment.error_message AS deployment_error_message,
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
                lease.operation_id AS lease_operation_id,
                fence.locked_until AS fence_locked_until,
                fence.reclaim_after AS fence_reclaim_after,
                fence.operation_kind AS fence_operation_kind,
                fence.fence_operation_id,
                app_row.status = 'deleting'::app_status_enum AS app_deleting
           FROM apps AS app_row
           LEFT JOIN LATERAL (
               -- Canonical job-first, deterministic legacy-fallback ordering
               -- (mirrors latest_deployment_id_for_app in deploy.rs)
               SELECT dep.id, dep.status::text AS status, dep.spec_snapshot, dep.created_at,
                      dep.completed_at, dep.observing_since, dep.error_message
                 FROM deployments AS dep
                 LEFT JOIN deployment_apply_jobs AS apply_job
                        ON apply_job.deployment_id = dep.id
                WHERE dep.app_id = app_row.id
                ORDER BY (apply_job.generation IS NOT NULL) DESC,
                         apply_job.generation DESC NULLS LAST,
                         dep.created_at DESC,
                         dep.id DESC
                LIMIT 1
           ) AS deployment ON true
           LEFT JOIN deployment_apply_jobs AS job
                  ON job.deployment_id = deployment.id
           LEFT JOIN LATERAL (
               SELECT locked_until, reclaim_after, operation_kind, operation_id
                 FROM app_mutation_leases
                WHERE app_id = app_row.id
                  AND owner_token IS NOT NULL
                  AND reclaim_after > clock_timestamp()
                LIMIT 1
           ) AS lease ON true
           LEFT JOIN LATERAL (
               SELECT locked_until,
                      NULLIF(reclaim_after, 'infinity'::timestamptz)
                          AS reclaim_after,
                      operation_kind,
                      operation_id AS fence_operation_id
                 FROM external_resource_mutation_leases
                WHERE resource_scope = 'kubernetes_namespace'
                  AND resource_key = app_row.namespace
                  AND owner_token IS NOT NULL
                  AND (
                      reclaim_after = 'infinity'::timestamptz
                      OR reclaim_after > clock_timestamp()
                  )
                LIMIT 1
           ) AS fence ON true
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
/// the row blocks until `reclaim_after` (lost-owner quarantine). A fence
/// (or lease) with `reclaim_after = infinity` is NULLed in SQL and yields
/// no deadline — blocked with no automatic release time.
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

/// Which foreign holder (if any) blocks the app mutation lane for this
/// deployment, and until when. Own-lane leases never block while their
/// job worker lock is live. A held namespace fence blocks unless it is
/// this deployment's own apply fence under a live worker — including
/// poisoned fences, which carry no automatic release time and thus
/// promise no admission deadline at all.
struct ForeignBlock {
    operation: Option<&'static str>,
    until: Option<DateTime<Utc>>,
}

fn foreign_block(row: &DiagnosticsRow, now: DateTime<Utc>) -> ForeignBlock {
    let worker_live = job_worker_lock_live(row, now);
    let lease_blocks = (!is_own_operation(
        row.lease_operation_kind.as_deref(),
        row.lease_operation_id,
        row.deployment_id,
    ) || !worker_live)
        && lease_admission_deadline(row.lease_locked_until, row.lease_reclaim_after, now).is_some();

    // A poisoned fence never admits: when it is visible alongside a
    // finite lease deadline it dominates the combined wait, because the
    // lane only opens once EVERY holder clears and this one never does.
    // A finite fence visible with a finite lease similarly means the
    // lane opens only at the LATER of the two deadlines. Compute both,
    // then pick the dominating blocker.
    let mut block = ForeignBlock {
        operation: None,
        until: None,
    };
    if lease_blocks {
        block.operation = public_operation_kind(row.lease_operation_kind.as_deref());
        block.until =
            lease_admission_deadline(row.lease_locked_until, row.lease_reclaim_after, now);
    }
    if row.fence_operation_kind.is_some() {
        // The apply worker holds this deployment's own namespace fence
        // while it works: only report it once the worker lock has expired
        // (the fence then gates a replacement worker's claim until
        // `reclaim_after`). Foreign fences always report. A poisoned
        // fence (reclaim_after = infinity, NULLed here) reports no
        // deadline regardless of a live renewable lock: the claim
        // predicate can never reclaim it at the displayed time.
        let own_fence = worker_live
            && is_own_operation(
                row.fence_operation_kind.as_deref(),
                row.fence_operation_id,
                row.deployment_id,
            );
        let poisoned = row.fence_reclaim_after.is_none();
        if !own_fence {
            let fence_deadline = if poisoned {
                None
            } else {
                lease_admission_deadline(row.fence_locked_until, row.fence_reclaim_after, now)
            };
            // A poisoned fence dominates any finite lease deadline; a
            // finite fence dominates while its deadline is the later one.
            let dominates = poisoned
                || block
                    .until
                    .is_none_or(|lease_until| fence_deadline.is_some_and(|f| f > lease_until));
            if dominates {
                block = ForeignBlock {
                    operation: public_operation_kind(row.fence_operation_kind.as_deref()),
                    until: fence_deadline,
                };
            }
        }
    }
    block
}

/// Whether this deployment's apply-job worker still holds its job lock:
/// the durable signal that the worker owning the app mutation lease and
/// the namespace fence is alive and renewing.
fn job_worker_lock_live(row: &DiagnosticsRow, now: DateTime<Utc>) -> bool {
    row.job_lock_token.is_some() && row.job_locked_until.is_some_and(|until| until > now)
}

fn project_diagnostics(row: Option<DiagnosticsRow>) -> DeploymentDiagnostics {
    let Some(row) = row else {
        return unknown_diagnostics();
    };
    let now = Utc::now();
    let blocked = foreign_block(&row, now);
    let foreign_blocked = blocked.operation.is_some();

    let base = DeploymentDiagnostics {
        deployment_id: row.deployment_id,
        started_at: row.created_at,
        last_progress_at: row.job_updated_at.or(row.completed_at),
        attempts: row.attempts.unwrap_or(0),
        observing_since: row
            .observing_since
            .filter(|_| row.deployment_status.as_deref() == Some("watching")),
        blocked_until: if foreign_blocked { blocked.until } else { None },
        blocking_operation: blocked
            .operation
            .filter(|_| foreign_blocked)
            .map(str::to_string),
        ..unknown_diagnostics()
    };
    // An app being destroyed owns the lifecycle; the deployment underneath
    // is being torn down, not advanced. This is NOT terminal: teardown is
    // an in-progress platform operation. The live `app_delete` lease is
    // the deletion's own machinery, never a foreign blocker to print.
    // Deletion has no durable background job: `delete_app_before` only
    // resumes when the client issues another DELETE. Once the delete
    // lease has fully lapsed (past its reclaim quarantine — another
    // delete request can claim the lane again), a still-`deleting` app
    // is abandoned mid-teardown: tell the owner to retry the DELETE
    // rather than wait forever.
    if row.app_deleting {
        let delete_lease_live = row.lease_locked_until.is_some_and(|until| until > now)
            || row.lease_reclaim_after.is_some_and(|after| after > now);
        let condition = if delete_lease_live {
            if row.lease_locked_until.is_some_and(|until| until > now) {
                DeploymentCondition::Progressing
            } else {
                DeploymentCondition::WaitingExternal
            }
        } else {
            DeploymentCondition::BlockedByOperation
        };
        // Even when the delete lease has fully lapsed, a live or poisoned
        // namespace fence from the interrupted teardown still rejects the
        // retry DELETE: classify waiting rather than "retry now" while it
        // holds. A poisoned fence (never auto-reclaims) keeps the owner
        // waiting exactly like the API's own 409 semantics.
        //
        // IMPORTANT: The in-progress deletion's own namespace fence (armed by
        // delete_app_before with app_delete operation kind) must NOT be treated
        // as foreign while the delete lease is still live. Once it expires, the
        // app_delete fence may be poisoned (never auto-reclaims) and blocks
        // forever — treat it as foreign to get proper diagnostics.
        let fence_holds = row.fence_operation_kind.is_some()
            && !(delete_lease_live
                && matches!(row.fence_operation_kind.as_deref(), Some("app_delete")))
            && !is_own_operation(
                row.fence_operation_kind.as_deref(),
                row.fence_operation_id,
                row.deployment_id,
            );
        let condition = if fence_holds && condition == DeploymentCondition::BlockedByOperation {
            // Delete lease expired but foreign fence still holds: the deletion
            // is abandoned (no worker will resume). Don't say "retry DELETE" —
            // nothing will pick it up. Tell owner to wait for the fence.
            DeploymentCondition::WaitingExternal
        } else {
            condition
        };
        // A poisoned fence blocks forever with no automatic release: escalate
        // to a distinct reason that tells the CLI to prompt operator action.
        let reason = if fence_holds && row.fence_reclaim_after.is_none() {
            DeploymentReason::AppDeletionBlockedByPoisonedFence
        } else if !delete_lease_live && fence_holds {
            // Delete lease expired while waiting on foreign finite fence: the
            // deletion is abandoned, nothing will resume it. Give a reason
            // that tells CLI to prompt for action rather than "wait for
            // teardown" which implies automatic completion.
            DeploymentReason::AppDeletionAbandonedWaitingOnForeignFence
        } else {
            DeploymentReason::AppDeleting
        };
        // For an abandoned deletion waiting on a finite foreign fence,
        // surface the fence's claim admission boundary (reclaim_after) as
        // blocked_until: the retry DELETE stays Busy until then, and
        // without this the owner has no indication of when the retry can
        // succeed (the delete lease's own blocked_until was cleared
        // above). The renewable locked_until is deliberately NOT used —
        // a live holder extends it every heartbeat, and the claim
        // predicate (claim_resource_rows) admits only at reclaim_after;
        // reclaim_after may itself move for a live holder, but it is the
        // honest lower bound. A poisoned fence keeps no deadline — it
        // never auto-reclaims.
        let blocked_until = if !delete_lease_live && fence_holds {
            row.fence_reclaim_after.filter(|reclaim| reclaim > &now)
        } else {
            None
        };
        return DeploymentDiagnostics {
            phase: DeploymentPhase::Destroying,
            condition,
            reason: Some(reason),
            next_retry_at: None,
            blocked_until,
            blocking_operation: None,
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

    let phase = classify_phase(deployment_status, row.job_state.as_deref());
    let reason = classify_reason(deployment_status, row.job_state.as_deref(), &row);
    let (condition, next_retry_at) = classify_condition_and_retry(phase, &row, &blocked, now);
    let reason = match condition {
        DeploymentCondition::BlockedByOperation => {
            Some(DeploymentReason::MutationLeaseHeldByOperation)
        }
        _ => reason,
    };

    // Blocker metadata is only meaningful when the condition actually
    // says blocked_by_operation. A terminal deployment (healthy, or
    // failed without cleanup work) cannot be blocked by a concurrent
    // mutation: a 409 on the lane cannot undo the durable outcome, and
    // printing a red Blocked:/Holder: section under a completed
    // deployment misleads the owner. Non-terminal cleanup work keeps
    // the blocker fields via its own (non-terminal) condition.
    let show_blocker = condition == DeploymentCondition::BlockedByOperation;
    DeploymentDiagnostics {
        phase,
        condition,
        reason,
        next_retry_at,
        blocked_until: if show_blocker {
            base.blocked_until
        } else {
            None
        },
        blocking_operation: if show_blocker {
            base.blocking_operation.clone()
        } else {
            None
        },
        ..base
    }
}

/// The deployment row is the sub-phase authority; the job row carries the
/// worker/dispatcher view. Both are needed: `pending` + deployment
/// `watching` is a watch slice gap, while `pending` + `applying` is a
/// queued apply; `completed` + deployment `failed` is a terminal rollout
/// failure, not health.
fn classify_phase(deployment_status: &str, job_state: Option<&str>) -> DeploymentPhase {
    match (deployment_status, job_state) {
        // Terminal rollout publishes clear the job error code; the
        // deployment row alone distinguishes success from failure.
        ("failed", _) => DeploymentPhase::Failed,
        ("healthy", _) => DeploymentPhase::Healthy,
        ("rolled_back", _) => DeploymentPhase::RolledBack,
        // A deployment is inserted at status `pending` and only moves to
        // `applying` after setup finished, so live setup work rides on a
        // `pending` deployment with a setup job (the `applying` arm is
        // defensive for any future writer).
        ("pending" | "applying", Some("setup_pending" | "setting_up")) => {
            DeploymentPhase::SettingUp
        }
        ("pending", _) => DeploymentPhase::Queued,
        ("applying", _) => DeploymentPhase::Applying,
        ("watching", _) => DeploymentPhase::Watching,
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
    // code cleared, so the durable `deployments.error_message` public
    // token (and finally the rollout-failed fallback) carries the reason.
    if deployment_status == "failed" {
        return row
            .last_error_code
            .as_deref()
            .and_then(error_code_reason)
            .or_else(|| {
                row.deployment_error_message
                    .as_deref()
                    .and_then(error_code_reason)
            })
            .or(Some(DeploymentReason::DeploymentRolloutFailed));
    }
    if deployment_status == "healthy" {
        return None;
    }
    // A rolled-back deployment is terminal exactly like a healthy one:
    // the retained row legitimately has no apply job (the rollback flow
    // retires it), and `job_state = None` here is not a durability
    // anomaly. Reporting one would print a support-worthy warning under
    // a successful rollback.
    if deployment_status == "rolled_back" {
        return None;
    }
    match job_state {
        // A committed non-terminal deployment must have an active job
        // (deferred constraint, migration 0038); none is a durability
        // anomaly surfaced as a stall, not a setup classification.
        None => Some(DeploymentReason::NoApplyJobRecorded),
        // DNS setup spans setup_pending AND setting_up: the setup_state
        // marker stays `dns_pending` while the worker runs setup.
        Some("setup_pending" | "setting_up")
            if row.setup_state.as_deref() == Some("dns_pending") =>
        {
            Some(DeploymentReason::DnsSetupPending)
        }
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
///
/// Precedence, per the durable state machine:
/// 1. A live worker lease is durable progress evidence, always.
/// 2. A foreign lease or an armed namespace fence blocks the lane when a
///    claim would still 409 at the scheduled attempt time — i.e. unless
///    the blocker's finite admission deadline expires before
///    `next_attempt_at`. A poisoned fence (no automatic release time)
///    always wins.
/// 3. A future `next_attempt_at` is deliberate dispatch pacing.
/// 4. Otherwise the job is claimable (due now, or a running state with an
///    expired lock): the dispatcher picks it up as soon as an apply slot
///    frees, which is normal queueing — progressing, never stalled.
///
/// Job payload versions outside this replica's supported range are NOT
/// stalled: during a rolling upgrade an older replica can serve
/// diagnostics for a newer-payload job that a newer replica claims
/// moments later, and a replica-local verdict would flip the answer
/// depending on which instance answered. Those jobs classify through the
/// same schedule rules above.
fn classify_condition_and_retry(
    phase: DeploymentPhase,
    row: &DiagnosticsRow,
    blocked: &ForeignBlock,
    now: DateTime<Utc>,
) -> (DeploymentCondition, Option<DateTime<Utc>>) {
    match phase {
        DeploymentPhase::Healthy => (DeploymentCondition::Terminal, None),
        DeploymentPhase::RolledBack => (DeploymentCondition::Terminal, None),
        DeploymentPhase::Failed => {
            // A failed deployment with a cleanup job still rolling back
            // is not finished: cleanup holds the lane (redeploy 409s on
            // it) and retries on its own schedule.
            if matches!(
                row.job_state.as_deref(),
                Some("cleanup_pending" | "cleaning_up")
            ) {
                worker_or_schedule_condition(row, blocked, now)
            } else {
                (DeploymentCondition::Terminal, None)
            }
        }
        DeploymentPhase::Unknown => (DeploymentCondition::Unknown, None),
        DeploymentPhase::Queued
        | DeploymentPhase::SettingUp
        | DeploymentPhase::Applying
        | DeploymentPhase::Watching => {
            if row.job_state.is_none() {
                // Non-terminal deployment without a job row violates the
                // schema invariant: nothing can advance it.
                return (DeploymentCondition::Stalled, None);
            }
            worker_or_schedule_condition(row, blocked, now)
        }
        // Destroying/Cancelled compute their condition at the short-circuit
        // in project_diagnostics; unreachable here.
        DeploymentPhase::Destroying | DeploymentPhase::Cancelled => {
            (DeploymentCondition::Unknown, None)
        }
    }
}

fn worker_or_schedule_condition(
    row: &DiagnosticsRow,
    blocked: &ForeignBlock,
    now: DateTime<Utc>,
) -> (DeploymentCondition, Option<DateTime<Utc>>) {
    if job_worker_lock_live(row, now) {
        // A worker holds the job: lease renewals are durable progress
        // evidence even when the phase looks static.
        return (DeploymentCondition::Progressing, None);
    }
    if blocked.operation.is_some() {
        // A poisoned fence carries no automatic release time: no retry
        // schedule can outlive it, so it always wins the condition.
        let Some(_blocker_until) = blocked.until else {
            return (DeploymentCondition::BlockedByOperation, None);
        };
        // Compare against the actual claim admission boundary (reclaim_after),
        // not the displayed blocker_until (which may be a live renewable
        // locked_until that could be extended). The claim predicate admits
        // only when reclaim_after <= now, so use that for the comparison.
        // Check both lease and fence reclaim_after - use whichever is active.
        let lease_reclaim = row.lease_reclaim_after.filter(|ra| ra > &now);
        let fence_reclaim = row.fence_reclaim_after.filter(|ra| ra > &now);
        let Some(reclaim_after) = lease_reclaim.or(fence_reclaim) else {
            // No active reclaim boundary - fall through to schedule-based
            return classify_condition_by_schedule(row, now);
        };
        let attempt_after_reclaim = row
            .next_attempt_at
            .is_some_and(|attempt_at| attempt_at > reclaim_after);
        if !attempt_after_reclaim {
            return (DeploymentCondition::BlockedByOperation, None);
        }
    }

    classify_condition_by_schedule(row, now)
}

fn classify_condition_by_schedule(
    row: &DiagnosticsRow,
    now: DateTime<Utc>,
) -> (DeploymentCondition, Option<DateTime<Utc>>) {
    // Determine if this is a claimed state (running, setting_up, cleaning_up)
    let is_claimed_state = matches!(
        row.job_state.as_deref(),
        Some("running" | "setting_up" | "cleaning_up")
    );

    // For claimed states with expired locks, the job is immediately reclaimable
    // regardless of next_attempt_at. For unclaimed states, next_attempt_at
    // applies as the scheduled retry time.
    if is_claimed_state {
        // Lock expired but job still in claimed state: ready for immediate
        // recovery by any worker. Normal progress, not waiting.
        (DeploymentCondition::Progressing, None)
    } else if let Some(attempt_at) = row.next_attempt_at.filter(|a| a > &now) {
        // Dispatch scheduled but not yet due. For a `watching`
        // deployment this is the steady state between observation
        // slices — deliberate pacing, not a fault.
        (DeploymentCondition::WaitingExternal, Some(attempt_at))
    } else {
        // Claimable now (due retry): waits only for a free apply slot. Normal
        // dispatcher queueing, not a stall.
        (DeploymentCondition::Progressing, None)
    }
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
            deployment_error_message: None,
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
            lease_operation_id: None,
            fence_locked_until: None,
            fence_reclaim_after: None,
            fence_operation_kind: None,
            fence_operation_id: None,
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
    fn due_watch_retry_is_progressing_not_stalled() {
        // The due tail of a watch-slice gap: claimable the moment an apply
        // slot frees. With CAP_MAX_CONCURRENT_APPLIES=1 that wait is the
        // normal multi-app steady state — never a stall, never
        // "contact support".
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() - chrono::Duration::seconds(20));
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Watching);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert_eq!(diagnostics.reason, None);
    }

    #[test]
    fn expired_worker_lock_is_progressing_not_stalled() {
        // A running job whose lock expired is claimable by the claim
        // predicate: the dispatcher reclaims it, this is not a stall.
        let mut input = row("applying", Some("running"), None);
        input.job_locked_until = Some(Utc::now() - chrono::Duration::seconds(30));
        input.next_attempt_at = None;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Applying);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
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
    fn terminal_failure_reason_survives_via_durable_error_token() {
        // The publish path also persists the public error token on the
        // deployment row; it must classify even with the job code cleared.
        let mut input = row("failed", Some("completed"), None);
        input.last_error_code = None;
        input.deployment_error_message = Some("deployment_rollout_failed".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentRolloutFailed)
        );
    }

    #[test]
    fn superseded_deployment_is_failed_with_superseded_reason() {
        // Supersession sets job last_error_code = deployment_superseded
        // and deployment status failed (deploy.rs).
        let mut input = row("failed", Some("failed"), None);
        input.last_error_code = Some("deployment_superseded".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::DeploymentSuperseded)
        );
    }

    #[test]
    fn failed_setup_cleanup_retry_is_waiting_external_not_terminal() {
        // release_cleanup_for_retry_in_tx requeues the cleanup job with a
        // 30s retry while the deployment stays failed: the failure is
        // durable but rollback still runs (and blocks redeploy).
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
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert!(diagnostics.next_retry_at.is_some());
    }

    #[test]
    fn failed_setup_cleanup_in_flight_is_progressing() {
        let mut input = row("failed", Some("cleaning_up"), Some("cleanup_pending"));
        input.last_error_code = Some("deployment_setup_failed".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Failed);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
    }

    #[test]
    fn failed_deployment_without_cleanup_job_is_terminal() {
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
    fn deleting_app_is_destroying_not_terminal() {
        // Delete holds the app_delete lease across external teardown;
        // teardown is an in-progress operation the owner waits out, not a
        // finished lifecycle. The delete lease is the deletion's own
        // machinery: it must never render as a foreign Blocked:/Holder:
        // section while teardown progresses.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::AppDeleting));
        assert!(diagnostics.blocking_operation.is_none());
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn deleting_app_in_reclaim_quarantine_still_waits() {
        // Lock lapsed but the reclaim quarantine still holds the lane:
        // a retry DELETE would 409, so the owner waits.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::seconds(5));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert!(diagnostics.blocking_operation.is_none());
    }

    #[test]
    fn deleting_app_with_fully_lapsed_lease_requires_retry() {
        // Deletion has no durable background job: once the delete lease
        // (and its quarantine) has fully lapsed, a still-`deleting` app
        // is abandoned mid-teardown and only a client DELETE resumes it.
        // Report it as needing action, not as automatically advancing.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        input.lease_reclaim_after = Some(Utc::now() - chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
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
    fn nonterminal_deployment_without_job_row_is_stalled() {
        // The schema guarantees a committed non-terminal deployment has an
        // active job; a missing row is a durability anomaly nothing can
        // advance — the one true stall.
        let input = row("watching", None, None);
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Watching);
        assert_eq!(diagnostics.condition, DeploymentCondition::Stalled);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::NoApplyJobRecorded)
        );
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
    fn live_setup_on_pending_deployment_is_setting_up_with_dns_reason() {
        // Deployments are inserted at status `pending`; setup work rides a
        // setup job under it, and the DNS reason spans setup_pending AND
        // setting_up (setup_state stays dns_pending while claimed).
        let mut pending = row("pending", Some("setup_pending"), Some("dns_pending"));
        pending.job_lock_token = None;
        pending.job_locked_until = None;
        let diagnostics = project_diagnostics(Some(pending));
        assert_eq!(diagnostics.phase, DeploymentPhase::SettingUp);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::DnsSetupPending));

        let mut claimed = row("pending", Some("setting_up"), Some("dns_pending"));
        claimed.job_lock_token = None;
        claimed.job_locked_until = None;
        let diagnostics = project_diagnostics(Some(claimed));
        assert_eq!(diagnostics.phase, DeploymentPhase::SettingUp);
        assert_eq!(diagnostics.reason, Some(DeploymentReason::DnsSetupPending));
    }

    #[test]
    fn own_lane_lease_under_live_worker_never_blocks() {
        // The deployment's own worker holds deployment_apply (matching
        // operation id) while it works: never blocked by itself.
        let mut input = row("applying", Some("running"), None);
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("deployment_apply".to_string());
        input.lease_operation_id = input.deployment_id;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert_eq!(diagnostics.reason, None);
        assert!(diagnostics.blocking_operation.is_none());
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn abandoned_own_lane_lease_is_a_recovery_blocker() {
        // The worker died after acquiring the mutation lease: the lease
        // still carries this deployment's operation id, but the claim
        // predicate rejects a replacement worker until reclaim_after.
        // Diagnostics must surface that gate instead of "progressing".
        let mut input = row("applying", Some("running"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::seconds(30));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("deployment_apply".to_string());
        input.lease_operation_id = input.deployment_id;
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
            Some("deployment_apply")
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn stale_own_kind_lease_from_older_deployment_blocks() {
        // A superseded deployment's expired lease can carry the same kind
        // with a foreign operation id: kind-only matching would hide a
        // real lane holder from the newer deployment.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("deployment_apply".to_string());
        input.lease_operation_id = Some(Uuid::new_v4());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn foreign_lease_beats_a_scheduled_retry() {
        // A foreign holder wins the condition over a future retry: the
        // admission deadline outlives the schedule and an immediate claim
        // would 409. The action must not promise the earlier retry time.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::seconds(30));
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(3));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(6));
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
        assert!(diagnostics.next_retry_at.is_none());
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
    fn armed_namespace_fence_is_visible_as_the_blocker() {
        // Kubernetes-namespace ambiguity is fenced on
        // external_resource_mutation_leases; after the app-row lease
        // lapses this is the thing a redeploy would 409 on.
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() - chrono::Duration::seconds(10));
        input.fence_locked_until = Some(Utc::now() - chrono::Duration::minutes(1));
        input.fence_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(10));
        input.fence_operation_kind = Some("deployment_apply".to_string());
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
            Some("deployment_apply")
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn own_namespace_fence_under_live_worker_is_not_foreign() {
        // During an in-flight apply the worker's mutation claim arms the
        // kubernetes_namespace fence with THIS deployment's operation id:
        // reporting it as foreign would print a Blocked: section for the
        // worker's own fence while the apply progresses.
        let mut input = row("applying", Some("running"), None);
        input.fence_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.fence_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.fence_operation_kind = Some("deployment_apply".to_string());
        input.fence_operation_id = input.deployment_id;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.condition, DeploymentCondition::Progressing);
        assert!(diagnostics.blocking_operation.is_none());
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn abandoned_own_fence_after_worker_loss_blocks_until_reclaim() {
        // Same fence once the worker lock expired: it gates the
        // replacement worker's claim until reclaim_after, so it must be
        // visible as the recovery blocker.
        let mut input = row("applying", Some("running"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.fence_locked_until = Some(Utc::now() - chrono::Duration::seconds(30));
        input.fence_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.fence_operation_kind = Some("deployment_apply".to_string());
        input.fence_operation_id = input.deployment_id;
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("deployment_apply")
        );
        assert!(diagnostics.blocked_until.is_some());
    }

    #[test]
    fn poisoned_fence_dominates_a_finite_foreign_lease_deadline() {
        // The lane opens only once EVERY holder clears. A finite foreign
        // lease plus a poisoned (never-reclaiming) fence therefore never
        // admits at the lease's locked_until/reclaim_after: the fence
        // must win the combined verdict and promise no deadline, instead
        // of the early-returned lease deadline that a 409 would refute.
        let mut input = row("applying", Some("running"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(5));
        input.lease_operation_kind = Some("app_delete".to_string());
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("custom_domain_set"),
            "the poisoned fence, not the finite lease, is the dominating blocker"
        );
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn later_fence_deadline_dominates_an_earlier_lease_deadline() {
        // Both holders finite: the lane admits only at the LATER
        // deadline; reporting the lease's earlier one would promise an
        // admission a 409 refutes.
        let mut input = row("applying", Some("running"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(1));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        input.fence_locked_until = Some(Utc::now() - chrono::Duration::minutes(1));
        input.fence_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(8));
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("custom_domain_set")
        );
        let blocked_until = diagnostics.blocked_until.expect("later fence deadline");
        assert!(blocked_until > Utc::now() + chrono::Duration::minutes(7));
    }

    #[test]
    fn rolled_back_deployment_without_job_row_is_terminal_with_no_reason() {
        // A retained rolled_back row legitimately has no apply job (the
        // rollback flow retires it): terminal like healthy, and never a
        // durability-anomaly reason.
        let diagnostics = project_diagnostics(Some(row("rolled_back", None, None)));
        assert_eq!(diagnostics.phase, DeploymentPhase::RolledBack);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(diagnostics.reason, None);
    }

    #[test]
    fn rolled_back_deployment_with_completed_job_is_terminal_with_no_reason() {
        let diagnostics = project_diagnostics(Some(row("rolled_back", Some("completed"), None)));
        assert_eq!(diagnostics.phase, DeploymentPhase::RolledBack);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert_eq!(diagnostics.reason, None);
    }

    #[test]
    fn abandoned_deletion_on_finite_foreign_fence_promises_the_fence_deadline() {
        // Delete lease fully lapsed, finite foreign fence still holding:
        // the retry DELETE stays Busy until the fence's reclaim_after, so
        // the projection must surface that boundary. The renewable
        // locked_until (earlier, extended by every holder heartbeat)
        // must NOT be promised: claim_resource_rows admits only at
        // reclaim_after.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        input.lease_reclaim_after = Some(Utc::now() - chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        input.fence_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.fence_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(9));
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::AppDeletionAbandonedWaitingOnForeignFence)
        );
        let blocked_until = diagnostics
            .blocked_until
            .expect("fence reclaim boundary must be surfaced");
        assert!(
            blocked_until > Utc::now() + chrono::Duration::minutes(8),
            "must promise reclaim_after, not the renewable locked_until"
        );
    }

    #[test]
    fn abandoned_deletion_on_poisoned_fence_promises_no_deadline() {
        // A poisoned fence never auto-reclaims: no blocked_until may be
        // promised, and the support escalation reason applies.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        input.lease_reclaim_after = Some(Utc::now() - chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        input.fence_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::AppDeletionBlockedByPoisonedFence)
        );
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn deleting_app_with_lapsed_lease_and_holding_fence_still_waits() {
        // The delete lease fully lapsed but the interrupted teardown's
        // namespace fence still rejects the retry DELETE: do not tell
        // the owner to retry a request that would 409.
        let mut input = row("applying", Some("running"), None);
        input.app_deleting = true;
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        input.lease_reclaim_after = Some(Utc::now() - chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("app_delete".to_string());
        input.fence_operation_id = Some(Uuid::new_v4());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Destroying);
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
    }

    #[test]
    fn poisoned_fence_with_live_lock_promises_no_deadline() {
        // A poisoned fence (reclaim_after = infinity) still under a live
        // renewable lock: the claim predicate can never reclaim it at
        // locked_until, so no admission deadline may be promised.
        let mut input = row("watching", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() - chrono::Duration::seconds(10));
        input.fence_locked_until = Some(Utc::now() + chrono::Duration::minutes(2));
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("custom_domain_set")
        );
        assert!(
            diagnostics.blocked_until.is_none(),
            "poisoned fence must not promise locked_until as an admission deadline"
        );
    }

    #[test]
    fn poisoned_fence_blocks_without_a_deadline() {
        // reclaim_after = infinity is NULLed in SQL: blocked with no
        // automatic release time. Still blocked, still named.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = None;
        input.fence_locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert_eq!(
            diagnostics.blocking_operation.as_deref(),
            Some("custom_domain_set")
        );
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn later_retry_schedule_beats_earlier_finite_blocker() {
        // The foreign lease (and its quarantine) expires BEFORE the
        // scheduled attempt: the dispatcher's attempt will be admitted,
        // so the retry schedule — not the stale lease deadline — is the
        // actual reason for waiting.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::minutes(10));
        input.lease_locked_until = Some(Utc::now() - chrono::Duration::minutes(1));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(2));
        input.lease_operation_kind = Some("app_delete".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.condition, DeploymentCondition::WaitingExternal);
        assert_eq!(diagnostics.reason, None);
        assert!(diagnostics.next_retry_at.is_some());
        assert!(
            diagnostics.blocked_until.is_none(),
            "no Blocked: section when the retry outlives the blocker"
        );
    }

    #[test]
    fn poisoned_blocker_still_wins_over_any_retry_schedule() {
        // A poisoned fence has no automatic release: no retry schedule
        // can outlive it, so blocked_by_operation wins even with a far
        // future next_attempt_at.
        let mut input = row("applying", Some("pending"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.next_attempt_at = Some(Utc::now() + chrono::Duration::hours(1));
        input.fence_reclaim_after = None;
        input.fence_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(
            diagnostics.condition,
            DeploymentCondition::BlockedByOperation
        );
        assert!(diagnostics.next_retry_at.is_none());
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
    fn terminal_healthy_deployment_hides_unrelated_blockers() {
        // A healthy deployment with a concurrent custom_domain_set lease
        // is not blocked by it: the durable outcome cannot be undone by
        // a lane 409, and a red Blocked:/Holder: section under a
        // completed deployment misleads the owner.
        let mut input = row("healthy", Some("completed"), None);
        input.job_lock_token = None;
        input.job_locked_until = None;
        input.lease_locked_until = Some(Utc::now() + chrono::Duration::minutes(3));
        input.lease_reclaim_after = Some(Utc::now() + chrono::Duration::minutes(6));
        input.lease_operation_kind = Some("custom_domain_set".to_string());
        let diagnostics = project_diagnostics(Some(input));
        assert_eq!(diagnostics.phase, DeploymentPhase::Healthy);
        assert_eq!(diagnostics.condition, DeploymentCondition::Terminal);
        assert!(diagnostics.blocking_operation.is_none());
        assert!(diagnostics.blocked_until.is_none());
    }

    #[test]
    fn missing_job_with_dns_marker_keeps_setup_reason() {
        let diagnostics = project_diagnostics(Some(row("pending", None, Some("dns_pending"))));
        assert_eq!(diagnostics.condition, DeploymentCondition::Stalled);
        assert_eq!(
            diagnostics.reason,
            Some(DeploymentReason::NoApplyJobRecorded)
        );
    }
}
