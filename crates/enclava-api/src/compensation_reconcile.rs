//! Periodic reconciliation of unresolved post-create compensations (cap#254).
//!
//! The apply path records the POST-returned UID before it returns from an
//! unresolved compensating DELETE. This loop is what a restarted process uses
//! to finish that delete. It never deletes by name, never touches mutation
//! fences, and never writes provider-state columns (`deployments`,
//! `app_mutation_leases`, creation-ledger rows). A database error leaves the
//! row in place and does not fall through to a name-only delete.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use kube::api::{Api, DeleteParams, DynamicObject, Preconditions};
use kube::{Client, Resource};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::state::AppState;
use enclava_engine::apply::compensation::{
    UnresolvedCompensationRecord, UnresolvedCompensationSink,
};
use enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(20);
const DEFAULT_BATCH: i64 = 8;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds for one reconcile pass. Production uses [`Self::production`];
/// tests shrink the confirmation wait so a finalizer case does not sleep.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompensationReconcileLimits {
    pub batch: i64,
    pub request_timeout: Duration,
    pub confirm_attempts: usize,
    pub confirm_interval: Duration,
}

impl CompensationReconcileLimits {
    fn production() -> Self {
        Self {
            batch: DEFAULT_BATCH,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            confirm_attempts: 2,
            confirm_interval: Duration::from_secs(1),
        }
    }
}

impl Default for CompensationReconcileLimits {
    fn default() -> Self {
        Self::production()
    }
}

/// Control-plane sink installed on the apply engine. Captures the failed
/// apply's identity so the engine, which has no database, can persist the
/// POST-returned UID before it returns.
pub struct DbCompensationSink {
    pool: PgPool,
    app_id: Uuid,
    deployment_id: Uuid,
}

impl DbCompensationSink {
    pub fn new(pool: PgPool, app_id: Uuid, deployment_id: Uuid) -> Self {
        Self {
            pool,
            app_id,
            deployment_id,
        }
    }
}

impl UnresolvedCompensationSink for DbCompensationSink {
    fn persist<'a>(
        &'a self,
        record: &'a UnresolvedCompensationRecord,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            persist_unresolved_compensation(&self.pool, self.app_id, self.deployment_id, record)
                .await
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        uid = %record.uid,
                        "compensation record write failed"
                    );
                    "persist_failed".to_string()
                })
        })
    }

    fn clear_resolved<'a>(
        &'a self,
        uid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            mark_compensation_resolved(&self.pool, uid, "deleted")
                .await
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        uid,
                        error_code = "compensation_resolve_unpersisted",
                        "could not clear a confirmed-absent compensation row"
                    );
                    "resolve_failed".to_string()
                })
        })
    }
}

/// Durably record a POST-returned UID. Idempotent on UID. A previously
/// resolved row for the same UID is reopened: the object was observed again
/// and the obligation is not finished. Does not write any other table.
pub(crate) async fn persist_unresolved_compensation(
    pool: &PgPool,
    app_id: Uuid,
    deployment_id: Uuid,
    record: &UnresolvedCompensationRecord,
) -> Result<(), sqlx::Error> {
    if record.uid.is_empty() || record.name.is_empty() {
        return Err(sqlx::Error::Protocol(
            "compensation record requires a non-empty name and UID".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO unresolved_post_create_compensations
            (app_id, deployment_id, kind, namespace, name, uid, mutation_generation)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (uid) DO UPDATE SET
            app_id = EXCLUDED.app_id,
            deployment_id = EXCLUDED.deployment_id,
            kind = EXCLUDED.kind,
            namespace = EXCLUDED.namespace,
            name = EXCLUDED.name,
            mutation_generation = EXCLUDED.mutation_generation,
            resolved_at = NULL,
            resolve_reason = NULL,
            last_error = NULL,
            next_attempt_at = clock_timestamp()
         WHERE unresolved_post_create_compensations.resolved_at IS NOT NULL",
    )
    .bind(app_id)
    .bind(deployment_id)
    .bind(&record.kind)
    .bind(&record.namespace)
    .bind(&record.name)
    .bind(&record.uid)
    .bind(record.mutation_generation)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn mark_compensation_resolved(
    pool: &PgPool,
    uid: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE unresolved_post_create_compensations
            SET resolved_at = clock_timestamp(),
                resolve_reason = $2,
                last_error = NULL
          WHERE uid = $1
            AND resolved_at IS NULL",
    )
    .bind(uid)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

async fn note_compensation_retry(pool: &PgPool, id: i64, code: &str) -> Result<(), sqlx::Error> {
    // Bounded backoff, never a terminal give-up: eventual clearance requires
    // the row to stay until the UID is confirmed absent, deleted, or replaced.
    sqlx::query(
        "UPDATE unresolved_post_create_compensations
            SET last_error = $2,
                next_attempt_at = clock_timestamp()
                    + LEAST(
                        interval '600 seconds',
                        interval '5 seconds' * power(2, LEAST(attempt_count, 7))
                    )
          WHERE id = $1
            AND resolved_at IS NULL",
    )
    .bind(id)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(())
}

/// A full reconcile pass can spend one timeout on the GET, one on the DELETE,
/// and one per confirmation read. The claim lease must cover that so a second
/// replica cannot issue another delete while the first pass is still confirming.
const CLAIM_LEASE: &str = "180 seconds";

#[derive(Debug, sqlx::FromRow)]
struct CompensationRow {
    id: i64,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    mutation_generation: i64,
}

/// Claim a bounded batch of due rows. The CTE `FOR UPDATE SKIP LOCKED` shape
/// is the one `deployment_jobs` uses: the lock is taken on the candidate
/// select, then the update publishes the lease. This write touches only this
/// table.
async fn claim_due_compensations(
    pool: &PgPool,
    batch: i64,
) -> Result<Vec<CompensationRow>, sqlx::Error> {
    sqlx::query_as(
        "WITH candidate AS (
             SELECT id
               FROM unresolved_post_create_compensations
              WHERE resolved_at IS NULL
                AND next_attempt_at <= clock_timestamp()
              ORDER BY next_attempt_at
              LIMIT $1
                FOR UPDATE SKIP LOCKED
         )
         UPDATE unresolved_post_create_compensations AS row
            SET attempt_count = row.attempt_count + 1,
                next_attempt_at = clock_timestamp() + $2::interval
           FROM candidate
          WHERE row.id = candidate.id
         RETURNING row.id, row.kind, row.namespace, row.name, row.uid,
                   row.mutation_generation",
    )
    .bind(batch)
    .bind(CLAIM_LEASE)
    .fetch_all(pool)
    .await
}

fn compensation_api_resource(kind: &str) -> Option<kube::api::ApiResource> {
    match kind {
        "Secret"
        | "StatefulSet"
        | "ServiceAccount"
        | "ResourceQuota"
        | "Service"
        | "ConfigMap"
        | "CiliumNetworkPolicy"
        | "EnvoyProxy"
        | "Gateway"
        | "TLSRoute"
        | "Namespace" => Some(crate::deployment_failure_cleanup::sweep_api_resource(kind)),
        _ => None,
    }
}

struct OwnedVersion {
    resource_version: String,
}

enum LiveView {
    Absent,
    DifferentUid,
    /// A later apply wrote this same UID. It is no longer the failed create.
    LaterGeneration,
    Owned(OwnedVersion),
    Unreadable(&'static str),
}

fn live_mutation_generation(live: &DynamicObject) -> Option<i64> {
    live.meta()
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
        .and_then(|raw| raw.parse().ok())
        .filter(|generation| *generation > 0)
}

fn classify_live(live: &DynamicObject, expected_uid: &str, recorded_generation: i64) -> LiveView {
    match live.meta().uid.as_deref() {
        Some(uid) if uid != expected_uid => LiveView::DifferentUid,
        Some(_) => {
            // A newer mutation-generation annotation means a later apply
            // adopted this UID after the failed create. Cleanup releases the
            // fence so that retry can proceed; deleting the UID now would
            // destroy the live namespace, including tenant volumes.
            if live_mutation_generation(live)
                .is_some_and(|generation| generation > recorded_generation)
            {
                return LiveView::LaterGeneration;
            }
            match live
                .meta()
                .resource_version
                .clone()
                .filter(|version| !version.is_empty())
            {
                Some(resource_version) => LiveView::Owned(OwnedVersion { resource_version }),
                None => LiveView::Unreadable("unpinned_resource_version"),
            }
        }
        None => LiveView::Unreadable("live_uid_missing"),
    }
}

async fn read_live(
    api: &Api<DynamicObject>,
    name: &str,
    expected_uid: &str,
    recorded_generation: i64,
    timeout: Duration,
) -> LiveView {
    match tokio::time::timeout(timeout, api.get_opt(name)).await {
        Ok(Ok(None)) => LiveView::Absent,
        Ok(Ok(Some(live))) => classify_live(&live, expected_uid, recorded_generation),
        Ok(Err(kube::Error::Api(error))) if error.code == 404 => LiveView::Absent,
        Ok(Err(_)) => LiveView::Unreadable("get_error"),
        Err(_) => LiveView::Unreadable("get_timeout"),
    }
}

/// One reconcile pass. Returns the number of rows still unresolved after the
/// pass (claimed rows that were not resolved). A claim-query failure returns
/// `Err` and issues no Kubernetes request.
pub(crate) async fn reconcile_unresolved_post_create_compensations(
    pool: &PgPool,
    client: &Client,
    limits: CompensationReconcileLimits,
) -> Result<usize, sqlx::Error> {
    let rows = claim_due_compensations(pool, limits.batch).await?;
    let mut unresolved = 0usize;
    for row in rows {
        if !reconcile_one(pool, client, &row, limits).await {
            unresolved += 1;
        }
    }
    Ok(unresolved)
}

/// `true` when the row was resolved. Kubernetes errors and write failures
/// leave it unresolved. Never deletes a UID other than `row.uid`.
async fn reconcile_one(
    pool: &PgPool,
    client: &Client,
    row: &CompensationRow,
    limits: CompensationReconcileLimits,
) -> bool {
    if row.uid.is_empty() || row.name.is_empty() {
        return leave_unresolved(pool, row.id, "unpinned_identity").await;
    }
    let Some(resource) = compensation_api_resource(&row.kind) else {
        tracing::error!(
            kind = %row.kind,
            uid = %row.uid,
            error_code = "compensation_unknown_kind",
            "refusing to address an unmapped kind; the row stays unresolved"
        );
        return leave_unresolved(pool, row.id, "unknown_kind").await;
    };
    let api: Api<DynamicObject> = if row.kind == "Namespace" {
        Api::all_with(client.clone(), &resource)
    } else {
        let Some(namespace) = row.namespace.as_deref() else {
            return leave_unresolved(pool, row.id, "missing_namespace").await;
        };
        Api::namespaced_with(client.clone(), namespace, &resource)
    };

    match read_live(
        &api,
        &row.name,
        &row.uid,
        row.mutation_generation,
        limits.request_timeout,
    )
    .await
    {
        LiveView::Absent => resolve_or_keep(pool, row, "absent").await,
        LiveView::DifferentUid => {
            tracing::info!(
                kind = %row.kind,
                name = %row.name,
                uid = %row.uid,
                "compensation target was replaced; refusing a name-only delete"
            );
            resolve_or_keep(pool, row, "stale_replacement").await
        }
        LiveView::LaterGeneration => {
            tracing::info!(
                kind = %row.kind,
                name = %row.name,
                uid = %row.uid,
                recorded_generation = row.mutation_generation,
                "later apply adopted this UID; refusing the compensating delete"
            );
            resolve_or_keep(pool, row, "later_generation").await
        }
        LiveView::Unreadable(code) => leave_unresolved(pool, row.id, code).await,
        LiveView::Owned(owned) => {
            match issue_pinned_delete(
                &api,
                &row.name,
                &row.uid,
                &owned.resource_version,
                limits.request_timeout,
            )
            .await
            {
                DeleteOutcome::Absent => resolve_or_keep(pool, row, "absent").await,
                DeleteOutcome::Accepted => confirm_pinned_delete(pool, &api, row, limits).await,
                DeleteOutcome::Conflict => reclassify_after_conflict(pool, &api, row, limits).await,
                DeleteOutcome::Rejected => leave_unresolved(pool, row.id, "delete_rejected").await,
                DeleteOutcome::Ambiguous(code) => leave_unresolved(pool, row.id, code).await,
            }
        }
    }
}

enum DeleteOutcome {
    Absent,
    Accepted,
    /// UID or resourceVersion precondition failed. Re-read; do not fall back
    /// to a UID-only or name-only delete.
    Conflict,
    /// The API server rejected the request before accepting it (4xx other
    /// than 404/409). Nothing is in flight.
    Rejected,
    Ambiguous(&'static str),
}

async fn issue_pinned_delete(
    api: &Api<DynamicObject>,
    name: &str,
    uid: &str,
    resource_version: &str,
    timeout: Duration,
) -> DeleteOutcome {
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_string()),
            resource_version: Some(resource_version.to_string()),
        }),
        ..DeleteParams::default()
    };
    match tokio::time::timeout(timeout, api.delete(name, &params)).await {
        Ok(Ok(_)) => DeleteOutcome::Accepted,
        Ok(Err(kube::Error::Api(error))) if error.code == 404 => DeleteOutcome::Absent,
        Ok(Err(kube::Error::Api(error))) if error.code == 409 => DeleteOutcome::Conflict,
        Ok(Err(kube::Error::Api(error))) if (400..500).contains(&error.code) => {
            DeleteOutcome::Rejected
        }
        Ok(Err(_)) => DeleteOutcome::Ambiguous("delete_error"),
        Err(_) => DeleteOutcome::Ambiguous("delete_timeout"),
    }
}

/// A 409 means the owning GET's resourceVersion is stale. Re-read and apply
/// the same generation check. One pinned retry is allowed only when the fresh
/// object is still the failed create. A bare UID delete is never issued.
async fn reclassify_after_conflict(
    pool: &PgPool,
    api: &Api<DynamicObject>,
    row: &CompensationRow,
    limits: CompensationReconcileLimits,
) -> bool {
    match read_live(
        api,
        &row.name,
        &row.uid,
        row.mutation_generation,
        limits.request_timeout,
    )
    .await
    {
        LiveView::Absent => resolve_or_keep(pool, row, "absent").await,
        LiveView::DifferentUid => resolve_or_keep(pool, row, "stale_replacement").await,
        LiveView::LaterGeneration => resolve_or_keep(pool, row, "later_generation").await,
        LiveView::Unreadable(code) => leave_unresolved(pool, row.id, code).await,
        LiveView::Owned(owned) => {
            match issue_pinned_delete(
                api,
                &row.name,
                &row.uid,
                &owned.resource_version,
                limits.request_timeout,
            )
            .await
            {
                DeleteOutcome::Absent => resolve_or_keep(pool, row, "absent").await,
                DeleteOutcome::Accepted => confirm_pinned_delete(pool, api, row, limits).await,
                DeleteOutcome::Conflict => {
                    leave_unresolved(pool, row.id, "precondition_rejected").await
                }
                DeleteOutcome::Rejected => leave_unresolved(pool, row.id, "delete_rejected").await,
                DeleteOutcome::Ambiguous(code) => leave_unresolved(pool, row.id, code).await,
            }
        }
    }
}

async fn confirm_pinned_delete(
    pool: &PgPool,
    api: &Api<DynamicObject>,
    row: &CompensationRow,
    limits: CompensationReconcileLimits,
) -> bool {
    for _ in 0..limits.confirm_attempts {
        if !limits.confirm_interval.is_zero() {
            tokio::time::sleep(limits.confirm_interval).await;
        }
        match read_live(
            api,
            &row.name,
            &row.uid,
            row.mutation_generation,
            limits.request_timeout,
        )
        .await
        {
            LiveView::Absent => return resolve_or_keep(pool, row, "deleted").await,
            LiveView::DifferentUid => return resolve_or_keep(pool, row, "stale_replacement").await,
            LiveView::LaterGeneration => {
                return resolve_or_keep(pool, row, "later_generation").await;
            }
            LiveView::Owned(_) => continue,
            LiveView::Unreadable(code) => return leave_unresolved(pool, row.id, code).await,
        }
    }
    // Still the same UID (finalizer, or the delete was accepted but not
    // observed). Leave the row. The next pass retries the pinned delete.
    leave_unresolved(pool, row.id, "finalizer").await
}

async fn resolve_or_keep(pool: &PgPool, row: &CompensationRow, reason: &str) -> bool {
    match mark_compensation_resolved(pool, &row.uid, reason).await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(
                error = %error,
                uid = %row.uid,
                error_code = "compensation_resolve_unpersisted",
                "could not record compensation resolution; leaving the row"
            );
            false
        }
    }
}

async fn leave_unresolved(pool: &PgPool, id: i64, code: &str) -> bool {
    if let Err(error) = note_compensation_retry(pool, id, code).await {
        tracing::error!(
            error = %error,
            id,
            error_code = "compensation_retry_unpersisted",
            "could not record a compensation retry; the row stays due"
        );
    }
    false
}

pub fn spawn_unresolved_compensation_reconciler(
    state: AppState,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    crate::reconciler::spawn_reconciler(
        "unresolved-post-create-compensation",
        shutdown,
        async move {
            let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(error) = reconcile_unresolved_post_create_compensations(
                    &state.db,
                    &state.kube_client,
                    CompensationReconcileLimits::production(),
                )
                .await
                {
                    tracing::error!(
                        error = %error,
                        error_code = "compensation_reconcile_db_failed",
                        "unresolved compensation reconcile could not read its rows; no delete was issued"
                    );
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use kube::Client;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tower::service_fn;

    #[derive(Clone, Copy)]
    enum DeleteMode {
        Gone,
        Finalizer,
        Timeout,
        ConflictThenNewer,
    }

    struct Cluster {
        live_uid: Option<String>,
        annotations: Value,
        resource_version: String,
        delete_mode: DeleteMode,
        deletes: Vec<String>,
        paths: Vec<String>,
        calls: usize,
    }

    fn cluster(
        live_uid: Option<&str>,
        annotations: Value,
        mode: DeleteMode,
    ) -> Arc<Mutex<Cluster>> {
        Arc::new(Mutex::new(Cluster {
            live_uid: live_uid.map(str::to_string),
            annotations,
            resource_version: "3".to_string(),
            delete_mode: mode,
            deletes: Vec::new(),
            paths: Vec::new(),
            calls: 0,
        }))
    }

    fn limits() -> CompensationReconcileLimits {
        CompensationReconcileLimits {
            batch: 8,
            request_timeout: Duration::from_millis(200),
            confirm_attempts: 1,
            confirm_interval: Duration::ZERO,
        }
    }

    fn client(state: Arc<Mutex<Cluster>>) -> Client {
        Client::new(
            service_fn(move |request: Request<kube::client::Body>| {
                let state = Arc::clone(&state);
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let action = {
                        let mut cluster = state.lock().expect("cluster");
                        cluster.calls += 1;
                        cluster.paths.push(path);
                        if method == Method::GET {
                            let Some(uid) = cluster.live_uid.clone() else {
                                return Ok::<_, std::io::Error>(status(StatusCode::NOT_FOUND));
                            };
                            let object = json!({
                                "apiVersion": "v1",
                                "kind": "Secret",
                                "metadata": {
                                    "name": "pull-secret",
                                    "namespace": "tenant-ns",
                                    "uid": uid,
                                    "resourceVersion": cluster.resource_version.clone(),
                                    "annotations": cluster.annotations.clone(),
                                }
                            });
                            return Ok(json_response(StatusCode::OK, &object));
                        }
                        if method == Method::DELETE {
                            let payload = String::from_utf8_lossy(&body).to_string();
                            cluster.deletes.push(payload);
                            let mode = cluster.delete_mode;
                            if matches!(mode, DeleteMode::Gone) {
                                cluster.live_uid = None;
                            }
                            if matches!(mode, DeleteMode::ConflictThenNewer) {
                                cluster.annotations = json!({
                                    "enclava.dev/cap-provider-mutation-generation": "99"
                                });
                                cluster.resource_version = "9".to_string();
                            }
                            mode
                        } else {
                            return Err(std::io::Error::other(format!("unexpected {method}")));
                        }
                    };
                    match action {
                        DeleteMode::Gone | DeleteMode::Finalizer => Ok(status(StatusCode::OK)),
                        DeleteMode::ConflictThenNewer => Ok(status(StatusCode::CONFLICT)),
                        DeleteMode::Timeout => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            Ok(status(StatusCode::OK))
                        }
                    }
                }
            }),
            "default",
        )
    }

    fn status(code: StatusCode) -> Response<kube::client::Body> {
        let reason = match code {
            StatusCode::NOT_FOUND => "NotFound",
            StatusCode::CONFLICT => "Conflict",
            StatusCode::INTERNAL_SERVER_ERROR => "InternalError",
            _ => "Failure",
        };
        json_response(
            code,
            &json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": reason,
                "message": reason,
                "code": code.as_u16()
            }),
        )
    }

    fn json_response(code: StatusCode, value: &Value) -> Response<kube::client::Body> {
        Response::builder()
            .status(code)
            .body(kube::client::Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    }

    fn db_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        &LOCK
    }

    async fn isolated() -> (
        tokio::sync::MutexGuard<'static, ()>,
        crate::test_support::IsolatedDatabaseCleanup,
        PgPool,
    ) {
        let guard = db_lock().lock().await;
        let (cleanup, pool) =
            crate::test_support::isolated_database_test_pool("compensation").await;
        (guard, cleanup, pool)
    }

    async fn insert_restart_row(pool: &PgPool, uid: &str) {
        sqlx::query(
            "INSERT INTO unresolved_post_create_compensations
                (app_id, deployment_id, kind, namespace, name, uid, mutation_generation)
             VALUES ($1, $2, 'Secret', 'tenant-ns', 'pull-secret', $3, 7)",
        )
        .bind(Uuid::nil())
        .bind(Uuid::nil())
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn reason(pool: &PgPool, uid: &str) -> (Option<String>, Option<String>) {
        sqlx::query_as(
            "SELECT resolve_reason, last_error
               FROM unresolved_post_create_compensations
              WHERE uid = $1",
        )
        .bind(uid)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn restart_deletes_only_the_recorded_uid_of_an_unmarked_object() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-restart";
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        insert_restart_row(&pool, uid).await;
        let state = cluster(Some(uid), json!({}), DeleteMode::Gone);
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        let deletes = state.lock().unwrap().deletes.clone();
        let paths = state.lock().unwrap().paths.clone();
        assert_eq!(deletes.len(), 1);
        assert!(
            deletes[0].contains(uid)
                && deletes[0].contains("preconditions")
                && deletes[0].contains("resourceVersion"),
            "delete was not pinned to UID and resourceVersion: {}",
            deletes[0]
        );
        assert!(
            paths
                .iter()
                .any(|path| path.contains("/namespaces/tenant-ns/secrets/")),
            "delete was not aimed at the recorded namespace: {paths:?}"
        );
        let (resolve, last_error) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("deleted"));
        assert!(last_error.is_none());
    }

    #[tokio::test]
    async fn same_name_replacement_is_not_deleted() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-replaced";
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        insert_restart_row(&pool, uid).await;
        let state = cluster(Some("replacement-uid"), json!({}), DeleteMode::Gone);
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert!(state.lock().unwrap().deletes.is_empty());
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("stale_replacement"));
    }

    #[tokio::test]
    async fn absence_resolves_without_a_delete() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-absent";
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        insert_restart_row(&pool, uid).await;
        let state = cluster(None, json!({}), DeleteMode::Gone);
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert!(state.lock().unwrap().deletes.is_empty());
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("absent"));
    }

    #[tokio::test]
    async fn finalizer_keeps_the_row_after_a_pinned_delete() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-finalizer";
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        insert_restart_row(&pool, uid).await;
        let state = cluster(
            Some(uid),
            json!({"rewritten": "by-webhook"}),
            DeleteMode::Finalizer,
        );
        let unresolved = reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert_eq!(unresolved, 1);
        let deletes = state.lock().unwrap().deletes.clone();
        assert_eq!(deletes.len(), 1);
        assert!(deletes[0].contains(uid));
        let (resolve, last_error) = reason(&pool, uid).await;
        assert!(resolve.is_none());
        assert_eq!(last_error.as_deref(), Some("finalizer"));
    }

    #[tokio::test]
    async fn ambiguous_delete_stays_unresolved_and_stays_pinned() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-timeout";
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        insert_restart_row(&pool, uid).await;
        let state = cluster(Some(uid), json!({}), DeleteMode::Timeout);
        let unresolved = reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert_eq!(unresolved, 1);
        let deletes = state.lock().unwrap().deletes.clone();
        assert_eq!(deletes.len(), 1);
        assert!(
            deletes[0].contains("preconditions")
                && deletes[0].contains("resourceVersion")
                && deletes[0].contains(uid)
        );
        let (resolve, last_error) = reason(&pool, uid).await;
        assert!(resolve.is_none());
        assert_eq!(last_error.as_deref(), Some("delete_timeout"));
    }

    #[tokio::test]
    async fn database_read_failure_issues_no_kubernetes_request() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://invalid:invalid@127.0.0.1:1/none")
            .unwrap();
        let state = cluster(Some("should-not-be-read"), json!({}), DeleteMode::Gone);
        let error = reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .expect_err("closed pool must fail the claim");
        assert!(state.lock().unwrap().calls == 0, "{error}");
    }

    #[tokio::test]
    async fn persist_records_apply_identity_and_post_uid() {
        let (_guard, _cleanup, pool) = isolated().await;
        let app_id = Uuid::from_u128(0x254);
        let deployment_id = Uuid::from_u128(0x2540);
        let record = UnresolvedCompensationRecord {
            kind: "Secret".to_string(),
            namespace: Some("tenant-ns".to_string()),
            name: "pull-secret".to_string(),
            uid: "post-uid-identity".to_string(),
            mutation_generation: 9,
        };
        sqlx::query("DELETE FROM unresolved_post_create_compensations WHERE uid = $1")
            .bind(&record.uid)
            .execute(&pool)
            .await
            .unwrap();
        persist_unresolved_compensation(&pool, app_id, deployment_id, &record)
            .await
            .unwrap();
        let row: (Uuid, Uuid, String, Option<String>, String, i64) = sqlx::query_as(
            "SELECT app_id, deployment_id, kind, namespace, name, mutation_generation
               FROM unresolved_post_create_compensations WHERE uid = $1",
        )
        .bind(&record.uid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                app_id,
                deployment_id,
                "Secret".to_string(),
                Some("tenant-ns".to_string()),
                "pull-secret".to_string(),
                9,
            )
        );
    }

    #[tokio::test]
    async fn resolve_write_failure_is_not_swallowed() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://invalid:invalid@127.0.0.1:1/none")
            .unwrap();
        let error = mark_compensation_resolved(&pool, "uid", "absent")
            .await
            .expect_err("a failed resolution write must surface");
        let _ = error;
    }

    #[tokio::test]
    async fn later_generation_on_the_same_uid_is_not_deleted() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-adopted";
        insert_restart_row(&pool, uid).await;
        let state = cluster(
            Some(uid),
            json!({"enclava.dev/cap-provider-mutation-generation": "12"}),
            DeleteMode::Gone,
        );
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert!(
            state.lock().unwrap().deletes.is_empty(),
            "a later apply's generation must not be deleted"
        );
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("later_generation"));
    }

    #[tokio::test]
    async fn later_generation_on_a_namespace_uid_is_not_deleted() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-ns-adopted";
        sqlx::query(
            "INSERT INTO unresolved_post_create_compensations
                (app_id, deployment_id, kind, namespace, name, uid, mutation_generation)
             VALUES ($1, $2, 'Namespace', NULL, 'tenant-ns', $3, 7)",
        )
        .bind(Uuid::nil())
        .bind(Uuid::nil())
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();
        let state = cluster(
            Some(uid),
            json!({"enclava.dev/cap-provider-mutation-generation": "8"}),
            DeleteMode::Gone,
        );
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        {
            let locked = state.lock().unwrap();
            assert!(locked.deletes.is_empty());
            assert!(
                locked
                    .paths
                    .iter()
                    .any(|path| path == "/api/v1/namespaces/tenant-ns"),
                "namespace reconcile did not GET the recorded name: {:?}",
                locked.paths
            );
        }
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("later_generation"));
    }

    #[tokio::test]
    async fn conflict_reread_refuses_a_newer_generation_without_a_second_delete() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-conflict";
        insert_restart_row(&pool, uid).await;
        let state = cluster(Some(uid), json!({}), DeleteMode::ConflictThenNewer);
        reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert_eq!(
            state.lock().unwrap().deletes.len(),
            1,
            "the 409 must not be followed by a bare UID delete"
        );
        assert!(state.lock().unwrap().deletes[0].contains("resourceVersion"));
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("later_generation"));
    }

    #[tokio::test]
    async fn a_later_pass_clears_a_finalizer_once_the_uid_is_gone() {
        let (_guard, _cleanup, pool) = isolated().await;
        let uid = "post-uid-eventual";
        insert_restart_row(&pool, uid).await;
        let state = cluster(Some(uid), json!({}), DeleteMode::Finalizer);
        let unresolved = reconcile_unresolved_post_create_compensations(
            &pool,
            &client(Arc::clone(&state)),
            limits(),
        )
        .await
        .unwrap();
        assert_eq!(unresolved, 1);
        state.lock().unwrap().live_uid = None;
        sqlx::query(
            "UPDATE unresolved_post_create_compensations
                SET next_attempt_at = clock_timestamp()
              WHERE uid = $1",
        )
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();
        reconcile_unresolved_post_create_compensations(&pool, &client(state), limits())
            .await
            .unwrap();
        let (resolve, _) = reason(&pool, uid).await;
        assert_eq!(resolve.as_deref(), Some("absent"));
    }
}
