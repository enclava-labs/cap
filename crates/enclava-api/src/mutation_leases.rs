//! Durable generation fencing for application and provider mutations.
//!
//! Advisory locks serialize healthy connections, but disappear immediately
//! when a connection is lost.  These renewable rows remain authoritative
//! through connection loss and through a provider's hard request deadline.
//! Provider-scoped rows are intentionally not foreign-keyed to `apps`, so a
//! late response cannot clobber a hostname/backend reused by a new app ID.

use std::{future::Future, time::Duration};

use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::{OwnedSemaphorePermit, watch};
use uuid::Uuid;

use crate::state::AppState;

const LEASE_SECONDS: i64 = 180;
// kube-client's default read/write timeout is 295s. Keep a full minute of
// margin after a canceled/accepted Kubernetes request before another durable
// generation may reuse the same external resource.
const RECLAIM_QUARANTINE_SECONDS: i64 = 360;
const HEARTBEAT_SECONDS: u64 = 30;
const RENEW_TIMEOUT_SECONDS: u64 = 10;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceFence {
    pub scope: String,
    pub key: String,
}

impl ResourceFence {
    pub fn new(scope: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            key: key.into(),
        }
    }

    pub fn dns(hostname: &str) -> Self {
        Self::new(
            "dns_hostname",
            hostname.trim_end_matches('.').to_ascii_lowercase(),
        )
    }

    pub fn edge(key: &str) -> Self {
        Self::new("edge_route", key.to_ascii_lowercase())
    }

    pub fn edge_config() -> Self {
        Self::new("edge_config", "global")
    }

    pub fn kbs_policy() -> Self {
        Self::new("kbs_policy", "global")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MutationLeaseError {
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("application mutation is already in progress")]
    Busy,
    #[error("application mutation authority is unavailable")]
    AppUnavailable,
    #[error("application mutation lease was lost")]
    Lost,
    #[error("side-effect admission limiter closed")]
    AdmissionClosed,
}

#[derive(Clone, Debug)]
struct ClaimedResource {
    fence: ResourceFence,
    generation: i64,
}

/// A live mutation owner. Dropping without `finish_in_tx` intentionally leaves
/// the durable rows owned until lease+quarantine expiry. That is the safe
/// outcome after an uncertain provider response.
pub struct AppMutationLease {
    pool: PgPool,
    app_id: Uuid,
    token: Uuid,
    generation: i64,
    resources: Vec<ClaimedResource>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    heartbeat_lost: watch::Receiver<bool>,
    _admission: OwnedSemaphorePermit,
}

impl std::fmt::Debug for AppMutationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppMutationLease")
            .field("app_id", &self.app_id)
            .field("generation", &self.generation)
            .field("resource_count", &self.resources.len())
            .finish_non_exhaustive()
    }
}

impl AppMutationLease {
    pub fn app_id(&self) -> Uuid {
        self.app_id
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn resource_generation(&self, fence: &ResourceFence) -> Option<i64> {
        self.resources
            .iter()
            .find(|resource| &resource.fence == fence)
            .map(|resource| resource.generation)
    }

    fn stop_heartbeat(&mut self) {
        if let Some(task) = self.heartbeat.take() {
            task.abort();
        }
    }

    /// Cancel the provider future as soon as durable renewal is lost.  The
    /// rows intentionally remain owned through reclaim quarantine, which is
    /// longer than one bounded in-flight provider request.
    pub fn guard_provider<'a, F, T>(
        &'a self,
        future: F,
    ) -> impl Future<Output = Result<T, MutationLeaseError>> + 'a + use<'a, F, T>
    where
        F: Future<Output = T> + 'a,
        T: 'a,
    {
        guard_provider_future(self.heartbeat_lost.clone(), future)
    }

    /// Assert generation/token ownership and clear it in the caller's
    /// publication transaction. The caller must acquire the app advisory lane
    /// before invoking this method.
    pub async fn finish_in_tx(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), MutationLeaseError> {
        self.stop_heartbeat();
        assert_current_rows(
            tx,
            self.app_id,
            self.token,
            self.generation,
            &self.resources,
        )
        .await?;

        let app = sqlx::query(
            "UPDATE app_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE app_id = $1
                AND owner_token = $2
                AND generation = $3",
        )
        .bind(self.app_id)
        .bind(self.token)
        .bind(self.generation)
        .execute(&mut **tx)
        .await?;
        if app.rows_affected() != 1 {
            return Err(MutationLeaseError::Lost);
        }

        for resource in &self.resources {
            let result = sqlx::query(
                "UPDATE external_resource_mutation_leases
                    SET owner_token = NULL,
                        operation_kind = NULL,
                        operation_id = NULL,
                        locked_until = NULL,
                        reclaim_after = NULL,
                        updated_at = clock_timestamp()
                  WHERE resource_scope = $1
                    AND resource_key = $2
                    AND owner_token = $3
                    AND generation = $4",
            )
            .bind(&resource.fence.scope)
            .bind(&resource.fence.key)
            .bind(self.token)
            .bind(resource.generation)
            .execute(&mut **tx)
            .await?;
            if result.rows_affected() != 1 {
                return Err(MutationLeaseError::Lost);
            }
        }
        Ok(())
    }

    /// Verify ownership without releasing it. Use this for a durable failure
    /// publication after an uncertain provider result; dropping the lease then
    /// preserves the reclaim quarantine for mandatory reconciliation.
    pub async fn assert_current_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), MutationLeaseError> {
        assert_current_rows(
            tx,
            self.app_id,
            self.token,
            self.generation,
            &self.resources,
        )
        .await
    }

    /// Release one globally shared resource after its durable reconciliation
    /// succeeds while retaining app/other-resource quarantine for a different
    /// uncertain provider operation.
    pub async fn release_resource_in_tx(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        fence: &ResourceFence,
    ) -> Result<(), MutationLeaseError> {
        self.stop_heartbeat();
        assert_current_rows(
            tx,
            self.app_id,
            self.token,
            self.generation,
            &self.resources,
        )
        .await?;
        let index = self
            .resources
            .iter()
            .position(|resource| &resource.fence == fence)
            .ok_or(MutationLeaseError::Lost)?;
        let released = self.resources[index].clone();
        clear_resource_rows(tx, self.token, std::slice::from_ref(&released)).await?;
        self.resources.remove(index);
        let (heartbeat, heartbeat_lost) = spawn_app_heartbeat(
            self.pool.clone(),
            self.app_id,
            self.token,
            self.generation,
            self.resources.clone(),
            Duration::from_secs(HEARTBEAT_SECONDS),
            Duration::from_secs(RENEW_TIMEOUT_SECONDS),
        );
        self.heartbeat = Some(heartbeat);
        self.heartbeat_lost = heartbeat_lost;
        Ok(())
    }

    /// Arm every claimed resource in `resource_scope` before sending an
    /// unconditional provider mutation. Cloudflare does not expose a
    /// generation precondition, so a caller crash or lost response must leave
    /// the resource poisoned indefinitely rather than allowing elapsed time to
    /// authorize reuse.
    ///
    /// This intentionally does not require the renewable deadline to still be
    /// current. The token/generation CAS is the authority: after a heartbeat
    /// loss the old owner may still poison its exact generation, but it cannot
    /// touch a generation that has already been reclaimed.
    pub async fn arm_resource_scope_until_reconciled(
        &self,
        resource_scope: &str,
    ) -> Result<(), MutationLeaseError> {
        let mut tx = self.pool.begin().await?;
        let retained =
            poison_resource_scope(&mut tx, self.token, &self.resources, resource_scope).await?;
        if retained == 0 {
            return Err(MutationLeaseError::Lost);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Fail closed after an external provider response is fundamentally
    /// unreconcilable (Cloudflare has no conditional mutation primitive).
    /// These rows require explicit/durable provider reconciliation before
    /// reuse; elapsed wall-clock time alone is not authority to reclaim them.
    pub async fn retain_resource_scope_until_reconciled_in_tx(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        resource_scope: &str,
    ) -> Result<(), MutationLeaseError> {
        self.stop_heartbeat();
        let retained =
            poison_resource_scope(tx, self.token, &self.resources, resource_scope).await?;
        if retained == 0 {
            return Err(MutationLeaseError::Lost);
        }
        Ok(())
    }

    pub async fn retain_resource_scope_until_reconciled(
        &mut self,
        resource_scope: &str,
    ) -> Result<(), MutationLeaseError> {
        let mut tx = self.pool.begin().await?;
        crate::deploy::lock_app_deployment_lane(&mut tx, self.app_id).await?;
        self.retain_resource_scope_until_reconciled_in_tx(&mut tx, resource_scope)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Release a successful mutation when there is no other database
    /// publication to make.
    pub async fn finish(mut self) -> Result<(), MutationLeaseError> {
        self.stop_heartbeat();
        let mut tx = self.pool.begin().await?;
        crate::deploy::lock_app_deployment_lane(&mut tx, self.app_id).await?;
        self.finish_in_tx(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl Drop for AppMutationLease {
    fn drop(&mut self) {
        self.stop_heartbeat();
    }
}

/// A provider-resource owner not tied to a live app row.  This is used by
/// startup/periodic global reconciliation (for example an empty signed KBS
/// deny-set after the last app was deleted) and contends with app mutations
/// through the exact same resource rows.
pub struct ResourceMutationLease {
    pool: PgPool,
    token: Uuid,
    resources: Vec<ClaimedResource>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    heartbeat_lost: watch::Receiver<bool>,
    _admission: OwnedSemaphorePermit,
}

impl ResourceMutationLease {
    pub fn resource_generation(&self, fence: &ResourceFence) -> Option<i64> {
        self.resources
            .iter()
            .find(|resource| &resource.fence == fence)
            .map(|resource| resource.generation)
    }

    fn stop_heartbeat(&mut self) {
        if let Some(task) = self.heartbeat.take() {
            task.abort();
        }
    }

    pub fn guard_provider<'a, F, T>(
        &'a self,
        future: F,
    ) -> impl Future<Output = Result<T, MutationLeaseError>> + 'a + use<'a, F, T>
    where
        F: Future<Output = T> + 'a,
        T: 'a,
    {
        guard_provider_future(self.heartbeat_lost.clone(), future)
    }

    pub async fn finish(mut self) -> Result<(), MutationLeaseError> {
        self.stop_heartbeat();
        let mut tx = self.pool.begin().await?;
        assert_current_resource_rows(&mut tx, self.token, &self.resources).await?;
        clear_resource_rows(&mut tx, self.token, &self.resources).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl Drop for ResourceMutationLease {
    fn drop(&mut self) {
        self.stop_heartbeat();
    }
}

fn guard_provider_future<F, T>(
    mut heartbeat_lost: watch::Receiver<bool>,
    future: F,
) -> impl Future<Output = Result<T, MutationLeaseError>>
where
    F: Future<Output = T>,
{
    let mut future = Box::pin(future);
    async move {
        if *heartbeat_lost.borrow() {
            return Err(MutationLeaseError::Lost);
        }
        loop {
            tokio::select! {
                biased;
                changed = heartbeat_lost.changed() => {
                    if changed.is_err() || *heartbeat_lost.borrow() {
                        return Err(MutationLeaseError::Lost);
                    }
                }
                output = &mut future => return Ok(output),
            }
        }
    }
}

fn spawn_app_heartbeat(
    pool: PgPool,
    app_id: Uuid,
    token: Uuid,
    generation: i64,
    resources: Vec<ClaimedResource>,
    heartbeat_interval: Duration,
    renew_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, watch::Receiver<bool>) {
    let (lost_tx, lost_rx) = watch::channel(false);
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The claim transaction already authored the first deadline.
        interval.tick().await;
        loop {
            interval.tick().await;
            if !matches!(
                tokio::time::timeout(
                    renew_timeout,
                    renew(&pool, app_id, token, generation, &resources),
                )
                .await,
                Ok(Ok(()))
            ) {
                let _ = lost_tx.send(true);
                return;
            }
        }
    });
    (heartbeat, lost_rx)
}

fn spawn_resource_heartbeat(
    pool: PgPool,
    token: Uuid,
    resources: Vec<ClaimedResource>,
    heartbeat_interval: Duration,
    renew_timeout: Duration,
) -> (tokio::task::JoinHandle<()>, watch::Receiver<bool>) {
    let (lost_tx, lost_rx) = watch::channel(false);
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            if !matches!(
                tokio::time::timeout(renew_timeout, renew_resources(&pool, token, &resources),)
                    .await,
                Ok(Ok(()))
            ) {
                let _ = lost_tx.send(true);
                return;
            }
        }
    });
    (heartbeat, lost_rx)
}

/// Claim only durable provider-resource generations.  Resource keys are
/// canonicalized by callers and sorted here so multi-resource claims cannot
/// invert row-lock order.
pub async fn claim_resources(
    state: &AppState,
    operation_kind: &str,
    operation_id: Uuid,
    mut resources: Vec<ResourceFence>,
) -> Result<ResourceMutationLease, MutationLeaseError> {
    let admission = state
        .admit_side_effect()
        .await
        .map_err(|_| MutationLeaseError::AdmissionClosed)?;
    resources.sort();
    resources.dedup();
    let token = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let claimed_resources =
        claim_resource_rows(&mut tx, token, operation_kind, operation_id, resources).await?;
    tx.commit().await?;
    let (heartbeat, heartbeat_lost) = spawn_resource_heartbeat(
        state.db.clone(),
        token,
        claimed_resources.clone(),
        Duration::from_secs(HEARTBEAT_SECONDS),
        Duration::from_secs(RENEW_TIMEOUT_SECONDS),
    );
    Ok(ResourceMutationLease {
        pool: state.db.clone(),
        token,
        resources: claimed_resources,
        heartbeat: Some(heartbeat),
        heartbeat_lost,
        _admission: admission,
    })
}

pub async fn claim(
    state: &AppState,
    app_id: Uuid,
    operation_kind: &str,
    operation_id: Uuid,
    allow_deleting: bool,
    mut resources: Vec<ResourceFence>,
) -> Result<AppMutationLease, MutationLeaseError> {
    let admission = state
        .admit_side_effect()
        .await
        .map_err(|_| MutationLeaseError::AdmissionClosed)?;
    resources.sort();
    resources.dedup();

    let token = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app_id).await?;
    let app_available: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM apps
              WHERE id = $1
                AND ($2 OR status <> 'deleting'::app_status_enum)
         )",
    )
    .bind(app_id)
    .bind(allow_deleting)
    .fetch_one(&mut *tx)
    .await?;
    if !app_available {
        return Err(MutationLeaseError::AppUnavailable);
    }

    sqlx::query(
        "INSERT INTO app_mutation_leases(app_id)
         VALUES ($1)
         ON CONFLICT (app_id) DO NOTHING",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await?;
    let generation: Option<i64> = sqlx::query_scalar(
        "UPDATE app_mutation_leases
            SET generation = generation + 1,
                owner_token = $2,
                operation_kind = $3,
                operation_id = $4,
                locked_until = clock_timestamp()
                    + ($5::bigint * interval '1 second'),
                reclaim_after = clock_timestamp()
                    + (($5 + $6)::bigint * interval '1 second'),
                updated_at = clock_timestamp()
          WHERE app_id = $1
            AND (owner_token IS NULL OR reclaim_after <= clock_timestamp())
        RETURNING generation",
    )
    .bind(app_id)
    .bind(token)
    .bind(operation_kind)
    .bind(operation_id)
    .bind(LEASE_SECONDS)
    .bind(RECLAIM_QUARANTINE_SECONDS)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(generation) = generation else {
        return Err(MutationLeaseError::Busy);
    };

    let claimed_resources =
        claim_resource_rows(&mut tx, token, operation_kind, operation_id, resources).await?;
    tx.commit().await?;

    let (heartbeat, heartbeat_lost) = spawn_app_heartbeat(
        state.db.clone(),
        app_id,
        token,
        generation,
        claimed_resources.clone(),
        Duration::from_secs(HEARTBEAT_SECONDS),
        Duration::from_secs(RENEW_TIMEOUT_SECONDS),
    );

    Ok(AppMutationLease {
        pool: state.db.clone(),
        app_id,
        token,
        generation,
        resources: claimed_resources,
        heartbeat: Some(heartbeat),
        heartbeat_lost,
        _admission: admission,
    })
}

async fn claim_resource_rows(
    tx: &mut Transaction<'_, Postgres>,
    token: Uuid,
    operation_kind: &str,
    operation_id: Uuid,
    resources: Vec<ResourceFence>,
) -> Result<Vec<ClaimedResource>, MutationLeaseError> {
    let mut claimed_resources = Vec::with_capacity(resources.len());
    for fence in resources {
        sqlx::query(
            "INSERT INTO external_resource_mutation_leases(resource_scope, resource_key)
             VALUES ($1, $2)
             ON CONFLICT (resource_scope, resource_key) DO NOTHING",
        )
        .bind(&fence.scope)
        .bind(&fence.key)
        .execute(&mut **tx)
        .await?;
        let resource_generation: Option<i64> = sqlx::query_scalar(
            "UPDATE external_resource_mutation_leases
                SET generation = generation + 1,
                    owner_token = $3,
                    operation_kind = $4,
                    operation_id = $5,
                    locked_until = clock_timestamp()
                        + ($6::bigint * interval '1 second'),
                    reclaim_after = clock_timestamp()
                        + (($6 + $7)::bigint * interval '1 second'),
                    updated_at = clock_timestamp()
              WHERE resource_scope = $1
                AND resource_key = $2
                AND (owner_token IS NULL OR reclaim_after <= clock_timestamp())
            RETURNING generation",
        )
        .bind(&fence.scope)
        .bind(&fence.key)
        .bind(token)
        .bind(operation_kind)
        .bind(operation_id)
        .bind(LEASE_SECONDS)
        .bind(RECLAIM_QUARANTINE_SECONDS)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(resource_generation) = resource_generation else {
            return Err(MutationLeaseError::Busy);
        };
        claimed_resources.push(ClaimedResource {
            fence,
            generation: resource_generation,
        });
    }
    Ok(claimed_resources)
}

async fn renew(
    pool: &PgPool,
    app_id: Uuid,
    token: Uuid,
    generation: i64,
    resources: &[ClaimedResource],
) -> Result<(), MutationLeaseError> {
    let mut tx = pool.begin().await?;
    let app = sqlx::query(
        "UPDATE app_mutation_leases
            SET locked_until = clock_timestamp()
                    + ($4::bigint * interval '1 second'),
                reclaim_after = clock_timestamp()
                    + (($4 + $5)::bigint * interval '1 second'),
                updated_at = clock_timestamp()
          WHERE app_id = $1
            AND owner_token = $2
            AND generation = $3
            AND locked_until > clock_timestamp()",
    )
    .bind(app_id)
    .bind(token)
    .bind(generation)
    .bind(LEASE_SECONDS)
    .bind(RECLAIM_QUARANTINE_SECONDS)
    .execute(&mut *tx)
    .await?;
    if app.rows_affected() != 1 {
        return Err(MutationLeaseError::Lost);
    }
    for resource in resources {
        let result = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp()
                        + ($5::bigint * interval '1 second'),
                    reclaim_after = CASE
                        WHEN reclaim_after = 'infinity'::timestamptz
                            THEN reclaim_after
                        ELSE clock_timestamp()
                            + (($5 + $6)::bigint * interval '1 second')
                    END,
                    updated_at = clock_timestamp()
              WHERE resource_scope = $1
                AND resource_key = $2
                AND owner_token = $3
                AND generation = $4
                AND locked_until > clock_timestamp()",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .bind(LEASE_SECONDS)
        .bind(RECLAIM_QUARANTINE_SECONDS)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MutationLeaseError::Lost);
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn renew_resources(
    pool: &PgPool,
    token: Uuid,
    resources: &[ClaimedResource],
) -> Result<(), MutationLeaseError> {
    let mut tx = pool.begin().await?;
    for resource in resources {
        let result = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp()
                        + ($5::bigint * interval '1 second'),
                    reclaim_after = CASE
                        WHEN reclaim_after = 'infinity'::timestamptz
                            THEN reclaim_after
                        ELSE clock_timestamp()
                            + (($5 + $6)::bigint * interval '1 second')
                    END,
                    updated_at = clock_timestamp()
              WHERE resource_scope = $1
                AND resource_key = $2
                AND owner_token = $3
                AND generation = $4
                AND locked_until > clock_timestamp()",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .bind(LEASE_SECONDS)
        .bind(RECLAIM_QUARANTINE_SECONDS)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MutationLeaseError::Lost);
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn assert_current_resource_rows(
    tx: &mut Transaction<'_, Postgres>,
    token: Uuid,
    resources: &[ClaimedResource],
) -> Result<(), MutationLeaseError> {
    for resource in resources {
        let current: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM external_resource_mutation_leases
                  WHERE resource_scope = $1
                    AND resource_key = $2
                    AND owner_token = $3
                    AND generation = $4
                    AND locked_until > clock_timestamp()
             )",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .fetch_one(&mut **tx)
        .await?;
        if !current {
            return Err(MutationLeaseError::Lost);
        }
    }
    Ok(())
}

async fn clear_resource_rows(
    tx: &mut Transaction<'_, Postgres>,
    token: Uuid,
    resources: &[ClaimedResource],
) -> Result<(), MutationLeaseError> {
    for resource in resources {
        let result = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE resource_scope = $1
                AND resource_key = $2
                AND owner_token = $3
                AND generation = $4",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MutationLeaseError::Lost);
        }
    }
    Ok(())
}

async fn poison_resource_scope(
    tx: &mut Transaction<'_, Postgres>,
    token: Uuid,
    resources: &[ClaimedResource],
    resource_scope: &str,
) -> Result<usize, MutationLeaseError> {
    let mut retained = 0usize;
    for resource in resources
        .iter()
        .filter(|resource| resource.fence.scope == resource_scope)
    {
        let result = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET reclaim_after = 'infinity'::timestamptz,
                    updated_at = clock_timestamp()
              WHERE resource_scope = $1
                AND resource_key = $2
                AND owner_token = $3
                AND generation = $4",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(MutationLeaseError::Lost);
        }
        retained += 1;
    }
    Ok(retained)
}

async fn assert_current_rows(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    token: Uuid,
    generation: i64,
    resources: &[ClaimedResource],
) -> Result<(), MutationLeaseError> {
    let current: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM app_mutation_leases
              WHERE app_id = $1
                AND owner_token = $2
                AND generation = $3
                AND locked_until > clock_timestamp()
         )",
    )
    .bind(app_id)
    .bind(token)
    .bind(generation)
    .fetch_one(&mut **tx)
    .await?;
    if !current {
        return Err(MutationLeaseError::Lost);
    }
    for resource in resources {
        let current: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM external_resource_mutation_leases
                  WHERE resource_scope = $1
                    AND resource_key = $2
                    AND owner_token = $3
                    AND generation = $4
                    AND locked_until > clock_timestamp()
             )",
        )
        .bind(&resource.fence.scope)
        .bind(&resource.fence.key)
        .bind(token)
        .bind(resource.generation)
        .fetch_one(&mut **tx)
        .await?;
        if !current {
            return Err(MutationLeaseError::Lost);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::get};
    use serde_json::{Value, json};
    use sqlx::postgres::PgPoolOptions;
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::sync::{Mutex, Notify};

    fn test_app_mutation_lease(heartbeat_lost: watch::Receiver<bool>) -> AppMutationLease {
        AppMutationLease {
            pool: PgPoolOptions::new()
                .connect_lazy("postgresql://stack-size.invalid/enclava")
                .expect("lazy pool does not connect"),
            app_id: Uuid::nil(),
            token: Uuid::nil(),
            generation: 1,
            resources: Vec::new(),
            heartbeat: None,
            heartbeat_lost,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .expect("app admission permit"),
        }
    }

    fn test_resource_mutation_lease(
        heartbeat_lost: watch::Receiver<bool>,
    ) -> ResourceMutationLease {
        ResourceMutationLease {
            pool: PgPoolOptions::new()
                .connect_lazy("postgresql://stack-size.invalid/enclava")
                .expect("lazy pool does not connect"),
            token: Uuid::nil(),
            resources: Vec::new(),
            heartbeat: None,
            heartbeat_lost,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .expect("resource admission permit"),
        }
    }

    #[tokio::test]
    async fn provider_guard_does_not_duplicate_large_future_state() {
        fn large_provider() -> impl Future<Output = ()> + Send + 'static {
            let payload = [0_u8; 32 * 1024];
            async move {
                std::future::pending::<()>().await;
                std::hint::black_box(payload);
            }
        }

        let (_app_lost_tx, app_lost_rx) = watch::channel(false);
        let app_lease = test_app_mutation_lease(app_lost_rx);
        let (_resource_lost_tx, resource_lost_rx) = watch::channel(false);
        let resource_lease = test_resource_mutation_lease(resource_lost_rx);

        let (_helper_lost_tx, helper_lost_rx) = watch::channel(false);
        let provider = large_provider();
        let provider_size = std::mem::size_of_val(&provider);
        assert!(
            provider_size >= 32 * 1024,
            "size canary must retain its 32 KiB payload, got {provider_size}"
        );
        let helper_guard = guard_provider_future(helper_lost_rx, provider);
        let helper_size = std::mem::size_of_val(&helper_guard);
        let app_guard = app_lease.guard_provider(large_provider());
        let app_size = std::mem::size_of_val(&app_guard);
        let resource_guard = resource_lease.guard_provider(large_provider());
        let resource_size = std::mem::size_of_val(&resource_guard);

        fn assert_send<T: Send>(_: &T) {}
        assert_send(&helper_guard);
        assert_send(&app_guard);
        assert_send(&resource_guard);

        assert!(
            helper_size <= 4 * 1024 && app_size <= 4 * 1024 && resource_size <= 4 * 1024,
            "provider guard amplified {provider_size}-byte state: helper={helper_size}, app={app_size}, resource={resource_size}"
        );
    }

    #[tokio::test]
    async fn public_provider_guard_preserves_completion_and_cancellation() {
        let (_lost_tx, lost_rx) = watch::channel(false);
        let app_lease = test_app_mutation_lease(lost_rx);
        assert_eq!(
            app_lease
                .guard_provider(async { 7_u8 })
                .await
                .expect("provider completion passes through"),
            7
        );

        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (lost_tx, lost_rx) = watch::channel(false);
        let app_lease = test_app_mutation_lease(lost_rx);
        let entered = Arc::new(Notify::new());
        let provider_entered = entered.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let provider_dropped = dropped.clone();
        let guarded = app_lease.guard_provider(async move {
            let _drop_signal = DropSignal(provider_dropped);
            provider_entered.notify_one();
            std::future::pending::<()>().await;
        });
        let signal_loss = async {
            entered.notified().await;
            lost_tx.send(true).expect("signal lease loss");
        };
        let (guarded, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(guarded, signal_loss)
        })
        .await
        .expect("provider guard must react promptly to lease loss");
        assert!(matches!(guarded, Err(MutationLeaseError::Lost)));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[derive(Default)]
    struct DelayedCloudflare {
        records: Mutex<HashMap<String, Value>>,
        accepted: Notify,
        release: Notify,
        applied: Notify,
    }

    async fn list_delayed_cloudflare_records() -> Json<Value> {
        Json(json!({"success": true, "result": [], "errors": []}))
    }

    async fn create_delayed_cloudflare_record(
        State(state): State<Arc<DelayedCloudflare>>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        state.accepted.notify_one();
        let detached = state.clone();
        tokio::spawn(async move {
            detached.release.notified().await;
            detached
                .records
                .lock()
                .await
                .insert("accepted-record".to_string(), payload);
            detached.applied.notify_one();
        });

        // Model an accepted provider request whose response never reaches the
        // caller. The detached mutation above survives cancellation of this
        // response future.
        std::future::pending::<()>().await;
        unreachable!("pending provider response completed")
    }

    async fn delayed_cloudflare_server()
    -> (String, Arc<DelayedCloudflare>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(DelayedCloudflare::default());
        let app = Router::new()
            .route(
                "/zones/{zone_id}/dns_records",
                get(list_delayed_cloudflare_records).post(create_delayed_cloudflare_record),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind delayed Cloudflare");
        let address = listener.local_addr().expect("delayed Cloudflare address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve delayed Cloudflare");
        });
        (format!("http://{address}"), state, server)
    }

    async fn database_test_pool(max_connections: u32) -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&database_url)
            .await
            .expect("connect mutation lease test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate mutation lease test database");
        pool
    }

    async fn insert_app(pool: &PgPool, hostname: &str) -> (Uuid, Uuid) {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = app_id.simple().to_string();
        sqlx::query("INSERT INTO organizations(id, name, cust_slug) VALUES ($1, $2, $3)")
            .bind(org_id)
            .bind(format!("mutation-{suffix}"))
            .bind(&suffix[..8])
            .execute(pool)
            .await
            .expect("insert mutation organization");
        sqlx::query(
            "INSERT INTO apps(
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                 status, egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, 'password', $10, $11,
                 'running', '[]'::jsonb, 'restricted'
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("app-{}", &suffix[..12]))
        .bind(format!("ns-{}", &suffix[..12]))
        .bind(format!("instance-{suffix}"))
        .bind(format!("tenant-{suffix}"))
        .bind(format!("service-{suffix}"))
        .bind("owner-hash")
        .bind("identity-hash")
        .bind(hostname)
        .bind(format!("tee-{hostname}"))
        .execute(pool)
        .await
        .expect("insert mutation app");
        (org_id, app_id)
    }

    fn state_with_pool(pool: PgPool) -> AppState {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool;
        state
    }

    #[tokio::test]
    async fn pool_two_waiter_holds_no_connection_and_owner_can_renew() {
        let pool = database_test_pool(2).await;
        let (_, app_one) = insert_app(&pool, "pool-one.example.test").await;
        let (_, app_two) = insert_app(&pool, "pool-two.example.test").await;
        let state = std::sync::Arc::new(state_with_pool(pool.clone()));
        assert_eq!(crate::state::side_effect_admission_limit(&pool), 1);

        let first = claim(
            &state,
            app_one,
            "stalled_provider",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns("pool-one.example.test")],
        )
        .await
        .expect("claim first provider mutation");
        let waiter_state = state.clone();
        let waiter = tokio::spawn(async move {
            claim(
                &waiter_state,
                app_two,
                "queued_provider",
                Uuid::new_v4(),
                false,
                vec![ResourceFence::dns("pool-two.example.test")],
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            renew(
                &pool,
                first.app_id,
                first.token,
                first.generation,
                &first.resources,
            ),
        )
        .await
        .expect("reserved pool headroom keeps heartbeat live")
        .expect("renew first owner");
        let one: i32 = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sqlx::query_scalar("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("ordinary query is not pool-starved")
        .expect("ordinary query succeeds");
        assert_eq!(one, 1);

        first.finish().await.expect("release first mutation");
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("queued mutation enters after release")
            .expect("queued mutation task joins")
            .expect("queued mutation claims");
        second.finish().await.expect("release second mutation");
    }

    #[tokio::test]
    async fn hung_renew_cancels_provider_and_retains_reclaim_quarantine() {
        let pool = database_test_pool(2).await;
        let hostname = format!("hung-renew-{}.example.test", Uuid::new_v4().simple());
        let (_, app_id) = insert_app(&pool, &hostname).await;
        let state = state_with_pool(pool.clone());
        let mut owner = claim(
            &state,
            app_id,
            "hung_renew_provider",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("claim provider generation");
        owner.stop_heartbeat();

        // Model a pool/network stall: renewal cannot obtain a connection and
        // must time out rather than leaving the provider future alive.
        let connection_one = pool.acquire().await.expect("hold first connection");
        let connection_two = pool.acquire().await.expect("hold second connection");
        let (heartbeat, lost) = spawn_app_heartbeat(
            pool.clone(),
            owner.app_id,
            owner.token,
            owner.generation,
            owner.resources.clone(),
            Duration::from_millis(5),
            Duration::from_millis(20),
        );
        owner.heartbeat = Some(heartbeat);
        owner.heartbeat_lost = lost;

        let provider_completed = Arc::new(AtomicBool::new(false));
        let completed = provider_completed.clone();
        let guarded = owner
            .guard_provider(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                completed.store(true, Ordering::SeqCst);
            })
            .await;
        assert!(matches!(guarded, Err(MutationLeaseError::Lost)));
        assert!(!provider_completed.load(Ordering::SeqCst));
        drop(connection_two);
        drop(connection_one);
        drop(owner);

        let reclaim_after: bool = sqlx::query_scalar(
            "SELECT reclaim_after > clock_timestamp()
               FROM external_resource_mutation_leases
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .fetch_one(&pool)
        .await
        .expect("load retained provider quarantine");
        assert!(reclaim_after);
        let replacement = claim(
            &state,
            app_id,
            "replacement_provider",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect_err("replacement cannot overlap quarantined provider request");
        assert!(matches!(replacement, MutationLeaseError::Busy));

        sqlx::query(
            "UPDATE app_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE app_id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("advance app quarantine for replacement proof");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .execute(&pool)
        .await
        .expect("advance provider quarantine for replacement proof");
        let replacement = claim(
            &state,
            app_id,
            "replacement_after_quarantine",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("claim replacement after quarantine");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !provider_completed.load(Ordering::SeqCst),
            "canceled old provider future cannot issue a late write after replacement"
        );
        replacement.finish().await.expect("finish replacement");
    }

    #[tokio::test]
    async fn prearmed_dns_rejects_reuse_after_detached_provider_outlives_caller() {
        let pool = database_test_pool(4).await;
        let hostname = format!("detached-{}.example.test", Uuid::new_v4().simple());
        let (org_id, app_id) = insert_app(&pool, &hostname).await;
        let state = state_with_pool(pool.clone());
        let mut owner = claim(
            &state,
            app_id,
            "detached_dns_create",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("claim detached DNS generation");
        let owner_token = owner.token;
        let app_generation = owner.generation;
        let resource_generation = owner.resources[0].generation;
        owner
            .arm_resource_scope_until_reconciled("dns_hostname")
            .await
            .expect("poison hostname before provider request");

        let (base_url, provider, server) = delayed_cloudflare_server().await;
        let dns_config = crate::dns::DnsConfig {
            cloudflare_api_token: "fake-token".to_string(),
            cloudflare_api_base_url: base_url,
            cloudflare_zone_id: Some("zone-1".to_string()),
            cloudflare_zone_name: "example.test".to_string(),
            target: "192.0.2.44".to_string(),
            required: true,
        };
        let request_pool = pool.clone();
        let request_hostname = hostname.clone();
        let request = tokio::spawn(async move {
            crate::dns::ensure_dns_record(
                &request_pool,
                &reqwest::Client::new(),
                Some(&dns_config),
                app_id,
                &request_hostname,
                false,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), provider.accepted.notified())
            .await
            .expect("provider accepts old create");

        // Simulate process death after provider acceptance: the request future
        // is gone, but the fake provider's detached accepted work remains.
        request.abort();
        assert!(
            request
                .await
                .expect_err("request is canceled")
                .is_cancelled()
        );
        owner.stop_heartbeat();
        drop(owner);

        sqlx::query(
            "UPDATE app_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE app_id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("advance app reclaim boundary");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds'
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .execute(&pool)
        .await
        .expect("expire resource lease while preserving poison");
        let poisoned: bool = sqlx::query_scalar(
            "SELECT reclaim_after = 'infinity'::timestamptz
               FROM external_resource_mutation_leases
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .fetch_one(&pool)
        .await
        .expect("load pre-send DNS poison");
        assert!(poisoned);

        let inverse = claim(
            &state,
            app_id,
            "newer_dns_delete",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect_err("poison rejects newer inverse mutation after timed reclaim");
        assert!(matches!(inverse, MutationLeaseError::Busy));

        provider.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), provider.applied.notified())
            .await
            .expect("detached accepted provider write completes");
        let records = provider.records.lock().await;
        let record = records
            .get("accepted-record")
            .expect("detached create reached provider");
        assert_eq!(
            record.get("name").and_then(Value::as_str),
            Some(hostname.as_str())
        );
        assert_eq!(
            record.get("content").and_then(Value::as_str),
            Some("192.0.2.44")
        );
        drop(records);

        let still_rejected = claim(
            &state,
            app_id,
            "retry_dns_delete",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect_err("provider completion alone cannot authorize hostname reuse");
        assert!(matches!(still_rejected, MutationLeaseError::Busy));
        let persisted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM dns_records WHERE app_id = $1 AND hostname = $2)",
        )
        .bind(app_id)
        .bind(&hostname)
        .fetch_one(&pool)
        .await
        .expect("check canceled caller publication");
        assert!(!persisted, "canceled caller must not publish a provider ID");

        // Model the documented operator path only after the detached provider
        // is known quiescent: converge the exact provider record, then clear
        // the poison with the captured token/generation CAS. A stale incident
        // record cannot unpoison a later generation.
        provider.records.lock().await.remove("accepted-record");
        let cleared_resource = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE resource_scope = 'dns_hostname'
                AND resource_key = $1
                AND generation = $2
                AND owner_token = $3
                AND reclaim_after = 'infinity'::timestamptz
                AND locked_until <= clock_timestamp()",
        )
        .bind(&hostname)
        .bind(resource_generation)
        .bind(owner_token)
        .execute(&pool)
        .await
        .expect("operator clears reconciled DNS poison");
        assert_eq!(cleared_resource.rows_affected(), 1);
        let cleared_app = sqlx::query(
            "UPDATE app_mutation_leases AS app
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL,
                    updated_at = clock_timestamp()
              WHERE app.app_id = $1
                AND app.generation = $2
                AND app.owner_token = $3
                AND app.locked_until <= clock_timestamp()
                AND NOT EXISTS (
                    SELECT 1 FROM external_resource_mutation_leases AS resource
                     WHERE resource.owner_token = app.owner_token
                )",
        )
        .bind(app_id)
        .bind(app_generation)
        .bind(owner_token)
        .execute(&pool)
        .await
        .expect("operator clears reconciled app owner");
        assert_eq!(cleared_app.rows_affected(), 1);
        let reconciled = claim(
            &state,
            app_id,
            "post_operator_reconciliation",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("exact reconciliation permits a new generation");
        assert_eq!(reconciled.generation(), app_generation + 1);
        reconciled
            .finish()
            .await
            .expect("finish post-reconciliation generation");
        assert!(provider.records.lock().await.is_empty());
        server.abort();
        sqlx::query(
            "DELETE FROM external_resource_mutation_leases
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .execute(&pool)
        .await
        .expect("remove detached DNS poison fixture");
        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("remove detached DNS app fixture");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("remove detached DNS organization fixture");
    }

    #[tokio::test]
    async fn prearmed_kubernetes_namespace_survives_process_loss_and_rejects_reclaim() {
        let pool = database_test_pool(4).await;
        let namespace = format!("detached-kube-{}", Uuid::new_v4().simple());
        let hostname = format!("{namespace}.example.test");
        let (org_id, app_id) = insert_app(&pool, &hostname).await;
        sqlx::query("UPDATE apps SET namespace = $1 WHERE id = $2")
            .bind(&namespace)
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("set unique Kubernetes namespace fixture");
        let state = state_with_pool(pool.clone());
        let mut owner = claim(
            &state,
            app_id,
            "detached_kubernetes_apply",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::new("kubernetes_namespace", &namespace)],
        )
        .await
        .expect("claim Kubernetes namespace generation");
        let generation = owner.resources[0].generation;
        owner
            .arm_resource_scope_until_reconciled("kubernetes_namespace")
            .await
            .expect("arm namespace before first Kubernetes write");

        // Model API process loss after a detached Kubernetes handler accepted
        // the request: no Drop cleanup or elapsed deadline may authorize a
        // newer inverse generation while that handler can still complete.
        owner.stop_heartbeat();
        drop(owner);
        sqlx::query(
            "UPDATE app_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE app_id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("advance app reclaim boundary");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds'
              WHERE resource_scope = 'kubernetes_namespace'
                AND resource_key = $1",
        )
        .bind(&namespace)
        .execute(&pool)
        .await
        .expect("expire renewable namespace lease");

        let poisoned: (i64, bool) = sqlx::query_as(
            "SELECT generation,
                    reclaim_after = 'infinity'::timestamptz
               FROM external_resource_mutation_leases
              WHERE resource_scope = 'kubernetes_namespace'
                AND resource_key = $1",
        )
        .bind(&namespace)
        .fetch_one(&pool)
        .await
        .expect("load durable Kubernetes ambiguity fence");
        assert_eq!(poisoned, (generation, true));

        let inverse = claim(
            &state,
            app_id,
            "newer_kubernetes_delete",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::new("kubernetes_namespace", &namespace)],
        )
        .await
        .expect_err("infinite provider fence rejects timed namespace reclaim");
        assert!(matches!(inverse, MutationLeaseError::Busy));

        sqlx::query(
            "DELETE FROM external_resource_mutation_leases
              WHERE resource_scope = 'kubernetes_namespace'
                AND resource_key = $1",
        )
        .bind(&namespace)
        .execute(&pool)
        .await
        .expect("remove Kubernetes ambiguity fixture");
        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("remove Kubernetes app fixture");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("remove Kubernetes organization fixture");
    }

    #[tokio::test]
    async fn successful_publication_clears_prearmed_kubernetes_namespace_atomically() {
        let pool = database_test_pool(4).await;
        let namespace = format!("finished-kube-{}", Uuid::new_v4().simple());
        let hostname = format!("{namespace}.example.test");
        let (org_id, app_id) = insert_app(&pool, &hostname).await;
        let state = state_with_pool(pool.clone());
        let owner = claim(
            &state,
            app_id,
            "successful_kubernetes_apply",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::new("kubernetes_namespace", &namespace)],
        )
        .await
        .expect("claim Kubernetes namespace generation");
        owner
            .arm_resource_scope_until_reconciled("kubernetes_namespace")
            .await
            .expect("arm namespace before Kubernetes write");
        owner.finish().await.expect("publish and clear exact owner");

        let cleared: (bool, bool) = sqlx::query_as(
            "SELECT owner_token IS NULL, reclaim_after IS NULL
               FROM external_resource_mutation_leases
              WHERE resource_scope = 'kubernetes_namespace'
                AND resource_key = $1",
        )
        .bind(&namespace)
        .fetch_one(&pool)
        .await
        .expect("load cleared Kubernetes fence");
        assert_eq!(cleared, (true, true));

        sqlx::query(
            "DELETE FROM external_resource_mutation_leases
              WHERE resource_scope = 'kubernetes_namespace'
                AND resource_key = $1",
        )
        .bind(&namespace)
        .execute(&pool)
        .await
        .expect("remove successful Kubernetes fence fixture");
        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("remove successful Kubernetes app fixture");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("remove successful Kubernetes organization fixture");
    }

    #[tokio::test]
    async fn reclaim_quarantine_rejects_late_owner_then_allows_new_generation() {
        let pool = database_test_pool(4).await;
        let hostname = format!("reclaim-{}.example.test", Uuid::new_v4().simple());
        let (_, app_id) = insert_app(&pool, &hostname).await;
        let state = state_with_pool(pool.clone());
        let mut old = claim(
            &state,
            app_id,
            "old_provider_call",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("claim old generation");
        old.stop_heartbeat();
        sqlx::query(
            "UPDATE app_mutation_leases
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE app_id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("expire app deadline only");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '1 second'
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .execute(&pool)
        .await
        .expect("expire resource deadline only");

        let quarantined = claim(
            &state,
            app_id,
            "too_early_reclaim",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect_err("provider quarantine blocks immediate reclaim");
        assert!(matches!(quarantined, MutationLeaseError::Busy));

        sqlx::query(
            "UPDATE app_mutation_leases
                SET reclaim_after = clock_timestamp() - interval '1 second'
              WHERE app_id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("advance app reclaim boundary");
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET reclaim_after = clock_timestamp() - interval '1 second'
              WHERE resource_scope = 'dns_hostname' AND resource_key = $1",
        )
        .bind(&hostname)
        .execute(&pool)
        .await
        .expect("advance resource reclaim boundary");
        let next = claim(
            &state,
            app_id,
            "new_provider_call",
            Uuid::new_v4(),
            false,
            vec![ResourceFence::dns(&hostname)],
        )
        .await
        .expect("claim next generation after quarantine");
        assert_eq!(next.generation(), old.generation() + 1);
        let mut late_publish = pool.begin().await.expect("begin late publication");
        crate::deploy::lock_app_deployment_lane(&mut late_publish, app_id)
            .await
            .expect("lock late publication lane");
        assert!(matches!(
            old.assert_current_in_tx(&mut late_publish).await,
            Err(MutationLeaseError::Lost)
        ));
        late_publish
            .rollback()
            .await
            .expect("rollback late publisher");
        next.finish().await.expect("finish current generation");
    }

    #[tokio::test]
    async fn provider_tombstone_survives_app_delete_and_hostname_reuse() {
        let pool = database_test_pool(4).await;
        let (old_org, old_app) = insert_app(&pool, "reuse.example.test").await;
        let state = state_with_pool(pool.clone());
        let mut old = claim(
            &state,
            old_app,
            "old_app_delete",
            old_app,
            true,
            vec![ResourceFence::dns("reuse.example.test")],
        )
        .await
        .expect("claim old app resource");
        let old_token = old.token;
        let old_resource_generation = old.resources[0].generation;
        let mut deletion = pool.begin().await.expect("begin fenced app deletion");
        crate::deploy::lock_app_deployment_lane(&mut deletion, old_app)
            .await
            .expect("lock old app lane");
        old.finish_in_tx(&mut deletion)
            .await
            .expect("finish old app generation");
        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(old_app)
            .execute(&mut *deletion)
            .await
            .expect("delete old app");
        deletion.commit().await.expect("commit old app deletion");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(old_org)
            .execute(&pool)
            .await
            .expect("delete old organization");

        let (_, new_app) = insert_app(&pool, "reuse.example.test").await;
        let next = claim(
            &state,
            new_app,
            "new_app_create",
            new_app,
            false,
            vec![ResourceFence::dns("reuse.example.test")],
        )
        .await
        .expect("claim reused hostname for new app");
        assert_eq!(next.resources[0].generation, old_resource_generation + 1);
        let stale = sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET updated_at = clock_timestamp()
              WHERE resource_scope = 'dns_hostname'
                AND resource_key = $1
                AND owner_token = $2
                AND generation = $3",
        )
        .bind("reuse.example.test")
        .bind(old_token)
        .bind(old_resource_generation)
        .execute(&pool)
        .await
        .expect("attempt stale resource publication");
        assert_eq!(stale.rows_affected(), 0);
        next.finish().await.expect("finish reused hostname owner");
    }
}
