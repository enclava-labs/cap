//! Scoped KBS deployment-authorization publisher.

use std::time::Duration;

use enclava_common::kbs_authorization::authorization_digest;
use reqwest::{StatusCode, Url};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct KbsPublisherConfig {
    base_url: Url,
    bearer_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KbsPublisherError {
    #[error("KBS authorization publisher is not configured")]
    NotConfigured,
    #[error("invalid KBS authorization publisher configuration: {0}")]
    InvalidConfig(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("KBS authorization publisher request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KBS authorization publisher returned status {0}")]
    UpstreamStatus(StatusCode),
    #[error("KBS authorization read-back did not match published bytes")]
    ReadbackMismatch,
    #[error("KBS authorization publication state conflict")]
    StateConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveAuthorizationAuditAction {
    Confirm,
    Repair,
    Retry,
}

#[derive(Debug)]
enum ActiveAuthorizationReadback {
    Exact,
    Missing,
    Mismatch,
    Transport(reqwest::Error),
    Body(reqwest::Error),
    RetryableStatus(StatusCode),
    UpstreamStatus(StatusCode),
    Unauthorized(StatusCode),
    UnexpectedStatus(StatusCode),
}

impl ActiveAuthorizationReadback {
    fn action(&self) -> ActiveAuthorizationAuditAction {
        match self {
            Self::Exact => ActiveAuthorizationAuditAction::Confirm,
            Self::Missing | Self::Mismatch => ActiveAuthorizationAuditAction::Repair,
            Self::Transport(_)
            | Self::Body(_)
            | Self::RetryableStatus(_)
            | Self::UpstreamStatus(_)
            | Self::Unauthorized(_)
            | Self::UnexpectedStatus(_) => ActiveAuthorizationAuditAction::Retry,
        }
    }

    fn result_code(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Missing => "missing",
            Self::Mismatch => "mismatch",
            Self::Transport(_) => "transport_error",
            Self::Body(_) => "body_error",
            Self::RetryableStatus(_) => "retryable_status",
            Self::UpstreamStatus(_) => "upstream_error",
            Self::Unauthorized(_) => "unauthorized",
            Self::UnexpectedStatus(_) => "unexpected_status",
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PublishEvent {
    event_id: uuid::Uuid,
    descriptor_core_hash: Vec<u8>,
    payload_digest: Option<Vec<u8>>,
    payload_bytes: Option<Vec<u8>>,
    attempt_count: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct LifecycleEvent {
    event_id: uuid::Uuid,
    idempotency_key: String,
    descriptor_core_hash: Vec<u8>,
    operation: String,
    operation_reason: Option<String>,
    attempt_count: i32,
}

impl KbsPublisherConfig {
    pub fn new(base_url: String, bearer_token: String) -> Result<Self, KbsPublisherError> {
        let mut base_url = Url::parse(&base_url)
            .map_err(|err| KbsPublisherError::InvalidConfig(err.to_string()))?;
        if base_url.scheme() != "https" {
            return Err(KbsPublisherError::InvalidConfig(
                "publisher URL must use HTTPS".into(),
            ));
        }
        if bearer_token.trim().is_empty() {
            return Err(KbsPublisherError::InvalidConfig(
                "publisher bearer token is empty".into(),
            ));
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        Ok(Self {
            base_url,
            bearer_token,
        })
    }

    fn authorization_url(&self, descriptor_core_hash: &[u8]) -> Result<Url, KbsPublisherError> {
        if descriptor_core_hash.len() != 32 {
            return Err(KbsPublisherError::StateConflict);
        }
        self.base_url
            .join(&format!(
                "kbs/v0/deployment-authorization/{}",
                hex::encode(descriptor_core_hash)
            ))
            .map_err(|err| KbsPublisherError::InvalidConfig(err.to_string()))
    }
}

pub fn config_from_env() -> Result<Option<KbsPublisherConfig>, KbsPublisherError> {
    let Some(url) = std::env::var("KBS_AUTHORIZATION_PUBLISHER_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let token = std::env::var("KBS_AUTHORIZATION_PUBLISHER_TOKEN").map_err(|_| {
        KbsPublisherError::InvalidConfig(
            "KBS_AUTHORIZATION_PUBLISHER_TOKEN is required when publisher URL is set".into(),
        )
    })?;
    KbsPublisherConfig::new(url, token).map(Some)
}

/// Publish one descriptor's pending outbox event and activate it only after
/// exact-byte read-back. Concurrent workers safely skip an already claimed
/// event; an already-active authorization is idempotent success.
pub async fn publish_descriptor(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    descriptor_core_hash: &[u8; 32],
) -> Result<(), KbsPublisherError> {
    let event = sqlx::query_as::<_, PublishEvent>(
        "UPDATE kbs_authorization_outbox
         SET state = 'processing', updated_at = now()
         WHERE event_id = (
             SELECT event_id FROM kbs_authorization_outbox
             WHERE descriptor_core_hash = $1
               AND operation = 'publish'
               AND state IN ('pending', 'failed')
               AND next_attempt_at <= now()
             ORDER BY created_at
             FOR UPDATE SKIP LOCKED
             LIMIT 1
         )
         RETURNING event_id, descriptor_core_hash, payload_digest,
                   payload_bytes, attempt_count",
    )
    .bind(descriptor_core_hash.to_vec())
    .fetch_optional(pool)
    .await?;

    let Some(event) = event else {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM workload_artifact_authorizations
                 WHERE descriptor_core_hash = $1 AND publication_state = 'active'
                   AND terminally_revoked_at IS NULL
             )",
        )
        .bind(descriptor_core_hash.to_vec())
        .fetch_one(pool)
        .await?;
        return if active {
            Ok(())
        } else {
            Err(KbsPublisherError::StateConflict)
        };
    };
    let config = config.ok_or(KbsPublisherError::NotConfigured)?;

    let result = publish_and_read_back(client, config, &event).await;
    match result {
        Ok(()) => {
            crate::metrics::publication("success");
            mark_succeeded(pool, &event).await
        }
        Err(error) => {
            crate::metrics::publication(stable_error_code(&error));
            mark_failed(pool, &event, stable_error_code(&error)).await?;
            Err(error)
        }
    }
}

/// Bind a new rollback management deployment to an older signed descriptor.
/// Terminally revoked descriptors are never eligible; an already-active KBS
/// receipt only needs the new CAP activation, while an inactive receipt gets a
/// fresh idempotent publish event.
pub async fn prepare_rollback_activation(
    pool: &PgPool,
    management_deployment_id: uuid::Uuid,
    app_id: uuid::Uuid,
    target_deployment_id: uuid::Uuid,
) -> Result<Option<[u8; 32]>, KbsPublisherError> {
    #[derive(sqlx::FromRow)]
    struct Target {
        descriptor_core_hash: Vec<u8>,
        publication_state: String,
        authorization_digest: Vec<u8>,
        authorization_bytes: Vec<u8>,
        terminally_revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        kbs_tombstoned_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let mut tx = pool.begin().await?;
    let target = sqlx::query_as::<_, Target>(
        "SELECT wa.descriptor_core_hash, auth.publication_state,
                auth.authorization_digest, auth.authorization_bytes,
                auth.terminally_revoked_at, auth.kbs_tombstoned_at
         FROM workload_artifacts wa
         JOIN workload_artifact_authorizations auth
           ON auth.descriptor_core_hash = wa.descriptor_core_hash
         WHERE wa.app_id = $1 AND wa.deploy_id = $2
         FOR UPDATE OF auth",
    )
    .bind(app_id)
    .bind(target_deployment_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target) = target else {
        tx.commit().await?;
        return Ok(None);
    };
    if target.terminally_revoked_at.is_some()
        || target.kbs_tombstoned_at.is_some()
        || target.publication_state == "tombstoned"
        || target.descriptor_core_hash.len() != 32
        || target.authorization_digest.len() != 32
    {
        return Err(KbsPublisherError::StateConflict);
    }
    let descriptor_hash: [u8; 32] = target
        .descriptor_core_hash
        .as_slice()
        .try_into()
        .map_err(|_| KbsPublisherError::StateConflict)?;
    let activation_state = if target.publication_state == "active" {
        "active"
    } else {
        "pending_publication"
    };
    sqlx::query(
        "INSERT INTO deployment_artifact_activations (
             management_deployment_id, descriptor_core_hash, activation_state, activated_at
         ) VALUES ($1, $2, $3, CASE WHEN $3 = 'active' THEN now() ELSE NULL END)
         ON CONFLICT (management_deployment_id) DO NOTHING",
    )
    .bind(management_deployment_id)
    .bind(&target.descriptor_core_hash)
    .bind(activation_state)
    .execute(&mut *tx)
    .await?;
    if activation_state == "pending_publication" {
        sqlx::query(
            "INSERT INTO kbs_authorization_outbox (
                 idempotency_key, descriptor_core_hash, operation,
                 payload_digest, payload_bytes
             ) VALUES ($1, $2, 'publish', $3, $4)
             ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(format!(
            "publish:{}:{}",
            hex::encode(&target.authorization_digest),
            management_deployment_id
        ))
        .bind(&target.descriptor_core_hash)
        .bind(&target.authorization_digest)
        .bind(&target.authorization_bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(descriptor_hash))
}

/// Once a replacement deployment is healthy, remove every older management
/// activation for the app. Receipts shared with the new deployment stay
/// active; descriptors with no remaining activation are denied by CAP first
/// and then deactivated in KBS by the reconciler.
pub async fn supersede_old_activations(
    pool: &PgPool,
    app_id: uuid::Uuid,
    current_deployment_id: uuid::Uuid,
) -> Result<(), KbsPublisherError> {
    let mut tx = pool.begin().await?;
    let hashes: Vec<Vec<u8>> = sqlx::query_scalar(
        "UPDATE deployment_artifact_activations activation
         SET activation_state = 'inactive',
             deactivated_at = COALESCE(deactivated_at, now()), updated_at = now()
         FROM deployments deployment
         WHERE activation.management_deployment_id = deployment.id
           AND deployment.app_id = $1
           AND activation.management_deployment_id <> $2
           AND activation.activation_state = 'active'
         RETURNING activation.descriptor_core_hash",
    )
    .bind(app_id)
    .bind(current_deployment_id)
    .fetch_all(&mut *tx)
    .await?;

    for hash in hashes {
        let still_active: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM deployment_artifact_activations
             WHERE descriptor_core_hash = $1 AND activation_state = 'active')",
        )
        .bind(&hash)
        .fetch_one(&mut *tx)
        .await?;
        if still_active {
            continue;
        }
        sqlx::query(
            "UPDATE workload_artifact_authorizations
             SET publication_state = 'inactive',
                 deactivated_at = COALESCE(deactivated_at, now())
             WHERE descriptor_core_hash = $1 AND publication_state = 'active'
               AND terminally_revoked_at IS NULL",
        )
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO kbs_authorization_outbox (
                 idempotency_key, descriptor_core_hash, operation
             ) VALUES ($1, $2, 'deactivate')
             ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(format!(
            "supersede:{current_deployment_id}:{}",
            hex::encode(&hash)
        ))
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn deactivate_app(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    app_id: uuid::Uuid,
) -> Result<(), KbsPublisherError> {
    let hashes: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT auth.descriptor_core_hash
         FROM workload_artifact_authorizations auth
         JOIN workload_artifacts wa
           ON wa.descriptor_core_hash = auth.descriptor_core_hash
         WHERE wa.app_id = $1
           AND auth.publication_state IN ('pending', 'active', 'inactive')
           AND auth.terminally_revoked_at IS NULL",
    )
    .bind(app_id)
    .fetch_all(pool)
    .await?;
    if hashes.is_empty() {
        return Ok(());
    }
    for hash in hashes {
        deactivate_descriptor(pool, client, config, app_id, &hash).await?;
    }
    Ok(())
}

async fn deactivate_descriptor(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    app_id: uuid::Uuid,
    descriptor_hash: &[u8],
) -> Result<(), KbsPublisherError> {
    let idempotency_key = format!("deactivate:{}:{app_id}", hex::encode(descriptor_hash));
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO kbs_authorization_outbox (
             idempotency_key, descriptor_core_hash, operation
         ) VALUES ($1, $2, 'deactivate')
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(&idempotency_key)
    .bind(descriptor_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE workload_artifact_authorizations
         SET publication_state = 'inactive', deactivated_at = COALESCE(deactivated_at, now())
         WHERE descriptor_core_hash = $1
           AND publication_state <> 'tombstoned' AND terminally_revoked_at IS NULL",
    )
    .bind(descriptor_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE deployment_artifact_activations
         SET activation_state = 'inactive', deactivated_at = COALESCE(deactivated_at, now()),
             updated_at = now()
         WHERE descriptor_core_hash = $1
           AND activation_state IN ('pending_publication', 'active')",
    )
    .bind(descriptor_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let config = config.ok_or(KbsPublisherError::NotConfigured)?;
    process_lifecycle_event(pool, client, config, &idempotency_key).await
}

pub async fn terminally_revoke_descriptor(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    descriptor_hash: &[u8; 32],
    reason: &str,
) -> Result<(), KbsPublisherError> {
    let idempotency_key = enqueue_terminal_revoke_descriptor(pool, descriptor_hash, reason).await?;
    let config = config.ok_or(KbsPublisherError::NotConfigured)?;
    process_lifecycle_event(pool, client, config, &idempotency_key).await
}

/// Commit CAP's irreversible deny state and durable KBS revoke event without
/// waiting on either Kubernetes or KBS. Emergency callers use this first so
/// every later failure remains fail-closed and retryable.
pub async fn enqueue_terminal_revoke_descriptor(
    pool: &PgPool,
    descriptor_hash: &[u8; 32],
    reason: &str,
) -> Result<String, KbsPublisherError> {
    if reason.trim().is_empty() || reason.len() > 1024 {
        return Err(KbsPublisherError::StateConflict);
    }
    let idempotency_key = format!("revoke:{}", hex::encode(descriptor_hash));
    let mut tx = pool.begin().await?;
    mark_terminally_revoked(&mut tx, descriptor_hash, reason).await?;
    tx.commit().await?;
    Ok(idempotency_key)
}

/// Attempt the KBS half of a previously committed terminal revocation.
/// Failures remain in the outbox for the background reconciler.
pub async fn publish_terminal_revoke_descriptor(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    idempotency_key: &str,
) -> Result<(), KbsPublisherError> {
    let config = config.ok_or(KbsPublisherError::NotConfigured)?;
    process_lifecycle_event(pool, client, config, idempotency_key).await
}

/// Terminally revoke every receipt owned by an app. All CAP-side tombstones
/// are committed together before any KBS call, so partial upstream failure
/// cannot leave a sibling descriptor fetchable from CAP.
pub async fn terminally_revoke_app(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&KbsPublisherConfig>,
    app_id: uuid::Uuid,
    reason: &str,
) -> Result<(), KbsPublisherError> {
    if reason.trim().is_empty() || reason.len() > 1024 {
        return Err(KbsPublisherError::StateConflict);
    }
    let mut tx = pool.begin().await?;
    let hashes: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT auth.descriptor_core_hash
         FROM workload_artifact_authorizations auth
         JOIN workload_artifacts artifact
           ON artifact.descriptor_core_hash = auth.descriptor_core_hash
         WHERE artifact.app_id = $1
         ORDER BY auth.created_at
         FOR UPDATE OF auth, artifact",
    )
    .bind(app_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut descriptor_hashes = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| KbsPublisherError::StateConflict)?;
        mark_terminally_revoked(&mut tx, &hash, reason).await?;
        descriptor_hashes.push(hash);
    }
    tx.commit().await?;
    if descriptor_hashes.is_empty() {
        return Ok(());
    }
    let config = config.ok_or(KbsPublisherError::NotConfigured)?;
    for hash in descriptor_hashes {
        process_lifecycle_event(
            pool,
            client,
            config,
            &format!("revoke:{}", hex::encode(hash)),
        )
        .await?;
    }
    Ok(())
}

async fn mark_terminally_revoked(
    conn: &mut sqlx::PgConnection,
    descriptor_hash: &[u8; 32],
    reason: &str,
) -> Result<(), KbsPublisherError> {
    let idempotency_key = format!("revoke:{}", hex::encode(descriptor_hash));
    let inserted = sqlx::query(
        "INSERT INTO kbs_authorization_outbox (
             idempotency_key, descriptor_core_hash, operation, operation_reason
         ) VALUES ($1, $2, 'revoke', $3)
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(&idempotency_key)
    .bind(descriptor_hash.to_vec())
    .bind(reason)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        let existing_reason: Option<String> = sqlx::query_scalar(
            "SELECT operation_reason FROM kbs_authorization_outbox
             WHERE idempotency_key = $1",
        )
        .bind(&idempotency_key)
        .fetch_optional(&mut *conn)
        .await?
        .flatten();
        if existing_reason.as_deref() != Some(reason) {
            return Err(KbsPublisherError::StateConflict);
        }
    }
    let ledger = sqlx::query(
        "INSERT INTO kbs_authorization_tombstone_ledger (
             descriptor_core_hash, revocation_reason
         ) VALUES ($1, $2)
         ON CONFLICT (descriptor_core_hash) DO NOTHING",
    )
    .bind(descriptor_hash.to_vec())
    .bind(reason)
    .execute(&mut *conn)
    .await?;
    if ledger.rows_affected() == 0 {
        let existing_reason: String = sqlx::query_scalar(
            "SELECT revocation_reason FROM kbs_authorization_tombstone_ledger
             WHERE descriptor_core_hash = $1",
        )
        .bind(descriptor_hash.to_vec())
        .fetch_one(&mut *conn)
        .await?;
        if existing_reason != reason {
            return Err(KbsPublisherError::StateConflict);
        }
    }
    let revoked = sqlx::query(
        "UPDATE workload_artifact_authorizations
         SET publication_state = 'tombstoned', terminally_revoked_at = COALESCE(terminally_revoked_at, now()),
             deactivated_at = COALESCE(deactivated_at, now())
         WHERE descriptor_core_hash = $1",
    )
    .bind(descriptor_hash.to_vec())
    .execute(&mut *conn)
    .await?;
    if revoked.rows_affected() != 1 {
        return Err(KbsPublisherError::StateConflict);
    }
    sqlx::query(
        "UPDATE workload_artifacts
         SET terminally_revoked_at = COALESCE(terminally_revoked_at, now()),
             revocation_reason = COALESCE(revocation_reason, $2)
         WHERE descriptor_core_hash = $1",
    )
    .bind(descriptor_hash.to_vec())
    .bind(reason)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE deployment_artifact_activations
         SET activation_state = 'terminally_revoked',
             deactivated_at = COALESCE(deactivated_at, now()), updated_at = now()
         WHERE descriptor_core_hash = $1",
    )
    .bind(descriptor_hash.to_vec())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Retry every due outbox operation. CAP state is changed before deactivate or
/// revoke is attempted, so a KBS outage can delay cleanup but can never reopen
/// the CAP artifact endpoint.
pub async fn reconcile_due_events(
    pool: &PgPool,
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    limit: i64,
) -> Result<usize, KbsPublisherError> {
    let mut processed = expire_due_owner_rotations(pool, limit.clamp(1, 100)).await?;
    // A process may die after claiming an event but before recording success or
    // failure. Reclaim only leases older than the maximum publisher request
    // window; exact-byte/idempotency semantics make replay safe.
    sqlx::query(
        "UPDATE kbs_authorization_outbox
         SET state = 'failed', next_attempt_at = now(),
             last_error_code = 'publisher_lease_expired', updated_at = now()
         WHERE state = 'processing'
           AND updated_at < now() - interval '2 minutes'",
    )
    .execute(pool)
    .await?;
    let events: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT idempotency_key, operation, descriptor_core_hash
         FROM kbs_authorization_outbox
         WHERE state IN ('pending', 'failed') AND next_attempt_at <= now()
         ORDER BY created_at LIMIT $1",
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;
    for (key, operation, hash) in events {
        let result = if operation == "publish" {
            let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else {
                continue;
            };
            publish_descriptor(pool, client, Some(config), &hash).await
        } else {
            process_lifecycle_event(pool, client, config, &key).await
        };
        if let Err(error) = result {
            tracing::warn!(idempotency_key = %key, error = %error, "KBS authorization reconciliation attempt failed");
        }
        processed += 1;
    }
    processed += audit_active_authorizations(pool, client, config, limit.clamp(1, 100)).await?;
    processed += reconcile_terminal_tombstones(pool, client, config, limit.clamp(1, 100)).await?;
    crate::metrics::refresh_outbox(pool).await?;
    Ok(processed)
}

/// Reconcile one known outbox event without competing with unrelated rows.
/// This is useful for deterministic recovery tooling and integration tests;
/// the normal background worker should continue using `reconcile_due_events`.
#[doc(hidden)]
pub async fn reconcile_event_by_id(
    pool: &PgPool,
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    event_id: uuid::Uuid,
) -> Result<(), KbsPublisherError> {
    sqlx::query(
        "UPDATE kbs_authorization_outbox
         SET state = 'failed', next_attempt_at = now(),
             last_error_code = 'publisher_lease_expired', updated_at = now()
         WHERE event_id = $1 AND state = 'processing'
           AND updated_at < now() - interval '2 minutes'",
    )
    .bind(event_id)
    .execute(pool)
    .await?;

    let event: Option<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT idempotency_key, operation, descriptor_core_hash
         FROM kbs_authorization_outbox
         WHERE event_id = $1 AND state IN ('pending', 'failed')
           AND next_attempt_at <= now()",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    let Some((idempotency_key, operation, descriptor_hash)) = event else {
        return Err(KbsPublisherError::StateConflict);
    };

    if operation == "publish" {
        let descriptor_hash: [u8; 32] = descriptor_hash
            .try_into()
            .map_err(|_| KbsPublisherError::StateConflict)?;
        publish_descriptor(pool, client, Some(config), &descriptor_hash).await
    } else {
        process_lifecycle_event(pool, client, config, &idempotency_key).await
    }
}

/// End an approved owner-rotation grace window. Every authorization carrying
/// the retired owner fingerprint is made locally non-rollbackable in one
/// transaction before its terminal KBS revoke events are processed.
#[doc(hidden)]
pub async fn expire_due_owner_rotations(
    pool: &PgPool,
    limit: i64,
) -> Result<usize, KbsPublisherError> {
    #[derive(sqlx::FromRow)]
    struct Rotation {
        rotation_id: uuid::Uuid,
        org_id: uuid::Uuid,
        old_owner_version: i64,
        old_owner_pubkey_sha256: Vec<u8>,
        replacement_owner_version: i64,
    }

    let rotations = sqlx::query_as::<_, Rotation>(
        "SELECT rotation_id, org_id, old_owner_version,
                old_owner_pubkey_sha256, replacement_owner_version
         FROM org_owner_authorization_rotations
         WHERE completed_at IS NULL AND grace_expires_at <= now()
         ORDER BY grace_expires_at
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut processed = 0;
    for rotation in rotations {
        let mut tx = pool.begin().await?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT auth.descriptor_core_hash, auth.authorization_bytes
             FROM workload_artifact_authorizations auth
             JOIN workload_artifacts artifact
               ON artifact.descriptor_core_hash = auth.descriptor_core_hash
             JOIN apps app ON app.id = artifact.app_id
             WHERE app.org_id = $1 AND auth.terminally_revoked_at IS NULL
             FOR UPDATE OF auth, artifact",
        )
        .bind(rotation.org_id)
        .fetch_all(&mut *tx)
        .await?;
        for (hash, bytes) in rows {
            let authorization =
                enclava_common::kbs_authorization::DeploymentAuthorizationV1::parse_exact_json(
                    &bytes,
                )
                .map_err(|_| KbsPublisherError::StateConflict)?;
            if authorization.org_id != rotation.org_id
                || i64::try_from(authorization.org_owner_version).ok()
                    != Some(rotation.old_owner_version)
                || authorization.org_owner_pubkey_sha256.as_slice()
                    != rotation.old_owner_pubkey_sha256.as_slice()
            {
                continue;
            }
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| KbsPublisherError::StateConflict)?;
            mark_terminally_revoked(
                &mut tx,
                &hash,
                &format!(
                    "org_owner_rotation_to_version_{}",
                    rotation.replacement_owner_version
                ),
            )
            .await?;
        }
        sqlx::query(
            "UPDATE org_owner_authorization_rotations
             SET completed_at = now()
             WHERE rotation_id = $1 AND completed_at IS NULL",
        )
        .bind(rotation.rotation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        processed += 1;
    }
    Ok(processed)
}

/// Verify active CAP rows against exact KBS read-back. An authoritative missing
/// record or successful byte mismatch is denied in CAP before a fresh immutable
/// publish event is created. Transport, response-body, authentication,
/// rate-limit, and upstream failures are inconclusive: they preserve the last
/// confirmed active state and are retried on the normal audit cadence.
async fn audit_active_authorizations(
    pool: &PgPool,
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    limit: i64,
) -> Result<usize, KbsPublisherError> {
    #[derive(sqlx::FromRow)]
    struct Candidate {
        descriptor_core_hash: Vec<u8>,
        authorization_digest: Vec<u8>,
        authorization_bytes: Vec<u8>,
    }

    let candidates = sqlx::query_as::<_, Candidate>(
        "SELECT descriptor_core_hash, authorization_digest, authorization_bytes
         FROM workload_artifact_authorizations
         WHERE publication_state = 'active'
           AND terminally_revoked_at IS NULL
           AND (last_reconciled_at IS NULL
                OR last_reconciled_at < now() - interval '5 minutes')
         ORDER BY last_reconciled_at NULLS FIRST, created_at
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut processed = 0;
    for candidate in candidates {
        let hash: [u8; 32] = candidate
            .descriptor_core_hash
            .as_slice()
            .try_into()
            .map_err(|_| KbsPublisherError::StateConflict)?;
        let url = config.authorization_url(&hash)?;
        let outcome = read_back_active_authorization(
            client,
            url,
            &config.bearer_token,
            &candidate.authorization_bytes,
            &candidate.authorization_digest,
        )
        .await;
        let result_code = outcome.result_code();
        crate::metrics::authorization_reconciliation(result_code);
        match outcome.action() {
            ActiveAuthorizationAuditAction::Confirm => {
                mark_active_authorization_audit_attempt(pool, &candidate.descriptor_core_hash)
                    .await?;
            }
            ActiveAuthorizationAuditAction::Repair => {
                queue_restore_repair(
                    pool,
                    &hash,
                    &candidate.authorization_digest,
                    &candidate.authorization_bytes,
                )
                .await?;
                tracing::error!(
                    descriptor_core_hash = %hex::encode(hash),
                    result = result_code,
                    "KBS active authorization read-back drift; CAP denied it and queued repair"
                );
            }
            ActiveAuthorizationAuditAction::Retry => {
                // Recording the attempt keeps an outage from hot-looping every
                // five-second worker tick. The row remains active and becomes
                // eligible again on the normal five-minute audit cadence.
                mark_active_authorization_audit_attempt(pool, &candidate.descriptor_core_hash)
                    .await?;
                match &outcome {
                    ActiveAuthorizationReadback::Transport(error)
                    | ActiveAuthorizationReadback::Body(error) => {
                        tracing::warn!(
                            descriptor_core_hash = %hex::encode(hash),
                            result = result_code,
                            error = %error,
                            "KBS active authorization read-back was inconclusive; preserving active state"
                        );
                    }
                    ActiveAuthorizationReadback::RetryableStatus(status)
                    | ActiveAuthorizationReadback::UpstreamStatus(status) => {
                        tracing::warn!(
                            descriptor_core_hash = %hex::encode(hash),
                            result = result_code,
                            status = status.as_u16(),
                            "KBS active authorization read-back was inconclusive; preserving active state"
                        );
                    }
                    ActiveAuthorizationReadback::Unauthorized(status)
                    | ActiveAuthorizationReadback::UnexpectedStatus(status) => {
                        tracing::error!(
                            descriptor_core_hash = %hex::encode(hash),
                            result = result_code,
                            status = status.as_u16(),
                            "KBS active authorization audit requires operator attention; preserving last confirmed active state"
                        );
                    }
                    ActiveAuthorizationReadback::Exact
                    | ActiveAuthorizationReadback::Missing
                    | ActiveAuthorizationReadback::Mismatch => unreachable!("action is retry"),
                }
            }
        }
        processed += 1;
    }
    Ok(processed)
}

async fn read_back_active_authorization(
    client: &reqwest::Client,
    url: Url,
    bearer_token: &str,
    expected_bytes: &[u8],
    expected_digest: &[u8],
) -> ActiveAuthorizationReadback {
    let response = match client.get(url).bearer_auth(bearer_token).send().await {
        Ok(response) => response,
        Err(error) => return ActiveAuthorizationReadback::Transport(error),
    };
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ActiveAuthorizationReadback::Missing;
    }
    if matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) {
        return ActiveAuthorizationReadback::RetryableStatus(status);
    }
    if status.is_server_error() {
        return ActiveAuthorizationReadback::UpstreamStatus(status);
    }
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return ActiveAuthorizationReadback::Unauthorized(status);
    }
    if !status.is_success() {
        return ActiveAuthorizationReadback::UnexpectedStatus(status);
    }
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => return ActiveAuthorizationReadback::Body(error),
    };
    if bytes.as_ref() == expected_bytes
        && authorization_digest(&bytes).as_slice() == expected_digest
    {
        ActiveAuthorizationReadback::Exact
    } else {
        ActiveAuthorizationReadback::Mismatch
    }
}

async fn mark_active_authorization_audit_attempt(
    pool: &PgPool,
    descriptor_hash: &[u8],
) -> Result<(), KbsPublisherError> {
    sqlx::query(
        "UPDATE workload_artifact_authorizations
         SET last_reconciled_at = now()
         WHERE descriptor_core_hash = $1
           AND publication_state = 'active'
           AND terminally_revoked_at IS NULL",
    )
    .bind(descriptor_hash)
    .execute(pool)
    .await?;
    Ok(())
}

#[doc(hidden)]
pub async fn queue_restore_repair(
    pool: &PgPool,
    descriptor_hash: &[u8; 32],
    expected_digest: &[u8],
    authorization_bytes: &[u8],
) -> Result<(), KbsPublisherError> {
    if expected_digest.len() != 32
        || expected_digest != authorization_digest(authorization_bytes).as_slice()
    {
        return Err(KbsPublisherError::StateConflict);
    }
    let mut tx = pool.begin().await?;
    let denied = sqlx::query(
        "UPDATE workload_artifact_authorizations
         SET publication_state = 'pending', deactivated_at = now(),
             last_reconciled_at = now()
         WHERE descriptor_core_hash = $1
           AND publication_state = 'active'
           AND terminally_revoked_at IS NULL",
    )
    .bind(descriptor_hash.to_vec())
    .execute(&mut *tx)
    .await?;
    if denied.rows_affected() == 1 {
        sqlx::query(
            "UPDATE deployment_artifact_activations
             SET activation_state = 'pending_publication',
                 deactivated_at = now(), updated_at = now()
             WHERE descriptor_core_hash = $1
               AND activation_state = 'active'",
        )
        .bind(descriptor_hash.to_vec())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO kbs_authorization_outbox (
                 idempotency_key, descriptor_core_hash, operation,
                 payload_digest, payload_bytes
             ) VALUES ($1, $2, 'publish', $3, $4)",
        )
        .bind(format!(
            "restore-repair:{}:{}",
            hex::encode(descriptor_hash),
            uuid::Uuid::new_v4()
        ))
        .bind(descriptor_hash.to_vec())
        .bind(expected_digest)
        .bind(authorization_bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Replay every durable terminal tombstone periodically. The ledger survives
/// artifact purge, allowing CAP to repair a KBS restore that predates a
/// security revocation without retaining the full customer bundle.
async fn reconcile_terminal_tombstones(
    pool: &PgPool,
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    limit: i64,
) -> Result<usize, KbsPublisherError> {
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT descriptor_core_hash, revocation_reason
         FROM kbs_authorization_tombstone_ledger
         WHERE last_reconciled_at IS NULL
            OR last_reconciled_at < now() - interval '5 minutes'
         ORDER BY last_reconciled_at NULLS FIRST, created_at
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut processed = 0;
    for (hash, reason) in rows {
        let hash_array: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| KbsPublisherError::StateConflict)?;
        let mut url = config.authorization_url(&hash_array)?;
        url.set_path(&format!("{}/revoke", url.path().trim_end_matches('/')));
        let result = client
            .post(url)
            .bearer_auth(&config.bearer_token)
            .header(
                "Idempotency-Key",
                format!("reconcile-revoke:{}", hex::encode(hash_array)),
            )
            .json(&serde_json::json!({"reason": reason}))
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {
                sqlx::query(
                    "UPDATE kbs_authorization_tombstone_ledger
                     SET kbs_confirmed_at = COALESCE(kbs_confirmed_at, now()),
                         last_reconciled_at = now(), last_error_code = NULL,
                         updated_at = now()
                     WHERE descriptor_core_hash = $1",
                )
                .bind(&hash)
                .execute(pool)
                .await?;
            }
            Ok(response) => {
                sqlx::query(
                    "UPDATE kbs_authorization_tombstone_ledger
                     SET last_reconciled_at = now(),
                         last_error_code = 'publisher_upstream_error', updated_at = now()
                     WHERE descriptor_core_hash = $1",
                )
                .bind(&hash)
                .execute(pool)
                .await?;
                tracing::error!(
                    descriptor_core_hash = %hex::encode(&hash),
                    status = response.status().as_u16(),
                    "KBS terminal tombstone reconciliation failed"
                );
            }
            Err(error) => {
                sqlx::query(
                    "UPDATE kbs_authorization_tombstone_ledger
                     SET last_reconciled_at = now(),
                         last_error_code = 'publisher_transport_error', updated_at = now()
                     WHERE descriptor_core_hash = $1",
                )
                .bind(&hash)
                .execute(pool)
                .await?;
                tracing::error!(
                    descriptor_core_hash = %hex::encode(&hash),
                    error = %error,
                    "KBS terminal tombstone reconciliation transport failed"
                );
            }
        }
        processed += 1;
    }
    Ok(processed)
}

pub fn spawn_reconciler(
    pool: PgPool,
    client: reqwest::Client,
    config: KbsPublisherConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = reconcile_due_events(&pool, &client, &config, 50).await {
                tracing::error!(error = %error, "KBS authorization reconciler failed");
            }
        }
    })
}

async fn process_lifecycle_event(
    pool: &PgPool,
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    idempotency_key: &str,
) -> Result<(), KbsPublisherError> {
    let event = sqlx::query_as::<_, LifecycleEvent>(
        "UPDATE kbs_authorization_outbox
         SET state = 'processing', updated_at = now()
         WHERE event_id = (
             SELECT event_id FROM kbs_authorization_outbox
             WHERE idempotency_key = $1 AND operation IN ('deactivate', 'revoke')
               AND state IN ('pending', 'failed') AND next_attempt_at <= now()
             FOR UPDATE SKIP LOCKED
         )
         RETURNING event_id, idempotency_key, descriptor_core_hash, operation,
                   operation_reason, attempt_count",
    )
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    let Some(event) = event else {
        let succeeded: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM kbs_authorization_outbox
             WHERE idempotency_key = $1 AND state = 'succeeded')",
        )
        .bind(idempotency_key)
        .fetch_one(pool)
        .await?;
        return if succeeded {
            Ok(())
        } else {
            Err(KbsPublisherError::StateConflict)
        };
    };

    let result = send_lifecycle_event(client, config, &event).await;
    match result {
        Ok(()) => {
            if event.operation == "revoke" {
                sqlx::query(
                    "UPDATE workload_artifact_authorizations
                     SET kbs_tombstoned_at = COALESCE(kbs_tombstoned_at, now())
                     WHERE descriptor_core_hash = $1
                       AND publication_state = 'tombstoned'
                       AND terminally_revoked_at IS NOT NULL",
                )
                .bind(&event.descriptor_core_hash)
                .execute(pool)
                .await?;
                sqlx::query(
                    "UPDATE kbs_authorization_tombstone_ledger
                     SET kbs_confirmed_at = COALESCE(kbs_confirmed_at, now()),
                         last_reconciled_at = now(), last_error_code = NULL,
                         updated_at = now()
                     WHERE descriptor_core_hash = $1",
                )
                .bind(&event.descriptor_core_hash)
                .execute(pool)
                .await?;
            }
            sqlx::query(
                "UPDATE kbs_authorization_outbox SET state = 'succeeded',
                 completed_at = now(), updated_at = now(), last_error_code = NULL
                 WHERE event_id = $1 AND state = 'processing'",
            )
            .bind(event.event_id)
            .execute(pool)
            .await?;
            Ok(())
        }
        Err(error) => {
            mark_lifecycle_failed(pool, &event, stable_error_code(&error)).await?;
            Err(error)
        }
    }
}

async fn send_lifecycle_event(
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    event: &LifecycleEvent,
) -> Result<(), KbsPublisherError> {
    let mut url = config.authorization_url(&event.descriptor_core_hash)?;
    let request = match event.operation.as_str() {
        "deactivate" => client.delete(url),
        "revoke" => {
            url.set_path(&format!("{}/revoke", url.path().trim_end_matches('/')));
            let reason = event
                .operation_reason
                .as_deref()
                .ok_or(KbsPublisherError::StateConflict)?;
            client
                .post(url)
                .json(&serde_json::json!({"reason": reason}))
        }
        _ => return Err(KbsPublisherError::StateConflict),
    };
    let response = request
        .bearer_auth(&config.bearer_token)
        .header("Idempotency-Key", &event.idempotency_key)
        .send()
        .await?;
    if response.status().is_success()
        || (event.operation == "deactivate" && response.status() == StatusCode::NOT_FOUND)
    {
        Ok(())
    } else {
        Err(KbsPublisherError::UpstreamStatus(response.status()))
    }
}

async fn mark_lifecycle_failed(
    pool: &PgPool,
    event: &LifecycleEvent,
    code: &'static str,
) -> Result<(), KbsPublisherError> {
    let exponent = event.attempt_count.clamp(0, 8) as u32;
    let retry = Duration::from_secs(2_u64.pow(exponent).min(300));
    sqlx::query(
        "UPDATE kbs_authorization_outbox SET state = 'failed',
         attempt_count = attempt_count + 1,
         next_attempt_at = now() + ($2 * interval '1 second'),
         last_error_code = $3, updated_at = now()
         WHERE event_id = $1 AND state = 'processing'",
    )
    .bind(event.event_id)
    .bind(i64::try_from(retry.as_secs()).unwrap_or(300))
    .bind(code)
    .execute(pool)
    .await?;
    Ok(())
}

/// Product retention is currently zero after a completed app destroy. This
/// explicit cleanup is allowed only after every receipt has a confirmed KBS
/// terminal tombstone and all lifecycle outbox events have completed.
pub async fn purge_deactivated_app_artifacts(
    pool: &PgPool,
    app_id: uuid::Uuid,
) -> Result<(), KbsPublisherError> {
    let mut tx = pool.begin().await?;
    let unsafe_rows: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM workload_artifact_authorizations auth
         JOIN workload_artifacts wa
           ON wa.descriptor_core_hash = auth.descriptor_core_hash
         WHERE wa.app_id = $1
           AND (auth.publication_state <> 'tombstoned'
                OR auth.terminally_revoked_at IS NULL
                OR auth.kbs_tombstoned_at IS NULL)",
    )
    .bind(app_id)
    .fetch_one(&mut *tx)
    .await?;
    let unfinished_events: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM kbs_authorization_outbox event
         JOIN workload_artifacts wa
           ON wa.descriptor_core_hash = event.descriptor_core_hash
         WHERE wa.app_id = $1 AND event.state <> 'succeeded'",
    )
    .bind(app_id)
    .fetch_one(&mut *tx)
    .await?;
    if unsafe_rows != 0 || unfinished_events != 0 {
        return Err(KbsPublisherError::StateConflict);
    }
    sqlx::query(
        "DELETE FROM kbs_authorization_outbox
         WHERE descriptor_core_hash IN (
             SELECT descriptor_core_hash FROM workload_artifacts WHERE app_id = $1
         )",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM deployment_artifact_activations
         WHERE descriptor_core_hash IN (
             SELECT descriptor_core_hash FROM workload_artifacts WHERE app_id = $1
         )",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM workload_artifact_authorizations
         WHERE descriptor_core_hash IN (
             SELECT descriptor_core_hash FROM workload_artifacts WHERE app_id = $1
         )",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM workload_artifacts WHERE app_id = $1")
        .bind(app_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn publish_and_read_back(
    client: &reqwest::Client,
    config: &KbsPublisherConfig,
    event: &PublishEvent,
) -> Result<(), KbsPublisherError> {
    let bytes = event
        .payload_bytes
        .as_deref()
        .ok_or(KbsPublisherError::StateConflict)?;
    let digest = event
        .payload_digest
        .as_deref()
        .ok_or(KbsPublisherError::StateConflict)?;
    if bytes.len() > 16 * 1024
        || digest.len() != 32
        || authorization_digest(bytes).as_slice() != digest
        || event.descriptor_core_hash.len() != 32
    {
        return Err(KbsPublisherError::StateConflict);
    }
    let url = config.authorization_url(&event.descriptor_core_hash)?;
    let response = client
        .put(url.clone())
        .bearer_auth(&config.bearer_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            format!("publish:{}", hex::encode(digest)),
        )
        .body(bytes.to_vec())
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(KbsPublisherError::UpstreamStatus(response.status()));
    }

    let response = client
        .get(url)
        .bearer_auth(&config.bearer_token)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(KbsPublisherError::UpstreamStatus(response.status()));
    }
    let readback = response.bytes().await?;
    if readback.as_ref() != bytes || authorization_digest(&readback).as_slice() != digest {
        return Err(KbsPublisherError::ReadbackMismatch);
    }
    Ok(())
}

async fn mark_succeeded(pool: &PgPool, event: &PublishEvent) -> Result<(), KbsPublisherError> {
    let mut tx = pool.begin().await?;
    let deployment_still_eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM deployment_artifact_activations activation
             JOIN deployments deployment
               ON deployment.id = activation.management_deployment_id
             WHERE activation.descriptor_core_hash = $1
               AND activation.activation_state = 'pending_publication'
               AND deployment.status IN ('pending', 'applying', 'watching', 'healthy')
         )",
    )
    .bind(&event.descriptor_core_hash)
    .fetch_one(&mut *tx)
    .await?;
    if !deployment_still_eligible {
        sqlx::query(
            "UPDATE workload_artifact_authorizations
             SET publication_state = 'inactive',
                 published_at = COALESCE(published_at, now()),
                 deactivated_at = COALESCE(deactivated_at, now()),
                 publication_digest = $2
             WHERE descriptor_core_hash = $1
               AND publication_state IN ('pending', 'inactive')
               AND terminally_revoked_at IS NULL",
        )
        .bind(&event.descriptor_core_hash)
        .bind(event.payload_digest.as_deref())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE deployment_artifact_activations
             SET activation_state = 'inactive',
                 deactivated_at = COALESCE(deactivated_at, now()), updated_at = now()
             WHERE descriptor_core_hash = $1
               AND activation_state = 'pending_publication'",
        )
        .bind(&event.descriptor_core_hash)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO kbs_authorization_outbox (
                 idempotency_key, descriptor_core_hash, operation
             ) VALUES ($1, $2, 'deactivate')
             ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(format!("late-publish-deactivate:{}", event.event_id))
        .bind(&event.descriptor_core_hash)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE kbs_authorization_outbox
             SET state = 'succeeded', completed_at = now(), updated_at = now(),
                 last_error_code = NULL
             WHERE event_id = $1 AND state = 'processing'",
        )
        .bind(event.event_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(());
    }
    let authorization = sqlx::query(
        "UPDATE workload_artifact_authorizations
         SET publication_state = 'active', published_at = COALESCE(published_at, now()),
             deactivated_at = NULL, publication_digest = $2
         WHERE descriptor_core_hash = $1
           AND publication_state IN ('pending', 'inactive')
           AND terminally_revoked_at IS NULL
           AND kbs_tombstoned_at IS NULL",
    )
    .bind(&event.descriptor_core_hash)
    .bind(event.payload_digest.as_deref())
    .execute(&mut *tx)
    .await?;
    if authorization.rows_affected() != 1 {
        return Err(KbsPublisherError::StateConflict);
    }
    sqlx::query(
        "UPDATE deployment_artifact_activations
         SET activation_state = 'active', activated_at = COALESCE(activated_at, now()),
             deactivated_at = NULL, updated_at = now()
         WHERE descriptor_core_hash = $1 AND activation_state = 'pending_publication'",
    )
    .bind(&event.descriptor_core_hash)
    .execute(&mut *tx)
    .await?;
    let outbox = sqlx::query(
        "UPDATE kbs_authorization_outbox
         SET state = 'succeeded', completed_at = now(), updated_at = now(),
             last_error_code = NULL
         WHERE event_id = $1 AND state = 'processing'",
    )
    .bind(event.event_id)
    .execute(&mut *tx)
    .await?;
    if outbox.rows_affected() != 1 {
        return Err(KbsPublisherError::StateConflict);
    }
    tx.commit().await?;
    Ok(())
}

async fn mark_failed(
    pool: &PgPool,
    event: &PublishEvent,
    code: &'static str,
) -> Result<(), KbsPublisherError> {
    let exponent = event.attempt_count.clamp(0, 8) as u32;
    let retry = Duration::from_secs(2_u64.pow(exponent).min(300));
    sqlx::query(
        "UPDATE kbs_authorization_outbox
         SET state = 'failed', attempt_count = attempt_count + 1,
             next_attempt_at = now() + ($2 * interval '1 second'),
             last_error_code = $3, updated_at = now()
         WHERE event_id = $1 AND state = 'processing'",
    )
    .bind(event.event_id)
    .bind(i64::try_from(retry.as_secs()).unwrap_or(300))
    .bind(code)
    .execute(pool)
    .await?;
    Ok(())
}

pub fn stable_error_code(error: &KbsPublisherError) -> &'static str {
    match error {
        KbsPublisherError::NotConfigured => "publisher_unconfigured",
        KbsPublisherError::InvalidConfig(_) => "publisher_invalid_config",
        KbsPublisherError::Db(_) => "publisher_database_error",
        KbsPublisherError::Http(_) => "publisher_transport_error",
        KbsPublisherError::UpstreamStatus(StatusCode::CONFLICT) => "publisher_immutable_conflict",
        KbsPublisherError::UpstreamStatus(_) => "publisher_upstream_error",
        KbsPublisherError::ReadbackMismatch => "publisher_readback_mismatch",
        KbsPublisherError::StateConflict => "publisher_state_conflict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use tokio::task::JoinHandle;

    async fn spawn_readback_server(
        status: StatusCode,
        body: Vec<u8>,
        delay: Duration,
    ) -> (Url, JoinHandle<()>) {
        let app = Router::new().fallback(move || {
            let body = body.clone();
            async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                (status, body)
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            Url::parse(&format!("http://{address}/readback")).unwrap(),
            task,
        )
    }

    #[test]
    fn publisher_requires_https_and_nonempty_token() {
        assert!(KbsPublisherConfig::new("http://kbs.test/".into(), "token".into()).is_err());
        assert!(KbsPublisherConfig::new("https://kbs.test/".into(), "".into()).is_err());
        assert!(KbsPublisherConfig::new("https://kbs.test/".into(), "token".into()).is_ok());
    }

    #[test]
    fn publisher_url_is_fully_anchored_by_descriptor_hash() {
        let config =
            KbsPublisherConfig::new("https://kbs.test/internal/".into(), "token".into()).unwrap();
        assert_eq!(
            config.authorization_url(&[0xab; 32]).unwrap().as_str(),
            format!(
                "https://kbs.test/internal/kbs/v0/deployment-authorization/{}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn publisher_errors_have_bounded_stable_reason_codes() {
        assert_eq!(
            stable_error_code(&KbsPublisherError::ReadbackMismatch),
            "publisher_readback_mismatch"
        );
        assert_eq!(
            stable_error_code(&KbsPublisherError::UpstreamStatus(
                StatusCode::SERVICE_UNAVAILABLE
            )),
            "publisher_upstream_error"
        );
    }

    #[tokio::test]
    async fn active_audit_repairs_only_authoritative_absence_or_byte_drift() {
        let expected = b"exact authorization bytes".to_vec();
        let digest = authorization_digest(&expected);
        let cases = [
            (
                StatusCode::OK,
                expected.clone(),
                "exact",
                ActiveAuthorizationAuditAction::Confirm,
            ),
            (
                StatusCode::OK,
                b"different authorization bytes".to_vec(),
                "mismatch",
                ActiveAuthorizationAuditAction::Repair,
            ),
            (
                StatusCode::NOT_FOUND,
                Vec::new(),
                "missing",
                ActiveAuthorizationAuditAction::Repair,
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                Vec::new(),
                "retryable_status",
                ActiveAuthorizationAuditAction::Retry,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Vec::new(),
                "upstream_error",
                ActiveAuthorizationAuditAction::Retry,
            ),
            (
                StatusCode::UNAUTHORIZED,
                Vec::new(),
                "unauthorized",
                ActiveAuthorizationAuditAction::Retry,
            ),
            (
                StatusCode::BAD_REQUEST,
                Vec::new(),
                "unexpected_status",
                ActiveAuthorizationAuditAction::Retry,
            ),
        ];

        for (status, body, expected_result, expected_action) in cases {
            let (url, task) = spawn_readback_server(status, body, Duration::ZERO).await;
            let outcome = read_back_active_authorization(
                &reqwest::Client::new(),
                url,
                "publisher-token",
                &expected,
                &digest,
            )
            .await;
            task.abort();
            assert_eq!(outcome.result_code(), expected_result, "status {status}");
            assert_eq!(outcome.action(), expected_action, "status {status}");
        }
    }

    #[tokio::test]
    async fn active_audit_timeout_is_inconclusive_and_retried() {
        let expected = b"exact authorization bytes".to_vec();
        let digest = authorization_digest(&expected);
        let (url, task) =
            spawn_readback_server(StatusCode::OK, expected.clone(), Duration::from_millis(250))
                .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        let outcome =
            read_back_active_authorization(&client, url, "publisher-token", &expected, &digest)
                .await;
        task.abort();

        assert_eq!(outcome.result_code(), "transport_error");
        assert_eq!(outcome.action(), ActiveAuthorizationAuditAction::Retry);
    }
}
