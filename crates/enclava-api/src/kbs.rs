use std::collections::{BTreeMap, HashSet};

use chrono::Utc;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, PostParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use enclava_engine::manifest::cc_init_data::compute_cc_init_data;
use enclava_engine::types::ConfidentialApp;

const DEFAULT_SIGNED_POLICY_RETENTION: i64 = 6;
const DEFAULT_SIGNED_POLICY_MAX_BYTES: usize = 900 * 1024;
const SIGNED_POLICY_SET_SCHEMA_VERSION_V1: &str = "enclava-signed-policy-set-v1";
const SIGNED_POLICY_SET_SCHEMA_VERSION: &str = "enclava-signed-policy-set-v2";
const POLICY_AUTHORITY_EPOCH_ANNOTATION: &str = "enclava.dev/cap-authority-epoch";
const POLICY_GENERATION_ANNOTATION: &str = "enclava.dev/cap-policy-generation";
const POLICY_SHA256_ANNOTATION: &str = "enclava.dev/cap-policy-sha256";
const POLICY_PUBLICATION_TOKEN_ANNOTATION: &str = "enclava.dev/cap-policy-publication-token";
const KUBERNETES_CAS_ATTEMPTS: usize = 8;

#[derive(Debug, Clone)]
pub struct KbsPolicyConfig {
    pub namespace: String,
    pub configmap_name: String,
    pub policy_key: String,
    pub deployment_name: String,
    pub required: bool,
    pub signed_policy_retention: i64,
    pub signed_policy_max_bytes: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum KbsPolicyError {
    #[error("KBS policy management is required but not configured")]
    NotConfigured,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Kubernetes mutating request exceeded its 30 second deadline")]
    ProviderWriteTimeout,
    #[error("resource-policy ConfigMap is missing data key '{0}'")]
    MissingPolicyKey(String),
    #[error("resource-policy.rego does not contain an owner_resource_bindings block")]
    MissingOwnerBindingsBlock,
    #[error("resource-policy.rego does not contain a resource_bindings block")]
    MissingResourceBindingsBlock,
    #[error("failed to serialize signed policy artifact: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error(
        "signed policy artifact set exceeds byte budget: required_artifacts={required_artifacts}, policy_bytes={policy_bytes}, max_policy_bytes={max_policy_bytes}"
    )]
    SignedPolicyBudgetExceeded {
        required_artifacts: usize,
        policy_bytes: usize,
        max_policy_bytes: usize,
    },
    #[error("signed KBS policy generation metadata is invalid")]
    InvalidPolicyGeneration,
    #[error("signed KBS policy generation has conflicting content")]
    PolicyGenerationConflict,
    #[error("signed KBS policy artifact is not current deployment authority")]
    ArtifactNotCurrent,
    #[error("signed KBS policy compare-and-swap retries were exhausted")]
    PolicyCasExhausted,
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum KbsPolicyReconciliationError {
    #[error("durable KBS mutation fence failed")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
    #[error("KBS policy reconciliation failed")]
    Policy(#[from] KbsPolicyError),
}

async fn bounded_kube_write<F, T>(future: F) -> Result<T, KbsPolicyError>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| KbsPolicyError::ProviderWriteTimeout)?
        .map_err(KbsPolicyError::Kube)
}

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
struct KbsOwnerBinding {
    binding_key: String,
    repository: String,
    allowed_tags: Vec<String>,
    namespace: String,
    service_account: String,
    tenant_instance_identity_hash: String,
}

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
struct KbsTlsBinding {
    binding_key: String,
    repository: String,
    tag: String,
    image_digest: Option<String>,
    init_data_hash: Option<Vec<u8>>,
    signer_identity_subject: Option<String>,
    signer_identity_issuer: Option<String>,
    namespace: String,
    service_account: String,
    tenant_instance_identity_hash: String,
}

#[derive(Debug, Serialize)]
struct SignedPolicyArtifactSet<'a> {
    schema_version: &'static str,
    artifacts: Vec<CompactSignedPolicyArtifact<'a>>,
}

#[derive(Debug, Serialize)]
struct CompactSignedPolicyArtifact<'a> {
    metadata: &'a crate::signing_service::PolicyMetadata,
    rego_text: &'a str,
    rego_sha256: &'a str,
    agent_policy_sha256: &'a str,
    signature: &'a str,
    verify_pubkey_b64: &'a str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_keyring: Option<&'a serde_json::Value>,
}

impl<'a> From<&'a crate::signing_service::SignedPolicyArtifact>
    for CompactSignedPolicyArtifact<'a>
{
    fn from(artifact: &'a crate::signing_service::SignedPolicyArtifact) -> Self {
        Self {
            metadata: &artifact.metadata,
            rego_text: &artifact.rego_text,
            rego_sha256: &artifact.rego_sha256,
            agent_policy_sha256: &artifact.agent_policy_sha256,
            signature: &artifact.signature,
            verify_pubkey_b64: &artifact.verify_pubkey_b64,
            org_keyring: artifact.org_keyring.as_ref(),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SignedPolicyArtifactRow {
    signed_policy_artifact: serde_json::Value,
    required: bool,
}

#[derive(Debug, Clone)]
struct SignedPolicyArtifactCandidate {
    artifact: crate::signing_service::SignedPolicyArtifact,
    required: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SignedPolicyReconciliationRow {
    authority_epoch: Uuid,
    desired_generation: i64,
    applied_generation: i64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct AnnotatedPolicyGeneration<'a> {
    authority_epoch: Option<Uuid>,
    generation: i64,
    policy_hash: &'a str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum GenerationDecision {
    Replace,
    Current,
    Superseded,
}

pub async fn ensure_owner_binding(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app: &ConfidentialApp,
) -> Result<(), KbsPolicyError> {
    if config.is_none() {
        return Ok(());
    }

    let binding_key = app.owner_resource_type();
    sqlx::query(
        "INSERT INTO kbs_owner_bindings (
            app_id, binding_key, repository, allowed_tags, namespace, service_account,
            tenant_instance_identity_hash, deleted_at
         )
         VALUES ($1, $2, 'default', ARRAY['seed-encrypted', 'seed-sealed'], $3, $4, $5, NULL)
         ON CONFLICT (app_id) DO UPDATE
         SET binding_key = EXCLUDED.binding_key,
             repository = EXCLUDED.repository,
             allowed_tags = EXCLUDED.allowed_tags,
             namespace = EXCLUDED.namespace,
             service_account = EXCLUDED.service_account,
             tenant_instance_identity_hash = EXCLUDED.tenant_instance_identity_hash,
             deleted_at = NULL,
             updated_at = now()",
    )
    .bind(app.app_id)
    .bind(&binding_key)
    .bind(&app.namespace)
    .bind(&app.service_account)
    .bind(&app.tenant_instance_identity_hash)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn ensure_tls_binding(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app: &ConfidentialApp,
) -> Result<(), KbsPolicyError> {
    if config.is_none() {
        return Ok(());
    }

    let binding_key = app.tls_resource_type();
    let primary = app
        .primary_container()
        .expect("app must have a primary container");
    let (_encoded, init_data_hash_hex) = compute_cc_init_data(app);
    let init_data_hash =
        hex::decode(&init_data_hash_hex).expect("cc_init_data hash must be valid hex");
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
            app_id, binding_key, repository, tag, namespace, service_account,
            tenant_instance_identity_hash, image_digest, init_data_hash,
            signer_identity_subject, signer_identity_issuer, deleted_at
         )
         VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5, $6, $7, $8, $9, NULL)
         ON CONFLICT (app_id) DO UPDATE
         SET binding_key = EXCLUDED.binding_key,
             repository = EXCLUDED.repository,
             tag = EXCLUDED.tag,
             namespace = EXCLUDED.namespace,
             service_account = EXCLUDED.service_account,
             tenant_instance_identity_hash = EXCLUDED.tenant_instance_identity_hash,
             image_digest = EXCLUDED.image_digest,
             init_data_hash = EXCLUDED.init_data_hash,
             signer_identity_subject = EXCLUDED.signer_identity_subject,
             signer_identity_issuer = EXCLUDED.signer_identity_issuer,
             deleted_at = NULL,
             updated_at = now()",
    )
    .bind(app.app_id)
    .bind(&binding_key)
    .bind(&app.namespace)
    .bind(&app.service_account)
    .bind(&app.tenant_instance_identity_hash)
    .bind(primary.image.digest_ref())
    .bind(init_data_hash)
    .bind(app.signer_identity_subject.as_deref())
    .bind(app.signer_identity_issuer.as_deref())
    .execute(db)
    .await?;

    Ok(())
}

pub async fn soft_delete_owner_binding(db: &PgPool, app_id: Uuid) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_owner_bindings
         SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
         WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn soft_delete_tls_binding(
    db: &PgPool,
    _config: Option<&KbsPolicyConfig>,
    app_id: Uuid,
) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_tls_bindings
         SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
         WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn reconcile_policy(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Err(KbsPolicyError::NotConfigured);
    };

    let client = kube::Client::try_default().await?;
    if signed_policy_mode_active(db).await? {
        tracing::info!(
            namespace = %config.namespace,
            configmap = %config.configmap_name,
            "durable signed KBS authority supersedes legacy marker reconciliation"
        );
        return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
            .await;
    }

    let bindings: Vec<KbsOwnerBinding> = sqlx::query_as(
        "SELECT binding_key, repository, allowed_tags, namespace, service_account,
                tenant_instance_identity_hash
         FROM kbs_owner_bindings
         WHERE deleted_at IS NULL
         ORDER BY binding_key",
    )
    .fetch_all(db)
    .await?;
    let tls_bindings: Vec<KbsTlsBinding> = sqlx::query_as(
        "SELECT binding_key, repository, tag, namespace, service_account,
                tenant_instance_identity_hash, image_digest, init_data_hash,
                signer_identity_subject, signer_identity_issuer
         FROM kbs_tls_bindings
         WHERE deleted_at IS NULL
         ORDER BY binding_key",
    )
    .fetch_all(db)
    .await?;

    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        // Recheck on every retry. A signed acceptance that commits after the
        // initial read must fence this legacy writer before it can retry a
        // resourceVersion conflict with stale Rego.
        if signed_policy_mode_active(db).await? {
            return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
                .await;
        }

        let mut configmap = cm_api.get(&config.configmap_name).await?;
        let current_policy = configmap
            .data
            .as_ref()
            .and_then(|data| data.get(&config.policy_key))
            .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
        if is_signed_policy_artifact_body(current_policy) {
            tracing::info!(
                namespace = %config.namespace,
                configmap = %config.configmap_name,
                "bootstrapping durable authority from an existing signed Trustee policy"
            );
            let mut tx = db.begin().await?;
            enqueue_signed_policy_bootstrap_if_idle(&mut tx).await?;
            tx.commit().await?;
            return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
                .await;
        }
        let next_policy = replace_tls_resource_bindings_block(current_policy, &tls_bindings)?;
        let next_policy = replace_owner_bindings_block(&next_policy, &bindings)?;
        if next_policy == *current_policy {
            return Ok(());
        }

        configmap
            .data
            .get_or_insert_with(BTreeMap::new)
            .insert(config.policy_key.clone(), next_policy);
        match bounded_kube_write(cm_api.replace(
            &config.configmap_name,
            &PostParams::default(),
            &configmap,
        ))
        .await
        {
            Ok(_) => {
                // If signed authority committed after the ConfigMap CAS, let
                // it repair the brief legacy write before this call returns.
                if signed_policy_mode_active(db).await? {
                    return reconcile_pending_signed_policy_artifacts_with_client(
                        db, config, None, client,
                    )
                    .await;
                }
                restart_trustee_deployment(client, config).await?;
                return Ok(());
            }
            Err(KbsPolicyError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

/// Enqueue a signed-policy generation in the caller's authority transaction.
/// Use this for a signed deployment acceptance or any other transition known
/// to operate in signed-policy mode.
pub async fn enqueue_signed_policy_reconciliation(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<i64, KbsPolicyError> {
    let generation: i64 = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation + 1,
                updated_at = clock_timestamp()
          WHERE singleton
        RETURNING desired_generation",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(generation)
}

/// Enqueue revocation only when CAP has entered signed-policy mode.  Call this
/// before deleting the final app/artifact row so the durable intent cannot be
/// mistaken for an unsigned-only installation.
pub async fn enqueue_signed_policy_revocation_if_active(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<i64>, KbsPolicyError> {
    let generation = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation + 1,
                updated_at = clock_timestamp()
          WHERE singleton
            AND (
                desired_generation > 0
                OR EXISTS (SELECT 1 FROM workload_artifacts)
            )
        RETURNING desired_generation",
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(generation)
}

async fn enqueue_signed_policy_bootstrap_if_idle(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<bool, KbsPolicyError> {
    let result = sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1,
                updated_at = clock_timestamp()
          WHERE singleton
            AND desired_generation = 0",
    )
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn load_signed_policy_reconciliation(
    db: &PgPool,
) -> Result<SignedPolicyReconciliationRow, KbsPolicyError> {
    Ok(sqlx::query_as(
        "SELECT authority.authority_epoch,
                reconciliation.desired_generation,
                reconciliation.applied_generation
           FROM kbs_signed_policy_reconciliation AS reconciliation
           CROSS JOIN cap_runtime_authority AS authority
          WHERE reconciliation.singleton
            AND authority.singleton",
    )
    .fetch_one(db)
    .await?)
}

async fn signed_policy_mode_active(db: &PgPool) -> Result<bool, KbsPolicyError> {
    Ok(sqlx::query_scalar(
        "SELECT desired_generation > 0
           FROM kbs_signed_policy_reconciliation
          WHERE singleton",
    )
    .fetch_one(db)
    .await?)
}

/// Select policy authority from the latest operation generation, not from the
/// historical deployment that owns an artifact.  A rollback therefore makes
/// its exact source artifact required.  Apps whose latest operation is failed,
/// unsigned, stopped, or deleting contribute no retained authorization.
async fn load_signed_policy_candidates(
    db: &PgPool,
    retention: i64,
) -> Result<Vec<SignedPolicyArtifactCandidate>, KbsPolicyError> {
    let rows: Vec<SignedPolicyArtifactRow> = sqlx::query_as(
        r#"
        WITH ranked_job_operations AS (
            SELECT
                job.deployment_id,
                job.app_id,
                job.generation,
                job.artifact_deployment_id,
                job.artifact_descriptor_core_hash,
                job.state AS job_state,
                deployment.status::text AS deployment_status,
                app.status::text AS app_status,
                ROW_NUMBER() OVER (
                    PARTITION BY job.app_id
                    ORDER BY job.generation DESC
                ) AS current_operation_rank
            FROM deployment_apply_jobs AS job
            JOIN deployments AS deployment
              ON deployment.id = job.deployment_id
             AND deployment.app_id = job.app_id
             AND deployment.org_id = job.org_id
            JOIN apps AS app ON app.id = job.app_id
        ),
        eligible_current_job_operations AS (
            SELECT *
              FROM ranked_job_operations
             WHERE current_operation_rank = 1
               AND app_status IN ('creating', 'running')
               AND deployment_status IN ('pending', 'applying', 'watching', 'healthy')
               AND job_state IN ('setup_pending', 'setting_up', 'pending', 'running', 'completed')
               AND artifact_deployment_id IS NOT NULL
               AND artifact_descriptor_core_hash IS NOT NULL
               AND EXISTS (
                   SELECT 1
                     FROM workload_artifacts AS current_artifact
                    WHERE current_artifact.app_id = ranked_job_operations.app_id
                      AND current_artifact.deploy_id = artifact_deployment_id
                      AND current_artifact.descriptor_core_hash
                          = artifact_descriptor_core_hash
               )
        ),
        job_artifact_candidates AS (
            SELECT DISTINCT ON (current.app_id, artifact.descriptor_core_hash)
                current.app_id,
                historical.generation AS operation_generation,
                artifact.created_at AS artifact_created_at,
                artifact.descriptor_core_hash,
                artifact.signed_policy_artifact,
                (
                    historical.artifact_deployment_id = current.artifact_deployment_id
                    AND historical.artifact_descriptor_core_hash
                        = current.artifact_descriptor_core_hash
                ) AS required
            FROM eligible_current_job_operations AS current
            JOIN deployment_apply_jobs AS historical
              ON historical.app_id = current.app_id
            JOIN deployments AS historical_deployment
              ON historical_deployment.id = historical.deployment_id
             AND historical_deployment.app_id = historical.app_id
             AND historical_deployment.status::text
                 IN ('pending', 'applying', 'watching', 'healthy')
            JOIN workload_artifacts AS artifact
              ON artifact.app_id = historical.app_id
             AND artifact.deploy_id = historical.artifact_deployment_id
             AND artifact.descriptor_core_hash
                 = historical.artifact_descriptor_core_hash
            ORDER BY
                current.app_id,
                artifact.descriptor_core_hash,
                historical.generation DESC
        ),
        ranked_job_artifacts AS (
            SELECT
                signed_policy_artifact,
                required,
                operation_generation,
                artifact_created_at,
                descriptor_core_hash,
                ROW_NUMBER() OVER (
                    PARTITION BY app_id
                    ORDER BY required DESC,
                             operation_generation DESC,
                             artifact_created_at DESC,
                             descriptor_core_hash
                ) AS app_artifact_rank
            FROM job_artifact_candidates
        ),
        ranked_legacy_operations AS (
            SELECT
                deployment.id AS deployment_id,
                deployment.app_id,
                deployment.status::text AS deployment_status,
                app.status::text AS app_status,
                deployment.created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY deployment.app_id
                    ORDER BY deployment.created_at DESC, deployment.id DESC
                ) AS current_operation_rank
            FROM deployments AS deployment
            JOIN apps AS app ON app.id = deployment.app_id
            WHERE NOT EXISTS (
                SELECT 1
                  FROM deployment_apply_jobs AS any_job
                 WHERE any_job.app_id = deployment.app_id
            )
        ),
        legacy_artifacts AS (
            SELECT
                artifact.signed_policy_artifact,
                true AS required,
                NULL::bigint AS operation_generation,
                artifact.created_at AS artifact_created_at,
                artifact.descriptor_core_hash,
                1::bigint AS app_artifact_rank
            FROM ranked_legacy_operations AS legacy
            JOIN workload_artifacts AS artifact
              ON artifact.app_id = legacy.app_id
             AND artifact.deploy_id = legacy.deployment_id
            WHERE legacy.current_operation_rank = 1
              AND legacy.app_status IN ('creating', 'running')
              AND legacy.deployment_status = 'healthy'
        ),
        selected AS (
            SELECT *
              FROM ranked_job_artifacts
             WHERE app_artifact_rank <= $1
            UNION ALL
            SELECT * FROM legacy_artifacts
        )
        SELECT signed_policy_artifact, required
          FROM selected
         ORDER BY required DESC,
                  app_artifact_rank ASC,
                  operation_generation DESC NULLS LAST,
                  artifact_created_at DESC,
                  descriptor_core_hash
        "#,
    )
    .bind(retention)
    .fetch_all(db)
    .await?;

    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row.signed_policy_artifact)
                .map(|artifact| SignedPolicyArtifactCandidate {
                    artifact,
                    required: row.required,
                })
                .map_err(KbsPolicyError::Serialize)
        })
        .collect()
}

pub async fn reconcile_signed_policy_artifacts(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    extra_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Err(KbsPolicyError::NotConfigured);
    };

    let mut tx = db.begin().await?;
    enqueue_signed_policy_reconciliation(&mut tx).await?;
    tx.commit().await?;
    reconcile_pending_signed_policy_artifacts_inner(db, config, extra_artifact).await
}

/// Converge every currently pending desired generation.  This is safe to call
/// periodically and after a process restart; Kubernetes resourceVersion plus
/// monotonic generation annotations fence late older writers.
pub async fn reconcile_pending_signed_policy_artifacts(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Err(KbsPolicyError::NotConfigured);
    };
    reconcile_pending_signed_policy_artifacts_inner(db, config, None).await
}

/// Recover a committed desired generation after process or provider failure.
/// The resource-only lease is shared with app apply/delete paths, so this loop
/// also works after the final app row and its artifacts have cascaded away.
pub async fn reconcile_signed_policy_once(
    state: &crate::state::AppState,
) -> Result<(), KbsPolicyReconciliationError> {
    if state.kbs_policy.is_none() {
        return Ok(());
    }
    let lease = crate::mutation_leases::claim_resources(
        state,
        "kbs_policy_reconcile",
        Uuid::new_v4(),
        vec![crate::mutation_leases::ResourceFence::kbs_policy()],
    )
    .await?;
    lease
        .guard_provider(reconcile_pending_signed_policy_artifacts(
            &state.db,
            state.kbs_policy.as_ref(),
        ))
        .await??;
    lease.finish().await?;
    Ok(())
}

pub fn spawn_signed_policy_reconciler(state: crate::state::AppState) {
    if state.kbs_policy.is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            match reconcile_signed_policy_once(&state).await {
                Ok(()) => {}
                Err(KbsPolicyReconciliationError::Mutation(
                    crate::mutation_leases::MutationLeaseError::Busy,
                )) => {}
                Err(KbsPolicyReconciliationError::Mutation(_)) => tracing::warn!(
                    error_code = "kbs_policy_fence_unavailable",
                    "could not claim durable global KBS reconciliation"
                ),
                Err(KbsPolicyReconciliationError::Policy(_)) => tracing::warn!(
                    error_code = "kbs_policy_reconciliation_failed",
                    "durable global KBS policy reconciliation remains pending"
                ),
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn reconcile_pending_signed_policy_artifacts_inner(
    db: &PgPool,
    config: &KbsPolicyConfig,
    expected_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
) -> Result<(), KbsPolicyError> {
    let client = kube::Client::try_default().await?;
    reconcile_pending_signed_policy_artifacts_with_client(db, config, expected_artifact, client)
        .await
}

async fn reconcile_pending_signed_policy_artifacts_with_client(
    db: &PgPool,
    config: &KbsPolicyConfig,
    expected_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
    client: kube::Client,
) -> Result<(), KbsPolicyError> {
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        let state = load_signed_policy_reconciliation(db).await?;
        if state.desired_generation == 0 {
            // A pre-0041 installation may have deleted every artifact while a
            // stale signed policy remained live in Trustee. Do not convert a
            // genuine legacy Rego install, but durably enter signed mode when
            // the current body itself proves that signed authority existed.
            let configmap = cm_api.get(&config.configmap_name).await?;
            let current_policy = configmap
                .data
                .as_ref()
                .and_then(|data| data.get(&config.policy_key))
                .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
            if is_signed_policy_artifact_body(current_policy) {
                let mut tx = db.begin().await?;
                let bootstrapped = enqueue_signed_policy_bootstrap_if_idle(&mut tx).await?;
                tx.commit().await?;
                if bootstrapped {
                    tracing::warn!(
                        namespace = %config.namespace,
                        configmap = %config.configmap_name,
                        "recovering stale signed KBS authority into durable reconciliation"
                    );
                }
                continue;
            }
            // An acceptance may have committed while Kubernetes was read.
            // Recheck before deciding this is a genuine unsigned-only install.
            if signed_policy_mode_active(db).await? {
                continue;
            }
            return Ok(());
        }
        let generation = state.desired_generation;
        let authority_epoch = state.authority_epoch;
        let previously_applied = state.applied_generation >= generation;
        let candidates = load_signed_policy_candidates(db, config.signed_policy_retention).await?;
        if let Some(expected) = expected_artifact
            && !candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == expected.metadata.descriptor_core_hash
            })
        {
            return Err(KbsPolicyError::ArtifactNotCurrent);
        }
        let candidate_count = candidates.len();
        let artifacts = select_signed_policy_artifacts_for_policy_body(
            candidates,
            config.signed_policy_max_bytes,
        )?;
        let next_policy = signed_policy_artifact_policy_body(&artifacts)?;
        let policy_sha256 = Sha256::digest(next_policy.as_bytes()).to_vec();
        let policy_sha256_hex = hex::encode(&policy_sha256);

        tracing::info!(
            policy_generation = generation,
            candidate_artifacts = candidate_count,
            selected_artifacts = artifacts.len(),
            policy_bytes = next_policy.len(),
            max_policy_bytes = config.signed_policy_max_bytes,
            "converging bounded signed KBS policy artifacts"
        );

        let cm_result = converge_signed_policy_configmap(
            &cm_api,
            config,
            authority_epoch,
            generation,
            &next_policy,
            &policy_sha256_hex,
        )
        .await?;
        let (configmap_replaced, resource_version, publication_token) = match cm_result {
            ConfigMapConvergence::Current {
                resource_version,
                publication_token,
            } => (false, resource_version, publication_token),
            ConfigMapConvergence::Replaced {
                resource_version,
                publication_token,
            } => (true, resource_version, publication_token),
            ConfigMapConvergence::Superseded => continue,
        };
        if !record_configmap_generation(db, generation, &policy_sha256, &resource_version).await? {
            continue;
        }

        match converge_trustee_policy_generation(
            client.clone(),
            config,
            authority_epoch,
            generation,
            &policy_sha256_hex,
            &publication_token,
        )
        .await?
        {
            GenerationDecision::Superseded => continue,
            GenerationDecision::Replace | GenerationDecision::Current => {}
        }

        // Re-read after rollout. If an external or newer CAP writer replaced
        // the ConfigMap while Trustee was restarting, do not mark this
        // generation applied. A same-generation replacement requires another
        // deterministic Trustee rollout; a newer generation supersedes us.
        match converge_signed_policy_configmap(
            &cm_api,
            config,
            authority_epoch,
            generation,
            &next_policy,
            &policy_sha256_hex,
        )
        .await?
        {
            ConfigMapConvergence::Superseded => continue,
            ConfigMapConvergence::Replaced { .. } => continue,
            ConfigMapConvergence::Current {
                publication_token: current_token,
                ..
            } if current_token == publication_token => {}
            ConfigMapConvergence::Current { .. } => continue,
        }

        let applied = record_applied_generation(db, generation, &policy_sha256).await?;
        if applied {
            if !previously_applied {
                tracing::info!(
                    policy_generation = generation,
                    "signed KBS policy generation is durably applied"
                );
            }
            return Ok(());
        }
        if configmap_replaced {
            tracing::info!(
                policy_generation = generation,
                "signed KBS policy desired generation advanced during rollout"
            );
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

#[derive(Debug)]
enum ConfigMapConvergence {
    Current {
        resource_version: String,
        publication_token: String,
    },
    Replaced {
        resource_version: String,
        publication_token: String,
    },
    Superseded,
}

fn annotated_policy_generation(
    annotations: Option<&BTreeMap<String, String>>,
) -> Result<Option<AnnotatedPolicyGeneration<'_>>, KbsPolicyError> {
    let authority_epoch =
        annotations.and_then(|values| values.get(POLICY_AUTHORITY_EPOCH_ANNOTATION));
    let generation = annotations.and_then(|values| values.get(POLICY_GENERATION_ANNOTATION));
    let policy_hash = annotations.and_then(|values| values.get(POLICY_SHA256_ANNOTATION));
    match (generation, policy_hash) {
        (None, None) if authority_epoch.is_none() => Ok(None),
        (Some(generation), Some(policy_hash)) => {
            let generation = generation
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(KbsPolicyError::InvalidPolicyGeneration)?;
            if policy_hash.len() != 64 || hex::decode(policy_hash).is_err() {
                return Err(KbsPolicyError::InvalidPolicyGeneration);
            }
            let authority_epoch = authority_epoch
                .map(|epoch| {
                    epoch
                        .parse::<Uuid>()
                        .map_err(|_| KbsPolicyError::InvalidPolicyGeneration)
                })
                .transpose()?;
            Ok(Some(AnnotatedPolicyGeneration {
                authority_epoch,
                generation,
                policy_hash: policy_hash.as_str(),
            }))
        }
        _ => Err(KbsPolicyError::InvalidPolicyGeneration),
    }
}

fn generation_decision(
    existing: Option<AnnotatedPolicyGeneration<'_>>,
    existing_content_hash: Option<&str>,
    desired_authority_epoch: Uuid,
    desired_generation: i64,
    desired_hash: &str,
) -> Result<GenerationDecision, KbsPolicyError> {
    let Some(existing) = existing else {
        return Ok(GenerationDecision::Replace);
    };
    if existing.authority_epoch != Some(desired_authority_epoch) {
        return Ok(GenerationDecision::Replace);
    }
    if existing.generation > desired_generation {
        return Ok(GenerationDecision::Superseded);
    }
    if existing.generation < desired_generation {
        return Ok(GenerationDecision::Replace);
    }
    if existing.policy_hash != desired_hash {
        return Err(KbsPolicyError::PolicyGenerationConflict);
    }
    // The generation annotation is content-bound. If a stale legacy writer
    // changed only data while preserving that annotation, the durable desired
    // hash authorizes an exact CAS repair at the same generation.
    if existing_content_hash != Some(desired_hash) {
        return Ok(GenerationDecision::Replace);
    }
    Ok(GenerationDecision::Current)
}

fn is_kubernetes_conflict(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(status) if status.code == 409)
}

async fn converge_signed_policy_configmap(
    cm_api: &Api<ConfigMap>,
    config: &KbsPolicyConfig,
    authority_epoch: Uuid,
    generation: i64,
    policy: &str,
    policy_sha256_hex: &str,
) -> Result<ConfigMapConvergence, KbsPolicyError> {
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        let mut configmap = cm_api.get(&config.configmap_name).await?;
        let prior_resource_version = configmap
            .metadata
            .resource_version
            .clone()
            .ok_or(KbsPolicyError::InvalidPolicyGeneration)?;
        let current_policy = configmap
            .data
            .as_ref()
            .and_then(|data| data.get(&config.policy_key))
            .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
        let current_content_hash = hex::encode(Sha256::digest(current_policy.as_bytes()));
        let existing = annotated_policy_generation(configmap.metadata.annotations.as_ref())?;
        let existing_publication_token = configmap
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .filter(|token| !token.is_empty())
            .cloned();
        match generation_decision(
            existing,
            Some(&current_content_hash),
            authority_epoch,
            generation,
            policy_sha256_hex,
        )? {
            GenerationDecision::Current => {
                if let Some(publication_token) = existing_publication_token {
                    return Ok(ConfigMapConvergence::Current {
                        resource_version: prior_resource_version,
                        publication_token,
                    });
                }
            }
            GenerationDecision::Superseded => return Ok(ConfigMapConvergence::Superseded),
            GenerationDecision::Replace => {}
        }

        configmap
            .data
            .get_or_insert_with(BTreeMap::new)
            .insert(config.policy_key.clone(), policy.to_string());
        let annotations = configmap
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new);
        annotations.insert(
            POLICY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
            authority_epoch.to_string(),
        );
        annotations.insert(
            POLICY_GENERATION_ANNOTATION.to_string(),
            generation.to_string(),
        );
        annotations.insert(
            POLICY_SHA256_ANNOTATION.to_string(),
            policy_sha256_hex.to_string(),
        );
        // Kubernetes assigns the next resourceVersion only after a successful
        // CAS. Binding the publication to the version it replaces yields a
        // stable token that changes on every CAP policy publication, including
        // a same-generation repair after a stale legacy overwrite.
        let publication_token = prior_resource_version;
        annotations.insert(
            POLICY_PUBLICATION_TOKEN_ANNOTATION.to_string(),
            publication_token.clone(),
        );
        match bounded_kube_write(cm_api.replace(
            &config.configmap_name,
            &PostParams::default(),
            &configmap,
        ))
        .await
        {
            Ok(updated) => {
                let resource_version = updated
                    .metadata
                    .resource_version
                    .ok_or(KbsPolicyError::InvalidPolicyGeneration)?;
                return Ok(ConfigMapConvergence::Replaced {
                    resource_version,
                    publication_token,
                });
            }
            Err(KbsPolicyError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

async fn record_configmap_generation(
    db: &PgPool,
    generation: i64,
    policy_sha256: &[u8],
    resource_version: &str,
) -> Result<bool, KbsPolicyError> {
    let result = sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET configmap_generation = $1,
                configmap_policy_sha256 = $2,
                configmap_resource_version = $3,
                updated_at = clock_timestamp()
          WHERE singleton
            AND desired_generation = $1
            AND configmap_generation <= $1",
    )
    .bind(generation)
    .bind(policy_sha256)
    .bind(resource_version)
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn record_applied_generation(
    db: &PgPool,
    generation: i64,
    policy_sha256: &[u8],
) -> Result<bool, KbsPolicyError> {
    let result = sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET applied_generation = $1,
                applied_policy_sha256 = $2,
                updated_at = clock_timestamp()
          WHERE singleton
            AND desired_generation = $1
            AND configmap_generation = $1
            AND configmap_policy_sha256 = $2",
    )
    .bind(generation)
    .bind(policy_sha256)
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn converge_trustee_policy_generation(
    client: kube::Client,
    config: &KbsPolicyConfig,
    authority_epoch: Uuid,
    generation: i64,
    policy_sha256_hex: &str,
    publication_token: &str,
) -> Result<GenerationDecision, KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        let mut deployment = deploy_api.get(&config.deployment_name).await?;
        let template_annotations = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.metadata.as_ref())
            .and_then(|metadata| metadata.annotations.as_ref());
        let existing = annotated_policy_generation(template_annotations)?;
        let mut decision = generation_decision(
            existing,
            existing.map(|annotated| annotated.policy_hash),
            authority_epoch,
            generation,
            policy_sha256_hex,
        )?;
        let existing_publication_token = template_annotations
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .map(String::as_str);
        if decision == GenerationDecision::Current
            && existing_publication_token != Some(publication_token)
        {
            decision = GenerationDecision::Replace;
        }
        match decision {
            GenerationDecision::Superseded => return Ok(GenerationDecision::Superseded),
            GenerationDecision::Current => {
                return wait_for_deployment_policy_generation(
                    &deploy_api,
                    &config.deployment_name,
                    authority_epoch,
                    generation,
                    policy_sha256_hex,
                    publication_token,
                )
                .await;
            }
            GenerationDecision::Replace => {}
        }

        let template = &mut deployment
            .spec
            .as_mut()
            .ok_or(KbsPolicyError::InvalidPolicyGeneration)?
            .template;
        let annotations = template
            .metadata
            .get_or_insert_with(Default::default)
            .annotations
            .get_or_insert_with(BTreeMap::new);
        annotations.insert(
            POLICY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
            authority_epoch.to_string(),
        );
        annotations.insert(
            POLICY_GENERATION_ANNOTATION.to_string(),
            generation.to_string(),
        );
        annotations.insert(
            POLICY_SHA256_ANNOTATION.to_string(),
            policy_sha256_hex.to_string(),
        );
        annotations.insert(
            POLICY_PUBLICATION_TOKEN_ANNOTATION.to_string(),
            publication_token.to_string(),
        );
        match bounded_kube_write(deploy_api.replace(
            &config.deployment_name,
            &PostParams::default(),
            &deployment,
        ))
        .await
        {
            Ok(_) => {
                let readiness = wait_for_deployment_policy_generation(
                    &deploy_api,
                    &config.deployment_name,
                    authority_epoch,
                    generation,
                    policy_sha256_hex,
                    publication_token,
                )
                .await?;
                if readiness == GenerationDecision::Superseded {
                    return Ok(readiness);
                }
                return Ok(GenerationDecision::Replace);
            }
            Err(KbsPolicyError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

async fn wait_for_deployment_policy_generation(
    deploy_api: &Api<Deployment>,
    name: &str,
    desired_authority_epoch: Uuid,
    desired_generation: i64,
    desired_hash: &str,
    desired_publication_token: &str,
) -> Result<GenerationDecision, KbsPolicyError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(180);

    loop {
        let deployment = deploy_api.get(name).await?;
        let template_annotations = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.metadata.as_ref())
            .and_then(|metadata| metadata.annotations.as_ref());
        let annotated = annotated_policy_generation(template_annotations)?;
        let decision = generation_decision(
            annotated,
            annotated.map(|metadata| metadata.policy_hash),
            desired_authority_epoch,
            desired_generation,
            desired_hash,
        )?;
        if decision == GenerationDecision::Superseded {
            return Ok(decision);
        }
        let publication_token = template_annotations
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .map(String::as_str);
        if decision == GenerationDecision::Current
            && publication_token != Some(desired_publication_token)
        {
            return Ok(GenerationDecision::Superseded);
        }
        if decision != GenerationDecision::Current {
            return Err(KbsPolicyError::PolicyGenerationConflict);
        }

        let spec_replicas = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1);
        let status = deployment.status.as_ref();
        let observed = status
            .and_then(|status| status.observed_generation)
            .unwrap_or(0);
        let kubernetes_generation = deployment.metadata.generation.unwrap_or(0);
        let updated = status
            .and_then(|status| status.updated_replicas)
            .unwrap_or(0);
        let available = status
            .and_then(|status| status.available_replicas)
            .unwrap_or(0);
        if observed >= kubernetes_generation
            && updated >= spec_replicas
            && available >= spec_replicas
        {
            return Ok(GenerationDecision::Current);
        }
        if start.elapsed() >= timeout {
            return Err(KbsPolicyError::RolloutTimedOut);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn signed_policy_artifact_policy_body(
    artifacts: &[crate::signing_service::SignedPolicyArtifact],
) -> Result<String, KbsPolicyError> {
    let artifacts = artifacts.iter().map(Into::into).collect();
    Ok(serde_json::to_string(&SignedPolicyArtifactSet {
        schema_version: SIGNED_POLICY_SET_SCHEMA_VERSION,
        artifacts,
    })?)
}

fn select_signed_policy_artifacts_for_policy_body(
    candidates: Vec<SignedPolicyArtifactCandidate>,
    max_policy_bytes: usize,
) -> Result<Vec<crate::signing_service::SignedPolicyArtifact>, KbsPolicyError> {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();

    for candidate in candidates {
        let artifact = candidate.artifact;
        if !seen.insert(artifact.metadata.descriptor_core_hash.clone()) {
            continue;
        }

        let mut candidate_selection = selected.clone();
        candidate_selection.push(artifact.clone());
        let candidate_body = signed_policy_artifact_policy_body(&candidate_selection)?;
        if candidate_body.len() <= max_policy_bytes {
            selected.push(artifact);
        } else if candidate.required {
            return Err(KbsPolicyError::SignedPolicyBudgetExceeded {
                required_artifacts: candidate_selection.len(),
                policy_bytes: candidate_body.len(),
                max_policy_bytes,
            });
        }
    }

    Ok(selected)
}

fn is_signed_policy_artifact_body(policy: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(policy) else {
        return false;
    };
    let is_single = value.get("metadata").is_some()
        && value.get("rego_text").is_some()
        && value.get("signature").is_some();
    let is_set = matches!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_str),
        Some(SIGNED_POLICY_SET_SCHEMA_VERSION_V1 | SIGNED_POLICY_SET_SCHEMA_VERSION)
    ) && value
        .get("artifacts")
        .is_some_and(serde_json::Value::is_array);
    is_single || is_set
}

async fn restart_trustee_deployment(
    client: kube::Client,
    config: &KbsPolicyConfig,
) -> Result<(), KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    let restarted_at = Utc::now().to_rfc3339();
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        let mut deployment = deploy_api.get(&config.deployment_name).await?;
        deployment
            .spec
            .as_mut()
            .ok_or(KbsPolicyError::InvalidPolicyGeneration)?
            .template
            .metadata
            .get_or_insert_with(Default::default)
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(
                "enclava.dev/cap-policy-restarted-at".to_string(),
                restarted_at.clone(),
            );
        match bounded_kube_write(deploy_api.replace(
            &config.deployment_name,
            &PostParams::default(),
            &deployment,
        ))
        .await
        {
            Ok(_) => {
                wait_for_deployment_ready(&deploy_api, &config.deployment_name).await?;
                return Ok(());
            }
            Err(KbsPolicyError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

async fn wait_for_deployment_ready(
    deploy_api: &Api<Deployment>,
    name: &str,
) -> Result<(), KbsPolicyError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(180);

    loop {
        let deployment = deploy_api.get(name).await?;
        let spec_replicas = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1);
        let status = deployment.status.as_ref();
        let observed = status.and_then(|s| s.observed_generation).unwrap_or(0);
        let generation = deployment.metadata.generation.unwrap_or(0);
        let updated = status.and_then(|s| s.updated_replicas).unwrap_or(0);
        let available = status.and_then(|s| s.available_replicas).unwrap_or(0);

        if observed >= generation && updated >= spec_replicas && available >= spec_replicas {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(KbsPolicyError::RolloutTimedOut);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn replace_tls_resource_bindings_block(
    policy: &str,
    bindings: &[KbsTlsBinding],
) -> Result<String, KbsPolicyError> {
    let marker = "resource_bindings := {";
    let cap_begin = "# BEGIN CAP MANAGED TLS RESOURCE BINDINGS";
    let cap_end = "# END CAP MANAGED TLS RESOURCE BINDINGS";
    let start = policy
        .find(marker)
        .ok_or(KbsPolicyError::MissingResourceBindingsBlock)?;
    replace_bindings_block(
        policy,
        marker,
        start,
        cap_begin,
        cap_end,
        &render_cap_tls_resource_bindings_section(bindings),
    )
}

fn replace_owner_bindings_block(
    policy: &str,
    bindings: &[KbsOwnerBinding],
) -> Result<String, KbsPolicyError> {
    let marker = "owner_resource_bindings := {";
    let cap_begin = "# BEGIN CAP MANAGED OWNER BINDINGS";
    let cap_end = "# END CAP MANAGED OWNER BINDINGS";
    let start = policy
        .find(marker)
        .ok_or(KbsPolicyError::MissingOwnerBindingsBlock)?;
    replace_bindings_block(
        policy,
        marker,
        start,
        cap_begin,
        cap_end,
        &render_cap_owner_bindings_section(bindings),
    )
}

fn replace_bindings_block(
    policy: &str,
    marker: &str,
    start: usize,
    cap_begin: &str,
    cap_end: &str,
    cap_section: &str,
) -> Result<String, KbsPolicyError> {
    let open_brace = start + marker.len() - 1;
    let mut depth = 0i32;
    let mut end = None;

    for (offset, ch) in policy[open_brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open_brace + offset + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(end) = end else {
        return Err(if marker == "resource_bindings := {" {
            KbsPolicyError::MissingResourceBindingsBlock
        } else {
            KbsPolicyError::MissingOwnerBindingsBlock
        });
    };

    let block_body_start = open_brace + 1;
    let block_body_end = end - 1;
    let block_body = &policy[block_body_start..block_body_end];

    if let (Some(begin_rel), Some(end_rel)) = (block_body.find(cap_begin), block_body.find(cap_end))
    {
        let begin = block_body_start + begin_rel;
        let end_marker_end = block_body_start + end_rel + cap_end.len();
        let line_end = policy[end_marker_end..]
            .find('\n')
            .map(|offset| end_marker_end + offset)
            .unwrap_or(end_marker_end);

        let mut next = String::with_capacity(policy.len() + cap_section.len());
        next.push_str(&policy[..begin]);
        next.push_str(cap_section.trim_start_matches(','));
        next.push_str(&policy[line_end..]);
        return Ok(next);
    }

    let section = if block_body.trim().is_empty() {
        cap_section.trim_start_matches(',').to_string()
    } else {
        cap_section.to_string()
    };
    let mut next = String::with_capacity(policy.len() + section.len());
    next.push_str(&policy[..block_body_end]);
    next.push_str(&section);
    next.push_str(&policy[block_body_end..]);
    Ok(next)
}

fn render_cap_tls_resource_bindings_section(bindings: &[KbsTlsBinding]) -> String {
    let mut out = String::new();
    out.push(',');
    out.push_str("\n  # BEGIN CAP MANAGED TLS RESOURCE BINDINGS\n");
    let entries: Vec<String> = bindings
        .iter()
        .map(|binding| {
            let allowed_images = optional_string_array(binding.image_digest.as_deref());
            let allowed_init_data_hashes = optional_string_array(
                binding
                    .init_data_hash
                    .as_ref()
                    .map(hex::encode)
                    .as_deref(),
            );
            let allowed_signer_identity_subjects =
                optional_string_array(binding.signer_identity_subject.as_deref());
            let allowed_signer_identity_issuers =
                optional_string_array(binding.signer_identity_issuer.as_deref());
            format!(
                "  {key}: {{\n    \"repository\": {repo},\n    \"tag\": {tag},\n    \"allowed_images\": {allowed_images},\n    \"allowed_image_tag_prefixes\": [],\n    \"allowed_init_data_hashes\": {allowed_init_data_hashes},\n    \"allowed_signer_identity_subjects\": {allowed_signer_identity_subjects},\n    \"allowed_signer_identity_issuers\": {allowed_signer_identity_issuers},\n    \"allowed_namespaces\": [{namespace}],\n    \"allowed_service_accounts\": [{service_account}],\n    \"allowed_identity_hashes\": [{identity_hash}]\n  }}",
                key = json_string(&binding.binding_key),
                repo = json_string(&binding.repository),
                tag = json_string(&binding.tag),
                allowed_images = allowed_images,
                allowed_init_data_hashes = allowed_init_data_hashes,
                allowed_signer_identity_subjects = allowed_signer_identity_subjects,
                allowed_signer_identity_issuers = allowed_signer_identity_issuers,
                namespace = json_string(&binding.namespace),
                service_account = json_string(&binding.service_account),
                identity_hash = json_string(&binding.tenant_instance_identity_hash),
            )
        })
        .collect();
    out.push_str(&entries.join(",\n"));
    if !entries.is_empty() {
        out.push('\n');
    }
    out.push_str("  # END CAP MANAGED TLS RESOURCE BINDINGS\n");
    out
}

fn render_cap_owner_bindings_section(bindings: &[KbsOwnerBinding]) -> String {
    let mut out = String::new();
    out.push(',');
    out.push_str("\n  # BEGIN CAP MANAGED OWNER BINDINGS\n");
    let entries: Vec<String> = bindings
        .iter()
        .map(|binding| {
            format!(
                "  {key}: {{\n    \"repository\": {repo},\n    \"allowed_tags\": {tags},\n    \"allowed_namespaces\": [{namespace}],\n    \"allowed_service_accounts\": [{service_account}],\n    \"allowed_identity_hashes\": [{identity_hash}]\n  }}",
                key = json_string(&binding.binding_key),
                repo = json_string(&binding.repository),
                tags = json_string_array(&binding.allowed_tags),
                namespace = json_string(&binding.namespace),
                service_account = json_string(&binding.service_account),
                identity_hash = json_string(&binding.tenant_instance_identity_hash),
            )
        })
        .collect();
    out.push_str(&entries.join(",\n"));
    if !entries.is_empty() {
        out.push('\n');
    }
    out.push_str("  # END CAP MANAGED OWNER BINDINGS\n");
    out
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}

fn json_string_array(values: &[String]) -> String {
    serde_json::to_string(values).expect("string array serialization is infallible")
}

fn optional_string_array(value: Option<&str>) -> String {
    value
        .filter(|v| !v.trim().is_empty())
        .map(|v| serde_json::to_string(&[v]).expect("string array serialization is infallible"))
        .unwrap_or_else(|| "[]".to_string())
}

pub fn config_from_env() -> Option<KbsPolicyConfig> {
    let required = std::env::var("KBS_POLICY_MANAGEMENT_REQUIRED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let enabled = required
        || std::env::var("KBS_POLICY_MANAGEMENT_ENABLED")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

    if !enabled {
        return None;
    }

    Some(KbsPolicyConfig {
        namespace: std::env::var("KBS_POLICY_NAMESPACE")
            .unwrap_or_else(|_| "trustee-operator-system".to_string()),
        configmap_name: std::env::var("KBS_POLICY_CONFIGMAP")
            .unwrap_or_else(|_| "resource-policy".to_string()),
        policy_key: std::env::var("KBS_POLICY_KEY").unwrap_or_else(|_| "policy.rego".to_string()),
        deployment_name: std::env::var("KBS_POLICY_DEPLOYMENT")
            .unwrap_or_else(|_| "trustee-deployment".to_string()),
        required,
        signed_policy_retention: std::env::var("KBS_SIGNED_POLICY_RETENTION")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SIGNED_POLICY_RETENTION),
        signed_policy_max_bytes: std::env::var("KBS_SIGNED_POLICY_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SIGNED_POLICY_MAX_BYTES),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(key: &str) -> KbsOwnerBinding {
        KbsOwnerBinding {
            binding_key: key.to_string(),
            repository: "default".to_string(),
            allowed_tags: vec!["seed-encrypted".to_string(), "seed-sealed".to_string()],
            namespace: "cap-test".to_string(),
            service_account: "cap-test-sa".to_string(),
            tenant_instance_identity_hash: "abc123".to_string(),
        }
    }

    fn tls_binding(key: &str) -> KbsTlsBinding {
        KbsTlsBinding {
            binding_key: key.to_string(),
            repository: "default".to_string(),
            tag: "workload-secret-seed".to_string(),
            image_digest: Some(
                "ghcr.io/test/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                    .to_string(),
            ),
            init_data_hash: Some(vec![0xab; 32]),
            signer_identity_subject: Some(
                "https://github.com/test/app/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
            ),
            signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            namespace: "cap-test".to_string(),
            service_account: "cap-test-sa".to_string(),
            tenant_instance_identity_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn replaces_only_owner_bindings_block() {
        let policy = r#"package policy

resource_bindings := {
  "legacy": {"repository": "default"}
}

owner_resource_bindings := {
  "old-owner": {
    "repository": "default"
  }
}

allow if {
  binding := owner_resource_bindings["x"]
}
"#;

        let next = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap();
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"old-owner\""));
        assert!(next.contains("\"new-owner\""));
        assert!(next.contains("BEGIN CAP MANAGED OWNER BINDINGS"));
        assert!(next.contains("allow if"));
    }

    #[test]
    fn replaces_existing_cap_managed_section() {
        let policy = r#"owner_resource_bindings := {
  "legacy-owner": {
    "repository": "default"
  },
  # BEGIN CAP MANAGED OWNER BINDINGS
  "old-cap-owner": {
    "repository": "default"
  }
  # END CAP MANAGED OWNER BINDINGS
}
"#;

        let next = replace_owner_bindings_block(policy, &[binding("new-cap-owner")]).unwrap();
        assert!(next.contains("\"legacy-owner\""));
        assert!(next.contains("\"new-cap-owner\""));
        assert!(!next.contains("\"old-cap-owner\""));
    }

    #[test]
    fn renders_empty_cap_section() {
        assert_eq!(
            render_cap_owner_bindings_section(&[]),
            ",\n  # BEGIN CAP MANAGED OWNER BINDINGS\n  # END CAP MANAGED OWNER BINDINGS\n"
        );
    }

    #[test]
    fn replaces_tls_resource_bindings_block() {
        let policy = r#"package policy

resource_bindings := {
  "legacy": {"repository": "default"}
}

owner_resource_bindings := {}
"#;

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-test-app-tls")])
            .unwrap();
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"cap-test-app-tls\""));
        assert!(next.contains("\"allowed_images\": [\"ghcr.io/test/app@sha256:abcd"));
        assert!(next.contains("\"allowed_init_data_hashes\": [\"abababab"));
        assert!(
            next.contains("\"allowed_signer_identity_subjects\": [\"https://github.com/test/app")
        );
        assert!(next.contains(
            "\"allowed_signer_identity_issuers\": [\"https://token.actions.githubusercontent.com\"]"
        ));
        assert!(next.contains("BEGIN CAP MANAGED TLS RESOURCE BINDINGS"));
        assert!(next.contains("owner_resource_bindings := {}"));
    }

    fn test_signed_policy_artifact(
        descriptor_hash_byte: &str,
        payload_bytes: usize,
    ) -> crate::signing_service::SignedPolicyArtifact {
        crate::signing_service::SignedPolicyArtifact {
            metadata: crate::signing_service::PolicyMetadata {
                app_id: "22222222-2222-2222-2222-222222222222".to_string(),
                deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
                descriptor_core_hash: descriptor_hash_byte.repeat(32),
                descriptor_signing_pubkey: "bb".repeat(32),
                platform_release_version: "platform-2026.04".to_string(),
                policy_template_id: "trustee-resource-policy-v1".to_string(),
                policy_template_sha256: "cc".repeat(32),
                agent_policy_sha256: "11".repeat(32),
                genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
                signed_at: "2026-04-01T12:30:00+00:00".to_string(),
                key_id: "policy-test-key-v1".to_string(),
            },
            rego_text: format!("package policy\n\n# {}\n", "x".repeat(payload_bytes)),
            rego_sha256: "dd".repeat(32),
            agent_policy_text: format!(
                "package agent_policy\n\n# {}\ndefault CreateContainerRequest := true\n",
                "y".repeat(payload_bytes)
            ),
            agent_policy_sha256: "11".repeat(32),
            signature: "ee".repeat(64),
            verify_pubkey_b64: "ZmFrZS1wdWJrZXk=".to_string(),
            org_keyring: None,
        }
    }

    fn signed_policy_candidate(
        artifact: crate::signing_service::SignedPolicyArtifact,
        required: bool,
    ) -> SignedPolicyArtifactCandidate {
        SignedPolicyArtifactCandidate { artifact, required }
    }

    #[test]
    fn signed_policy_artifact_body_is_authoritative_envelope() {
        let artifact = crate::signing_service::SignedPolicyArtifact {
            metadata: crate::signing_service::PolicyMetadata {
                app_id: "22222222-2222-2222-2222-222222222222".to_string(),
                deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
                descriptor_core_hash: "aa".repeat(32),
                descriptor_signing_pubkey: "bb".repeat(32),
                platform_release_version: "platform-2026.04".to_string(),
                policy_template_id: "trustee-resource-policy-v1".to_string(),
                policy_template_sha256: "cc".repeat(32),
                agent_policy_sha256: "11".repeat(32),
                genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
                signed_at: "2026-04-01T12:30:00+00:00".to_string(),
                key_id: "policy-test-key-v1".to_string(),
            },
            rego_text: "package policy\n\ndefault allow := false\n".to_string(),
            rego_sha256: "dd".repeat(32),
            agent_policy_text: "package agent_policy\n\ndefault CreateContainerRequest := true\n"
                .to_string(),
            agent_policy_sha256: "11".repeat(32),
            signature: "ee".repeat(64),
            verify_pubkey_b64: "ZmFrZS1wdWJrZXk=".to_string(),
            org_keyring: None,
        };

        let body = signed_policy_artifact_policy_body(std::slice::from_ref(&artifact)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["schema_version"], "enclava-signed-policy-set-v2");
        let compact = &parsed["artifacts"][0];
        assert_eq!(compact["rego_text"], artifact.rego_text);
        assert_eq!(
            compact["metadata"]["policy_template_id"],
            artifact.metadata.policy_template_id
        );
        assert!(compact.get("agent_policy_text").is_none());
        assert!(!body.contains("BEGIN CAP MANAGED"));
    }

    #[test]
    fn multiple_signed_policy_artifacts_are_written_as_policy_set() {
        let artifact = crate::signing_service::SignedPolicyArtifact {
            metadata: crate::signing_service::PolicyMetadata {
                app_id: "22222222-2222-2222-2222-222222222222".to_string(),
                deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
                descriptor_core_hash: "aa".repeat(32),
                descriptor_signing_pubkey: "bb".repeat(32),
                platform_release_version: "platform-2026.04".to_string(),
                policy_template_id: "trustee-resource-policy-v1".to_string(),
                policy_template_sha256: "cc".repeat(32),
                agent_policy_sha256: "11".repeat(32),
                genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
                signed_at: "2026-04-01T12:30:00+00:00".to_string(),
                key_id: "policy-test-key-v1".to_string(),
            },
            rego_text: "package policy\n\ndefault allow := false\n".to_string(),
            rego_sha256: "dd".repeat(32),
            agent_policy_text: "package agent_policy\n\ndefault CreateContainerRequest := true\n"
                .to_string(),
            agent_policy_sha256: "11".repeat(32),
            signature: "ee".repeat(64),
            verify_pubkey_b64: "ZmFrZS1wdWJrZXk=".to_string(),
            org_keyring: None,
        };

        let body =
            signed_policy_artifact_policy_body(&[artifact.clone(), artifact.clone()]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(parsed["schema_version"], "enclava-signed-policy-set-v2");
        assert_eq!(parsed["artifacts"].as_array().unwrap().len(), 2);
        assert!(is_signed_policy_artifact_body(&body));
    }

    #[test]
    fn signed_policy_selection_prefers_first_artifact_and_dedupes_by_descriptor_hash() {
        let current = test_signed_policy_artifact("aa", 16);
        let duplicate_old = test_signed_policy_artifact("aa", 4096);
        let recent_other = test_signed_policy_artifact("bb", 16);

        let selected = select_signed_policy_artifacts_for_policy_body(
            vec![
                signed_policy_candidate(current.clone(), true),
                signed_policy_candidate(duplicate_old, false),
                signed_policy_candidate(recent_other.clone(), false),
            ],
            usize::MAX,
        )
        .unwrap();

        assert_eq!(selected, vec![current, recent_other]);
    }

    #[test]
    fn signed_policy_selection_keeps_artifacts_without_global_retention_cap() {
        let current = test_signed_policy_artifact("aa", 16);
        let recent_one = test_signed_policy_artifact("bb", 16);
        let recent_two = test_signed_policy_artifact("cc", 16);

        let selected = select_signed_policy_artifacts_for_policy_body(
            vec![
                signed_policy_candidate(current.clone(), true),
                signed_policy_candidate(recent_one.clone(), true),
                signed_policy_candidate(recent_two.clone(), true),
            ],
            usize::MAX,
        )
        .unwrap();

        assert_eq!(selected, vec![current, recent_one, recent_two]);
    }

    #[test]
    fn signed_policy_selection_prunes_old_artifacts_to_byte_budget() {
        let current = test_signed_policy_artifact("aa", 128);
        let old = test_signed_policy_artifact("bb", 4096);
        let current_body_len = signed_policy_artifact_policy_body(std::slice::from_ref(&current))
            .unwrap()
            .len();

        let selected = select_signed_policy_artifacts_for_policy_body(
            vec![
                signed_policy_candidate(current.clone(), true),
                signed_policy_candidate(old, false),
            ],
            current_body_len + 32,
        )
        .unwrap();

        assert_eq!(selected, vec![current]);
        let selected_body = signed_policy_artifact_policy_body(&selected).unwrap();
        assert!(selected_body.len() <= current_body_len + 32);
    }

    #[test]
    fn signed_policy_selection_fails_if_required_artifact_exceeds_budget() {
        let current = test_signed_policy_artifact("aa", 128);

        let err = select_signed_policy_artifacts_for_policy_body(
            vec![signed_policy_candidate(current, true)],
            1,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            KbsPolicyError::SignedPolicyBudgetExceeded {
                required_artifacts: 1,
                max_policy_bytes: 1,
                ..
            }
        ));
    }

    #[test]
    fn empty_v2_policy_set_is_a_signed_fail_closed_body() {
        let body = signed_policy_artifact_policy_body(&[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["schema_version"], SIGNED_POLICY_SET_SCHEMA_VERSION);
        assert_eq!(parsed["artifacts"], serde_json::json!([]));
        assert!(is_signed_policy_artifact_body(&body));
    }

    #[test]
    fn stale_signed_configmap_is_distinct_from_legacy_policy_without_db_history() {
        let stale_v1 = serde_json::json!({
            "schema_version": SIGNED_POLICY_SET_SCHEMA_VERSION_V1,
            "artifacts": [{"stale": true}],
        })
        .to_string();
        let stale_v2 = serde_json::json!({
            "schema_version": SIGNED_POLICY_SET_SCHEMA_VERSION,
            "artifacts": [],
        })
        .to_string();
        assert!(is_signed_policy_artifact_body(&stale_v1));
        assert!(is_signed_policy_artifact_body(&stale_v2));
        assert!(!is_signed_policy_artifact_body(
            "package policy\nresource_bindings := {}\nowner_resource_bindings := {}"
        ));
    }

    #[test]
    fn policy_generation_decisions_are_monotonic_and_content_bound() {
        let authority_epoch = Uuid::new_v4();
        assert_eq!(
            generation_decision(None, None, authority_epoch, 3, &"aa".repeat(32)).unwrap(),
            GenerationDecision::Replace
        );
        assert_eq!(
            generation_decision(
                Some(AnnotatedPolicyGeneration {
                    authority_epoch: Some(authority_epoch),
                    generation: 4,
                    policy_hash: &"bb".repeat(32),
                }),
                Some(&"bb".repeat(32)),
                authority_epoch,
                3,
                &"aa".repeat(32),
            )
            .unwrap(),
            GenerationDecision::Superseded
        );
        assert!(matches!(
            generation_decision(
                Some(AnnotatedPolicyGeneration {
                    authority_epoch: Some(authority_epoch),
                    generation: 3,
                    policy_hash: &"bb".repeat(32),
                }),
                Some(&"bb".repeat(32)),
                authority_epoch,
                3,
                &"aa".repeat(32),
            ),
            Err(KbsPolicyError::PolicyGenerationConflict)
        ));
        assert_eq!(
            generation_decision(
                Some(AnnotatedPolicyGeneration {
                    authority_epoch: Some(authority_epoch),
                    generation: 3,
                    policy_hash: &"aa".repeat(32),
                }),
                Some(&"bb".repeat(32)),
                authority_epoch,
                3,
                &"aa".repeat(32),
            )
            .unwrap(),
            GenerationDecision::Replace,
            "a stale content-only overwrite is repaired under the durable hash"
        );
        assert_eq!(
            generation_decision(
                Some(AnnotatedPolicyGeneration {
                    authority_epoch: Some(Uuid::new_v4()),
                    generation: 99,
                    policy_hash: &"bb".repeat(32),
                }),
                Some(&"bb".repeat(32)),
                authority_epoch,
                1,
                &"aa".repeat(32),
            )
            .unwrap(),
            GenerationDecision::Replace,
            "a retained generation from another database lifetime is not newer authority"
        );
    }

    async fn database_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect KBS authority test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate KBS authority test database");
        pool
    }

    #[tokio::test]
    async fn signed_policy_bootstrap_generation_is_atomic_and_idempotent() {
        let pool = database_test_pool().await;
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            enqueue_signed_policy_bootstrap_if_idle(&mut tx)
                .await
                .unwrap()
        );
        assert!(
            !enqueue_signed_policy_bootstrap_if_idle(&mut tx)
                .await
                .unwrap()
        );
        let desired: i64 = sqlx::query_scalar(
            "SELECT desired_generation
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(desired, 1);
        tx.rollback().await.unwrap();
    }

    async fn insert_test_app(pool: &PgPool, status: &str) -> (Uuid, Uuid) {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = app_id.simple().to_string();
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("kbs-authority-{suffix}"))
        .bind(&suffix[..8])
        .execute(pool)
        .await
        .expect("insert KBS test organization");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, status
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 $11::app_status_enum
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("app-{}", &suffix[..12]))
        .bind(format!("cap-{}", &suffix[..12]))
        .bind(format!("instance-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-{}-sa", &suffix[..12]))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("{}.example.test", &suffix[..12]))
        .bind(status)
        .execute(pool)
        .await
        .expect("insert KBS test app");
        (org_id, app_id)
    }

    async fn insert_test_deployment(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        status: &str,
        created_at: chrono::DateTime<Utc>,
    ) {
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, status, spec_snapshot, created_at
             ) VALUES ($1, $2, $3, $4::deploy_status_enum, '{}'::jsonb, $5)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(status)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("insert KBS test deployment");
    }

    async fn insert_test_artifact(
        pool: &PgPool,
        app_id: Uuid,
        deployment_id: Uuid,
        hash_byte: &str,
    ) -> crate::signing_service::SignedPolicyArtifact {
        let mut artifact = test_signed_policy_artifact(hash_byte, 16);
        artifact.metadata.app_id = app_id.to_string();
        artifact.metadata.deploy_id = deployment_id.to_string();
        let descriptor_hash = hex::decode(&artifact.metadata.descriptor_core_hash).unwrap();
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                       '{}'::jsonb, $5, $6)",
        )
        .bind(&descriptor_hash)
        .bind(app_id)
        .bind(deployment_id)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&artifact).unwrap())
        .execute(pool)
        .await
        .expect("insert KBS test artifact");
        artifact
    }

    async fn insert_test_job(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        source_deployment_id: Uuid,
        artifact: Option<(Uuid, &crate::signing_service::SignedPolicyArtifact)>,
    ) {
        let artifact_deployment_id = artifact.map(|(deployment_id, _)| deployment_id);
        let artifact_hash = artifact
            .map(|(_, artifact)| hex::decode(&artifact.metadata.descriptor_core_hash).unwrap());
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state
             ) VALUES (
                 $1, $2, $3, $4, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $5, false, $6, $7, $8, NULL, 'completed'
             )",
        )
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .bind(source_deployment_id)
        .bind(vec![3u8; 32])
        .bind(artifact.is_some())
        .bind(artifact_deployment_id)
        .bind(artifact_hash)
        .execute(pool)
        .await
        .expect("insert KBS test apply job");
    }

    #[tokio::test]
    async fn selector_uses_current_operation_binding_and_legacy_fallback() {
        let pool = database_test_pool().await;
        let now = Utc::now();

        // A rollback operation points to an older exact artifact. It must rank
        // ahead of a newer historical artifact for the same app.
        let (rollback_org, rollback_app) = insert_test_app(&pool, "running").await;
        let source = Uuid::new_v4();
        insert_test_deployment(&pool, rollback_org, rollback_app, source, "healthy", now).await;
        let source_artifact = insert_test_artifact(&pool, rollback_app, source, "aa").await;
        insert_test_job(
            &pool,
            rollback_org,
            rollback_app,
            source,
            source,
            Some((source, &source_artifact)),
        )
        .await;
        let newer = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            rollback_org,
            rollback_app,
            newer,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let newer_artifact = insert_test_artifact(&pool, rollback_app, newer, "bb").await;
        insert_test_job(
            &pool,
            rollback_org,
            rollback_app,
            newer,
            newer,
            Some((newer, &newer_artifact)),
        )
        .await;
        let rollback = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            rollback_org,
            rollback_app,
            rollback,
            "healthy",
            now + chrono::Duration::seconds(2),
        )
        .await;
        insert_test_job(
            &pool,
            rollback_org,
            rollback_app,
            rollback,
            source,
            Some((source, &source_artifact)),
        )
        .await;

        // A pre-0038 healthy signed deployment has no job but remains current.
        let (legacy_org, legacy_app) = insert_test_app(&pool, "running").await;
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, legacy_org, legacy_app, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, legacy_app, legacy, "cc").await;

        // Failed/deleting apps, failed operation jobs, and an app whose current
        // generation is unsigned must contribute no historical authorization.
        let (failed_org, failed_app) = insert_test_app(&pool, "failed").await;
        let failed = Uuid::new_v4();
        insert_test_deployment(&pool, failed_org, failed_app, failed, "failed", now).await;
        let failed_artifact = insert_test_artifact(&pool, failed_app, failed, "dd").await;
        insert_test_job(
            &pool,
            failed_org,
            failed_app,
            failed,
            failed,
            Some((failed, &failed_artifact)),
        )
        .await;

        let (deleting_org, deleting_app) = insert_test_app(&pool, "deleting").await;
        let deleting = Uuid::new_v4();
        insert_test_deployment(&pool, deleting_org, deleting_app, deleting, "healthy", now).await;
        let deleting_artifact = insert_test_artifact(&pool, deleting_app, deleting, "ee").await;
        insert_test_job(
            &pool,
            deleting_org,
            deleting_app,
            deleting,
            deleting,
            Some((deleting, &deleting_artifact)),
        )
        .await;

        let (failed_job_org, failed_job_app) = insert_test_app(&pool, "running").await;
        let failed_job_deployment = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            failed_job_org,
            failed_job_app,
            failed_job_deployment,
            "healthy",
            now,
        )
        .await;
        let failed_job_artifact =
            insert_test_artifact(&pool, failed_job_app, failed_job_deployment, "12").await;
        insert_test_job(
            &pool,
            failed_job_org,
            failed_job_app,
            failed_job_deployment,
            failed_job_deployment,
            Some((failed_job_deployment, &failed_job_artifact)),
        )
        .await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'failed', updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(failed_job_deployment)
        .execute(&pool)
        .await
        .expect("terminalize failed KBS test job");

        let (unsigned_org, unsigned_app) = insert_test_app(&pool, "running").await;
        let old_signed = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            unsigned_org,
            unsigned_app,
            old_signed,
            "healthy",
            now,
        )
        .await;
        let old_artifact = insert_test_artifact(&pool, unsigned_app, old_signed, "ff").await;
        insert_test_job(
            &pool,
            unsigned_org,
            unsigned_app,
            old_signed,
            old_signed,
            Some((old_signed, &old_artifact)),
        )
        .await;
        let unsigned = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            unsigned_org,
            unsigned_app,
            unsigned,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        insert_test_job(&pool, unsigned_org, unsigned_app, unsigned, unsigned, None).await;

        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select exact KBS authority");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(source_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(hashes.contains(legacy_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(candidates.iter().all(|candidate| candidate.required));

        for org_id in [
            rollback_org,
            legacy_org,
            failed_org,
            deleting_org,
            failed_job_org,
            unsigned_org,
        ] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .expect("delete KBS selector fixture");
        }
    }

    #[tokio::test]
    async fn latest_deployment_prefers_jobs_then_deterministic_legacy_identity() {
        let pool = database_test_pool().await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let created_at = Utc::now();
        let older_id = Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();
        let larger_id = Uuid::parse_str("10000000-0000-0000-0000-000000000002").unwrap();
        insert_test_deployment(&pool, org_id, app_id, older_id, "healthy", created_at).await;
        insert_test_deployment(&pool, org_id, app_id, larger_id, "healthy", created_at).await;
        assert_eq!(
            crate::deploy::latest_deployment_id_for_app(&pool, app_id)
                .await
                .unwrap(),
            larger_id
        );
        insert_test_job(&pool, org_id, app_id, older_id, older_id, None).await;
        assert_eq!(
            crate::deploy::latest_deployment_id_for_app(&pool, app_id)
                .await
                .unwrap(),
            older_id,
            "any post-0038 job-backed generation is newer authority than legacy rows"
        );
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete latest-deployment fixture");
    }

    #[tokio::test]
    async fn receipt_authority_is_immutable_but_app_cascade_remains_available() {
        let pool = database_test_pool().await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let deployment_id = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, deployment_id, "healthy", Utc::now()).await;
        let receipt_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO unlock_transition_receipts (
                 id, app_id, deployment_id, from_mode, to_mode, receipt,
                 receipt_pubkey_sha256, receipt_timestamp
             ) VALUES ($1, $2, $3, 'auto', 'password', '{}'::jsonb, $4, $5)",
        )
        .bind(receipt_id)
        .bind(app_id)
        .bind(deployment_id)
        .bind(vec![7u8; 32])
        .bind(Utc::now())
        .execute(&pool)
        .await
        .expect("insert immutable receipt");

        let update_error = sqlx::query(
            "UPDATE unlock_transition_receipts
                SET created_at = created_at + interval '1 second'
              WHERE id = $1",
        )
        .bind(receipt_id)
        .execute(&pool)
        .await
        .expect_err("receipt created_at must be immutable");
        assert_eq!(
            update_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514")
        );
        let delete_error = sqlx::query("DELETE FROM unlock_transition_receipts WHERE id = $1")
            .bind(receipt_id)
            .execute(&pool)
            .await
            .expect_err("direct live receipt deletion must fail");
        assert_eq!(
            delete_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23503")
        );

        let (other_org, other_app) = insert_test_app(&pool, "running").await;
        let cross_deployment_id = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            cross_deployment_id,
            "healthy",
            Utc::now(),
        )
        .await;
        let cross_app_error = sqlx::query(
            "INSERT INTO unlock_transition_receipts (
                 app_id, deployment_id, from_mode, to_mode, receipt,
                 receipt_pubkey_sha256, receipt_timestamp
             ) VALUES ($1, $2, 'auto', 'password', '{}'::jsonb, $3, $4)",
        )
        .bind(other_app)
        .bind(cross_deployment_id)
        .bind(vec![8u8; 32])
        .bind(Utc::now() + chrono::Duration::seconds(1))
        .execute(&pool)
        .await
        .expect_err("cross-app receipt binding must fail");
        assert_eq!(
            cross_app_error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23503")
        );

        sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("parent app deletion cascades immutable receipt");
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE id = $1")
                .bind(receipt_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0);
        for cleanup_org in [org_id, other_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete receipt fixture organization");
        }
    }
}
