use std::collections::{BTreeMap, HashSet};

use chrono::Utc;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, PostParams};
use serde::ser::{SerializeMap, SerializeSeq};
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
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("Kubernetes API error")]
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
    #[error(
        "signed KBS policy generation has conflicting content: existing generation {existing_generation:?} annotates {existing_hash:?}, desired generation {desired_generation} hashes {desired_hash}"
    )]
    PolicyGenerationConflict {
        existing_generation: Option<i64>,
        existing_hash: Option<String>,
        desired_generation: i64,
        desired_hash: String,
    },
    #[error("signed KBS policy artifact is not current deployment authority")]
    ArtifactNotCurrent,
    #[error("signed KBS policy compare-and-swap retries were exhausted")]
    PolicyCasExhausted,
    #[error(
        "resource-policy.rego splice anchor is malformed: {0} (markers/assignments must be line-anchored, outside strings, and unique)"
    )]
    MalformedManagedMarkers(String),
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum KbsPolicyReconciliationError {
    #[error("durable KBS mutation fence failed: {0}")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
    #[error("KBS policy reconciliation failed: {0}")]
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

#[derive(Debug, Clone, Copy)]
struct PostgresJsonb<'a>(&'a serde_json::Value);

impl Serialize for PostgresJsonb<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            serde_json::Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&PostgresJsonb(value))?;
                }
                sequence.end()
            }
            serde_json::Value::Object(values) => {
                let mut entries = values.iter().collect::<Vec<_>>();
                // PostgreSQL JSONB emits object keys by byte length, then by
                // byte value. Reproduce that order only for the persisted
                // org_keyring fragment whose bytes bind the KBS policy hash.
                entries.sort_unstable_by(|(left, _), (right, _)| {
                    left.len()
                        .cmp(&right.len())
                        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
                });
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, &PostgresJsonb(value))?;
                }
                map.end()
            }
            value => value.serialize(serializer),
        }
    }
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
    org_keyring: Option<PostgresJsonb<'a>>,
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
            org_keyring: artifact.org_keyring.as_ref().map(PostgresJsonb),
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
    desired_generation: i64,
    configmap_generation: i64,
    applied_generation: i64,
    withdrawal_bumps_owed: i64,
    selector_bump_pending: bool,
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

pub async fn soft_delete_owner_binding(
    db: &PgPool,
    app_id: Uuid,
    namespace: &str,
    app_name: &str,
) -> Result<(), KbsPolicyError> {
    // If the confidential teardown never completed, the owner seed may still
    // exist in KBS: record the waiver FIRST, in a table that survives the app
    // row (kbs_owner_bindings cascades away with it), so a later recreate of
    // the same binding key is refused until the seed is erased.
    //
    // "Never completed" is derived from seed existence, not the flip-time
    // requirement flag alone: a teardown-required workload (signed paths
    // never create a binding row — the key is name-derived either way) OR
    // any workload with a live owner binding (a running-then-stopped app
    // keeps its seed; PaaS desired-state only scales it to zero) OR any
    // workload that ever deployed (requires_workload_teardown only matches
    // Running, so a stopped or failed app records teardown as not required —
    // and a signed deployment leaves no binding row, yet its name-derived
    // seed survives the scale-to-zero) waives when the completion marker is
    // absent. Completed teardowns and never-deployed apps record nothing:
    // absence of a waiver means recreate is allowed.
    sqlx::query(
        "INSERT INTO kbs_owner_seed_waivers (binding_key, app_id, org_name, app_name)
         SELECT $2, app.id, org.name, app.name
           FROM apps AS app
           JOIN organizations AS org ON org.id = app.org_id
          WHERE app.id = $1
            AND app.workload_teardown_completed_at IS NULL
            AND (
                app.workload_teardown_required
                OR EXISTS (
                    SELECT 1
                      FROM kbs_owner_bindings AS binding
                     WHERE binding.app_id = app.id
                )
                OR EXISTS (
                    SELECT 1
                      FROM deployments AS deployment
                     WHERE deployment.app_id = app.id
                )
            )
         ON CONFLICT (binding_key) DO UPDATE
            SET app_id = EXCLUDED.app_id,
                org_name = EXCLUDED.org_name,
                app_name = EXCLUDED.app_name,
                waived_at = now()",
    )
    .bind(app_id)
    .bind(owner_binding_key(namespace, app_name))
    .execute(db)
    .await?;
    sqlx::query(
        "UPDATE kbs_owner_bindings AS binding
            SET deleted_at = COALESCE(binding.deleted_at, now()),
                updated_at = now()
           WHERE binding.app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    Ok(())
}

/// Mirrors `enclava_engine::types::ConfidentialApp::owner_resource_type`: the
/// KBS owner binding key is derived from the tenant namespace and app name, so
/// it is identical across incarnations of the same name.
fn owner_binding_key(namespace: &str, name: &str) -> String {
    format!("{namespace}-{name}-owner")
}

/// Create-path re-check helper: the same derivation, callable from the
/// routes that guard their app inserts against a recorded waiver.
pub(crate) fn owner_binding_key_for(namespace: &str, name: &str) -> String {
    owner_binding_key(namespace, name)
}

/// Whether a soft-deleted owner binding with this key was destroyed without a
/// completed confidential teardown — its owner seed may still exist in KBS,
/// and a fresh create under the same name would boot already-claimed.
/// Post-insert recheck for the create paths: `stale_owner_seed_for_binding`
/// runs before the insert transaction, and the insert's own NOT EXISTS is
/// evaluated on its statement snapshot — under READ COMMITTED, an abandoned
/// destroy that commits while the insert waits out the old row's unique
/// constraint is invisible to both. A fresh statement inside the same
/// transaction sees every waiver committed by then. Callers refuse with the
/// shared `stale_owner_seed` response when this returns true (which also
/// covers the zero-rows-inserted case: a waiver that predates the statement
/// still exists when re-read).
pub(crate) async fn owner_seed_waiver_recorded_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    namespace: &str,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM kbs_owner_seed_waivers
              WHERE binding_key = $1
         )",
    )
    .bind(owner_binding_key(namespace, name))
    .fetch_one(&mut **tx)
    .await
}

pub async fn stale_owner_seed_for_binding(
    db: &PgPool,
    namespace: &str,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM kbs_owner_seed_waivers
              WHERE binding_key = $1
         )",
    )
    .bind(owner_binding_key(namespace, name))
    .fetch_one(db)
    .await
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

/// Enqueue a signed-policy recomputation only when CAP has already entered
/// signed-policy mode.  Keyring rotation changes which retained artifacts are
/// still authorized (#130); without a generation bump the reconciler would
/// treat the changed candidate set at an unchanged generation as a conflict
/// and keep the stale policy body live in Trustee.  Unsigned-only installs
/// stay untouched.
pub async fn enqueue_signed_policy_reconciliation_if_active(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<i64>, KbsPolicyError> {
    let generation = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation + 1,
                updated_at = clock_timestamp()
          WHERE singleton
            AND desired_generation > 0
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

/// Clear a stray deferred-selector marker from an unsigned-only row.
///
/// Migration 0050 marks the owed selector generation bump only where
/// `desired_generation > 0` (its own WHERE clause, mirroring
/// [`enqueue_signed_policy_reconciliation_if_active`]), so the marker
/// invariant is `selector_bump_pending => desired_generation > 0`.  If a
/// stray marker ever lands on an unsigned-only row (manual psql, a future
/// backfill), it is cleared here without bumping so the install cannot be
/// pushed into signed-policy mode.  This touches only the marker column, so
/// it is invisible to pre-0050 replicas and safe at any point in a run.
async fn clear_stray_selector_bump(db: &PgPool) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET selector_bump_pending = false,
                updated_at = clock_timestamp()
          WHERE singleton
            AND selector_bump_pending
            AND desired_generation = 0",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Commit the deferred candidate-selector generation bump marked by migration
/// 0050 -- and ONLY once the filtered policy body is live in the ConfigMap.
///
/// Only the post-0050 implementation -- the one filtering signed-policy
/// candidates by current keyring membership -- may interpret the marker.
/// `deploy/api/deployment.yaml` runs the API with
/// `DATABASE_MIGRATION_MODE=verify`, so the migration step can precede the
/// new binary by minutes while a pre-0050 replica keeps reconciling every 30
/// seconds: a generation bumped at migration time would be consumed by that
/// replica's unfiltered candidate query and published as the old policy body
/// at the new generation, after which this build would crash-loop on
/// [`KbsPolicyError::PolicyGenerationConflict`] with no bump left to
/// recover.
///
/// Publishing first and committing the increment second keeps that failure
/// unreachable on every crash path.  Until this call, `desired_generation`
/// stays unchanged and a pre-0050 reconciler keeps finding its unfiltered
/// hash matching the published body: it stays quiescent.  The filtered
/// replace annotates the ConfigMap with the owed generation while the durable
/// desired generation is still behind it, so a pre-0050 reconciler treats it
/// as [`GenerationDecision::Superseded`] and cannot overwrite; once the
/// increment lands here, the same content-bound annotation turns any late
/// unfiltered republication into a same-generation conflict.  A failure
/// before the replace leaves the marker set and the increment uncommitted,
/// so the next run simply republishes.
///
/// Consumption is a single guarded `UPDATE`, so concurrent replicas commit
/// the marker exactly once and every later call is a no-op.  A marker on an
/// unsigned-only row is never committed (the `desired_generation > 0` guard);
/// [`clear_stray_selector_bump`] removes it instead.
/// Returns the new desired generation when this call performed the bump.
async fn commit_deferred_selector_bump(db: &PgPool) -> Result<Option<i64>, KbsPolicyError> {
    let bumped: Option<i64> = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation + 1,
                selector_bump_pending = false,
                updated_at = clock_timestamp()
          WHERE singleton
            AND selector_bump_pending
            AND desired_generation > 0
        RETURNING desired_generation",
    )
    .fetch_optional(db)
    .await?;
    Ok(bumped)
}

async fn load_signed_policy_reconciliation(
    db: &PgPool,
) -> Result<SignedPolicyReconciliationRow, KbsPolicyError> {
    Ok(sqlx::query_as(
        "SELECT desired_generation, configmap_generation, applied_generation,
                withdrawal_bumps_owed,
                selector_bump_pending
           FROM kbs_signed_policy_reconciliation
          WHERE singleton",
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

/// An expired hold never replaced the legacy workload. Keep its policy
/// until release, stop/deletion, or a newer non-held operation takes over.
/// Published signed authority must still correlate with the held app.
async fn unreleased_signed_customer_config_hold_apps(
    db: &PgPool,
) -> Result<Vec<String>, KbsPolicyError> {
    Ok(sqlx::query_scalar(
        "SELECT job.app_id::text
           FROM deployment_apply_jobs AS job
           JOIN apps AS app ON app.id = job.app_id
          WHERE job.customer_config_hold
            AND job.customer_config_released_at IS NULL
            AND job.artifact_deployment_id IS NOT NULL
            AND app.status::text IN ('creating', 'running', 'failed')
            AND (
                 job.state = 'setup_pending'
                 OR (
                     job.state = 'failed'
                     AND job.last_error_code = 'customer_config_hold_expired'
                     AND NOT EXISTS (
                         SELECT 1
                           FROM deployment_apply_jobs AS newer
                          WHERE newer.app_id = job.app_id
                            AND newer.generation > job.generation
                            AND NOT (
                                newer.customer_config_hold
                                AND newer.customer_config_released_at IS NULL
                            )
                     )
                 )
            )",
    )
    .fetch_all(db)
    .await?)
}

/// App owners of every signed authority in a published policy body, in both
/// supported shapes: a schema-versioned artifact set and a single signed
/// artifact. A non-signed body (legacy Rego) contributes no owners.
fn published_authority_owners(policy: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(policy) else {
        return Vec::new();
    };
    let owner = |artifact: &serde_json::Value| -> Option<String> {
        artifact
            .get("metadata")?
            .get("app_id")?
            .as_str()
            .map(str::to_owned)
    };
    if let Some(artifacts) = value.get("artifacts").and_then(serde_json::Value::as_array) {
        return artifacts.iter().filter_map(owner).collect();
    }
    owner(&value).into_iter().collect()
}

/// Whether the empty-candidate deferral may protect the live holds. The
/// deferral is only legitimate when the authority converging would revoke
/// belongs to a held transition's own app: the hold is what deliberately
/// left that app's workload running (its signed authority is withheld, or,
/// with nothing signed published yet, converging would flip a legacy Rego
/// install into fail-closed signed mode and revoke that workload). A
/// dropped authority owned by an app without a live signed hold must
/// converge even while an unrelated hold is pending — revocation must not
/// wait for someone else's hold to release or expire.
fn hold_deferral_correlates(revoked_owners: &[String], hold_apps: &[String]) -> bool {
    revoked_owners
        .iter()
        .all(|owner| hold_apps.iter().any(|app| app == owner))
}

/// Clear a stray deferred-withdrawal debt from an unsigned-only row.
///
/// Migration 0052's apps trigger owes withdrawal generation bumps only
/// where `desired_generation > 0`, so the debt invariant is
/// `withdrawal_bumps_owed > 0 => desired_generation > 0`.  If a stray debt
/// ever lands on an unsigned-only row (manual psql, a future backfill), it
/// is cleared here without bumping so the install cannot be pushed into
/// signed-policy mode.  This touches only the debt column, so it is
/// invisible to pre-0052 replicas and safe at any point in a run.
async fn clear_stray_withdrawal_debt(db: &PgPool) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET withdrawal_bumps_owed = 0,
                updated_at = clock_timestamp()
          WHERE singleton
            AND withdrawal_bumps_owed > 0
            AND desired_generation = 0",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Commit the deferred signer-withdrawal generation bumps owed by
/// migration 0052 -- and ONLY once the withdrawal-filtered policy body is
/// live in the ConfigMap.
///
/// Only the post-0052 implementation -- the one refusing withdrawn
/// hashes in [`load_signed_policy_candidates`] -- may interpret the debt.
/// `deploy/api/deployment.yaml` runs the API with
/// `DATABASE_MIGRATION_MODE=verify`, so the migration step can precede the
/// new binary by minutes while a pre-0052 replica keeps reconciling every
/// 30 seconds: a generation bumped directly (migration or route) would be
/// consumed by that replica's unfiltered candidate query and published as
/// the old policy body at the new generation, after which this build would
/// crash-loop on [`KbsPolicyError::PolicyGenerationConflict`] with no bump
/// left to recover.
///
/// Publishing first and committing second keeps that failure unreachable on
/// every crash path.  Until this call, `desired_generation` stays unchanged
/// and a pre-0052 reconciler keeps finding its unfiltered hash matching the
/// published body: it stays quiescent.  The filtered replace annotates the
/// ConfigMap with the owed generation while the durable desired generation
/// is still behind it, so a pre-0052 reconciler treats it as
/// [`GenerationDecision::Superseded`] and cannot overwrite; once the
/// increment lands here, the same content-bound annotation turns any late
/// unfiltered republication into a same-generation conflict.  A failure
/// before the replace leaves the debt owed and the increment uncommitted,
/// so the next run simply republishes.
///
/// The debt is a COUNTER (not a boolean marker) re-armed by migration
/// 0052's apps signer-identity trigger, so it survives rotations committed
/// by a pre-0052 replica during the rollout (its route enqueues nothing of
/// its own).  That is why consumption is a compare-and-set on the exact
/// `(desired_generation, withdrawal_bumps_owed)` pair this run published
/// at: a rotation landing mid-run changes the pair, the CAS fails, `None`
/// is returned, and the caller's next loop attempt republishes the
/// post-rotation candidate set at the strictly higher generation instead of
/// recording a stale set as the final state of a generation.  A debt on an
/// unsigned-only row is never committed (the `desired_generation > 0`
/// guard); [`clear_stray_withdrawal_debt`] removes it instead.
/// Returns the new desired generation when this call performed the commit.
async fn consume_deferred_withdrawal_bumps(
    db: &PgPool,
    observed_desired_generation: i64,
    observed_withdrawal_bumps_owed: i64,
) -> Result<Option<i64>, KbsPolicyError> {
    let committed: Option<i64> = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation + withdrawal_bumps_owed,
                withdrawal_bumps_owed = 0,
                updated_at = clock_timestamp()
          WHERE singleton
            AND withdrawal_bumps_owed > 0
            AND desired_generation > 0
            AND desired_generation = $1
            AND withdrawal_bumps_owed = $2
          RETURNING desired_generation",
    )
    .bind(observed_desired_generation)
    .bind(observed_withdrawal_bumps_owed)
    .fetch_optional(db)
    .await?;
    Ok(committed)
}

/// Select policy authority from the latest operation generation, not from the
/// historical deployment that owns an artifact.  A rollback therefore makes
/// its exact source artifact required.  The active operation is authoritative
/// even while the app row still projects the preceding failed/stopped state.
/// Failed, unsigned, or deleting latest operations contribute no authorization,
/// except that a deleting app with confidential teardown still pending keeps
/// the authorization of every workload generation it may still be running
/// under — the newest completed generation (the last workload known applied;
/// supersession never rewrites completed jobs) plus any later generation that
/// reached the apply phase (apply failures are never reverted, and the delete
/// flip itself supersedes leased work) — until the teardown completes.
/// The prior healthy workload remains required until a replacement is healthy,
/// including when replacement setup fails without stopping the running workload.
/// Every candidate must still be signed by a key that is a member of the
/// org's *current* keyring generation (#130): a retained historical artifact
/// whose signer was removed by keyring rotation must not keep authorizing KBS
/// policy while its immutable row survives the retention window.  Candidates
/// fail closed when the org has no keyring row at all.
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
                job.org_id,
                job.generation,
                job.artifact_deployment_id,
                job.artifact_descriptor_core_hash,
                job.state AS job_state,
                deployment.status::text AS deployment_status,
                app.status::text AS app_status,
                app.workload_teardown_required,
                app.workload_teardown_completed_at,
                job.last_error_code,
                deployment.spec_snapshot->>'setup_state' AS deployment_setup_state,
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
            -- An unreleased customer-config hold has not replaced the running
            -- workload. Leaving it as the newest operation would drop that
            -- workload's signed policy, including after the hold expires failed.
            WHERE NOT (
                job.customer_config_hold
                AND job.customer_config_released_at IS NULL
            )
        ),
        -- The cast is safe at two levels: org_keyrings rows are written only
        -- by the put/rotate handlers, which serialize validated JSON, and the
        -- org_keyrings_payload_wellformed CHECK constraint (migration 0050)
        -- rejects any non-JSON or non-object payload or a non-array members
        -- entry at INSERT time, so a malformed row from a backfill script or
        -- manual psql fix can never take down candidate loading for every
        -- org at once.
        current_keyring_members AS (
            SELECT latest.org_id, member.value->>'pubkey' AS pubkey
              FROM (
                  SELECT DISTINCT ON (org_id)
                      org_id,
                      convert_from(keyring_payload, 'UTF8')::jsonb AS keyring
                    FROM org_keyrings
                   ORDER BY org_id, version DESC
              ) AS latest,
              jsonb_array_elements(latest.keyring->'members') AS member
            -- Mirror the verifier's deploy-authority predicate
            -- (enclava-verifier artifacts.rs: only owner/admin/deployer
            -- members may sign policy).  A member without a string role
            -- matches neither side and is excluded here, exactly as
            -- verification would reject its artifacts -- fail closed if a
            -- non-deploy role is ever added to keyring payloads.
            WHERE (member.value->>'role') IN ('owner', 'admin', 'deployer')
        ),
        eligible_current_job_operations AS (
            SELECT *
              FROM ranked_job_operations
             WHERE (
                    (
                        current_operation_rank = 1
                        AND app_status <> 'deleting'
                        AND deployment_status IN ('pending', 'applying', 'watching', 'healthy')
                        AND job_state IN ('setup_pending', 'setting_up', 'pending', 'running', 'completed')
                    )
                    OR (
                        -- Deleting with confidential teardown still pending:
                        -- every workload generation the app may still be
                        -- running under stays authorized until the teardown
                        -- completes, so the teardown's policy-governed KBS
                        -- deletes cannot be stranded by a reconciliation.
                        --
                        -- Soundness does not come from a generation count:
                        -- single-flight leases serialize concurrent
                        -- deployments, but sequentially failed generations
                        -- stack, so the live workload can sit at any rank.
                        -- It comes from workload state instead:
                        --   * the newest completed job is the last workload
                        --     known applied (a watching generation's job
                        --     completes, and supersession only rewrites
                        --     queued/leased jobs, so it stays completed) —
                        --     admitted however many later generations
                        --     failed;
                        --   * any later generation that reached the apply
                        --     phase may have written (or still be rolling
                        --     out) a workload spec — apply failures are
                        --     never reverted and the delete flip itself
                        --     supersedes leased work with
                        --     'deployment_superseded'. Two signals gate
                        --     this arm: only provable setup failures are
                        --     excluded by error code (setup completes
                        --     before any workload spec is written), and
                        --     the deployment must carry setup_state
                        --     'accepted' (the durable setup machine in
                        --     spec_snapshot, which supersession never
                        --     rewrites) — a deployment superseded while
                        --     still queued never entered the apply phase,
                        --     wrote no spec, and admitting a pile of them
                        --     would crowd the per-app retention slots and
                        --     could push the live workload's artifact out
                        --     of the published policy.
                        app_status = 'deleting'
                        AND workload_teardown_required
                        AND workload_teardown_completed_at IS NULL
                        AND (
                            (
                                job_state = 'completed'
                                AND NOT EXISTS (
                                    SELECT 1
                                      FROM deployment_apply_jobs AS newer
                                     WHERE newer.app_id = ranked_job_operations.app_id
                                       AND newer.state = 'completed'
                                       AND newer.generation
                                           > ranked_job_operations.generation
                                )
                            )
                            OR (
                                job_state <> 'completed'
                                AND COALESCE(
                                       ranked_job_operations.last_error_code,
                                       ''
                                   ) <> 'deployment_setup_failed'
                                AND ranked_job_operations.deployment_setup_state
                                    = 'accepted'
                                AND ranked_job_operations.generation > COALESCE(
                                       (
                                           SELECT MAX(applied.generation)
                                             FROM deployment_apply_jobs AS applied
                                            WHERE applied.app_id
                                                = ranked_job_operations.app_id
                                              AND applied.state = 'completed'
                                       ),
                                       0
                                   )
                            )
                        )
                    )
               )
               AND artifact_deployment_id IS NOT NULL
               AND artifact_descriptor_core_hash IS NOT NULL
               AND EXISTS (
                   SELECT 1
                     FROM workload_artifacts AS current_artifact
                    WHERE current_artifact.app_id = ranked_job_operations.app_id
                      AND current_artifact.deploy_id = artifact_deployment_id
                      AND current_artifact.descriptor_core_hash
                          = artifact_descriptor_core_hash
                      AND NOT EXISTS (
                          SELECT 1
                            FROM withdrawn_signer_artifacts AS withdrawn
                           WHERE withdrawn.descriptor_core_hash
                              = current_artifact.descriptor_core_hash
                      )
               )
            UNION ALL
            -- Keep the prior healthy authority required while admitting the
            -- replacement's artifact early enough for its TEE to bootstrap.
            SELECT *
              FROM ranked_job_operations AS running
             WHERE current_operation_rank > 1
               -- A failed attempt does not prove the prior TEE stopped;
               -- only confirmed takeover or explicit stop/deletion does.
               AND app_status IN ('creating', 'running', 'failed')
               AND deployment_status = 'healthy'
               AND artifact_deployment_id IS NOT NULL
               AND artifact_descriptor_core_hash IS NOT NULL
               AND EXISTS (
                   SELECT 1
                     FROM workload_artifacts AS running_artifact
                    WHERE running_artifact.app_id = running.app_id
                      AND running_artifact.deploy_id = running.artifact_deployment_id
                      AND running_artifact.descriptor_core_hash
                          = running.artifact_descriptor_core_hash
                      AND NOT EXISTS (
                          SELECT 1
                            FROM withdrawn_signer_artifacts AS withdrawn
                           WHERE withdrawn.descriptor_core_hash
                              = running_artifact.descriptor_core_hash
                      )
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM ranked_job_operations AS newer_running
                    WHERE newer_running.app_id = running.app_id
                      AND newer_running.current_operation_rank
                          < running.current_operation_rank
                      AND newer_running.deployment_status = 'healthy'
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
             -- Held artifacts are not authority even as retained history.
             AND NOT (
                 historical.customer_config_hold
                 AND historical.customer_config_released_at IS NULL
             )
             AND (
                  -- A deleting app contributes no optional (rollback/
                  -- retention) artifacts — there is no rollback from a
                  -- delete. Restricting the historical side to the current
                  -- row's own artifact keeps its candidate set bounded to
                  -- the admitted operations instead of cross-joining every
                  -- historical artifact, and keeps `required` deterministic
                  -- per artifact (every admitted row is its own current row).
                  current.app_status <> 'deleting'
                  OR (
                      historical.artifact_deployment_id
                          = current.artifact_deployment_id
                      AND historical.artifact_descriptor_core_hash
                          = current.artifact_descriptor_core_hash
                  )
             )
            JOIN deployments AS historical_deployment
              ON historical_deployment.id = historical.deployment_id
             AND historical_deployment.app_id = historical.app_id
             AND (
                  historical_deployment.status::text
                      IN ('pending', 'applying', 'watching', 'healthy')
                  OR (
                      current.app_status = 'deleting'
                      AND current.workload_teardown_required
                      AND current.workload_teardown_completed_at IS NULL
                  )
             )
            JOIN workload_artifacts AS artifact
              ON artifact.app_id = historical.app_id
             AND artifact.deploy_id = historical.artifact_deployment_id
             AND artifact.descriptor_core_hash
                 = historical.artifact_descriptor_core_hash
             AND NOT EXISTS (
                 SELECT 1
                   FROM withdrawn_signer_artifacts AS withdrawn
                  WHERE withdrawn.descriptor_core_hash
                      = artifact.descriptor_core_hash
             )
            -- Membership is compared case-insensitively on purpose: the
            -- keyring payload is stored verbatim from the request and
            -- `hex_bytes32` deserialization is case-insensitive, so an
            -- uppercase member pubkey hex survives validation and is
            -- stored as-is.  Artifact pubkeys, by contrast, are enforced
            -- lowercase at verification.  Do not "simplify" the lower()
            -- away or uppercase keyrings would silently lose authority.
            JOIN current_keyring_members AS member
              ON member.org_id = current.org_id
             AND lower(member.pubkey) = lower(
                 artifact.signed_policy_artifact
                     ->'metadata'->>'descriptor_signing_pubkey'
             )
            ORDER BY
                current.app_id,
                artifact.descriptor_core_hash,
                -- Prefer a required row when an artifact reaches this point
                -- with both required and optional bindings: DISTINCT ON must
                -- not let an optional row displace the running workload's
                -- authorization.
                required DESC,
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
                deployment.org_id,
                deployment.status::text AS deployment_status,
                app.status::text AS app_status,
                app.workload_teardown_required,
                app.workload_teardown_completed_at,
                deployment.created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY deployment.app_id
                    ORDER BY deployment.created_at DESC, deployment.id DESC
                ) AS current_operation_rank
            FROM deployments AS deployment
            JOIN apps AS app ON app.id = deployment.app_id
            -- Legacy workloads have no job rows. Retain their authority until
            -- a durable replacement becomes healthy.
            WHERE NOT EXISTS (
                SELECT 1
                  FROM ranked_job_operations AS operation
                 WHERE operation.app_id = deployment.app_id
                   AND operation.deployment_status = 'healthy'
            )
              AND NOT EXISTS (
                  SELECT 1
                    FROM deployment_apply_jobs AS job_row
                   WHERE job_row.deployment_id = deployment.id
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
            JOIN current_keyring_members AS member
              -- Case-insensitive membership join: see the comment at the
              -- job_artifact_candidates join above.
              ON member.org_id = legacy.org_id
             AND lower(member.pubkey) = lower(
                 artifact.signed_policy_artifact
                     ->'metadata'->>'descriptor_signing_pubkey'
             )
            WHERE legacy.current_operation_rank = 1
              -- App failure alone does not retire the last healthy workload.
              AND (
                  legacy.app_status IN ('creating', 'running', 'failed')
                  OR (legacy.workload_teardown_required
                      AND legacy.workload_teardown_completed_at IS NULL)
              )
              AND legacy.deployment_status = 'healthy'
              AND NOT EXISTS (
                  SELECT 1
                    FROM withdrawn_signer_artifacts AS withdrawn
                   WHERE withdrawn.descriptor_core_hash
                       = artifact.descriptor_core_hash
              )
        ),
        selected AS (
            -- Required artifacts are immune to retention pruning: during a
            -- handoff both authorities are mandatory, and the byte budget
            -- (not retention) is the bound that fails safe when they do not
            -- fit.
            SELECT *
              FROM ranked_job_artifacts
             WHERE app_artifact_rank <= $1
                OR required
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

/// Converge KBS authority before readiness or deployment dispatch.
///
/// Another starting replica may briefly own the global fence, so startup
/// waits for that replica instead of crash-looping.
pub async fn reconcile_signed_policy_at_startup(
    state: &crate::state::AppState,
) -> Result<(), KbsPolicyReconciliationError> {
    let mut fence_busy_logged = false;
    let mut busy_wait_started: Option<std::time::Instant> = None;
    loop {
        match reconcile_signed_policy_once(state).await {
            Err(KbsPolicyReconciliationError::Mutation(
                err @ crate::mutation_leases::MutationLeaseError::Busy,
            )) => {
                if fence_busy_logged {
                    tracing::debug!(
                        %err,
                        "startup KBS policy reconciliation still waiting on the kbs_policy fence"
                    );
                } else {
                    // Log the Busy arm at least once: while this spins, readiness
                    // answers 503 and an operator cannot tell a recovering lease
                    // from a hung reconcile without a disambiguating line.
                    tracing::warn!(
                        %err,
                        error_code = "kbs_policy_fence_busy",
                        "startup KBS policy reconciliation is waiting on the kbs_policy fence \
                         (another replica holds it or a dead lease is awaiting its finite \
                         reclaim); readiness stays pending until it clears"
                    );
                    fence_busy_logged = true;
                    busy_wait_started = Some(std::time::Instant::now());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            result => {
                if fence_busy_logged && result.is_ok() {
                    // Close the window the WARN opened so an operator can
                    // correlate the 503 span end-to-end without inferring its
                    // end from the generic readiness line.
                    tracing::info!(
                        error_code = "kbs_policy_fence_busy",
                        elapsed_secs = busy_wait_started
                            .map(|started| started.elapsed().as_secs())
                            .unwrap_or_default(),
                        "startup KBS policy reconciliation cleared the kbs_policy fence"
                    );
                }
                return result;
            }
        }
    }
}

/// Recover a committed desired generation after process or provider failure.
/// The resource-only lease is shared with app apply/delete paths, so this loop
/// also works after the final app row and its artifacts have cascaded away.
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
                Err(error @ KbsPolicyReconciliationError::Mutation(_)) => tracing::warn!(
                    %error,
                    error_code = "kbs_policy_fence_unavailable",
                    "could not claim durable global KBS reconciliation"
                ),
                Err(error @ KbsPolicyReconciliationError::Policy(_)) => tracing::warn!(
                    %error,
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
    // Clear any stray deferred-selector marker on an unsigned-only row (see
    // clear_stray_selector_bump).  A marker on a signed-mode row is left in
    // place here on purpose: the owed generation bump (migration 0050) is
    // published first and committed only after the filtered ConfigMap replace
    // succeeded (commit_deferred_selector_bump below), so no failure in this
    // run can expose a raw bumped generation to a pre-0050 reconciler.
    clear_stray_selector_bump(db).await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    // Clear any stray deferred-withdrawal debt on an unsigned-only row (see
    // clear_stray_withdrawal_debt).  A debt on a signed-mode row is left in
    // place here on purpose: the owed generation bump (migration 0052) is
    // published first and committed only after the filtered ConfigMap replace
    // succeeded (consume_deferred_withdrawal_bumps below), so no failure in
    // this run can expose a raw bumped generation to a pre-0052 reconciler.
    clear_stray_withdrawal_debt(db).await?;
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
        // Pending deferred withdrawal bumps (migration 0052) publish the owed
        // generation as desired_generation + withdrawal_bumps_owed without
        // committing the increment yet -- consume_deferred_withdrawal_bumps
        // does that only after the filtered replace below.  Pre-0052
        // replicas reading the same row keep seeing the unchanged
        // desired_generation and stay quiescent.
        // A pending deferred selector bump (migration 0050) likewise publishes
        // the owed generation as desired_generation + 1 without committing
        // the increment yet -- commit_deferred_selector_bump does that only
        // after the filtered replace below.  Pre-0050 replicas reading the
        // same row keep seeing the unchanged desired_generation and stay
        // quiescent.
        let generation = state.desired_generation
            + state.withdrawal_bumps_owed
            + i64::from(state.selector_bump_pending);
        let reset_bootstrap = state.configmap_generation == 0 && state.applied_generation == 0;
        let previously_applied = state.applied_generation >= generation;
        let candidates = load_signed_policy_candidates(db, config.signed_policy_retention).await?;
        // Every signed authority is withheld behind an unreleased
        // customer-config hold: publishing the empty body would flip a
        // legacy Rego install into fail-closed signed mode and revoke the
        // workload the hold deliberately left running. Defer this
        // generation until the held transition's lifecycle actually
        // advances — release, replacement, stop, or delete; expiry alone
        // leaves the workload running — but only when the revocation
        // converging would perform correlates with the held transition's
        // own app: an unrelated hold must not retain another app's
        // obsolete authority (see `hold_deferral_correlates`).
        if candidates.is_empty() {
            let hold_apps = unreleased_signed_customer_config_hold_apps(db).await?;
            if !hold_apps.is_empty() {
                let configmap = cm_api.get(&config.configmap_name).await?;
                let current_policy = configmap
                    .data
                    .as_ref()
                    .and_then(|data| data.get(&config.policy_key))
                    .map(String::as_str)
                    .unwrap_or_default();
                let revoked_owners = published_authority_owners(current_policy);
                if hold_deferral_correlates(&revoked_owners, &hold_apps) {
                    tracing::info!(
                        policy_generation = generation,
                        "deferring signed KBS policy convergence until held deployments release"
                    );
                    return Ok(());
                }
            }
        }
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
            generation,
            &next_policy,
            &policy_sha256_hex,
            reset_bootstrap,
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
        // The withdrawal-filtered body is now live at `generation` with its
        // content-bound generation annotation, and only now is the owed
        // increment (migration 0052) safe to commit: while
        // `desired_generation` was still behind, a pre-0052 reconciler saw
        // the annotated generation as Superseded and could not overwrite;
        // after the increment lands, the same annotation turns any late
        // unfiltered republication into a same-generation conflict.
        // Committing before this replace would expose a raw bumped
        // generation that a pre-0052 reconciler could consume with its
        // unfiltered query whenever this run fails before publishing.  The
        // CAS on the observed (desired, owed) pair is what fences OLD
        // identity writers: a rotation from a pre-0052 replica (or any
        // binary) owes its bump inside its own transaction through
        // migration 0052's apps trigger.  If such a write landed after this
        // run loaded its candidate set, owed has moved, the CAS fails, and
        // the loop retries -- republishing the post-rotation candidate set
        // at the strictly higher generation instead of sealing a stale one.
        if state.withdrawal_bumps_owed > 0
            && consume_deferred_withdrawal_bumps(
                db,
                state.desired_generation,
                state.withdrawal_bumps_owed,
            )
            .await?
            .is_none()
        {
            continue;
        }
        // The selector-filtered body is likewise live at `generation`, and
        // only now is the selector increment (migration 0050) safe to commit:
        // while `desired_generation` was still behind, a pre-0050 reconciler
        // saw the annotated generation as Superseded and could not overwrite;
        // after the increment lands, the same annotation turns any late
        // unfiltered republication into a same-generation conflict.
        if state.selector_bump_pending {
            commit_deferred_selector_bump(db).await?;
        }
        if !reset_bootstrap
            && !record_configmap_generation(db, generation, &policy_sha256, &resource_version)
                .await?
        {
            continue;
        }

        match converge_trustee_policy_generation(
            client.clone(),
            config,
            generation,
            &policy_sha256_hex,
            &publication_token,
            reset_bootstrap,
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
            generation,
            &next_policy,
            &policy_sha256_hex,
            reset_bootstrap,
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

        if reset_bootstrap
            && !record_configmap_generation(db, generation, &policy_sha256, &resource_version)
                .await?
        {
            continue;
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
) -> Result<Option<(i64, &str)>, KbsPolicyError> {
    let generation = annotations.and_then(|values| values.get(POLICY_GENERATION_ANNOTATION));
    let policy_hash = annotations.and_then(|values| values.get(POLICY_SHA256_ANNOTATION));
    match (generation, policy_hash) {
        (None, None) => Ok(None),
        (Some(generation), Some(policy_hash)) => {
            let generation = generation
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(KbsPolicyError::InvalidPolicyGeneration)?;
            if policy_hash.len() != 64 || hex::decode(policy_hash).is_err() {
                return Err(KbsPolicyError::InvalidPolicyGeneration);
            }
            Ok(Some((generation, policy_hash.as_str())))
        }
        _ => Err(KbsPolicyError::InvalidPolicyGeneration),
    }
}

fn generation_decision(
    existing: Option<(i64, &str)>,
    existing_content_hash: Option<&str>,
    desired_generation: i64,
    desired_hash: &str,
    allow_generation_reset: bool,
) -> Result<GenerationDecision, KbsPolicyError> {
    let Some((existing_generation, annotated_hash)) = existing else {
        return Ok(GenerationDecision::Replace);
    };
    // A new database has no durable ConfigMap or applied history. During that
    // one bootstrap, Kubernetes annotations from the retired database are not
    // authority; every later generation remains strictly monotonic.
    if existing_generation > desired_generation && !allow_generation_reset {
        return Ok(GenerationDecision::Superseded);
    }
    if existing_generation != desired_generation {
        return Ok(GenerationDecision::Replace);
    }
    if annotated_hash != desired_hash {
        return if allow_generation_reset {
            Ok(GenerationDecision::Replace)
        } else {
            Err(KbsPolicyError::PolicyGenerationConflict {
                existing_generation: Some(existing_generation),
                existing_hash: Some(annotated_hash.to_string()),
                desired_generation,
                desired_hash: desired_hash.to_string(),
            })
        };
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
    generation: i64,
    policy: &str,
    policy_sha256_hex: &str,
    allow_generation_reset: bool,
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
            generation,
            policy_sha256_hex,
            allow_generation_reset,
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
    generation: i64,
    policy_sha256_hex: &str,
    publication_token: &str,
    allow_generation_reset: bool,
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
            existing.map(|(_, policy_hash)| policy_hash),
            generation,
            policy_sha256_hex,
            allow_generation_reset,
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
                    generation,
                    policy_sha256_hex,
                    publication_token,
                    allow_generation_reset,
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
                    generation,
                    policy_sha256_hex,
                    publication_token,
                    allow_generation_reset,
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
    desired_generation: i64,
    desired_hash: &str,
    desired_publication_token: &str,
    allow_generation_reset: bool,
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
            annotated.map(|(_, policy_hash)| policy_hash),
            desired_generation,
            desired_hash,
            allow_generation_reset,
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
            return Err(KbsPolicyError::PolicyGenerationConflict {
                existing_generation: annotated.map(|(generation, _)| generation),
                existing_hash: annotated.map(|(_, policy_hash)| policy_hash.to_string()),
                desired_generation,
                desired_hash: desired_hash.to_string(),
            });
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
    let states = lex_rego_states(policy);
    let start = find_binding_assignment(policy, &states, marker)?
        .ok_or(KbsPolicyError::MissingResourceBindingsBlock)?;
    replace_bindings_block(
        policy,
        &states,
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
    let states = lex_rego_states(policy);
    let start = find_binding_assignment(policy, &states, marker)?
        .ok_or(KbsPolicyError::MissingOwnerBindingsBlock)?;
    replace_bindings_block(
        policy,
        &states,
        marker,
        start,
        cap_begin,
        cap_end,
        &render_cap_owner_bindings_section(bindings),
    )
}

/// Lexical state of a byte in a Rego policy. Rego has line comments
/// (`# ...`), quoted strings (`"..."` with `\` escapes) and multi-line raw
/// strings (`` `...` ``). Line-anchored substring search alone is not
/// enough: a marker or assignment sitting on its own line *inside a raw
/// string* satisfies any whitespace-prefix check, so splice points must be
/// validated against the lexical state, not just the line shape.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegoLexState {
    Code,
    LineComment,
    QuotedString,
    RawString,
}

/// Classify every byte of `policy`. Delimiter bytes (`#`, `"`, `` ` ``)
/// belong to the comment/string they open, and a newline inside a line
/// comment is Code again. An unterminated string or raw string leaves the
/// remainder classified as string content, which makes every lookup in it
/// invisible — malformed input fails closed downstream.
fn lex_rego_states(policy: &str) -> Vec<RegoLexState> {
    let bytes = policy.as_bytes();
    let mut states = Vec::with_capacity(bytes.len());
    let mut current = RegoLexState::Code;
    let mut escaped = false;
    for &byte in bytes {
        let mut state = current;
        match current {
            RegoLexState::Code => {
                if byte == b'#' {
                    current = RegoLexState::LineComment;
                    state = RegoLexState::LineComment;
                } else if byte == b'"' {
                    current = RegoLexState::QuotedString;
                    state = RegoLexState::QuotedString;
                    escaped = false;
                } else if byte == b'`' {
                    current = RegoLexState::RawString;
                    state = RegoLexState::RawString;
                }
            }
            RegoLexState::LineComment => {
                if byte == b'\n' {
                    current = RegoLexState::Code;
                    state = RegoLexState::Code;
                }
            }
            RegoLexState::QuotedString => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    current = RegoLexState::Code;
                }
            }
            RegoLexState::RawString => {
                if byte == b'`' {
                    current = RegoLexState::Code;
                }
            }
        }
        states.push(state);
    }
    states
}

/// Locate `marker` only where it is the line's leading token (nothing but
/// whitespace between the previous newline and the marker) AND every byte
/// of the match is lexical code — not inside a comment, quoted string, or
/// raw string. A binding assignment quoted inside a string, trailing a
/// comment, or embedded in a multi-line raw string no longer hijacks the
/// splice, and `resource_bindings := {` no longer matches the tail of an
/// `owner_resource_bindings := {` line. More than one real assignment is
/// an ambiguous splice target and fails closed instead of first-match.
fn find_binding_assignment(
    policy: &str,
    states: &[RegoLexState],
    marker: &str,
) -> Result<Option<usize>, KbsPolicyError> {
    let mut hits: Vec<usize> = Vec::new();
    let mut from = 0;
    while let Some(relative) = policy[from..].find(marker) {
        let at = from + relative;
        from = at + marker.len();
        let line_start = policy[..at].rfind('\n').map(|index| index + 1).unwrap_or(0);
        if !policy[line_start..at].chars().all(char::is_whitespace) {
            continue;
        }
        if !states[at..at + marker.len()]
            .iter()
            .all(|state| *state == RegoLexState::Code)
        {
            continue;
        }
        hits.push(at);
    }
    match hits.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        _ => Err(KbsPolicyError::MalformedManagedMarkers(format!(
            "binding assignment `{marker}` appears {} times outside comments and strings",
            hits.len()
        ))),
    }
}

/// Locate `marker` only where it occupies a whole line (optional leading
/// indentation, nothing but whitespace after it) outside a string literal.
/// The markers themselves are Rego comment lines (`# ...`), so comments are
/// fine; what must be rejected is marker text sitting on its own line
/// inside a quoted or multi-line raw string. Returns the byte offset of
/// the marker itself, `None` when absent, and errors when the marker line
/// appears more than once — an ambiguous splice target must fail closed
/// instead of silently replacing the wrong span.
fn find_managed_marker_unique(
    haystack: &str,
    states: &[RegoLexState],
    marker: &str,
    label: &str,
) -> Result<Option<usize>, KbsPolicyError> {
    let mut hits: Vec<usize> = Vec::new();
    let mut from = 0;
    while let Some(relative) = haystack[from..].find(marker) {
        let at = from + relative;
        from = at + marker.len();
        let line_start = haystack[..at]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let line_end = haystack[at..]
            .find('\n')
            .map(|offset| at + offset)
            .unwrap_or(haystack.len());
        let occupies_whole_line = haystack[line_start..at].chars().all(char::is_whitespace)
            && haystack[at + marker.len()..line_end]
                .chars()
                .all(char::is_whitespace);
        let inside_string = states[at..at + marker.len()]
            .iter()
            .any(|state| matches!(state, RegoLexState::QuotedString | RegoLexState::RawString));
        if inside_string {
            // Codex P2 (cap#165): marker text inside a string literal is
            // string content, never a splice target — skip regardless of
            // line shape.
            continue;
        }
        if !occupies_whole_line && haystack[line_start..at].chars().all(char::is_whitespace) {
            // Codex P2 (cap#165): a line-LEADING marker with trailing
            // non-whitespace (e.g. `# BEGIN CAP MANAGED ... # note`) is a
            // malformed marker, not an absent one — treating it as absent
            // would append a second managed section and leave the stale
            // bindings in the original one active. Fail closed.
            return Err(KbsPolicyError::MalformedManagedMarkers(format!(
                "{label} appears with trailing content on its line — \
                 malformed managed marker; refusing to splice"
            )));
        }
        if occupies_whole_line {
            hits.push(at);
        }
    }
    match hits.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        _ => Err(KbsPolicyError::MalformedManagedMarkers(format!(
            "{label} appears {} times",
            hits.len()
        ))),
    }
}

fn replace_bindings_block(
    policy: &str,
    states: &[RegoLexState],
    marker: &str,
    start: usize,
    cap_begin: &str,
    cap_end: &str,
    cap_section: &str,
) -> Result<String, KbsPolicyError> {
    let open_brace = start + marker.len() - 1;
    let mut depth = 0i32;
    let mut end = None;

    // Braces inside comments, quoted strings, and raw strings do not open
    // or close the binding map; counting them yields the wrong block.
    for (offset, ch) in policy[open_brace..].char_indices() {
        if states[open_brace + offset] != RegoLexState::Code {
            continue;
        }
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

    // Markers must sit on their own line in lexical code and appear at most
    // once inside the block; a marker string embedded mid-line in a policy
    // value, comment, or raw string is not a splice point, and a
    // half-present or inverted marker pair is a corrupted block that must
    // fail closed rather than be mis-spliced.
    let body_states = &states[block_body_start..block_body_end];
    let begin_hit = find_managed_marker_unique(
        block_body,
        body_states,
        cap_begin,
        "managed-block BEGIN marker",
    )?;
    let end_hit =
        find_managed_marker_unique(block_body, body_states, cap_end, "managed-block END marker")?;

    match (begin_hit, end_hit) {
        (None, None) => {}
        (Some(begin_rel), Some(end_rel)) if begin_rel < end_rel => {
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
        _ => {
            return Err(KbsPolicyError::MalformedManagedMarkers(
                "BEGIN present without a following END marker".to_string(),
            ));
        }
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

    #[test]
    fn startup_fence_busy_spin_logs_disambiguation() {
        // The Busy spin answers readiness with 503 the whole time; without a
        // logged arm an operator cannot distinguish "recovering lease" from
        // "hung reconcile" (as it looked during a real roll's ~9-minute reclaim).
        let source = include_str!("kbs.rs");
        assert!(
            source.contains("error_code = \"kbs_policy_fence_busy\""),
            "the startup kbs_policy fence Busy arm must keep its disambiguating log line"
        );
        assert!(
            source.contains("fence_busy_logged = true"),
            "the Busy arm must flip its flag so the WARN fires once, not per retry"
        );
        assert!(
            source.contains("still waiting on the kbs_policy fence"),
            "retries must demote to DEBUG instead of flooding WARN every 2s"
        );
        assert!(
            source.contains("cleared the kbs_policy fence"),
            "the WARN's window must be closed with an elapsed-time line an operator can correlate"
        );
    }

    #[test]
    fn reconciliation_error_display_redacts_upstream_detail() {
        let db = KbsPolicyReconciliationError::from(KbsPolicyError::Db(sqlx::Error::Protocol(
            "tenant-sensitive database detail".to_string(),
        )));
        assert!(!db.to_string().contains("tenant-sensitive"));

        let kube = KbsPolicyReconciliationError::from(KbsPolicyError::Kube(kube::Error::Api(
            kube::core::Status::failure(
                "tenant-sensitive Kubernetes detail",
                "tenant-sensitive reason",
            )
            .with_code(500)
            .boxed(),
        )));
        assert!(!kube.to_string().contains("tenant-sensitive"));
    }

    #[tokio::test]
    async fn rollout_without_policy_annotations_rejects_healthy_deployment() {
        let client = kube::Client::new(
            tower::service_fn(|_: axum::http::Request<kube::client::Body>| async {
                let deployment = serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "trustee", "generation": 1},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "trustee"}},
                        "template": {
                            "metadata": {"labels": {"app": "trustee"}},
                            "spec": {
                                "containers": [{"name": "trustee", "image": "trustee:test"}]
                            }
                        }
                    },
                    "status": {
                        "observedGeneration": 1,
                        "updatedReplicas": 1,
                        "availableReplicas": 1
                    }
                });
                Ok::<_, std::io::Error>(axum::http::Response::new(kube::client::Body::from(
                    serde_json::to_vec(&deployment).unwrap(),
                )))
            }),
            "default",
        );
        let deployments = Api::<Deployment>::namespaced(client, "trustee");
        let desired_hash = "cc".repeat(32);
        let error = wait_for_deployment_policy_generation(
            &deployments,
            "trustee",
            4,
            &desired_hash,
            "publication-token",
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            &error,
            KbsPolicyError::PolicyGenerationConflict {
                existing_generation: None,
                existing_hash: None,
                desired_generation: 4,
                desired_hash: hash,
            } if hash == &desired_hash
        ));
        assert!(
            KbsPolicyReconciliationError::from(error)
                .to_string()
                .contains(&desired_hash)
        );
    }

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

    #[test]
    fn tls_splice_targets_the_resource_bindings_line_not_the_owner_suffix() {
        // `resource_bindings := {` is a suffix of
        // `owner_resource_bindings := {`; an unanchored find() splices the
        // owner block (or the wrong span) when the owner map comes first.
        let policy = r#"package policy

owner_resource_bindings := {
  "owner": {"repository": "default"}
}

resource_bindings := {
  "legacy": {"repository": "default"}
}
"#;

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-tls")]).unwrap();
        // The owner block survives verbatim...
        assert!(
            next.contains(
                "owner_resource_bindings := {\n  \"owner\": {\"repository\": \"default\"}\n}"
            ),
            "owner block must survive the splice verbatim"
        );
        assert!(!next.contains("BEGIN CAP MANAGED OWNER BINDINGS"));
        // ...and nothing is spliced between the owner assignment and the
        // real `resource_bindings := {` line (the old unanchored find()
        // spliced into the owner block and still satisfied bare
        // substring-order assertions).
        let owner_pos = next.find("owner_resource_bindings := {").unwrap();
        let rb_pos = next
            .find("\nresource_bindings := {")
            .map(|index| index + 1)
            .unwrap();
        assert!(
            owner_pos < rb_pos,
            "owner block must come first for the suffix trap"
        );
        assert!(
            !next[owner_pos..rb_pos].contains("BEGIN CAP MANAGED"),
            "no CAP-managed section may land between the owner assignment and the real resource_bindings map"
        );
        // ...and the CAP TLS section lands inside resource_bindings.
        let tls_pos = next
            .find("BEGIN CAP MANAGED TLS RESOURCE BINDINGS")
            .unwrap();
        assert!(rb_pos < tls_pos);
    }

    #[test]
    fn binding_assignment_inside_raw_string_is_ignored() {
        // Rego raw strings (backticks) span lines; a line-start
        // `resource_bindings := {` inside one must not seed the brace
        // matcher. The splice targets the real map, and the raw string
        // content survives untouched.
        let policy = "package policy\n\ndocumentation := `example\nresource_bindings := {\n}`\n\nresource_bindings := {\n  \"legacy\": {\"repository\": \"default\"}\n}\n";

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-tls")]).unwrap();
        assert!(
            next.contains("documentation := `example\nresource_bindings := {\n}`"),
            "raw string must survive verbatim"
        );
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"cap-tls\""));
        let doc_pos = next.find("documentation := ").unwrap();
        let tls_pos = next
            .find("BEGIN CAP MANAGED TLS RESOURCE BINDINGS")
            .unwrap();
        let real_rb_pos = next.rfind("\nresource_bindings := {").unwrap();
        assert!(
            real_rb_pos < tls_pos,
            "CAP section must land inside the real map, not the raw string"
        );
        assert!(doc_pos < real_rb_pos);
        // The generated binding key appears exactly once: inside the real
        // map, never spliced into the raw string.
        assert_eq!(next.matches("\"cap-tls\"").count(), 1);
    }

    #[test]
    fn managed_marker_inside_raw_string_is_not_a_splice_point() {
        // Whole-line BEGIN/END markers inside a multi-line raw string value
        // in the block body are string content, not splice points; the
        // existing real managed section is what gets replaced.
        let policy = "owner_resource_bindings := {\n  \"legacy\": {\"repository\": \"default\"},\n  \"doc\": `see\n# BEGIN CAP MANAGED OWNER BINDINGS\n# END CAP MANAGED OWNER BINDINGS\nhere`,\n  # BEGIN CAP MANAGED OWNER BINDINGS\n  \"old-cap\": {\"repository\": \"default\"}\n  # END CAP MANAGED OWNER BINDINGS\n}\n";

        let next = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap();
        // The real managed section is replaced...
        assert!(next.contains("\"new-owner\""));
        assert!(!next.contains("\"old-cap\""));
        // ...and the raw-string documentation survives verbatim (its
        // marker-shaped lines are string content and stay as text).
        assert!(next.contains("\"doc\": `see"));
        assert!(next.contains("here`"));
        // Exactly one splice happened: the fresh section's END marker is
        // followed by the map's real closing content, not the old section.
        let fresh_end = next.find("here`").unwrap();
        let old_section_probe = "\"repository\": \"default\"\n  }".to_string();
        assert!(
            !next[fresh_end..].contains(&old_section_probe),
            "the old managed section after the raw string must be gone"
        );
    }

    #[test]
    fn braces_inside_raw_string_do_not_close_the_block() {
        // A `}` inside a raw string value must not terminate the map; the
        // splice keeps the entry and the block boundary is the real brace.
        let policy = "resource_bindings := {\n  \"legacy\": {\"repository\": \"default\"},\n  \"doc\": `template with } and { inside`\n}\n";

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-tls")]).unwrap();
        assert!(next.contains("\"doc\": `template with } and { inside`"));
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("BEGIN CAP MANAGED TLS RESOURCE BINDINGS"));
        // The closing brace of the map is the real one, after the raw string.
        let doc_pos = next.find("\"doc\"").unwrap();
        let tls_pos = next
            .find("BEGIN CAP MANAGED TLS RESOURCE BINDINGS")
            .unwrap();
        assert!(doc_pos < tls_pos);
    }

    #[test]
    fn duplicate_real_assignments_fail_closed() {
        // Two real (line-start, code) `resource_bindings := {` assignments
        // are an ambiguous splice target; first-match must not silently win.
        let policy = "package policy\n\nresource_bindings := {\n  \"first\": {\"repository\": \"default\"}\n}\n\nresource_bindings := {\n  \"second\": {\"repository\": \"default\"}\n}\n";

        let err =
            replace_tls_resource_bindings_block(policy, &[tls_binding("cap-tls")]).unwrap_err();
        assert!(matches!(err, KbsPolicyError::MalformedManagedMarkers(_)));
    }

    #[test]
    fn marker_embedded_mid_line_is_not_a_splice_point() {
        // A marker string quoted inside a policy value or trailing a comment
        // must not be treated as the managed block; only whole-line markers
        // are splice points.
        let policy = r#"package policy

owner_resource_bindings := {
  "legacy": {"repository": "default"},
  # note: see also # BEGIN CAP MANAGED OWNER BINDINGS elsewhere
  "doc": "the string # END CAP MANAGED OWNER BINDINGS is documented"
}
"#;

        let next = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap();
        // The legacy entries and embedded marker texts survive; the fresh CAP
        // section is inserted (no whole-line markers existed to replace).
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"doc\""));
        assert!(next.contains("see also # BEGIN CAP MANAGED OWNER BINDINGS elsewhere"));
        assert!(next.contains("\"new-owner\""));
    }

    #[test]
    fn duplicate_whole_line_markers_fail_closed() {
        let policy = r#"owner_resource_bindings := {
  # BEGIN CAP MANAGED OWNER BINDINGS
  "first": {"repository": "default"}
  # END CAP MANAGED OWNER BINDINGS
  # BEGIN CAP MANAGED OWNER BINDINGS
  "second": {"repository": "default"}
  # END CAP MANAGED OWNER BINDINGS
}
"#;

        let err = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap_err();
        assert!(matches!(err, KbsPolicyError::MalformedManagedMarkers(_)));
    }

    #[test]
    fn end_marker_without_begin_fails_closed() {
        let policy = r#"owner_resource_bindings := {
  "legacy": {"repository": "default"},
  # END CAP MANAGED OWNER BINDINGS
}
"#;

        let err = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap_err();
        assert!(matches!(err, KbsPolicyError::MalformedManagedMarkers(_)));
    }

    #[test]
    fn binding_assignment_embedded_in_string_is_ignored() {
        // The assignment marker quoted inside a value must not seed the
        // brace matcher; the real line-start assignment is the splice target.
        let policy = r#"package policy

owner_resource_bindings := {
  "doc": "resource_bindings := { is documented"
}

resource_bindings := {
  "legacy": {"repository": "default"}
}
"#;

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-tls")]).unwrap();
        assert!(next.contains("\"doc\""));
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"cap-tls\""));
        // Exactly one real assignment line each, still intact (the third
        // substring match is the doc string, the owner line doubles as a
        // resource_bindings substring match).
        assert_eq!(next.matches("resource_bindings := {").count(), 3);
        assert_eq!(next.matches("owner_resource_bindings := {").count(), 1);
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
    fn signed_policy_body_preserves_persisted_org_keyring_order() {
        let mut artifact = test_signed_policy_artifact("aa", 16);
        artifact.org_keyring = Some(
            serde_json::from_str(
                r#"{"bravo":{"bb":[null,{"cc":3,"a":4}],"a":2},"alpha":2,"zeta":1}"#,
            )
            .unwrap(),
        );

        let ordered_keyring =
            serde_json::to_string(&PostgresJsonb(artifact.org_keyring.as_ref().unwrap())).unwrap();
        let body = signed_policy_artifact_policy_body(&[artifact]).unwrap();

        assert_eq!(
            ordered_keyring,
            r#"{"zeta":1,"alpha":2,"bravo":{"a":2,"bb":[null,{"a":4,"cc":3}]}}"#
        );
        assert!(body.contains(&format!(r#""org_keyring":{ordered_keyring}"#)));
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
        assert_eq!(
            generation_decision(None, None, 3, &"aa".repeat(32), false).unwrap(),
            GenerationDecision::Replace
        );
        assert_eq!(
            generation_decision(
                Some((4, &"bb".repeat(32))),
                Some(&"bb".repeat(32)),
                3,
                &"aa".repeat(32),
                false,
            )
            .unwrap(),
            GenerationDecision::Superseded
        );
        assert_eq!(
            generation_decision(
                Some((4, &"bb".repeat(32))),
                Some(&"bb".repeat(32)),
                1,
                &"aa".repeat(32),
                true,
            )
            .unwrap(),
            GenerationDecision::Replace,
            "durable no-history bootstrap replaces a stale prior-cluster generation"
        );
        assert_eq!(
            generation_decision(
                Some((1, &"bb".repeat(32))),
                Some(&"bb".repeat(32)),
                1,
                &"aa".repeat(32),
                true,
            )
            .unwrap(),
            GenerationDecision::Replace,
            "reset bootstrap replaces an equal generation from a retired database"
        );
        let conflict = generation_decision(
            Some((3, &"bb".repeat(32))),
            Some(&"bb".repeat(32)),
            3,
            &"aa".repeat(32),
            false,
        )
        .unwrap_err();
        assert!(matches!(
            conflict,
            KbsPolicyError::PolicyGenerationConflict {
                existing_generation: Some(3),
                desired_generation: 3,
                ..
            }
        ));
        let message = conflict.to_string();
        assert!(
            message.contains(&"bb".repeat(32)),
            "conflict names the annotated hash: {message}"
        );
        assert!(
            message.contains(&"aa".repeat(32)),
            "conflict names the desired hash: {message}"
        );
        assert_eq!(
            generation_decision(
                Some((3, &"aa".repeat(32))),
                Some(&"bb".repeat(32)),
                3,
                &"aa".repeat(32),
                false,
            )
            .unwrap(),
            GenerationDecision::Replace,
            "a stale content-only overwrite is repaired under the durable hash"
        );
    }

    #[tokio::test]
    async fn signed_policy_bootstrap_generation_is_atomic_and_idempotent() {
        let pool = crate::test_support::database_test_pool().await;
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

    async fn insert_test_deployment_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, status, spec_snapshot, created_at
             ) VALUES ($1, $2, $3, $4::deploy_status_enum, '{}'::jsonb, now())",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(status)
        .execute(&mut **tx)
        .await
        .expect("insert KBS test deployment");
    }

    /// Stamp the durable setup machine a deployment would carry in
    /// spec_snapshot: 'accepted' once setup finished (the apply phase was
    /// entered), 'dns_pending' while still queued. Supersession never
    /// rewrites it, which is exactly why the selector can trust it.
    async fn set_test_setup_state(pool: &PgPool, deployment_id: Uuid, state: &str) {
        sqlx::query(
            "UPDATE deployments
                SET spec_snapshot = jsonb_set(
                        spec_snapshot,
                        '{setup_state}',
                        to_jsonb($2::text),
                        true
                    )
              WHERE id = $1",
        )
        .bind(deployment_id)
        .bind(state)
        .execute(pool)
        .await
        .expect("stamp KBS test setup state");
    }

    async fn insert_test_artifact(
        pool: &PgPool,
        app_id: Uuid,
        deployment_id: Uuid,
        hash_byte: &str,
    ) -> crate::signing_service::SignedPolicyArtifact {
        insert_test_artifact_signed_by(pool, app_id, deployment_id, hash_byte, "bb").await
    }

    /// Like insert_test_artifact, but lets each fixture pick its descriptor
    /// signer so keyring-rotation tests can distinguish removed and remaining
    /// members.
    async fn insert_test_artifact_signed_by(
        pool: &PgPool,
        app_id: Uuid,
        deployment_id: Uuid,
        hash_byte: &str,
        signer_hex: &str,
    ) -> crate::signing_service::SignedPolicyArtifact {
        let mut artifact = test_signed_policy_artifact(hash_byte, 16);
        artifact.metadata.app_id = app_id.to_string();
        artifact.metadata.deploy_id = deployment_id.to_string();
        artifact.metadata.descriptor_signing_pubkey = signer_hex.repeat(32);
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

    /// Insert one append-only org keyring version. The first member is the
    /// owner; the raw signature bytes are irrelevant to candidate selection.
    /// Returns the ids of the user and signing key rows it created so callers
    /// can clean them up without touching other tests' fixtures.
    async fn insert_test_keyring_version(
        pool: &PgPool,
        org_id: Uuid,
        version: i64,
        member_pubkeys: &[&str],
    ) -> (Uuid, Uuid) {
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'kbs keyring member')")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("insert KBS keyring user");
        let signing_key_id = Uuid::new_v4();
        sqlx::query("INSERT INTO user_signing_keys (id, user_id, pubkey) VALUES ($1, $2, $3)")
            .bind(signing_key_id)
            .bind(user_id)
            .bind(hex::decode(member_pubkeys[0]).expect("decode owner keyring pubkey"))
            .execute(pool)
            .await
            .expect("insert KBS keyring signing key");
        let members: Vec<serde_json::Value> = member_pubkeys
            .iter()
            .enumerate()
            .map(|(index, pubkey)| {
                serde_json::json!({
                    "user_id": user_id,
                    "pubkey": pubkey,
                    "role": if index == 0 { "owner" } else { "deployer" },
                    "added_at": "2026-01-01T00:00:00Z",
                })
            })
            .collect();
        let keyring = serde_json::json!({
            "org_id": org_id,
            "version": version,
            "members": members,
            "updated_at": "2026-01-01T00:00:00Z",
        });
        sqlx::query(
            "INSERT INTO org_keyrings (
                 org_id, version, keyring_payload, signature, signing_key_id
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(version)
        .bind(serde_json::to_vec(&keyring).expect("serialize test keyring"))
        .bind(vec![9u8; 64])
        .bind(signing_key_id)
        .execute(pool)
        .await
        .expect("insert KBS test keyring version");
        (user_id, signing_key_id)
    }

    #[tokio::test]
    async fn selector_uses_current_operation_binding_and_legacy_fallback() {
        // Candidate selection reads every org's artifacts, so on the shared
        // test database foreign fixtures leak into the exact assertions below
        // (the all(required) check would break on another test's retained
        // historical row).  Run against a per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_selector_ops").await;
        let now = Utc::now();
        // test_signed_policy_artifact signs every fixture with this pubkey.
        let signer = "bb".repeat(32);

        // A rollback operation points to an older exact artifact. It must rank
        // ahead of a newer historical artifact for the same app.
        let (rollback_org, rollback_app) = insert_test_app(&pool, "running").await;
        let mut fixture_users = Vec::new();
        fixture_users.push(insert_test_keyring_version(&pool, rollback_org, 1, &[&signer]).await);
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
        fixture_users.push(insert_test_keyring_version(&pool, legacy_org, 1, &[&signer]).await);
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, legacy_org, legacy_app, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, legacy_app, legacy, "cc").await;

        // A retry is current authority even before its stale failed app
        // projection advances to creating.
        let (retry_org, retry_app) = insert_test_app(&pool, "failed").await;
        fixture_users.push(insert_test_keyring_version(&pool, retry_org, 1, &[&signer]).await);
        let retry = Uuid::new_v4();
        insert_test_deployment(&pool, retry_org, retry_app, retry, "healthy", now).await;
        let retry_artifact = insert_test_artifact(&pool, retry_app, retry, "34").await;
        insert_test_job(
            &pool,
            retry_org,
            retry_app,
            retry,
            retry,
            Some((retry, &retry_artifact)),
        )
        .await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'pending'
              WHERE deployment_id = $1",
        )
        .bind(retry)
        .execute(&pool)
        .await
        .expect("make signed retry job pending");
        sqlx::query(
            "UPDATE deployments
                SET status = 'pending'::deploy_status_enum
              WHERE id = $1",
        )
        .bind(retry)
        .execute(&pool)
        .await
        .expect("make signed retry pending");

        // Failed/deleting latest operations, and an app whose current
        // generation is unsigned, must contribute no historical authorization.
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
        assert!(hashes.contains(source_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(hashes.contains(legacy_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(hashes.contains(retry_artifact.metadata.descriptor_core_hash.as_str()));
        for excluded in [
            &newer_artifact,
            &failed_artifact,
            &deleting_artifact,
            &failed_job_artifact,
            &old_artifact,
        ] {
            assert!(!hashes.contains(excluded.metadata.descriptor_core_hash.as_str()));
        }
        assert!(candidates.iter().all(|candidate| candidate.required));

        for org_id in [
            rollback_org,
            legacy_org,
            retry_org,
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
        for (user_id, signing_key_id) in fixture_users {
            sqlx::query("DELETE FROM user_signing_keys WHERE id = $1")
                .bind(signing_key_id)
                .execute(&pool)
                .await
                .expect("delete KBS selector fixture signing key");
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&pool)
                .await
                .expect("delete KBS selector fixture user");
        }
        crate::test_support::drop_isolated_database("cap130_selector_ops", pool).await;
    }

    /// Regression coverage for the #130 keyring-rotation generation bump.
    /// Runs against its own uniquely named per-process database (see
    /// [`crate::test_support::isolated_database_test_pool`]): this test asserts
    /// exact `kbs_signed_policy_reconciliation` singleton values and resets
    /// them, and on the shared test database another test process (a sibling
    /// CI worktree on the same PostgreSQL server) could bump the generation
    /// between this test's commit and its exact assertion, or have its own
    /// state clobbered by this test's final reset.  The process-local
    /// `SIGNED_POLICY_SINGLETON_LOCK` cannot fence across processes.
    #[tokio::test]
    async fn keyring_rotation_enqueues_signed_policy_reconciliation_only_when_active() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_rotation_enqueue").await;

        // Unsigned-only installs must not enter signed-policy mode.
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
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(
            enqueue_signed_policy_reconciliation_if_active(&mut tx)
                .await
                .unwrap()
                .is_none(),
            "idle installation must not enqueue a signed-policy generation"
        );
        tx.rollback().await.unwrap();

        // Once signed mode is active, every keyring rotation must bump the
        // generation so the reconciler withdraws rotated-out artifacts
        // (#130): the changed candidate set at an unchanged generation would
        // otherwise be rejected as a content conflict.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let bumped = enqueue_signed_policy_reconciliation_if_active(&mut tx)
            .await
            .unwrap()
            .expect("active installation enqueues a new generation");
        assert_eq!(bumped, 2);
        tx.commit().await.unwrap();
        let desired: i64 = sqlx::query_scalar(
            "SELECT desired_generation
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(desired, 2);

        crate::test_support::drop_isolated_database("cap130_rotation_enqueue", pool).await;
    }

    /// Migration 0050 marks its owed selector generation bump instead of
    /// performing it, so a pre-0050 replica still reconciling during the
    /// rollout cannot consume the bump with its unfiltered candidate query.
    /// Only the post-0050 reconciler interprets the marker, exactly once --
    /// and only after the filtered policy body is published
    /// (commit_deferred_selector_bump) -- and never on behalf of an
    /// unsigned-only install, which clear_stray_selector_bump disarms without
    /// bumping.  What this test pins down.  Runs against its own per-process
    /// database: like the rotation test, it asserts exact singleton state that
    /// another test process could perturb through the shared server.
    #[tokio::test]
    async fn deferred_selector_bump_is_committed_once_by_the_filtered_reconciler() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_selector_bump").await;
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    selector_bump_pending = false
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Nothing marked: committing is a no-op.
        assert_eq!(commit_deferred_selector_bump(&pool).await.unwrap(), None);

        // Migration 0050 marks signed-mode installs; the post-publication
        // commit performs the bump exactly once and clears the marker.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 3,
                    selector_bump_pending = true
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(commit_deferred_selector_bump(&pool).await.unwrap(), Some(4));
        let (desired, pending): (i64, bool) = sqlx::query_as(
            "SELECT desired_generation, selector_bump_pending
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, pending), (4, false));
        assert_eq!(commit_deferred_selector_bump(&pool).await.unwrap(), None);

        // A stray marker on an unsigned-only install must never push it into
        // signed-policy mode: the commit refuses to bump it (and leaves the
        // marker for the stray cleanup), and clear_stray_selector_bump then
        // disarms it without touching desired_generation.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    selector_bump_pending = true
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(commit_deferred_selector_bump(&pool).await.unwrap(), None);
        clear_stray_selector_bump(&pool).await.unwrap();
        let (desired, pending): (i64, bool) = sqlx::query_as(
            "SELECT desired_generation, selector_bump_pending
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, pending), (0, false));

        crate::test_support::drop_isolated_database("cap130_selector_bump", pool).await;
    }

    /// Regression for #130: a retained historical artifact must stop
    /// authorizing KBS policy as soon as its signer is no longer a member of
    /// the org's current keyring generation, even though the immutable
    /// workload_artifacts row survives the retention window.
    #[tokio::test]
    async fn selector_drops_artifacts_whose_signer_left_the_current_keyring() {
        // Same isolation as the selector operations test: candidate selection
        // is global across orgs, and the shared test database would leak other
        // tests' fixtures into these assertions.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_selector_rotation").await;
        let now = Utc::now();
        let signer = "bb".repeat(32);
        let remaining = "cd".repeat(32);
        let rotated_owner = "ab".repeat(32);

        // Job-backed app: the current operation binds an artifact signed by a
        // remaining member, while an older historical artifact (still inside
        // the retention window) was signed by the since-removed signer.
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let mut fixture_users = Vec::new();
        fixture_users
            .push(insert_test_keyring_version(&pool, org_id, 1, &[&remaining, &signer]).await);
        let historical = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, historical, "healthy", now).await;
        let stale_artifact =
            insert_test_artifact_signed_by(&pool, app_id, historical, "9a", "bb").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            historical,
            historical,
            Some((historical, &stale_artifact)),
        )
        .await;
        let deployment = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            deployment,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let artifact = insert_test_artifact_signed_by(&pool, app_id, deployment, "9b", "cd").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            deployment,
            deployment,
            Some((deployment, &artifact)),
        )
        .await;

        let selected = |candidates: &Vec<SignedPolicyArtifactCandidate>| {
            candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == artifact.metadata.descriptor_core_hash
            })
        };
        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select pre-rotation candidates");
        assert!(
            selected(&candidates),
            "artifact signed by a current keyring member must be a candidate"
        );

        // Keyring rotation removes the signer while the remaining member's
        // artifact stays live: the stale historical artifact must no longer be
        // re-admitted into the KBS policy authority set, and the remaining
        // member's artifact must survive the rotation.
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.artifact.metadata.descriptor_core_hash
                    == stale_artifact.metadata.descriptor_core_hash),
            "pre-rotation, the historical artifact inside the retention window is a candidate"
        );
        fixture_users.push(
            insert_test_keyring_version(&pool, org_id, 2, &[&remaining, &rotated_owner]).await,
        );
        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select post-rotation candidates");
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.artifact.metadata.descriptor_core_hash
                    == stale_artifact.metadata.descriptor_core_hash),
            "historical artifact whose signer was removed by keyring rotation must not be re-admitted"
        );
        assert!(
            selected(&candidates),
            "current artifact signed by a remaining member must survive the rotation"
        );

        // The same fence applies to pre-0038 legacy deployments without jobs.
        let (legacy_org, legacy_app) = insert_test_app(&pool, "running").await;
        fixture_users.push(insert_test_keyring_version(&pool, legacy_org, 1, &[&signer]).await);
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, legacy_org, legacy_app, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, legacy_app, legacy, "9c").await;
        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select pre-rotation legacy candidates");
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.artifact.metadata.descriptor_core_hash
                    == legacy_artifact.metadata.descriptor_core_hash),
            "legacy artifact signed by a current keyring member must be a candidate"
        );
        fixture_users
            .push(insert_test_keyring_version(&pool, legacy_org, 2, &[&rotated_owner]).await);
        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select post-rotation legacy candidates");
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.artifact.metadata.descriptor_core_hash
                    == legacy_artifact.metadata.descriptor_core_hash),
            "legacy artifact whose signer was removed must not be re-admitted"
        );

        for cleanup_org in [org_id, legacy_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete keyring rotation fixture");
        }
        for (user_id, signing_key_id) in fixture_users {
            sqlx::query("DELETE FROM user_signing_keys WHERE id = $1")
                .bind(signing_key_id)
                .execute(&pool)
                .await
                .expect("delete keyring rotation fixture signing key");
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&pool)
                .await
                .expect("delete keyring rotation fixture user");
        }
        crate::test_support::drop_isolated_database("cap130_selector_rotation", pool).await;
    }

    /// Fail closed for #130: an org with retained artifacts but no keyring row
    /// at all must contribute no authorization -- the INNER JOIN drops it, and
    /// the deferred selector bump publishes exactly that withdrawal on upgrade.
    #[tokio::test]
    async fn selector_fails_closed_for_orgs_without_a_keyring() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_selector_fail_closed").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let deployment = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, deployment, "healthy", Utc::now()).await;
        let artifact = insert_test_artifact(&pool, app_id, deployment, "42").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            deployment,
            deployment,
            Some((deployment, &artifact)),
        )
        .await;
        // No org_keyrings row is ever inserted for this org.
        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select candidates without a keyring");
        assert!(
            !candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == artifact.metadata.descriptor_core_hash
            }),
            "artifacts of an org without any keyring row must contribute no authority"
        );
        crate::test_support::drop_isolated_database("cap130_selector_fail_closed", pool).await;
    }

    #[tokio::test]
    async fn legacy_authority_survives_while_the_only_durable_job_is_an_unreleased_hold() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, app_id, legacy, "9a").await;

        // The app's first durable job is a held redeploy that has not been
        // released. The previous healthy deployment must stay authoritative,
        // including after the hold expires failed.
        let held = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            held,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        insert_test_job(&pool, org_id, app_id, held, held, None).await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'setup_pending',
                    customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() + interval '1 hour',
                    next_attempt_at = 'infinity'::timestamptz
              WHERE deployment_id = $1",
        )
        .bind(held)
        .execute(&pool)
        .await
        .expect("hold the redeploy job");
        sqlx::query("UPDATE deployments SET status = 'pending' WHERE id = $1")
            .bind(held)
            .execute(&pool)
            .await
            .expect("mark the held deployment pending after its durable job exists");

        let held_candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority while the roll is held");
        assert!(
            held_candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == legacy_artifact.metadata.descriptor_core_hash
            }),
            "the legacy artifact stays eligible while the only durable job is an unreleased hold"
        );

        // Releasing the hold starts the replacement's delayed apply, but the
        // legacy TEE is still the running workload until that replacement is
        // healthy, so its authority must stay selected and required through
        // the handoff.
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET customer_config_released_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(held)
        .execute(&pool)
        .await
        .expect("release the held job");
        let released_candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after the hold is released");
        assert!(
            released_candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == legacy_artifact.metadata.descriptor_core_hash
                    && candidate.required
            }),
            "the legacy artifact stays required until the released replacement is healthy"
        );

        sqlx::query(
            "WITH failed AS (
                UPDATE deployments SET status = 'failed' WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs SET state = 'failed'
              WHERE deployment_id IN (SELECT id FROM failed)",
        )
        .bind(held)
        .execute(&pool)
        .await
        .expect("fail replacement before apply");
        let failed_candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after setup failure");
        assert!(failed_candidates.iter().any(|candidate| {
            candidate.artifact.metadata.descriptor_core_hash
                == legacy_artifact.metadata.descriptor_core_hash
                && candidate.required
        }));

        sqlx::query(
            "WITH healthy AS (
                UPDATE deployments SET status = 'healthy' WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs SET state = 'completed'
              WHERE deployment_id IN (SELECT id FROM healthy)",
        )
        .bind(held)
        .execute(&pool)
        .await
        .expect("complete the released replacement's handoff");
        let settled_candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after the handoff");
        assert!(
            !settled_candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == legacy_artifact.metadata.descriptor_core_hash
            }),
            "the legacy artifact stops being selected once the replacement is healthy"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete KBS hold fixture");
    }

    #[tokio::test]
    async fn selector_drops_artifacts_withdrawn_by_signer_rotation() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let current = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, current, "healthy", now).await;
        // A per-run hash byte avoids PK collisions with leftover fixtures on
        // the shared regression database.
        let hash_byte = format!("{:02x}", app_id.as_bytes()[0]);
        let current_artifact = insert_test_artifact(&pool, app_id, current, &hash_byte).await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            current,
            current,
            Some((current, &current_artifact)),
        )
        .await;

        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select pre-rotation candidates");
        assert!(candidates.iter().any(|candidate| {
            candidate.artifact.metadata.descriptor_core_hash
                == current_artifact.metadata.descriptor_core_hash
        }));

        // Signer rotation withdraws every artifact signed under the previous
        // identity (issue #119): the withdrawal row is recorded and the
        // selector must refuse the hash on every path. (The runtime
        // subject/issuer predicate itself is exercised end-to-end by the
        // rotate_signer route test.)
        let mut tx = pool.begin().await.expect("begin withdrawal tx");
        sqlx::query(
            "INSERT INTO withdrawn_signer_artifacts (descriptor_core_hash, app_id)
             SELECT descriptor_core_hash, app_id
               FROM workload_artifacts
              WHERE descriptor_core_hash = $1
              ON CONFLICT DO NOTHING",
        )
        .bind(hex::decode(&current_artifact.metadata.descriptor_core_hash).unwrap())
        .execute(&mut *tx)
        .await
        .expect("withdraw rotated-out artifact");
        tx.commit().await.expect("commit withdrawal");

        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select post-rotation candidates");
        assert!(candidates.iter().all(|candidate| {
            candidate.artifact.metadata.descriptor_core_hash
                != current_artifact.metadata.descriptor_core_hash
        }));

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete signer rotation fixture");
    }

    fn required(
        candidates: &[SignedPolicyArtifactCandidate],
        artifact: &crate::signing_service::SignedPolicyArtifact,
    ) {
        let matched = candidates.iter().find(|candidate| {
            candidate.artifact.metadata.descriptor_core_hash
                == artifact.metadata.descriptor_core_hash
        });
        assert!(
            matched.is_some_and(|candidate| candidate.required),
            "artifact {} must stay required",
            &artifact.metadata.descriptor_core_hash[..2]
        );
    }

    fn absent(
        candidates: &[SignedPolicyArtifactCandidate],
        artifact: &crate::signing_service::SignedPolicyArtifact,
    ) {
        assert!(
            candidates.iter().all(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    != artifact.metadata.descriptor_core_hash
            }),
            "artifact {} must not be selected",
            &artifact.metadata.descriptor_core_hash[..2]
        );
    }

    #[tokio::test]
    async fn replacement_handoff_keeps_running_authority_required_until_healthy() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        // A signed replacement released from its hold whose apply has not
        // completed.
        let (signed_org, signed_app) = insert_test_app(&pool, "running").await;
        let signed_running = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            signed_org,
            signed_app,
            signed_running,
            "healthy",
            now,
        )
        .await;
        let signed_running_artifact =
            insert_test_artifact(&pool, signed_app, signed_running, "0d").await;
        insert_test_job(
            &pool,
            signed_org,
            signed_app,
            signed_running,
            signed_running,
            Some((signed_running, &signed_running_artifact)),
        )
        .await;
        let signed_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            signed_org,
            signed_app,
            signed_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let signed_replacement_artifact =
            insert_test_artifact(&pool, signed_app, signed_replacement, "1e").await;
        insert_test_job(
            &pool,
            signed_org,
            signed_app,
            signed_replacement,
            signed_replacement,
            Some((signed_replacement, &signed_replacement_artifact)),
        )
        .await;
        sqlx::query(
            "WITH pending_deployment AS (
                 UPDATE deployments SET status = 'pending'::deploy_status_enum
                  WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'pending',
                    customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() - interval '1 second',
                    customer_config_released_at = clock_timestamp()
              WHERE deployment_id IN (SELECT id FROM pending_deployment)",
        )
        .bind(signed_replacement)
        .execute(&pool)
        .await
        .expect("release the signed replacement from its hold");

        // An unsigned replacement: the running TEE is the only signed
        // authority for this app until the handoff completes.
        let (unsigned_org, unsigned_app) = insert_test_app(&pool, "running").await;
        let unsigned_running = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            unsigned_org,
            unsigned_app,
            unsigned_running,
            "healthy",
            now,
        )
        .await;
        let unsigned_running_artifact =
            insert_test_artifact(&pool, unsigned_app, unsigned_running, "2f").await;
        insert_test_job(
            &pool,
            unsigned_org,
            unsigned_app,
            unsigned_running,
            unsigned_running,
            Some((unsigned_running, &unsigned_running_artifact)),
        )
        .await;
        let unsigned_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            unsigned_org,
            unsigned_app,
            unsigned_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        insert_test_job(
            &pool,
            unsigned_org,
            unsigned_app,
            unsigned_replacement,
            unsigned_replacement,
            None,
        )
        .await;
        sqlx::query(
            "WITH pending_deployment AS (
                 UPDATE deployments SET status = 'pending'::deploy_status_enum
                  WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'pending',
                    customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() - interval '1 second',
                    customer_config_released_at = clock_timestamp()
              WHERE deployment_id IN (SELECT id FROM pending_deployment)",
        )
        .bind(unsigned_replacement)
        .execute(&pool)
        .await
        .expect("release the unsigned replacement from its hold");

        // A replacement whose hold expired without release: the running
        // workload must stay authoritative without applying.
        let (held_org, held_app) = insert_test_app(&pool, "running").await;
        let held_running = Uuid::new_v4();
        insert_test_deployment(&pool, held_org, held_app, held_running, "healthy", now).await;
        let held_running_artifact = insert_test_artifact(&pool, held_app, held_running, "3a").await;
        insert_test_job(
            &pool,
            held_org,
            held_app,
            held_running,
            held_running,
            Some((held_running, &held_running_artifact)),
        )
        .await;
        let held_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            held_org,
            held_app,
            held_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let held_replacement_artifact =
            insert_test_artifact(&pool, held_app, held_replacement, "4b").await;
        insert_test_job(
            &pool,
            held_org,
            held_app,
            held_replacement,
            held_replacement,
            Some((held_replacement, &held_replacement_artifact)),
        )
        .await;
        sqlx::query(
            "WITH pending_deployment AS (
                 UPDATE deployments SET status = 'pending'::deploy_status_enum
                  WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'setup_pending',
                    customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() - interval '1 second',
                    next_attempt_at = 'infinity'::timestamptz
              WHERE deployment_id IN (SELECT id FROM pending_deployment)",
        )
        .bind(held_replacement)
        .execute(&pool)
        .await
        .expect("arm the unreleased expired hold");

        let handoff = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority while applies are delayed");
        required(&handoff, &signed_running_artifact);
        required(&handoff, &signed_replacement_artifact);
        required(&handoff, &unsigned_running_artifact);
        required(&handoff, &held_running_artifact);
        absent(&handoff, &held_replacement_artifact);

        // Default retention (6) must not admit the unreleased hold's
        // pending artifact as an optional historical candidate; at
        // retention 1 the same absence is mere eviction, not exclusion.
        let default_retention =
            load_signed_policy_candidates(&pool, DEFAULT_SIGNED_POLICY_RETENTION)
                .await
                .expect("select authority at default retention");
        required(&default_retention, &held_running_artifact);
        required(&default_retention, &signed_replacement_artifact);
        absent(&default_retention, &held_replacement_artifact);

        // With a byte budget that fits only one authority, keeping both
        // required must fail the selection instead of evicting the running
        // workload's authority.
        let single_body =
            signed_policy_artifact_policy_body(std::slice::from_ref(&signed_running_artifact))
                .expect("render one authority")
                .len();
        let signed_app_id = signed_app.to_string();
        let signed_candidates: Vec<SignedPolicyArtifactCandidate> = handoff
            .iter()
            .filter(|candidate| candidate.artifact.metadata.app_id == signed_app_id)
            .map(|candidate| {
                signed_policy_candidate(candidate.artifact.clone(), candidate.required)
            })
            .collect();
        assert_eq!(
            signed_candidates.len(),
            2,
            "both the running and replacement authorities are candidates"
        );
        let tight =
            select_signed_policy_artifacts_for_policy_body(signed_candidates, single_body + 32)
                .unwrap_err();
        assert!(matches!(
            tight,
            KbsPolicyError::SignedPolicyBudgetExceeded { .. }
        ));

        for deployment_id in [signed_replacement, unsigned_replacement] {
            sqlx::query(
                "WITH failed AS (
                    UPDATE deployments SET status = 'failed' WHERE id = $1 RETURNING id
                 )
                 UPDATE deployment_apply_jobs SET state = 'failed'
                  WHERE deployment_id IN (SELECT id FROM failed)",
            )
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("fail replacement before apply");
        }
        let failed = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after setup failure");
        required(&failed, &signed_running_artifact);
        required(&failed, &unsigned_running_artifact);
        absent(&failed, &signed_replacement_artifact);

        // The handoff completes for both released replacements: the
        // replacement becomes the running workload and the old authority is
        // no longer required.
        for deployment_id in [signed_replacement, unsigned_replacement] {
            sqlx::query(
                "WITH healthy AS (
                    UPDATE deployments SET status = 'healthy' WHERE id = $1 RETURNING id
                 )
                 UPDATE deployment_apply_jobs SET state = 'completed'
                  WHERE deployment_id IN (SELECT id FROM healthy)",
            )
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("complete the replacement handoff");
        }
        let settled = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after the handoff");
        required(&settled, &signed_replacement_artifact);
        absent(&settled, &signed_running_artifact);
        absent(&settled, &unsigned_running_artifact);

        // An expired hold never rolls: the running workload keeps its
        // required authority after the sweep fails the held deployment.
        let expired = crate::deployment_jobs::expire_customer_config_holds(&pool)
            .await
            .expect("sweep the expired hold");
        assert!(expired >= 1);
        let swept = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select authority after the expired hold");
        required(&swept, &held_running_artifact);
        absent(&swept, &held_replacement_artifact);

        for org_id in [signed_org, unsigned_org, held_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .expect("delete KBS handoff fixture");
        }
    }

    // Mirror the committed failure state without bypassing the runner's private lease API.
    async fn fail_replacement_in_apply(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
    ) {
        let deployment = sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum,
                    error_message = 'deployment_apply_failed',
                    completed_at = clock_timestamp()
              WHERE id = $1
                AND app_id = $2
                AND org_id = $3
                AND status IN ('pending', 'applying', 'watching')",
        )
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .execute(pool)
        .await
        .expect("fail the replacement deployment");
        assert_eq!(
            deployment.rows_affected(),
            1,
            "fixture replacement must be mid-apply"
        );

        let job = sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'failed',
                    lock_token = NULL,
                    locked_until = NULL,
                    last_error_code = 'deployment_apply_failed'
              WHERE deployment_id = $1
                AND state = 'running'",
        )
        .bind(deployment_id)
        .execute(pool)
        .await
        .expect("fail the replacement job");
        assert_eq!(job.rows_affected(), 1, "fixture job must be running");
    }

    // Seed the post-release apply state without violating deferred job constraints.
    async fn arm_released_replacement_job(pool: &PgPool, deployment_id: Uuid) {
        sqlx::query(
            "WITH applying AS (
                 UPDATE deployments SET status = 'applying' WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'running',
                    lock_token = gen_random_uuid(),
                    locked_until = clock_timestamp() + interval '1 minute',
                    customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() + interval '1 minute',
                    customer_config_released_at = clock_timestamp()
              WHERE deployment_id IN (SELECT id FROM applying)",
        )
        .bind(deployment_id)
        .execute(pool)
        .await
        .expect("arm the released replacement job");
    }

    #[tokio::test]
    async fn failed_replacement_keeps_running_authority_until_confirmed_takeover() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        // The released replacement of a signed workload fails mid-apply:
        // the publication marks the app failed while the prior healthy
        // deployment's TEE keeps running.
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let running = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, running, "healthy", now).await;
        let running_artifact = insert_test_artifact(&pool, app_id, running, "5c").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            running,
            running,
            Some((running, &running_artifact)),
        )
        .await;
        let replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let replacement_artifact = insert_test_artifact(&pool, app_id, replacement, "6d").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            replacement,
            replacement,
            Some((replacement, &replacement_artifact)),
        )
        .await;
        arm_released_replacement_job(&pool, replacement).await;
        fail_replacement_in_apply(&pool, org_id, app_id, replacement).await;
        sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1
                AND org_id = $2
                AND status <> 'deleting'::app_status_enum",
        )
        .bind(app_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("publish the app failure");

        // The same failed replacement against a pre-job legacy workload.
        let (legacy_org, legacy_app) = insert_test_app(&pool, "running").await;
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, legacy_org, legacy_app, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, legacy_app, legacy, "7e").await;
        let legacy_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            legacy_org,
            legacy_app,
            legacy_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let legacy_replacement_artifact =
            insert_test_artifact(&pool, legacy_app, legacy_replacement, "8f").await;
        insert_test_job(
            &pool,
            legacy_org,
            legacy_app,
            legacy_replacement,
            legacy_replacement,
            Some((legacy_replacement, &legacy_replacement_artifact)),
        )
        .await;
        arm_released_replacement_job(&pool, legacy_replacement).await;
        fail_replacement_in_apply(&pool, legacy_org, legacy_app, legacy_replacement).await;
        sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1
                AND org_id = $2
                AND status <> 'deleting'::app_status_enum",
        )
        .bind(legacy_app)
        .bind(legacy_org)
        .execute(&pool)
        .await
        .expect("publish the legacy app failure");

        // Explicit stop and deletion override the preservation even though
        // the prior deployment stays healthy.
        let (stopped_org, stopped_app) = insert_test_app(&pool, "stopped").await;
        let stopped_running = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            stopped_org,
            stopped_app,
            stopped_running,
            "healthy",
            now,
        )
        .await;
        let stopped_artifact =
            insert_test_artifact(&pool, stopped_app, stopped_running, "a1").await;
        insert_test_job(
            &pool,
            stopped_org,
            stopped_app,
            stopped_running,
            stopped_running,
            Some((stopped_running, &stopped_artifact)),
        )
        .await;
        let stopped_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            stopped_org,
            stopped_app,
            stopped_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        insert_test_job(
            &pool,
            stopped_org,
            stopped_app,
            stopped_replacement,
            stopped_replacement,
            None,
        )
        .await;
        arm_released_replacement_job(&pool, stopped_replacement).await;
        fail_replacement_in_apply(&pool, stopped_org, stopped_app, stopped_replacement).await;

        let (deleting_org, deleting_app) = insert_test_app(&pool, "deleting").await;
        let deleting_running = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            deleting_org,
            deleting_app,
            deleting_running,
            "healthy",
            now,
        )
        .await;
        let deleting_artifact =
            insert_test_artifact(&pool, deleting_app, deleting_running, "b2").await;
        insert_test_job(
            &pool,
            deleting_org,
            deleting_app,
            deleting_running,
            deleting_running,
            Some((deleting_running, &deleting_artifact)),
        )
        .await;
        let deleting_replacement = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            deleting_org,
            deleting_app,
            deleting_replacement,
            "healthy",
            now + chrono::Duration::seconds(1),
        )
        .await;
        insert_test_job(
            &pool,
            deleting_org,
            deleting_app,
            deleting_replacement,
            deleting_replacement,
            None,
        )
        .await;
        arm_released_replacement_job(&pool, deleting_replacement).await;
        fail_replacement_in_apply(&pool, deleting_org, deleting_app, deleting_replacement).await;

        // A failed app with no prior healthy workload authorizes nothing.
        let (fresh_org, fresh_app) = insert_test_app(&pool, "failed").await;
        let only = Uuid::new_v4();
        insert_test_deployment(&pool, fresh_org, fresh_app, only, "failed", now).await;
        let only_artifact = insert_test_artifact(&pool, fresh_app, only, "c3").await;
        insert_test_job(
            &pool,
            fresh_org,
            fresh_app,
            only,
            only,
            Some((only, &only_artifact)),
        )
        .await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'failed', last_error_code = 'deployment_apply_failed'
              WHERE deployment_id = $1",
        )
        .bind(only)
        .execute(&pool)
        .await
        .expect("fail the only job");

        let failed = load_signed_policy_candidates(&pool, DEFAULT_SIGNED_POLICY_RETENTION)
            .await
            .expect("select authority after the failed replacement");
        required(&failed, &running_artifact);
        absent(&failed, &replacement_artifact);
        required(&failed, &legacy_artifact);
        absent(&failed, &legacy_replacement_artifact);
        absent(&failed, &stopped_artifact);
        absent(&failed, &deleting_artifact);
        absent(&failed, &only_artifact);

        // A retry of the failed app is admitted early while the prior
        // healthy authority stays required through the handoff.
        let retry = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            retry,
            "healthy",
            now + chrono::Duration::seconds(2),
        )
        .await;
        let retry_artifact = insert_test_artifact(&pool, app_id, retry, "d4").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            retry,
            retry,
            Some((retry, &retry_artifact)),
        )
        .await;
        sqlx::query(
            "WITH pending AS (
                 UPDATE deployments SET status = 'pending' WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'pending'
              WHERE deployment_id IN (SELECT id FROM pending)",
        )
        .bind(retry)
        .execute(&pool)
        .await
        .expect("make the retry pending");
        let retried = load_signed_policy_candidates(&pool, DEFAULT_SIGNED_POLICY_RETENTION)
            .await
            .expect("select authority while the retry is in flight");
        required(&retried, &running_artifact);
        required(&retried, &retry_artifact);
        absent(&retried, &replacement_artifact);

        // Healthy takeover ends mandatory retention of the prior authority.
        sqlx::query(
            "WITH healthy AS (
                 UPDATE deployments
                    SET status = 'healthy'::deploy_status_enum
                  WHERE id = $1 RETURNING id
             )
             UPDATE deployment_apply_jobs
                SET state = 'completed'
              WHERE deployment_id IN (SELECT id FROM healthy)",
        )
        .bind(retry)
        .execute(&pool)
        .await
        .expect("complete the retry takeover");
        sqlx::query(
            "UPDATE apps
                SET status = 'running'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1 AND org_id = $2",
        )
        .bind(app_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("restore the app to running");
        let settled = load_signed_policy_candidates(&pool, DEFAULT_SIGNED_POLICY_RETENTION)
            .await
            .expect("select authority after the confirmed takeover");
        required(&settled, &retry_artifact);
        assert!(!settled.iter().any(|candidate| {
            candidate.artifact.metadata.descriptor_core_hash
                == running_artifact.metadata.descriptor_core_hash
                && candidate.required
        }));
        absent(&settled, &replacement_artifact);

        for cleanup_org in [org_id, legacy_org, stopped_org, deleting_org, fresh_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete KBS failure fixture");
        }
    }

    /// Migration 0052 owes signer-withdrawal generation bumps in a counter
    /// instead of performing them, so a pre-0052 replica still reconciling
    /// during the rollout cannot consume the bump with its unfiltered
    /// candidate query.  Only the post-0052 reconciler interprets the debt
    /// -- exactly once per observed (desired, owed) pair, and only after
    /// the withdrawal-filtered policy body is published
    /// (consume_deferred_withdrawal_bumps).  A rotation landing between
    /// the reconciler's state read and its consumption (the review
    /// interleaving: a pre-0052 replica's rotate_signer committing after
    /// candidates were loaded) increments the counter, fails the CAS, and
    /// forces republication at a strictly higher generation -- never a
    /// same-generation conflict on a stale candidate set.  A stray debt on
    /// an unsigned-only install is disarmed by
    /// clear_stray_withdrawal_debt without entering signed-policy mode.
    /// Runs against its own per-process database: it asserts exact
    /// singleton state that another test process could perturb through the
    /// shared server.
    #[tokio::test]
    async fn deferred_withdrawal_bumps_are_cas_committed_once_by_the_withdrawal_aware_reconciler() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap119_withdrawal_bump").await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        // Pin a complete previous identity; the initial (NULL -> identity)
        // set owes nothing (migration 0052's trigger WHEN guard).
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = $1,
                    signer_identity_issuer  = $2
              WHERE id = $3",
        )
        .bind("old-subject")
        .bind("old-issuer")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();

        // Nothing owed: consuming is a no-op.
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 0, 0).await.unwrap(),
            None
        );

        // Migration 0052 marks signed-mode installs with one owed bump; the
        // post-publication commit lands exactly the observed pair.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 3,
                    withdrawal_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 3, 1).await.unwrap(),
            Some(4)
        );
        let (desired, owed): (i64, i64) = sqlx::query_as(
            "SELECT desired_generation, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, owed), (4, 0));
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 4, 0).await.unwrap(),
            None
        );

        // The review interleaving: the reconciler observed (3, 1) and
        // published at 4, but a pre-0052 replica's rotate_signer committed
        // in between -- migration 0052's apps trigger owed that write a
        // bump too.  The stale CAS must fail and leave the debt for the
        // retry, which republishes at a strictly higher generation.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 3,
                    withdrawal_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        // The old replica's rotation lands mid-run: debt grows to 2.
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = 'new-subject'
              WHERE id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 3, 1).await.unwrap(),
            None,
            "a mid-run rotation must fail the CAS and leave the debt"
        );
        let (desired, owed): (i64, i64) = sqlx::query_as(
            "SELECT desired_generation, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (desired, owed),
            (3, 2),
            "both bumps remain owed to the retry"
        );
        // The retry observes the full debt and lands it in one commit.
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 3, 2).await.unwrap(),
            Some(5)
        );

        // A stray debt on an unsigned-only install must never push it into
        // signed-policy mode: the commit refuses to bump it (and leaves the
        // debt for the stray cleanup), and clear_stray_withdrawal_debt
        // then disarms it without touching desired_generation.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    withdrawal_bumps_owed = 2
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_withdrawal_bumps(&pool, 0, 2).await.unwrap(),
            None
        );
        clear_stray_withdrawal_debt(&pool).await.unwrap();
        let (desired, owed): (i64, i64) = sqlx::query_as(
            "SELECT desired_generation, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, owed), (0, 0));

        crate::test_support::drop_isolated_database("cap119_withdrawal_bump", pool).await;
    }

    #[tokio::test]
    async fn latest_deployment_prefers_jobs_then_deterministic_legacy_identity() {
        let pool = crate::test_support::database_test_pool().await;
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
        let pool = crate::test_support::database_test_pool().await;
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

    #[tokio::test]
    async fn deleting_app_keeps_authorization_only_while_teardown_pending() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        let (pending_org, pending_app) = insert_test_app(&pool, "deleting").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(pending_app)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");
        let pending_deployment = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            pending_org,
            pending_app,
            pending_deployment,
            "healthy",
            now,
        )
        .await;
        let pending_artifact =
            insert_test_artifact(&pool, pending_app, pending_deployment, "de").await;
        insert_test_job(
            &pool,
            pending_org,
            pending_app,
            pending_deployment,
            pending_deployment,
            Some((pending_deployment, &pending_artifact)),
        )
        .await;

        let (completed_org, completed_app) = insert_test_app(&pool, "deleting").await;
        sqlx::query(
            "UPDATE apps
                SET workload_teardown_required = true,
                    workload_teardown_completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(completed_app)
        .execute(&pool)
        .await
        .expect("mark workload teardown completed");
        let completed_deployment = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            completed_org,
            completed_app,
            completed_deployment,
            "healthy",
            now,
        )
        .await;
        let completed_artifact =
            insert_test_artifact(&pool, completed_app, completed_deployment, "ef").await;
        insert_test_job(
            &pool,
            completed_org,
            completed_app,
            completed_deployment,
            completed_deployment,
            Some((completed_deployment, &completed_artifact)),
        )
        .await;

        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select teardown-pending KBS authority");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert!(
            hashes.contains(pending_artifact.metadata.descriptor_core_hash.as_str()),
            "a deleting app with teardown still pending must keep its authorization"
        );
        assert!(
            !hashes.contains(completed_artifact.metadata.descriptor_core_hash.as_str()),
            "a deleting app whose teardown completed must drop out"
        );

        for cleanup_org in [pending_org, completed_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete teardown-pending fixture organization");
        }
    }

    #[tokio::test]
    async fn teardown_pending_authorization_survives_deployment_supersession() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");

        // A long-dead historical operation (failed two generations back).
        // Its artifact must NOT re-enter the policy: nothing can still be
        // running under it, and re-admitting it would balloon the shared
        // signed-policy budget. Inserted first so its apply job gets the
        // lowest generation.
        let dead = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, dead, "failed", now).await;
        let dead_artifact = insert_test_artifact(&pool, app_id, dead, "ef").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            dead,
            dead,
            Some((dead, &dead_artifact)),
        )
        .await;

        // The still-running workload's signed deployment.
        let healthy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, healthy, "healthy", now).await;
        let healthy_artifact = insert_test_artifact(&pool, app_id, healthy, "ab").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            healthy,
            healthy,
            Some((healthy, &healthy_artifact)),
        )
        .await;

        // A newer upgrade that never finished applying. The three rows share
        // one transaction: a nonterminal deployment requires its apply job at
        // INSERT time (schema trigger), while the job's artifact binding and
        // the artifact's deployment reference are deferred FKs.
        let pending = Uuid::new_v4();
        let mut pending_artifact = test_signed_policy_artifact("cd", 16);
        pending_artifact.metadata.app_id = app_id.to_string();
        pending_artifact.metadata.deploy_id = pending.to_string();
        let pending_hash = hex::decode(&pending_artifact.metadata.descriptor_core_hash).unwrap();
        let mut fx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state
             ) VALUES ($1, $2, $3, $4, 1,
                       '{\"version\":1,\"log_encryption\":null}'::jsonb,
                       $5, true, true, $4, $6, NULL, 'pending')",
        )
        .bind(pending)
        .bind(app_id)
        .bind(org_id)
        .bind(pending)
        .bind(vec![4u8; 32])
        .bind(&pending_hash)
        .execute(&mut *fx)
        .await
        .expect("insert pending apply job");
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                       '{}'::jsonb, $5, $6)",
        )
        .bind(&pending_hash)
        .bind(app_id)
        .bind(pending)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&pending_artifact).unwrap())
        .execute(&mut *fx)
        .await
        .expect("insert pending apply artifact");
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot, created_at)
             VALUES ($1, $2, $3, 'pending'::deploy_status_enum, '{\"setup_state\":\"accepted\"}'::jsonb, $4)",
        )
        .bind(pending)
        .bind(org_id)
        .bind(app_id)
        .bind(now + chrono::Duration::seconds(1))
        .execute(&mut *fx)
        .await
        .expect("insert pending deployment");
        fx.commit().await.unwrap();

        // The delete supersedes the unfinished operation before teardown runs:
        // its job and deployment rows are marked failed.
        let mut tx = pool.begin().await.unwrap();
        crate::deploy::supersede_incomplete_deployments(&mut tx, app_id)
            .await
            .expect("supersede incomplete deployments");
        tx.commit().await.unwrap();

        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select teardown-pending authority after supersession");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert!(
            hashes.contains(healthy_artifact.metadata.descriptor_core_hash.as_str()),
            "the still-running workload's artifact must stay authorized through teardown"
        );
        assert!(
            hashes.contains(pending_artifact.metadata.descriptor_core_hash.as_str()),
            "a superseded-but-maybe-applied operation's artifact must stay authorized through teardown"
        );
        assert!(
            !hashes.contains(dead_artifact.metadata.descriptor_core_hash.as_str()),
            "a long-dead historical operation's artifact must not re-enter the policy"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete supersession fixture organization");
    }

    async fn seed_owner_binding_for_app(pool: &PgPool, app_id: Uuid) {
        sqlx::query(
            "INSERT INTO kbs_owner_bindings (
                 app_id, binding_key, repository, allowed_tags, namespace,
                 service_account, tenant_instance_identity_hash, deleted_at
             )
             SELECT id,
                    namespace || '-' || name || '-owner',
                    'default', ARRAY['seed-encrypted', 'seed-sealed'],
                    namespace, service_account, tenant_instance_identity_hash, NULL
               FROM apps WHERE id = $1",
        )
        .bind(app_id)
        .execute(pool)
        .await
        .expect("insert owner binding fixture");
    }

    async fn owner_binding_outcome(pool: &PgPool, app_id: Uuid) -> Option<chrono::DateTime<Utc>> {
        sqlx::query_scalar("SELECT waived_at FROM kbs_owner_seed_waivers WHERE app_id = $1")
            .bind(app_id)
            .fetch_optional(pool)
            .await
            .expect("read owner binding waiver")
    }

    #[tokio::test]
    async fn soft_delete_owner_binding_records_teardown_outcome() {
        let pool = crate::test_support::database_test_pool().await;

        // The mirrored binding-key format is load-bearing for the guard: a
        // drift in either string silently disables it. Pin it against the
        // engine's own derivation.
        {
            use enclava_engine::types::{
                AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec,
                VolumeSpec,
            };
            let dummy_digest = format!("sha256:{}", "a".repeat(64));
            let engine_app = ConfidentialApp {
                app_id: Uuid::new_v4(),
                deployment_id: Uuid::new_v4(),
                name: "mirror".into(),
                namespace: "cap-org-mirror".into(),
                instance_id: "org-mirror".into(),
                tenant_id: "org".into(),
                bootstrap_owner_pubkey_hash: "00".repeat(32),
                tenant_instance_identity_hash: "11".repeat(32),
                service_account: "cap-mirror-sa".into(),
                image_pull_secret_name: None,
                signer_identity_subject: None,
                signer_identity_issuer: None,
                containers: vec![Container {
                    name: "mirror".into(),
                    image: enclava_common::image::ImageRef::parse(&format!(
                        "ghcr.io/enclava-labs/demo@{dummy_digest}"
                    ))
                    .unwrap(),
                    port: Some(3000),
                    command: None,
                    env: std::collections::HashMap::new(),
                    storage_paths: vec![],
                    workload_security_profile:
                        enclava_engine::types::WorkloadSecurityProfile::Restricted,
                    is_primary: true,
                }],
                storage: StorageSpec {
                    app_data: VolumeSpec {
                        size: "1Gi".into(),
                        device_path: "/dev/csi0".into(),
                        mount_path: "/data".into(),
                        durability: enclava_common::types::Durability::DurableState,
                        bootstrap_policy: enclava_common::types::BootstrapPolicy::FirstBootOnly,
                        bind_mounts: vec![BindMount {
                            source: "/data/app".into(),
                            destination: "/app/data".into(),
                        }],
                    },
                    tls_data: VolumeSpec {
                        size: "1Gi".into(),
                        device_path: "/dev/csi1".into(),
                        mount_path: "/tls".into(),
                        durability: enclava_common::types::Durability::DisposableState,
                        bootstrap_policy: enclava_common::types::BootstrapPolicy::AllowReinit,
                        bind_mounts: vec![],
                    },
                },
                unlock_mode: enclava_common::types::UnlockMode::Password,
                domain: DomainSpec {
                    platform_domain: "mirror.example.test".into(),
                    tee_domain: "mirror.tee.example.test".into(),
                    custom_domain: None,
                },
                api_signing_pubkey: String::new(),
                api_url: String::new(),
                resources: enclava_common::types::ResourceLimits {
                    cpu: "1".into(),
                    memory: "512Mi".into(),
                },
                attestation: AttestationConfig {
                    proxy_image: enclava_common::image::ImageRef::parse(&format!(
                        "ghcr.io/enclava-labs/attestation-proxy@{dummy_digest}"
                    ))
                    .unwrap(),
                    caddy_image: enclava_common::image::ImageRef::parse(&format!(
                        "ghcr.io/enclava-labs/caddy-ingress@{dummy_digest}"
                    ))
                    .unwrap(),
                    acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                    caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                    trustee_policy_read_available: true,
                    workload_artifacts_url: None,
                    tls_certificate_broker_url: None,
                    amd_kds_base_url: None,
                    trustee_policy_url: None,
                    local_workload_artifacts_json: None,
                    local_trustee_policy_json: None,
                    platform_trustee_policy_pubkey_hex: None,
                    signing_service_pubkey_hex: None,
                    verification_material: None,
                },
                egress_mode: enclava_engine::types::EgressMode::Restricted,
                public_internet_egress_excluded_cidrs: vec![],
                allow_internal_egress: false,
                egress_allowlist: vec![],
                log_encryption: None,
                workload_artifact_binding: None,
                generated_agent_policy: None,
            };
            assert_eq!(
                owner_binding_key("cap-org-mirror", "mirror"),
                engine_app.owner_resource_type(),
                "kbs.rs and the engine must derive the same KBS owner binding key"
            );
        }

        async fn app_identity(pool: &PgPool, app_id: Uuid) -> (String, String) {
            sqlx::query_as("SELECT namespace, name FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(pool)
                .await
                .expect("read app identity")
        }

        // Required teardown, never completed: the wrap may survive — waived.
        let (waived_org, waived_app) = insert_test_app(&pool, "running").await;
        seed_owner_binding_for_app(&pool, waived_app).await;
        let waived_identity = app_identity(&pool, waived_app).await;
        soft_delete_owner_binding(&pool, waived_app, &waived_identity.0, &waived_identity.1)
            .await
            .expect("soft delete waived binding");
        assert!(owner_binding_outcome(&pool, waived_app).await.is_some());
        assert!(
            stale_owner_seed_for_binding(&pool, &waived_identity.0, &waived_identity.1)
                .await
                .expect("guard lookup"),
            "a waived binding must refuse recreation of the same name"
        );
        // The tombstone must survive the app row: the delete tail records the
        // waiver and then hard-deletes the app (kbs_owner_bindings cascades
        // away; the waiver table has no foreign keys by design).
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(waived_org)
            .execute(&pool)
            .await
            .expect("delete waived fixture organization (cascades the app)");
        assert!(
            stale_owner_seed_for_binding(&pool, &waived_identity.0, &waived_identity.1)
                .await
                .expect("guard lookup after cascade"),
            "the waiver must survive the app row deletion"
        );

        // A stopped app keeps its owner binding (PaaS desired-state only
        // scales the workload to zero, the seed survives) even though the
        // flip records teardown as not required: the binding row is the
        // seed-existence signal — waived.
        let (stopped_org, stopped_app) = insert_test_app(&pool, "stopped").await;
        seed_owner_binding_for_app(&pool, stopped_app).await;
        let stopped_identity = app_identity(&pool, stopped_app).await;
        soft_delete_owner_binding(&pool, stopped_app, &stopped_identity.0, &stopped_identity.1)
            .await
            .expect("soft delete stopped binding");
        assert!(
            owner_binding_outcome(&pool, stopped_app).await.is_some(),
            "a binding row without a completion marker means the seed may survive"
        );

        // A signed workload is teardown-required but never creates a binding
        // row: the key is name-derived either way — waived.
        let (signed_org, signed_app) = insert_test_app(&pool, "running").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(signed_app)
            .execute(&pool)
            .await
            .expect("mark signed workload teardown required");
        let signed_identity = app_identity(&pool, signed_app).await;
        soft_delete_owner_binding(&pool, signed_app, &signed_identity.0, &signed_identity.1)
            .await
            .expect("soft delete signed binding");
        assert!(
            owner_binding_outcome(&pool, signed_app).await.is_some(),
            "a teardown-required workload waives without a binding row (signed path)"
        );

        // Required teardown, completed: nothing survives — recreate freely.
        let (done_org, done_app) = insert_test_app(&pool, "running").await;
        seed_owner_binding_for_app(&pool, done_app).await;
        sqlx::query(
            "UPDATE apps SET workload_teardown_completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(done_app)
        .execute(&pool)
        .await
        .expect("mark teardown completed");
        let done_identity = app_identity(&pool, done_app).await;
        soft_delete_owner_binding(&pool, done_app, &done_identity.0, &done_identity.1)
            .await
            .expect("soft delete completed binding");
        assert!(owner_binding_outcome(&pool, done_app).await.is_none());

        // Never deployed: no binding, no teardown requirement, no wrap ever
        // existed — recreate freely.
        let (fresh_org, fresh_app) = insert_test_app(&pool, "creating").await;
        let fresh_identity = app_identity(&pool, fresh_app).await;
        soft_delete_owner_binding(&pool, fresh_app, &fresh_identity.0, &fresh_identity.1)
            .await
            .expect("soft delete never-deployed binding");
        assert!(owner_binding_outcome(&pool, fresh_app).await.is_none());
        let fresh_stale = stale_owner_seed_for_binding(&pool, &fresh_identity.0, &fresh_identity.1)
            .await
            .expect("guard lookup");
        assert!(!fresh_stale);

        for cleanup_org in [stopped_org, signed_org, done_org, fresh_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete teardown-outcome fixture organization");
        }
    }

    #[tokio::test]
    async fn soft_delete_owner_binding_waives_ever_deployed_workload_without_binding() {
        let pool = crate::test_support::database_test_pool().await;

        // A signed deployment leaves no owner binding row and a stopped (or
        // failed) workload records teardown as not required — the deployment
        // row is the only durable signal that a TEE boot may have left the
        // name-derived seed behind. The seed survives a scale-to-zero, so
        // the destroy must waive.
        let (org_id, app_id) = insert_test_app(&pool, "stopped").await;
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
             VALUES ($1, $2, $3, 'healthy'::deploy_status_enum, '{}'::jsonb)",
        )
        .bind(Uuid::new_v4())
        .bind(org_id)
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("seed historical deployment row");
        let (namespace, name): (String, String) =
            sqlx::query_as("SELECT namespace, name FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("read ever-deployed app identity");
        soft_delete_owner_binding(&pool, app_id, &namespace, &name)
            .await
            .expect("soft delete ever-deployed signed app");
        assert!(
            stale_owner_seed_for_binding(&pool, &namespace, &name)
                .await
                .expect("guard lookup"),
            "an ever-deployed workload without a binding row must still waive"
        );

        // The same stopped shape with no deployment row never booted a TEE:
        // no seed can exist, so recreate stays open.
        let (fresh_org, fresh_app) = insert_test_app(&pool, "stopped").await;
        let (fresh_namespace, fresh_name): (String, String) =
            sqlx::query_as("SELECT namespace, name FROM apps WHERE id = $1")
                .bind(fresh_app)
                .fetch_one(&pool)
                .await
                .expect("read never-deployed app identity");
        soft_delete_owner_binding(&pool, fresh_app, &fresh_namespace, &fresh_name)
            .await
            .expect("soft delete never-deployed app");
        assert!(
            !stale_owner_seed_for_binding(&pool, &fresh_namespace, &fresh_name)
                .await
                .expect("guard lookup"),
            "a never-deployed workload must not waive"
        );

        for cleanup_org in [org_id, fresh_org] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(cleanup_org)
                .execute(&pool)
                .await
                .expect("delete ever-deployed fixture organization");
        }
    }

    #[tokio::test]
    async fn teardown_pending_authorization_survives_stacked_failed_generations() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");

        // The still-running workload: a watching generation's job completed,
        // and two later generations failed on top of it. Generation-count
        // bounds would rank the live workload third and drop exactly the
        // artifact the teardown needs.
        let live = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, live, "healthy", now).await;
        let live_artifact = insert_test_artifact(&pool, app_id, live, "ab").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            live,
            live,
            Some((live, &live_artifact)),
        )
        .await;

        // A failed generation that never reached the apply phase: setup
        // completes before any workload spec is written, so nothing can be
        // running under it and it contributes no authorization.
        let setup_failed = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, setup_failed, "failed", now).await;
        let setup_failed_artifact = insert_test_artifact(&pool, app_id, setup_failed, "cd").await;
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, last_error_code
             ) VALUES ($1, $2, $3, $1, 1,
                       '{\"version\":1,\"log_encryption\":null}'::jsonb,
                       $4, false, true, $1, $5, NULL, 'failed',
                       'deployment_setup_failed')",
        )
        .bind(setup_failed)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![5u8; 32])
        .bind(hex::decode(&setup_failed_artifact.metadata.descriptor_core_hash).unwrap())
        .execute(&pool)
        .await
        .expect("insert setup-failed apply job");

        // A failed generation that reached the apply phase: apply failures
        // are never reverted, so its workload spec may be the one the
        // teardown hits.
        let apply_failed = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            apply_failed,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        set_test_setup_state(&pool, apply_failed, "accepted").await;
        let apply_failed_artifact = insert_test_artifact(&pool, app_id, apply_failed, "de").await;
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, last_error_code
             ) VALUES ($1, $2, $3, $1, 1,
                       '{\"version\":1,\"log_encryption\":null}'::jsonb,
                       $4, false, true, $1, $5, NULL, 'failed',
                       'deployment_apply_failed')",
        )
        .bind(apply_failed)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![6u8; 32])
        .bind(hex::decode(&apply_failed_artifact.metadata.descriptor_core_hash).unwrap())
        .execute(&pool)
        .await
        .expect("insert apply-failed apply job");

        let candidates = load_signed_policy_candidates(&pool, 2)
            .await
            .expect("select teardown-pending authority with stacked failures");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert!(
            hashes.contains(live_artifact.metadata.descriptor_core_hash.as_str()),
            "the live workload under two stacked failures must stay authorized"
        );
        assert!(
            hashes.contains(apply_failed_artifact.metadata.descriptor_core_hash.as_str()),
            "an apply-phase failure newer than the last applied workload must stay authorized"
        );
        assert!(
            !hashes.contains(setup_failed_artifact.metadata.descriptor_core_hash.as_str()),
            "a provable setup failure never wrote a workload spec and must stay excluded"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete stacked-failures fixture organization");
    }

    #[tokio::test]
    async fn queued_supersessions_do_not_crowd_out_live_teardown_authority() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");

        // The live workload: watching generation, its apply job completed.
        let live = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, live, "healthy", now).await;
        let live_artifact = insert_test_artifact(&pool, app_id, live, "ab").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            live,
            live,
            Some((live, &live_artifact)),
        )
        .await;

        // A pile of replacement deployments superseded while still queued:
        // their setup never completed (spec_snapshot stays at the initial
        // state), so they entered no apply phase and wrote no workload spec.
        // Admitting them as required artifacts would consume the per-app
        // retention slots ahead of the live workload and could push its
        // descriptor out of the published policy.
        let mut queued_hashes = Vec::new();
        for index in 0..4u32 {
            let queued = Uuid::new_v4();
            let mut artifact = test_signed_policy_artifact(&format!("{index:x}0"), 16);
            artifact.metadata.app_id = app_id.to_string();
            artifact.metadata.deploy_id = queued.to_string();
            let hash = hex::decode(&artifact.metadata.descriptor_core_hash).unwrap();
            let mut fx = pool.begin().await.unwrap();
            sqlx::query(
                "INSERT INTO deployment_apply_jobs (
                     deployment_id, app_id, org_id, source_deployment_id,
                     payload_version, payload, payload_sha256,
                     cleanup_app_on_setup_failure, signed_required,
                     artifact_deployment_id, artifact_descriptor_core_hash,
                     log_encryption, state, last_error_code
                 ) VALUES ($1, $2, $3, $1, 1,
                           '{\"version\":1,\"log_encryption\":null}'::jsonb,
                           $4, false, true, $1, $5, NULL, 'failed',
                           'deployment_superseded')",
            )
            .bind(queued)
            .bind(app_id)
            .bind(org_id)
            .bind(vec![7u8 + index as u8; 32])
            .bind(&hash)
            .execute(&mut *fx)
            .await
            .expect("insert queued-superseded apply job");
            sqlx::query(
                "INSERT INTO workload_artifacts (
                     descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                     descriptor_signature, descriptor_signing_key_id,
                     org_keyring_payload, org_keyring_signature,
                     signed_policy_artifact
                 ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                           '{}'::jsonb, $5, $6)",
            )
            .bind(&hash)
            .bind(app_id)
            .bind(queued)
            .bind(vec![3u8; 64])
            .bind(vec![4u8; 64])
            .bind(serde_json::to_value(&artifact).unwrap())
            .execute(&mut *fx)
            .await
            .expect("insert queued-superseded artifact");
            sqlx::query(
                "INSERT INTO deployments (
                     id, org_id, app_id, status, spec_snapshot, created_at
                 ) VALUES ($1, $2, $3, 'failed'::deploy_status_enum,
                           '{\"setup_state\":\"dns_pending\"}'::jsonb, $4)",
            )
            .bind(queued)
            .bind(org_id)
            .bind(app_id)
            .bind(now + chrono::Duration::seconds((index + 2) as i64))
            .execute(&mut *fx)
            .await
            .expect("insert queued-superseded deployment");
            fx.commit().await.unwrap();
            queued_hashes.push(artifact.metadata.descriptor_core_hash.clone());
        }

        // Retention 1: exactly one artifact per app survives. It must be the
        // live workload's — the queued supersessions never reached the apply
        // phase and must not even be admitted, let alone win the slot.
        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select teardown-pending authority with queued supersessions");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert_eq!(
            hashes.len(),
            1,
            "with retention 1 exactly one artifact survives: {hashes:?}"
        );
        assert!(
            hashes.contains(live_artifact.metadata.descriptor_core_hash.as_str()),
            "the live workload must keep the retention slot, not a queued supersession"
        );
        for hash in &queued_hashes {
            assert!(
                !hashes.contains(hash.as_str()),
                "a queued supersession must not enter the policy"
            );
        }

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete queued-supersessions fixture organization");
    }

    #[tokio::test]
    async fn unreleased_signed_customer_config_hold_defers_an_empty_policy() {
        let pool = crate::test_support::database_test_pool().await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;

        // The hold protects a still-running legacy workload: a healthy
        // job-less deployment that predates signed artifacts.
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", Utc::now()).await;

        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe hold before fixture")
                .is_empty(),
            "no held deployment exists yet"
        );

        // The first signed deployment on this app is held: the schema
        // trigger requires the job row first, then the pending deployment
        // lands in the same transaction. The held transition carries a
        // signed artifact (`artifact_deployment_id`), so its authority is
        // exactly what the candidate query withholds.
        let held = Uuid::new_v4();
        // The signed artifact the hold will withhold; its row lands in the
        // same transaction (artifact -> deployment FK is checked at commit).
        let mut artifact = test_signed_policy_artifact("09", 16);
        artifact.metadata.app_id = app_id.to_string();
        artifact.metadata.deploy_id = held.to_string();
        let artifact_hash = hex::decode(&artifact.metadata.descriptor_core_hash).unwrap();
        let mut tx = pool.begin().await.expect("begin held fixture");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, next_attempt_at,
                 customer_config_hold, customer_config_hold_until
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, true, $1, $5, NULL, 'setup_pending',
                 'infinity'::timestamptz,
                 true, clock_timestamp() + interval '1 hour'
             )",
        )
        .bind(held)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7u8; 32])
        .bind(&artifact_hash)
        .execute(&mut *tx)
        .await
        .expect("insert held apply job");
        insert_test_deployment_in_tx(&mut tx, org_id, app_id, held, "pending").await;
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                       '{}'::jsonb, $5, $6)",
        )
        .bind(&artifact_hash)
        .bind(app_id)
        .bind(held)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&artifact).unwrap())
        .execute(&mut *tx)
        .await
        .expect("insert held signed artifact");
        tx.commit().await.expect("commit held fixture");

        assert!(
            !unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe held deployment")
                .is_empty(),
            "the unreleased hold must defer an empty policy publish"
        );
        let candidates = load_signed_policy_candidates(&pool, 8)
            .await
            .expect("load candidates under a held first deploy");
        assert!(
            candidates.is_empty(),
            "the held artifact is withheld: converging here would publish {{artifacts: []}} and revoke the legacy workload"
        );
        for status in ["stopped", "deleting"] {
            sqlx::query("UPDATE apps SET status = $2::app_status_enum WHERE id = $1")
                .bind(app_id)
                .bind(status)
                .execute(&pool)
                .await
                .unwrap();
            assert!(
                unreleased_signed_customer_config_hold_apps(&pool)
                    .await
                    .unwrap()
                    .is_empty(),
                "{status} must clear even an unexpired hold's policy deferral"
            );
        }
        sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .unwrap();

        // Releasing the hold ends the deferral.
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET customer_config_released_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(held)
        .execute(&pool)
        .await
        .expect("release the hold");
        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe after release")
                .is_empty(),
            "a released hold no longer defers the policy"
        );

        // A second unreleased hold that the sweeper expires: the expiry
        // deliberately leaves the legacy TEE running, so the app must keep
        // deferring the empty publish after the job turns terminal.
        let held2 = Uuid::new_v4();
        let mut artifact2 = test_signed_policy_artifact("0b", 16);
        artifact2.metadata.app_id = app_id.to_string();
        artifact2.metadata.deploy_id = held2.to_string();
        let artifact2_hash = hex::decode(&artifact2.metadata.descriptor_core_hash).unwrap();
        let mut expiry_fixture = pool.begin().await.expect("begin expiring hold fixture");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, next_attempt_at,
                 customer_config_hold, customer_config_hold_until
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, true, $1, $5, NULL, 'setup_pending',
                 'infinity'::timestamptz,
                 true, clock_timestamp() - interval '1 second'
             )",
        )
        .bind(held2)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7u8; 32])
        .bind(&artifact2_hash)
        .execute(&mut *expiry_fixture)
        .await
        .expect("insert expiring held apply job");
        insert_test_deployment_in_tx(&mut expiry_fixture, org_id, app_id, held2, "pending").await;
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                       '{}'::jsonb, $5, $6)",
        )
        .bind(&artifact2_hash)
        .bind(app_id)
        .bind(held2)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&artifact2).unwrap())
        .execute(&mut *expiry_fixture)
        .await
        .expect("insert expiring held signed artifact");
        expiry_fixture
            .commit()
            .await
            .expect("commit expiring hold fixture");

        crate::deployment_jobs::expire_customer_config_holds(&pool)
            .await
            .expect("sweep the expired hold");
        let swept_state: String =
            sqlx::query_scalar("SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1")
                .bind(held2)
                .fetch_one(&pool)
                .await
                .expect("read swept hold job state");
        assert_eq!(swept_state, "failed", "the sweeper terminalizes the hold");
        assert!(
            !unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe after hold expiry")
                .is_empty(),
            "an expired hold still defers while the legacy workload it preserved keeps running"
        );

        // Lifecycle exit clears the protection: once the app stops serving,
        // an empty publish revokes nothing live.
        sqlx::query("UPDATE apps SET status = 'stopped'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("stop the app");
        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe after app stop")
                .is_empty(),
            "a stopped app has no workload left for the expired hold to protect"
        );
        sqlx::query("UPDATE apps SET status = 'running'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("restart the app fixture");
        sqlx::query("UPDATE apps SET status = 'deleting'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark the app deleting");
        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe while deleting")
                .is_empty(),
            "a deleting app cannot be protected by the expired hold"
        );
        sqlx::query("UPDATE apps SET status = 'running'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("restore the app fixture");

        // A newer durable operation takes over: the expired hold is history
        // and the replacement's own operation semantics govern the policy.
        let replacement = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, replacement, "healthy", Utc::now()).await;
        insert_test_job(&pool, org_id, app_id, replacement, legacy, None).await;
        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe after replacement")
                .is_empty(),
            "a newer durable operation ends the expired hold's protection"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete held fixture organization");
    }

    #[tokio::test]
    async fn unrelated_unsigned_hold_does_not_defer_an_empty_policy() {
        let pool = crate::test_support::database_test_pool().await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;

        // An unrelated app's hold on an UNSIGNED transition withholds no
        // signed authority: it cannot be what made the candidate set
        // empty. A revoked artifact must converge out of the policy body
        // even while this hold stays live — deferring on it would leave the
        // revoked artifact authorized for the full hold window.
        let held = Uuid::new_v4();
        let mut tx = pool.begin().await.expect("begin unsigned held fixture");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, next_attempt_at,
                 customer_config_hold, customer_config_hold_until
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, false, NULL, NULL, NULL, 'setup_pending',
                 'infinity'::timestamptz,
                 true, clock_timestamp() + interval '2 hours'
             )",
        )
        .bind(held)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7u8; 32])
        .execute(&mut *tx)
        .await
        .expect("insert unsigned held apply job");
        insert_test_deployment_in_tx(&mut tx, org_id, app_id, held, "pending").await;
        tx.commit().await.expect("commit unsigned held fixture");

        assert!(
            unreleased_signed_customer_config_hold_apps(&pool)
                .await
                .expect("probe unsigned held deployment")
                .is_empty(),
            "an unsigned hold withholds no authority and must not defer policy convergence"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete unsigned held fixture organization");
    }

    #[tokio::test]
    async fn expired_signed_hold_preserves_legacy_policy_until_lifecycle_advances() {
        let pool = crate::test_support::database_test_pool().await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;

        // The still-running workload the hold preserved: a healthy legacy
        // deployment with no signed artifact row.
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", Utc::now()).await;

        // The first signed redeploy is held past its expiry so the sweeper
        // terminalizes it without ever applying the workload.
        let held = Uuid::new_v4();
        let mut artifact = test_signed_policy_artifact("0d", 16);
        artifact.metadata.app_id = app_id.to_string();
        artifact.metadata.deploy_id = held.to_string();
        let artifact_hash = hex::decode(&artifact.metadata.descriptor_core_hash).unwrap();
        let mut tx = pool.begin().await.expect("begin expired hold fixture");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, next_attempt_at,
                 customer_config_hold, customer_config_hold_until
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, true, $1, $5, NULL, 'setup_pending',
                 'infinity'::timestamptz,
                 true, clock_timestamp() - interval '1 second'
             )",
        )
        .bind(held)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7u8; 32])
        .bind(&artifact_hash)
        .execute(&mut *tx)
        .await
        .expect("insert expired held apply job");
        insert_test_deployment_in_tx(&mut tx, org_id, app_id, held, "pending").await;
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature,
                 signed_policy_artifact
             ) VALUES ($1, $2, $3, '{}'::jsonb, $4, 'test-key',
                       '{}'::jsonb, $5, $6)",
        )
        .bind(&artifact_hash)
        .bind(app_id)
        .bind(held)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&artifact).unwrap())
        .execute(&mut *tx)
        .await
        .expect("insert expired held signed artifact");
        tx.commit().await.expect("commit expired hold fixture");

        crate::deployment_jobs::expire_customer_config_holds(&pool)
            .await
            .expect("sweep the expired hold");
        let swept_state: String =
            sqlx::query_scalar("SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1")
                .bind(held)
                .fetch_one(&pool)
                .await
                .expect("read swept hold job state");
        assert_eq!(swept_state, "failed", "the sweeper terminalizes the hold");

        // A pending reconciliation must keep the legacy Rego body: the
        // expired hold still protects the running workload.
        let mut gen_tx = pool.begin().await.expect("begin generation bump");
        enqueue_signed_policy_reconciliation(&mut gen_tx)
            .await
            .expect("enqueue a pending policy generation");
        gen_tx.commit().await.expect("commit generation bump");

        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = writes.clone();
        let client = kube::Client::new(
            tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
                let seen = seen.clone();
                async move {
                    if request.method() != axum::http::Method::GET {
                        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let status =
                            kube::core::Status::failure("write rejected by fixture", "Forbidden")
                                .with_code(403);
                        return Ok::<_, std::io::Error>(
                            axum::http::Response::builder()
                                .status(axum::http::StatusCode::FORBIDDEN)
                                .body(kube::client::Body::from(
                                    serde_json::to_vec(&status).unwrap(),
                                ))
                                .unwrap(),
                        );
                    }
                    let configmap = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {
                            "name": "resource-policy",
                            "namespace": "trustee-operator-system",
                            "resourceVersion": "7"
                        },
                        "data": {"policy.rego": "package authz\n# legacy rego\n"}
                    });
                    Ok(axum::http::Response::new(kube::client::Body::from(
                        serde_json::to_vec(&configmap).unwrap(),
                    )))
                }
            }),
            "default",
        );
        let config = KbsPolicyConfig {
            namespace: "trustee-operator-system".to_string(),
            configmap_name: "resource-policy".to_string(),
            policy_key: "policy.rego".to_string(),
            deployment_name: "trustee-deployment".to_string(),
            required: false,
            signed_policy_retention: 8,
            signed_policy_max_bytes: 1024 * 1024,
        };

        reconcile_pending_signed_policy_artifacts_with_client(&pool, &config, None, client.clone())
            .await
            .expect("the expired hold must defer the pending reconciliation");
        assert_eq!(
            writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the reconciliation must not publish an empty policy over the running legacy workload"
        );

        // Lifecycle exit clears the deferral: with the app stopped there is
        // no workload to protect, so the pending generation converges
        // (the fixture's 403 write rejection proves the publish was
        // attempted rather than deferred).
        sqlx::query("UPDATE apps SET status = 'stopped'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("stop the app");
        let converged =
            reconcile_pending_signed_policy_artifacts_with_client(&pool, &config, None, client)
                .await;
        assert!(
            converged.is_err(),
            "the fixture rejects the write; only the attempt matters"
        );
        assert!(
            writes.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "stopping the app must let the pending reconciliation publish"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete expired hold fixture organization");
    }

    #[test]
    fn hold_deferral_correlates_revocation_with_the_held_app() {
        // Nothing signed published yet (legacy Rego install): converging
        // would flip the mode and revoke the held app's running workload,
        // so the deferral is legitimate.
        assert!(hold_deferral_correlates(&[], &["b".to_owned()]));
        // The dropped authority belongs to the held app itself.
        assert!(hold_deferral_correlates(
            &["b".to_owned()],
            &["b".to_owned()]
        ));
        // An unrelated hold (app B) must not retain app A's obsolete
        // authority: revocation converges instead of waiting out the hold.
        assert!(!hold_deferral_correlates(
            &["a".to_owned()],
            &["b".to_owned()]
        ));
        // Mixed drops converge unless every owner is held.
        assert!(!hold_deferral_correlates(
            &["a".to_owned(), "b".to_owned()],
            &["b".to_owned()]
        ));
        assert!(hold_deferral_correlates(
            &["a".to_owned(), "b".to_owned()],
            &["b".to_owned(), "a".to_owned()]
        ));
    }

    #[test]
    fn published_authority_owners_parse_both_body_shapes() {
        assert!(published_authority_owners("package authz").is_empty());
        assert!(
            published_authority_owners("not json at all").is_empty(),
            "a non-JSON legacy body contributes no owners"
        );
        let set = serde_json::json!({
            "schema_version": "signed-policy-artifacts/v1",
            "artifacts": [
                {"metadata": {"app_id": "aaa", "deploy_id": "d1"}},
                {"metadata": {"app_id": "bbb", "deploy_id": "d2"}},
            ]
        })
        .to_string();
        assert_eq!(published_authority_owners(&set), ["aaa", "bbb"]);
        let single = serde_json::json!({
            "metadata": {"app_id": "ccc", "deploy_id": "d3"},
            "rego_text": "package authz",
            "signature": "sig"
        })
        .to_string();
        assert_eq!(published_authority_owners(&single), ["ccc"]);
    }
}
