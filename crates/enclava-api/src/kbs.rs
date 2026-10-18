use std::collections::{BTreeMap, HashSet};

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
    #[error("Kubernetes mutating request failed")]
    ProviderWriteFailed(#[source] kube::Error),
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
    #[error("signed KBS policy publication deferred by an unreleased customer-config hold")]
    PublicationDeferredByHold,
    #[error("signed KBS policy compare-and-swap retries were exhausted")]
    PolicyCasExhausted,
    #[error(
        "resource-policy.rego splice anchor is malformed: {0} (markers/assignments must be line-anchored, outside strings, and unique)"
    )]
    MalformedManagedMarkers(String),
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
    #[error("legacy publication obligation sentinel row is missing; migration invariant broken")]
    MissingPublicationSentinel,
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
        .map_err(KbsPolicyError::ProviderWriteFailed)
}

impl KbsPolicyError {
    /// True when the failure is a Kubernetes MUTATING request whose outcome
    /// may be unknown: `bounded_kube_write` funnels every provider write in
    /// this module, and both its timeout and its transport/API errors can
    /// leave a request that already reached (or may yet reach) the API
    /// server. Reads, client construction, database work, and serialization
    /// failures never set this: errors propagate the moment they occur and
    /// every write is awaited to a known outcome before later stages run, so
    /// any other failure proves no write is still in flight.
    pub(crate) fn provider_write_may_be_in_flight(&self) -> bool {
        matches!(
            self,
            KbsPolicyError::ProviderWriteFailed(_) | KbsPolicyError::ProviderWriteTimeout
        )
    }
}

impl KbsPolicyError {
    /// Return a bounded failure code safe for persistence and operator logs.
    ///
    /// The Display strings embed ConfigMap state and aggregate byte counts of
    /// other tenants' policy artifacts; those must stay internal. The budget
    /// variant gets its own code so operators can distinguish the shared
    /// signed-policy budget ceiling (#18) from other KBS authority failures
    /// without exposing the counts.
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::SignedPolicyBudgetExceeded { .. } => "signed_policy_budget_exceeded",
            _ => "kbs_policy_error",
        }
    }
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
pub(crate) struct KbsTlsBinding {
    pub(crate) binding_key: String,
    pub(crate) repository: String,
    pub(crate) tag: String,
    pub(crate) image_digest: Option<String>,
    pub(crate) init_data_hash: Option<Vec<u8>>,
    pub(crate) signer_identity_subject: Option<String>,
    pub(crate) signer_identity_issuer: Option<String>,
    pub(crate) namespace: String,
    pub(crate) service_account: String,
    pub(crate) tenant_instance_identity_hash: String,
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
    selector_bumps_owed: i64,
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

/// A withdrawal under the binding's signer identity closes the legacy Rego
/// path for that binding durably. Coincident image and init-data
/// measurements on a newer artifact do not prove the binding belongs to
/// that artifact, so a fresh deployment must authorize through
/// signed-policy candidates instead of readmitting the old binding.
pub(crate) async fn load_legacy_tls_bindings<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
) -> Result<Vec<KbsTlsBinding>, KbsPolicyError> {
    let bindings: Vec<KbsTlsBinding> = sqlx::query_as(
        "SELECT binding_key, repository, tag, namespace, service_account,
                tenant_instance_identity_hash, image_digest, init_data_hash,
                signer_identity_subject, signer_identity_issuer
         FROM kbs_tls_bindings AS binding
         WHERE deleted_at IS NULL
           AND NOT EXISTS (
                SELECT 1
                  FROM withdrawn_signer_artifacts AS withdrawn
                  JOIN workload_artifacts AS artifact
                    ON artifact.descriptor_core_hash = withdrawn.descriptor_core_hash
                 WHERE artifact.app_id = binding.app_id
                   AND artifact.descriptor_payload -> 'signer_identity' ->> 'subject'
                       = binding.signer_identity_subject
                   AND artifact.descriptor_payload -> 'signer_identity' ->> 'issuer'
                       = binding.signer_identity_issuer
           )
         ORDER BY binding_key",
    )
    .fetch_all(db)
    .await?;
    Ok(bindings)
}

/// Take the publication-obligation sentinel lock FOR UPDATE. Both the legacy
/// publication critical section and the signer-rotation gates take this
/// lock, which serializes the refusal decision with an in-flight legacy
/// publication: a rotation either commits before the publication reads its
/// bindings (and is carried into them) or it waits for the publication to
/// write its policy and then sees the recorded obligation and refuses.
/// Returns false when the sentinel row is missing: the migration keeps it,
/// so a missing row means that invariant is broken and fails closed.
pub(crate) async fn lock_legacy_publication_sentinel<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
) -> Result<bool, KbsPolicyError> {
    let sentinel: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM legacy_publication_obligation WHERE key = 'sentinel' FOR UPDATE",
    )
    .fetch_optional(db)
    .await?;
    Ok(sentinel.unwrap_or(false))
}

/// Read the obligation marker with a fresh snapshot. Deliberately a second
/// statement after `lock_legacy_publication_sentinel`: under READ COMMITTED
/// a statement's snapshot is taken before it waits on FOR UPDATE, and the
/// sentinel row is never updated, so a combined lock+read statement would
/// keep observing the pre-publication marker even after waiting out a
/// concurrent publisher. Because the publisher commits the marker before it
/// releases the sentinel, this post-lock read is ordered after it.
pub(crate) async fn read_legacy_publication_obligation<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
) -> Result<bool, KbsPolicyError> {
    let recorded: Option<bool> = sqlx::query_scalar(
        "SELECT recorded_at IS NOT NULL
           FROM legacy_publication_obligation
          WHERE key = 'obligation'",
    )
    .fetch_optional(db)
    .await?;
    Ok(recorded.unwrap_or(true))
}

/// Record the legacy publication obligation. This is its own committed
/// write on the obligation row only, taken while the sentinel lock is held
/// but independent of the publication transaction: even a publication whose
/// ConfigMap write is lost or whose deploy later fails must keep the
/// evidence, and the write must never block on the sentinel lock the caller
/// holds. Recorded once and never cleared -- soft-deleting a binding does
/// not un-publish the policy that already carried it.
pub(crate) async fn record_legacy_publication_obligation<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "INSERT INTO legacy_publication_obligation (key, recorded_at) VALUES ('obligation', now())
         ON CONFLICT (key) DO UPDATE
            SET recorded_at = COALESCE(legacy_publication_obligation.recorded_at, now())",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// An unchanged ConfigMap may still have an unfinished Trustee rollout.
async fn reconcile_legacy_rego_policy_with_client(
    db: &PgPool,
    config: &KbsPolicyConfig,
    client: kube::Client,
) -> Result<(), KbsPolicyError> {
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
        // Publication critical section: lock the publication-obligation
        // sentinel before reading authority so a signer rotation either
        // commits before this render reads the bindings (and is carried
        // into them) or waits for this publication to write its policy and
        // then sees the recorded obligation and refuses. Read authority
        // after the ConfigMap version, so a competing publication forces a
        // CAS retry and a fresh authority snapshot. The sentinel lock is
        // held across the ConfigMap write and released before the
        // convergence wait below.
        let mut publication_tx = db.begin().await?;
        // Lock and read are separate statements so the post-lock read (the
        // obligation-marker check below via the gates) observes the marker
        // with a fresh snapshot (see the helper docs). The publisher does
        // not read the marker here; it takes the lock and fails closed if
        // the sentinel row itself is gone.
        if !lock_legacy_publication_sentinel(&mut *publication_tx).await? {
            return Err(KbsPolicyError::MissingPublicationSentinel);
        }
        let bindings: Vec<KbsOwnerBinding> = sqlx::query_as(
            "SELECT binding_key, repository, allowed_tags, namespace, service_account,
                tenant_instance_identity_hash
         FROM kbs_owner_bindings
         WHERE deleted_at IS NULL
         ORDER BY binding_key",
        )
        .fetch_all(&mut *publication_tx)
        .await?;
        let tls_bindings = load_legacy_tls_bindings(&mut *publication_tx).await?;
        if tls_bindings.iter().any(|binding| {
            binding.signer_identity_subject.is_some() && binding.signer_identity_issuer.is_some()
        }) {
            // This render carries signer identities toward Trustee: record
            // the obligation as its own committed write on the pool -- not
            // the publication transaction -- so even a lost ConfigMap write
            // or a later deploy failure keeps the evidence (the render was
            // still owed and may have reached Trustee). This second
            // connection cannot deadlock against the sentinel lock held
            // above: it only touches the obligation row, which nothing ever
            // locks FOR UPDATE. Only a binding that pins a signer can keep
            // the rotated-out signer authorized; null-identity renders never
            // record it and never fence rotations.
            record_legacy_publication_obligation(db).await?;
        }
        let next_policy = replace_tls_resource_bindings_block(current_policy, &tls_bindings)?;
        let next_policy = replace_owner_bindings_block(&next_policy, &bindings)?;
        let policy_sha256_hex = hex::encode(Sha256::digest(next_policy.as_bytes()));
        let policy_token = legacy_publication_token(config, &policy_sha256_hex);
        let has_valid_publication_event = configmap
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .is_some_and(|token| {
                token
                    .strip_prefix(&policy_token)
                    .and_then(|suffix| suffix.strip_prefix(':'))
                    .is_some_and(|nonce| Uuid::parse_str(nonce).is_ok())
            });

        // Publish whenever the bytes change OR the ConfigMap carries no
        // valid single-use event for these bytes -- first adoption of a
        // pre-upgrade ConfigMap, or an annotation that is absent, malformed,
        // or left over from different policy bytes. Persisting a fresh nonce
        // rather than falling back to the deterministic hash token keeps
        // every adoption observable and single-use (Codex review finding on
        // #187): a Deployment retaining an older token for the same bytes
        // must not be accepted as a healthy rollout after another writer
        // published and rolled out different policy in between.
        if next_policy != *current_policy || !has_valid_publication_event {
            configmap
                .data
                .get_or_insert_with(BTreeMap::new)
                .insert(config.policy_key.clone(), next_policy);
            // Persist a new publication event with the content CAS. Restoring
            // identical bytes after an intervening write still needs a rollout.
            configmap
                .metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(
                    POLICY_PUBLICATION_TOKEN_ANNOTATION.to_string(),
                    format!("{policy_token}:{}", Uuid::new_v4()),
                );
            match bounded_kube_write(cm_api.replace(
                &config.configmap_name,
                &PostParams::default(),
                &configmap,
            ))
            .await
            {
                Ok(_) => {}
                Err(KbsPolicyError::ProviderWriteFailed(error))
                    if is_kubernetes_conflict(&error) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        // Release the sentinel before the convergence wait: the policy
        // content is written, and a rotation may now commit (it will see
        // the recorded obligation) while the rollout converges.
        publication_tx.commit().await?;
        let publication_token = configmap
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .filter(|token| {
                token
                    .strip_prefix(&policy_token)
                    .and_then(|suffix| suffix.strip_prefix(':'))
                    .is_some_and(|nonce| Uuid::parse_str(nonce).is_ok())
            })
            .unwrap_or(&policy_token);

        // If signed authority committed after the ConfigMap CAS, let it
        // repair the brief legacy write before this call returns.
        if signed_policy_mode_active(db).await? {
            return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
                .await;
        }
        if converge_legacy_trustee_publication(
            db,
            client.clone(),
            config,
            publication_token,
            &policy_sha256_hex,
        )
        .await?
            == GenerationDecision::Superseded
        {
            continue;
        }
        if signed_policy_mode_active(db).await? {
            return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
                .await;
        }

        // Re-read after the rollout. A ConfigMap whose policy content changed
        // underneath it (external writer or a signed acceptance) must not be
        // reported as a converged legacy publication; re-render and converge
        // again. Metadata-only churn is not a policy change.
        let configmap_after = cm_api.get(&config.configmap_name).await?;
        let policy_after = configmap_after
            .data
            .as_ref()
            .and_then(|data| data.get(&config.policy_key))
            .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
        let expected_policy = configmap
            .data
            .as_ref()
            .and_then(|data| data.get(&config.policy_key))
            .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
        if policy_after != expected_policy
            || configmap_after
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
                != configmap
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
        {
            continue;
        }
        return Ok(());
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

pub async fn reconcile_policy(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Err(KbsPolicyError::NotConfigured);
    };

    let client = reconcile_kube_client().await?;
    if signed_policy_mode_active(db).await? {
        tracing::info!(
            namespace = %config.namespace,
            configmap = %config.configmap_name,
            "durable signed KBS authority supersedes legacy marker reconciliation"
        );
        return reconcile_pending_signed_policy_artifacts_with_client(db, config, None, client)
            .await;
    }
    reconcile_legacy_rego_policy_with_client(db, config, client).await
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

/// Stray debts must not promote a legacy unsigned install into signed mode,
/// where an empty artifact set would deny every workload.
async fn clear_stray_policy_debts(db: &PgPool) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET selector_bumps_owed = 0,
                withdrawal_bumps_owed = 0,
                updated_at = clock_timestamp()
          WHERE singleton
            AND desired_generation = 0
            AND (selector_bumps_owed > 0 OR withdrawal_bumps_owed > 0)",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Commit both debts only after publishing the fully filtered ConfigMap.
///
/// Publishing first leaves old reconcilers behind its generation; committing
/// first would let them publish an unfiltered body at the owed generation.
/// The content-bound annotation also rejects stale writers after this commit.
///
/// Database triggers increment each counter in its writer's transaction.
/// Comparing the entire observed triple catches either revocation arriving
/// mid-publication. On mismatch, return `None` and retry with fresh candidates
/// at the higher generation; never consume the two counters separately.
async fn consume_deferred_policy_debts(
    db: &PgPool,
    observed_desired_generation: i64,
    observed_selector_bumps_owed: i64,
    observed_withdrawal_bumps_owed: i64,
) -> Result<Option<i64>, KbsPolicyError> {
    let committed: Option<i64> = sqlx::query_scalar(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = desired_generation
                + selector_bumps_owed + withdrawal_bumps_owed,
                selector_bumps_owed = 0,
                withdrawal_bumps_owed = 0,
                updated_at = clock_timestamp()
          WHERE singleton
            AND (selector_bumps_owed > 0 OR withdrawal_bumps_owed > 0)
            AND desired_generation > 0
            AND desired_generation = $1
            AND selector_bumps_owed = $2
            AND withdrawal_bumps_owed = $3
          RETURNING desired_generation",
    )
    .bind(observed_desired_generation)
    .bind(observed_selector_bumps_owed)
    .bind(observed_withdrawal_bumps_owed)
    .fetch_optional(db)
    .await?;
    Ok(committed)
}

async fn load_signed_policy_reconciliation(
    db: &PgPool,
) -> Result<SignedPolicyReconciliationRow, KbsPolicyError> {
    Ok(sqlx::query_as(
        "SELECT desired_generation, configmap_generation, applied_generation,
                withdrawal_bumps_owed,
                selector_bumps_owed
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
/// Every candidate must still be signed by a key that is a member of the
/// org's *current* keyring generation (#130): a retained historical artifact
/// whose signer was removed by keyring rotation must not keep authorizing KBS
/// policy while its immutable row survives the retention window.  Candidates
/// fail closed when the org has no keyring row at all.
/// The prior healthy workload remains required until a replacement is healthy,
/// including when replacement setup fails without stopping the running workload.
/// the last completed workload (supersession never rewrites completed jobs)
/// plus the newest later generation that published a StatefulSet, until teardown
/// completes. Setup acceptance is not publication. Apply failures are never
/// reverted, and the delete flip itself supersedes leased work; a later
/// publication supersedes older failed attempts, bounding the authority one
/// deleting app can force into the shared policy. The prior healthy workload
/// remains required until a replacement is healthy, including when replacement
/// setup fails without stopping the running workload.
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
                deployment.workload_spec_published_at,
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
        -- org_keyrings_payload_wellformed CHECK constraint (migration 0061)
        -- rejects any non-JSON or non-object payload or a non-array members
        -- entry at INSERT time, so a malformed row from a backfill script or
        -- manual psql fix can never take down candidate loading for every
        -- org at once.
        current_keyring_members AS (
            -- DISTINCT over (org_id, lower(pubkey)): an owner-signed keyring
            -- may legitimately carry two members with the same public key
            -- (PR #187 review), and every join below matches artifacts by
            -- key, not by member identity -- without the dedupe each
            -- matching artifact would be emitted once per member row and
            -- inflate the policy (SignedPolicyBudgetExceeded).
            SELECT DISTINCT latest.org_id, lower(member.value->>'pubkey') AS pubkey
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
                        -- Deleting with confidential teardown still pending.
                        -- Policy-governed KBS deletes stay possible until
                        -- teardown completes.
                        --
                        -- Failed generations stack. Two rows cover the
                        -- workloads that can still be serving, and bound what
                        -- one app can force into the shared policy:
                        --   * the newest completed job is the last workload
                        --     known applied (a watching generation's job
                        --     completes; supersession does not rewrite
                        --     completed jobs);
                        --   * the newest later generation with
                        --     workload_spec_published_at set has applied a
                        --     StatefulSet. That column is written only after
                        --     apply_statefulset returns. A later
                        --     setup-accepted failure — preflight, resources
                        --     before the StatefulSet, or supersession before
                        --     that write — neither replaces the spec nor
                        --     suppresses it. The probe below uses the same
                        --     column.
                        -- shortcut: intermediate publications between the last completed job and the newest publication are dropped, upgrade when teardown can name the pod that is still live
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
                                ranked_job_operations.workload_spec_published_at
                                    IS NOT NULL
                                AND NOT EXISTS (
                                    SELECT 1
                                      FROM ranked_job_operations AS newer_published
                                     WHERE newer_published.app_id
                                         = ranked_job_operations.app_id
                                       AND newer_published.generation
                                           > ranked_job_operations.generation
                                       AND newer_published.workload_spec_published_at
                                           IS NOT NULL
                                )
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
                ) AS required,
                (current.app_status = 'deleting') AS retention_exempt
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
                CASE
                    -- Both teardown artifacts can still be serving. Retention
                    -- must not drop either; the byte budget fail-closes.
                    WHEN retention_exempt THEN 1
                    ELSE ROW_NUMBER() OVER (
                        PARTITION BY app_id
                        ORDER BY required DESC,
                                 operation_generation DESC,
                                 artifact_created_at DESC,
                                 descriptor_core_hash
                    )
                END AS app_artifact_rank
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
              -- Repeated or case-equivalent member keys must not duplicate an
              -- artifact and exhaust the serialized policy budget.
              AND EXISTS (
                  SELECT 1
                    FROM current_keyring_members AS member
                   WHERE member.org_id = legacy.org_id
                     AND lower(member.pubkey) = lower(
                         artifact.signed_policy_artifact
                             ->'metadata'->>'descriptor_signing_pubkey'
                     )
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

/// The policy authority one app pins for confidential teardown: the newest
/// completed workload plus the newest later generation that published a
/// StatefulSet — the same two arms `load_signed_policy_candidates` admits for
/// a deleting app with teardown still pending — or the newest healthy
/// deployment's artifacts for a legacy app whose authority no job-backed
/// deployment has durably replaced (a failed job-backed replacement leaves the
/// pre-job healthy workload required, mirroring the selector's legacy
/// eligibility). The delete transition marks the app deleting and sets
/// `workload_teardown_required` together, so this projection is exactly what
/// the selector admits once that transition lands.
async fn load_teardown_policy_unit(
    db: &PgPool,
    app_id: Uuid,
) -> Result<Vec<crate::signing_service::SignedPolicyArtifact>, KbsPolicyError> {
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        r#"
        WITH ranked_job_operations AS (
            SELECT
                job.generation,
                job.state AS job_state,
                job.artifact_deployment_id,
                job.artifact_descriptor_core_hash,
                deployment.status::text AS deployment_status,
                deployment.workload_spec_published_at
            FROM deployment_apply_jobs AS job
            JOIN deployments AS deployment
              ON deployment.id = job.deployment_id
             AND deployment.app_id = job.app_id
             AND deployment.org_id = job.org_id
            WHERE job.app_id = $1
              AND NOT (
                  job.customer_config_hold
                  AND job.customer_config_released_at IS NULL
              )
        ),
        max_completed AS (
            SELECT MAX(generation) AS generation
              FROM deployment_apply_jobs
             WHERE app_id = $1 AND state = 'completed'
        ),
        picked AS (
            SELECT artifact_deployment_id, artifact_descriptor_core_hash
              FROM ranked_job_operations
             WHERE job_state = 'completed'
               AND generation = (SELECT generation FROM max_completed)
            UNION
            SELECT artifact_deployment_id, artifact_descriptor_core_hash
              FROM ranked_job_operations
             WHERE workload_spec_published_at IS NOT NULL
               AND generation > COALESCE((SELECT generation FROM max_completed), 0)
               AND generation = (
                   SELECT MAX(generation)
                     FROM ranked_job_operations
                    WHERE workload_spec_published_at IS NOT NULL
               )
        ),
        job_unit AS (
            SELECT artifact.descriptor_core_hash, artifact.signed_policy_artifact
              FROM picked
              JOIN workload_artifacts AS artifact
                ON artifact.app_id = $1
               AND artifact.deploy_id = picked.artifact_deployment_id
               AND artifact.descriptor_core_hash = picked.artifact_descriptor_core_hash
             WHERE picked.artifact_deployment_id IS NOT NULL
               AND picked.artifact_descriptor_core_hash IS NOT NULL
        ),
        ranked_legacy_operations AS (
            SELECT
                deployment.id AS deployment_id,
                deployment.status::text AS deployment_status,
                ROW_NUMBER() OVER (
                    ORDER BY deployment.created_at DESC, deployment.id DESC
                ) AS current_operation_rank
            FROM deployments AS deployment
            WHERE deployment.app_id = $1
              -- Failed or held replacements do not retire legacy authority.
              AND NOT EXISTS (
                  SELECT 1
                    FROM ranked_job_operations AS operation
                   WHERE operation.deployment_status = 'healthy'
              )
              AND NOT EXISTS (
                  SELECT 1
                    FROM deployment_apply_jobs AS own_job
                   WHERE own_job.deployment_id = deployment.id
              )
        ),
        legacy_unit AS (
            SELECT artifact.descriptor_core_hash, artifact.signed_policy_artifact
              FROM ranked_legacy_operations AS legacy
              JOIN workload_artifacts AS artifact
                ON artifact.app_id = $1
               AND artifact.deploy_id = legacy.deployment_id
             WHERE legacy.current_operation_rank = 1
               AND legacy.deployment_status = 'healthy'
        ),
        teardown_unit AS (
            SELECT descriptor_core_hash, signed_policy_artifact FROM job_unit
            UNION
            SELECT descriptor_core_hash, signed_policy_artifact FROM legacy_unit
        ),
        current_keyring AS (
            SELECT keyring_payload
              FROM org_keyrings
             WHERE org_id = (SELECT org_id FROM apps WHERE id = $1)
             ORDER BY version DESC
             LIMIT 1
        )
        SELECT unit.signed_policy_artifact
          FROM teardown_unit AS unit
         WHERE NOT EXISTS (
             SELECT 1
               FROM withdrawn_signer_artifacts AS withdrawn
              WHERE withdrawn.descriptor_core_hash = unit.descriptor_core_hash
         )
           AND EXISTS (
               SELECT 1
                 FROM current_keyring,
                 jsonb_array_elements(
                     convert_from(keyring_payload, 'UTF8')::jsonb->'members'
                 ) AS member
                WHERE member.value->>'role' IN ('owner', 'admin', 'deployer')
                  AND lower(member.value->>'pubkey') = lower(
                      unit.signed_policy_artifact
                          ->'metadata'->>'descriptor_signing_pubkey'
                  )
           )
        "#,
    )
    .bind(app_id)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|value| serde_json::from_value(value).map_err(KbsPolicyError::Serialize))
        .collect()
}

fn dedup_signed_policy_artifacts_by_hash(
    artifacts: Vec<crate::signing_service::SignedPolicyArtifact>,
) -> Vec<crate::signing_service::SignedPolicyArtifact> {
    let mut seen = HashSet::new();
    artifacts
        .into_iter()
        .filter(|artifact| seen.insert(artifact.metadata.descriptor_core_hash.clone()))
        .collect()
}

/// Admission control for confidential teardown (Codex security finding
/// 4a27950: teardown candidates can exhaust the global KBS policy budget).
///
/// A teardown-pending workload keeps required, retention-exempt authority in
/// the shared signed policy for as long as it can still be serving (it needs
/// that authority to erase its owner seed), and a delete can turn optional
/// retention artifacts into required pins — the only required artifacts that
/// grow without a deploy replacing them. When the required set overflows
/// `signed_policy_max_bytes`, the selection fail-closes the whole
/// reconciliation, so one tenant stacking deletions can stop every app's
/// policy from converging.
///
/// `delete_app_before` calls this under the global `kbs_policy` fence before
/// the app is marked deleting, so that overflow state is unreachable: the
/// delete is admitted only when this app's teardown unit still fits the
/// shared byte budget alongside every other required artifact. The fail-closed
/// selection stays authoritative as the backstop for anything that bypasses
/// this check, and nothing is ever dropped from the policy to make a delete
/// fit.
///
/// A delete that does not grow the required set is always admitted: an
/// already-overflowed deployment must still be able to shrink its way back.
pub async fn teardown_unit_fits_signed_policy_budget(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app_id: Uuid,
) -> Result<bool, KbsPolicyError> {
    let Some(config) = config else {
        return Ok(true);
    };
    // Completed teardowns contribute no policy authority: the selector's
    // deleting-app arms require `workload_teardown_completed_at IS NULL`.
    // A deletion retry after teardown succeeded but a later cleanup step
    // failed must therefore bypass admission — projecting its unit here
    // would return a phantom 409 that blocks the app's own removal.
    let teardown_completed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT workload_teardown_completed_at FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(db)
            .await?;
    if teardown_completed.is_some() {
        return Ok(true);
    }
    let candidates = load_signed_policy_candidates(db, config.signed_policy_retention).await?;
    let mut projected = Vec::new();
    let mut current = Vec::new();
    for candidate in candidates {
        if !candidate.required {
            continue;
        }
        if candidate.artifact.metadata.app_id != app_id.to_string() {
            projected.push(candidate.artifact.clone());
        }
        current.push(candidate.artifact);
    }
    projected.extend(load_teardown_policy_unit(db, app_id).await?);
    let projected = dedup_signed_policy_artifacts_by_hash(projected);
    let projected_len = signed_policy_artifact_policy_body(&projected)?.len();
    if projected_len <= config.signed_policy_max_bytes {
        return Ok(true);
    }
    let current = dedup_signed_policy_artifacts_by_hash(current);
    let current_len = signed_policy_artifact_policy_body(&current)?.len();
    Ok(projected_len <= current_len)
}

/// Whether a published signed-policy body already carries every artifact of a
/// projected teardown unit. Understands both body shapes (the artifact-set
/// document and the legacy single-artifact document); a non-JSON legacy Rego
/// body covers nothing.
fn signed_policy_body_covers_artifacts(
    policy: &str,
    artifacts: &[crate::signing_service::SignedPolicyArtifact],
) -> bool {
    if artifacts.is_empty() {
        return true;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(policy) else {
        return false;
    };
    let hash = |artifact: &serde_json::Value| {
        artifact
            .get("metadata")?
            .get("descriptor_core_hash")?
            .as_str()
            .map(str::to_owned)
    };
    let published: HashSet<String> = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .map(|artifacts| artifacts.iter().filter_map(hash).collect())
        .unwrap_or_else(|| hash(&value).into_iter().collect());
    artifacts
        .iter()
        .all(|artifact| published.contains(&artifact.metadata.descriptor_core_hash))
}

/// Whether the live signed policy already authorizes every artifact of the
/// app's teardown unit (Codex review on 0c678f57: let non-growing deletes
/// bypass over-budget republication). Admission deliberately admits a delete
/// whose teardown unit does not grow the required set — an already-overflowed
/// deployment (e.g. after `signed_policy_max_bytes` was lowered below the
/// published required set) must be able to shrink its way back — but
/// republication of that still-over-budget unit fail-closes in
/// `select_signed_policy_artifacts_for_policy_body`. When the exact authority
/// is already live, republication is unnecessary: teardown authorization is
/// evaluated against the live policy, so the delete may proceed to teardown
/// and the required set shrinks once teardown completes.
pub async fn teardown_unit_already_published(
    db: &PgPool,
    config: &KbsPolicyConfig,
    client: kube::Client,
    app_id: Uuid,
) -> Result<bool, KbsPolicyError> {
    let unit = dedup_signed_policy_artifacts_by_hash(load_teardown_policy_unit(db, app_id).await?);
    let applied: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT applied_generation, applied_policy_sha256
           FROM kbs_signed_policy_reconciliation
          WHERE singleton AND applied_generation > 0",
    )
    .fetch_optional(db)
    .await?;
    teardown_unit_already_published_with_applied(config, client, &unit, applied).await
}

// Accept the applied snapshot explicitly so tests can check publication
// without overwriting the shared database's global reconciliation singleton.
async fn teardown_unit_already_published_with_applied(
    config: &KbsPolicyConfig,
    client: kube::Client,
    unit: &[crate::signing_service::SignedPolicyArtifact],
    applied: Option<(i64, Vec<u8>)>,
) -> Result<bool, KbsPolicyError> {
    if unit.is_empty() {
        return Ok(true);
    }
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let configmap = cm_api.get(&config.configmap_name).await?;
    let current_policy = configmap
        .data
        .as_ref()
        .and_then(|data| data.get(&config.policy_key))
        .map(String::as_str)
        .unwrap_or_default();
    if !signed_policy_body_covers_artifacts(current_policy, unit) {
        return Ok(false);
    }
    // A ConfigMap write precedes Trustee rollout. Only an applied generation
    // proves that this particular publication made it through rollout; the
    // desired ConfigMap alone can be ahead of the serving policy.
    let Some((generation, applied_hash)) = applied else {
        return Ok(false);
    };
    let hash = hex::encode(Sha256::digest(current_policy.as_bytes()));
    let annotations = configmap.metadata.annotations.as_ref();
    if applied_hash != Sha256::digest(current_policy.as_bytes()).to_vec()
        || annotated_policy_generation(annotations)? != Some((generation, hash.as_str()))
    {
        return Ok(false);
    }
    let token = annotations
        .and_then(|a| a.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Ok(false);
    };
    let deployment: Api<Deployment> = Api::namespaced(client, &config.namespace);
    let trustee = deployment.get(&config.deployment_name).await?;
    let template = trustee
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|metadata| metadata.annotations.as_ref());
    Ok(
        annotated_policy_generation(template)? == Some((generation, hash.as_str()))
            && template.and_then(|a| a.get(POLICY_PUBLICATION_TOKEN_ANNOTATION)) == Some(token),
    )
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

/// Call after releasing the org transaction: publication claims the global KBS
/// fence, and missing provider configuration must not hide an active revocation.
pub async fn confirm_keyring_kbs_publication(
    state: &crate::state::AppState,
) -> Result<(), KbsPolicyReconciliationError> {
    if !signed_policy_mode_active(&state.db).await? {
        return Ok(());
    }
    if state.kbs_policy.is_none() {
        return Err(KbsPolicyError::NotConfigured.into());
    }
    reconcile_signed_policy_once(state).await
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
    let client = reconcile_kube_client().await?;
    reconcile_pending_signed_policy_artifacts_with_client(db, config, expected_artifact, client)
        .await
}

#[cfg(test)]
tokio::task_local! {
    pub(crate) static TEST_KUBE_CLIENT: kube::Client;
}

async fn reconcile_kube_client() -> Result<kube::Client, KbsPolicyError> {
    #[cfg(test)]
    if let Ok(client) = TEST_KUBE_CLIENT.try_with(Clone::clone) {
        return Ok(client);
    }
    kube::Client::try_default()
        .await
        .map_err(KbsPolicyError::Kube)
}

async fn reconcile_pending_signed_policy_artifacts_with_client(
    db: &PgPool,
    config: &KbsPolicyConfig,
    expected_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
    client: kube::Client,
) -> Result<(), KbsPolicyError> {
    // Do not let stray debt opt an unsigned installation into signed mode.
    clear_stray_policy_debts(db).await?;
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
            // Old binaries update bindings without publishing Rego. Converge
            // them on startup and periodic passes too. Box breaks the recursive
            // future type when a concurrent acceptance switches to signed mode.
            return Box::pin(reconcile_legacy_rego_policy_with_client(db, config, client)).await;
        }
        // Keep the owed generation private until the filtered body is published.
        let generation =
            state.desired_generation + state.selector_bumps_owed + state.withdrawal_bumps_owed;
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
                    // The hold protects the running workload, but it does not
                    // mean this generation reached Trustee. Callers that
                    // require published withdrawal (notably signer rotation)
                    // must retain their retry checkpoint instead of returning
                    // success while the old authority remains live.
                    return Err(KbsPolicyError::PublicationDeferredByHold);
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
        // Commit both debts after publication. A concurrent revocation changes
        // the observed triple, so retry with fresh candidates instead of sealing
        // a stale policy generation.
        if (state.selector_bumps_owed > 0 || state.withdrawal_bumps_owed > 0)
            && consume_deferred_policy_debts(
                db,
                state.desired_generation,
                state.selector_bumps_owed,
                state.withdrawal_bumps_owed,
            )
            .await?
            .is_none()
        {
            continue;
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
            Err(KbsPolicyError::ProviderWriteFailed(error)) if is_kubernetes_conflict(&error) => {
                continue;
            }
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
            Err(KbsPolicyError::ProviderWriteFailed(error)) if is_kubernetes_conflict(&error) => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

fn deployment_rollout_is_ready(deployment: &Deployment) -> bool {
    let desired = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1);
    let status = deployment.status.as_ref();
    let observed = status
        .and_then(|status| status.observed_generation)
        .unwrap_or(0);
    let generation = deployment.metadata.generation.unwrap_or(0);
    let replicas = status.and_then(|status| status.replicas).unwrap_or(0);
    let updated = status
        .and_then(|status| status.updated_replicas)
        .unwrap_or(0);
    let available = status
        .and_then(|status| status.available_replicas)
        .unwrap_or(0);
    // Available replicas can still belong to the old policy's ReplicaSet.
    observed >= generation && updated >= desired && replicas == updated && available >= updated
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

        if deployment_rollout_is_ready(&deployment) {
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

// Legacy tokens must not populate the signed generation/hash annotations.
fn legacy_publication_token(config: &KbsPolicyConfig, policy_sha256_hex: &str) -> String {
    format!(
        "legacy:{}/{}/{}:{policy_sha256_hex}",
        config.namespace, config.configmap_name, config.policy_key
    )
}

// Missing durable signed authority is a conflict, not permission to downgrade its template.
async fn converge_legacy_trustee_publication(
    db: &PgPool,
    client: kube::Client,
    config: &KbsPolicyConfig,
    publication_token: &str,
    policy_sha256_hex: &str,
) -> Result<GenerationDecision, KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        if signed_policy_mode_active(db).await? {
            return Ok(GenerationDecision::Superseded);
        }
        let mut deployment = deploy_api.get(&config.deployment_name).await?;
        let template_annotations = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.metadata.as_ref())
            .and_then(|metadata| metadata.annotations.as_ref());
        if let Some((generation, policy_hash)) = annotated_policy_generation(template_annotations)?
        {
            if signed_policy_mode_active(db).await? {
                return Ok(GenerationDecision::Superseded);
            }
            return Err(KbsPolicyError::PolicyGenerationConflict {
                existing_generation: Some(generation),
                existing_hash: Some(policy_hash.to_string()),
                desired_generation: 0,
                desired_hash: policy_sha256_hex.to_string(),
            });
        }
        let existing_token = template_annotations
            .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
            .map(String::as_str);
        if existing_token == Some(publication_token) {
            return wait_for_legacy_publication(
                &deploy_api,
                &config.deployment_name,
                publication_token,
            )
            .await;
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
                return wait_for_legacy_publication(
                    &deploy_api,
                    &config.deployment_name,
                    publication_token,
                )
                .await;
            }
            Err(KbsPolicyError::ProviderWriteFailed(error)) if is_kubernetes_conflict(&error) => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(KbsPolicyError::PolicyCasExhausted)
}

async fn wait_for_legacy_publication(
    deploy_api: &Api<Deployment>,
    name: &str,
    publication_token: &str,
) -> Result<GenerationDecision, KbsPolicyError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(180);

    loop {
        let deployment = deploy_api.get(name).await?;
        let annotations = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.metadata.as_ref())
            .and_then(|metadata| metadata.annotations.as_ref());
        if annotated_policy_generation(annotations)?.is_some()
            || annotations
                .and_then(|annotations| annotations.get(POLICY_PUBLICATION_TOKEN_ANNOTATION))
                .map(String::as_str)
                != Some(publication_token)
        {
            return Ok(GenerationDecision::Superseded);
        }
        if deployment_rollout_is_ready(&deployment) {
            return Ok(GenerationDecision::Current);
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
            next.push_str(cap_section.trim_start_matches(',').trim());
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
        cap_section.trim_start_matches(',')
    } else {
        cap_section
    };
    let mut next = String::with_capacity(policy.len() + section.len());
    next.push_str(&policy[..block_body_end]);
    next.push_str(section);
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
    use crate::test_support::KbsPolicyProvider;
    use chrono::Utc;

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

    #[test]
    fn provider_write_in_flight_classification_covers_only_mutations() {
        // The KBS fence release on a failed publication depends on this
        // classification: a mutating request's outcome can be unknown (it may
        // have reached the API server), while every other failure provably
        // precedes all provider writes and may release the fence.
        assert!(KbsPolicyError::ProviderWriteTimeout.provider_write_may_be_in_flight());
        let write_failure = KbsPolicyError::ProviderWriteFailed(kube::Error::Api(
            kube::core::Status::failure("boom", "reason")
                .with_code(500)
                .boxed(),
        ));
        assert!(write_failure.provider_write_may_be_in_flight());
        let read_failure = KbsPolicyError::Kube(kube::Error::Api(
            kube::core::Status::failure("boom", "reason")
                .with_code(404)
                .boxed(),
        ));
        assert!(!read_failure.provider_write_may_be_in_flight());
        assert!(
            !KbsPolicyError::MissingPolicyKey("data".to_string()).provider_write_may_be_in_flight()
        );
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
    fn managed_policy_updates_are_idempotent_and_preserve_unmanaged_bindings() {
        let render = |policy: &str, tls: &[KbsTlsBinding], owners: &[KbsOwnerBinding]| {
            let policy = replace_tls_resource_bindings_block(policy, tls).unwrap();
            replace_owner_bindings_block(&policy, owners).unwrap()
        };
        let policy = r#"package policy
resource_bindings := {"external-tls": {"repository": "default"}}
owner_resource_bindings := {"external-owner": {"repository": "default"}}
"#;
        let empty = render(policy, &[], &[]);
        assert_eq!(render(&empty, &[], &[]), empty);

        let tls = [tls_binding("new-tls")];
        let owners = [binding("new-owner")];
        let populated = render(&empty, &tls, &owners);
        assert_eq!(render(&populated, &tls, &owners), populated);
        assert!(populated.contains("\"new-tls\""));
        assert!(populated.contains("\"new-owner\""));

        let withdrawn = render(&populated, &[], &[]);
        assert_eq!(withdrawn, empty);
        assert!(withdrawn.contains("\"external-tls\""));
        assert!(withdrawn.contains("\"external-owner\""));
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
    fn signed_policy_budget_exceeded_maps_to_its_own_public_code() {
        // cap#220: the bounded code that migration 0082, the public-code
        // allowlist, and the error emitter all pin must stay mapped through
        // the type -- the tests writing the string literal themselves would
        // not notice this arm collapsing back to `kbs_policy_error`.
        let err = KbsPolicyError::SignedPolicyBudgetExceeded {
            required_artifacts: 2,
            policy_bytes: 2048,
            max_policy_bytes: 1024,
        };
        assert_eq!(err.public_code(), "signed_policy_budget_exceeded");
        assert_eq!(
            KbsPolicyError::NotConfigured.public_code(),
            "kbs_policy_error"
        );
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

    /// Stamp spec_snapshot.setup_state. Supersession never rewrites it.
    /// Setup acceptance indicates the apply phase was entered, but teardown
    /// authority does not treat 'accepted' as a published workload spec.
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

    async fn mark_test_workload_published(pool: &PgPool, deployment_id: Uuid) {
        sqlx::query(
            "UPDATE deployments
                SET workload_spec_published_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(pool)
        .await
        .expect("mark KBS test workload spec published");
    }

    /// Descriptor hash for a DB fixture artifact: workload_artifacts is keyed
    /// by descriptor_core_hash globally, so a bare repeated byte collides
    /// across tests (and leaked rows) on the shared test database. The prefix
    /// byte keeps fixture intent readable; the deployment id keeps it unique.
    fn unique_test_descriptor_hash(hash_byte: &str, deployment_id: Uuid) -> String {
        hex::encode(Sha256::digest(
            &[
                hex::decode(hash_byte)
                    .expect("decode fixture hash byte")
                    .as_slice(),
                deployment_id.as_bytes().as_slice(),
            ]
            .concat(),
        ))
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
        artifact.metadata.descriptor_core_hash =
            unique_test_descriptor_hash(hash_byte, deployment_id);
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
        let members: Vec<(&str, &str)> = member_pubkeys
            .iter()
            .enumerate()
            .map(|(index, pubkey)| (*pubkey, if index == 0 { "owner" } else { "deployer" }))
            .collect();
        insert_test_keyring_with_roles(pool, org_id, version, &members).await
    }

    /// Insert one append-only org keyring version whose member roles are
    /// chosen per member, so fixtures can exercise the non-deploy-role
    /// exclusion. The first member's pubkey signs the keyring row; the raw
    /// signature bytes are irrelevant to candidate selection. Returns the
    /// ids of the user and signing key rows it created.
    async fn insert_test_keyring_with_roles(
        pool: &PgPool,
        org_id: Uuid,
        version: i64,
        members_with_roles: &[(&str, &str)],
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
            .bind(hex::decode(members_with_roles[0].0).expect("decode owner keyring pubkey"))
            .execute(pool)
            .await
            .expect("insert KBS keyring signing key");
        let members: Vec<serde_json::Value> = members_with_roles
            .iter()
            .map(|(pubkey, role)| {
                serde_json::json!({
                    "user_id": user_id,
                    "pubkey": pubkey,
                    "role": role,
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

    /// A workload artifact pinned to a legacy signer identity with the given
    /// measurements, mirroring what a signed deployment leaves behind. The
    /// image_ref and init-data hash derive from the measurement so fixtures
    /// can give distinct artifacts coincident measurements.
    async fn insert_signer_identity_artifact(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        (subject, issuer): (&str, &str),
        measurement: &[u8],
        descriptor_hash: &[u8],
        created_at: chrono::DateTime<Utc>,
    ) -> crate::signing_service::SignedPolicyArtifact {
        let deploy_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot, created_at)
             VALUES ($1, $2, $3, 'healthy'::deploy_status_enum, '{}'::jsonb, $4)",
        )
        .bind(deploy_id)
        .bind(org_id)
        .bind(app_id)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("insert signer identity test deployment");
        let mut artifact = test_signed_policy_artifact("aa", 16);
        artifact.metadata.app_id = app_id.to_string();
        artifact.metadata.deploy_id = deploy_id.to_string();
        artifact.metadata.descriptor_core_hash = hex::encode(descriptor_hash);
        let measurement_hex = hex::encode(measurement);
        let descriptor_payload = serde_json::json!({
            "image_ref": format!("ghcr.io/acme/workload@sha256:{measurement_hex}"),
            "expected_cc_init_data_hash": measurement_hex,
            "signer_identity": {"subject": subject, "issuer": issuer},
        });
        sqlx::query(
            "INSERT INTO workload_artifacts (
                 descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                 descriptor_signature, descriptor_signing_key_id,
                 org_keyring_payload, org_keyring_signature, signed_policy_artifact
             ) VALUES ($1, $2, $3, $4, $5, 'test-key', '{}'::jsonb, $6, $7)",
        )
        .bind(descriptor_hash)
        .bind(app_id)
        .bind(deploy_id)
        .bind(&descriptor_payload)
        .bind(vec![1u8; 64])
        .bind(vec![2u8; 64])
        .bind(serde_json::to_value(&artifact).unwrap())
        .execute(pool)
        .await
        .expect("insert signer identity test artifact");
        artifact
    }

    /// A legacy kbs_tls_bindings row carrying a signer identity and its
    /// committed measurements, mirroring what ensure_tls_binding leaves
    /// behind after a deployment.
    async fn insert_measured_legacy_tls_binding(
        pool: &PgPool,
        app_id: Uuid,
        subject: &str,
        issuer: &str,
        image_ref: &str,
        init_data_hash: &[u8],
    ) {
        let suffix = app_id.simple().to_string();
        sqlx::query(
            "INSERT INTO kbs_tls_bindings (
                 app_id, binding_key, repository, tag, namespace, service_account,
                 tenant_instance_identity_hash, image_digest, init_data_hash,
                 signer_identity_subject, signer_identity_issuer
             ) VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(app_id)
        .bind(format!("tls-{}", &suffix[..12]))
        .bind(format!("cap-{}", &suffix[..12]))
        .bind(format!("cap-{}-sa", &suffix[..12]))
        .bind("22".repeat(32))
        .bind(image_ref)
        .bind(init_data_hash)
        .bind(subject)
        .bind(issuer)
        .execute(pool)
        .await
        .expect("insert measured legacy tls binding");
    }

    async fn withdraw_test_artifact(pool: &PgPool, descriptor_hash: &[u8], app_id: Uuid) {
        sqlx::query(
            "INSERT INTO withdrawn_signer_artifacts (descriptor_core_hash, app_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(descriptor_hash)
        .bind(app_id)
        .execute(pool)
        .await
        .expect("withdraw signer identity test artifact");
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
    /// Migration 0061's `org_keyrings` INSERT trigger owes one selector bump
    /// per keyring write while signed-policy mode is active -- including
    /// writes committed by a PRE-0061 replica during a rolling upgrade,
    /// which is the whole point of the trigger (the old binary enqueues
    /// nothing itself).  Runs against its own uniquely named per-process
    /// database (see [`crate::test_support::isolated_database_test_pool`]):
    /// this test asserts exact `kbs_signed_policy_reconciliation` singleton
    /// values and resets them, and on the shared test database another test
    /// process (a sibling CI worktree on the same PostgreSQL server) could
    /// owe bumps between this test's insert and its exact assertion, or have
    /// its own state clobbered by this test's final reset.  The process-local
    /// `SIGNED_POLICY_SINGLETON_LOCK` cannot fence across processes.
    #[tokio::test]
    async fn keyring_rotation_owes_selector_bump_only_when_active() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap130_rotation_enqueue").await;
        let (org_id, _app_id) = insert_test_app(&pool, "running").await;

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
        insert_test_keyring_version(&pool, org_id, 1, &["aa".repeat(32).as_str()]).await;
        let owed: i64 = sqlx::query_scalar(
            "SELECT selector_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            owed, 0,
            "keyring write on an idle installation must owe no selector bump"
        );

        // Once signed mode is active, every keyring write owes one bump so
        // the reconciler withdraws rotated-out artifacts (#130): the changed
        // candidate set at an unchanged generation would otherwise be
        // rejected as a content conflict.  desired_generation itself must
        // stay put -- a pre-0061 replica must never see a raw bump.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        insert_test_keyring_version(&pool, org_id, 2, &["bb".repeat(32).as_str()]).await;
        insert_test_keyring_version(&pool, org_id, 3, &["cc".repeat(32).as_str()]).await;
        let (desired, owed): (i64, i64) = sqlx::query_as(
            "SELECT desired_generation, selector_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(owed, 2, "each active-mode keyring insert owes one bump");
        assert_eq!(desired, 1, "the debt must not move desired_generation");

        crate::test_support::drop_isolated_database("cap130_rotation_enqueue", pool).await;
    }

    /// The deferred policy debts -- the keyring-membership and
    /// signer-withdrawal counters -- are owed in counters instead of being
    /// performed, so an old replica still reconciling during a rollout
    /// cannot consume them with its unfiltered candidate query.  Only this
    /// reconciler interprets either debt -- exactly once per observed
    /// (desired, selector_owed, withdrawal_owed) triple, and only after
    /// the fully filtered policy body is published
    /// (consume_deferred_policy_debts).  A write on either channel
    /// landing between the reconciler's state read and its consumption
    /// increments its counter, fails the single CAS, and forces
    /// republication at a strictly higher generation -- never a
    /// same-generation conflict on a stale candidate set.  Both debts are
    /// committed together, never one before the other.  Stray debts on an
    /// unsigned-only install are disarmed by clear_stray_policy_debts
    /// without entering signed-policy mode.  Runs against its own
    /// per-process database: it asserts exact singleton state that another
    /// test process could perturb through the shared server.
    #[tokio::test]
    async fn deferred_policy_debts_are_cas_committed_once_by_the_filtered_reconciler() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_policy_debt_cas").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // Pin a complete previous identity for the withdrawal channel; the
        // initial (NULL -> identity) set owes nothing.
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
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    selector_bumps_owed = 0,
                    withdrawal_bumps_owed = 0
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Nothing owed on either channel: consuming is a no-op.
        assert_eq!(
            consume_deferred_policy_debts(&pool, 0, 0, 0).await.unwrap(),
            None
        );

        // A selector-only debt commits exactly the observed triple.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 3,
                    selector_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_policy_debts(&pool, 3, 1, 0).await.unwrap(),
            Some(4)
        );
        let (desired, selector_owed, withdrawal_owed): (i64, i64, i64) = sqlx::query_as(
            "SELECT desired_generation, selector_bumps_owed, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, selector_owed, withdrawal_owed), (4, 0, 0));
        assert_eq!(
            consume_deferred_policy_debts(&pool, 4, 0, 0).await.unwrap(),
            None
        );

        // A withdrawal-only debt commits exactly the observed triple.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    withdrawal_bumps_owed = 2
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_policy_debts(&pool, 5, 0, 2).await.unwrap(),
            Some(7)
        );

        // Both debts at once commit together in one CAS.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 7,
                    selector_bumps_owed = 1,
                    withdrawal_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_policy_debts(&pool, 7, 1, 1).await.unwrap(),
            Some(9)
        );

        // The review interleaving on the keyring channel: the reconciler
        // observed (9, 1, 1) and published at 11, but an old replica's
        // keyring write committed in between -- the org_keyrings trigger
        // owed that write a selector bump.  The stale CAS must fail and
        // leave every debt for the retry.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 9,
                    selector_bumps_owed = 1,
                    withdrawal_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        insert_test_keyring_version(&pool, org_id, 1, &["dd".repeat(32).as_str()]).await;
        assert_eq!(
            consume_deferred_policy_debts(&pool, 9, 1, 1).await.unwrap(),
            None,
            "a mid-run keyring write must fail the CAS and leave the debt"
        );
        let (desired, selector_owed, withdrawal_owed): (i64, i64, i64) = sqlx::query_as(
            "SELECT desired_generation, selector_bumps_owed, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (desired, selector_owed, withdrawal_owed),
            (9, 2, 1),
            "the keyring debt grows and the withdrawal debt stays owed"
        );

        // The same interleaving on the withdrawal channel: a signer
        // rotation committed mid-run and the apps trigger owed it a
        // withdrawal bump.  The stale CAS fails again. The consumption
        // row is what lets the identity change commit under the 0067 fence.
        let mut rotation = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = 'new-subject'
              WHERE id = $1",
        )
        .bind(app_id)
        .execute(&mut *rotation)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO consumed_signer_rotation_tokens (
                 jti, user_id, org_id, app_id, subject, issuer, expires_at
             ) VALUES ($1, $2, $3, $4, 'new-subject', 'old-issuer', now() + interval '1 hour')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4())
        .bind(org_id)
        .bind(app_id)
        .execute(&mut *rotation)
        .await
        .unwrap();
        rotation.commit().await.unwrap();
        assert_eq!(
            consume_deferred_policy_debts(&pool, 9, 2, 1).await.unwrap(),
            None,
            "a mid-run signer rotation must fail the CAS and leave the debt"
        );
        let (desired, selector_owed, withdrawal_owed): (i64, i64, i64) = sqlx::query_as(
            "SELECT desired_generation, selector_bumps_owed, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (desired, selector_owed, withdrawal_owed),
            (9, 2, 2),
            "every debt remains owed to the retry"
        );

        // The retry observes every debt and lands them in one commit.
        assert_eq!(
            consume_deferred_policy_debts(&pool, 9, 2, 2).await.unwrap(),
            Some(13)
        );

        // Stray debts on an unsigned-only install must never push it into
        // signed-policy mode: the commit refuses to bump them (and leaves
        // them for the stray cleanup), and clear_stray_policy_debts then
        // disarms both without touching desired_generation.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    selector_bumps_owed = 2,
                    withdrawal_bumps_owed = 1
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            consume_deferred_policy_debts(&pool, 0, 2, 1).await.unwrap(),
            None
        );
        clear_stray_policy_debts(&pool).await.unwrap();
        let (desired, selector_owed, withdrawal_owed): (i64, i64, i64) = sqlx::query_as(
            "SELECT desired_generation, selector_bumps_owed, withdrawal_bumps_owed
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((desired, selector_owed, withdrawal_owed), (0, 0, 0));

        crate::test_support::drop_isolated_database("cap_policy_debt_cas", pool).await;
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

    #[tokio::test]
    async fn duplicate_keyring_members_authorize_each_legacy_artifact_once() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_pr187_duplicate_members").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", Utc::now()).await;
        let artifact = insert_test_artifact(&pool, app_id, legacy, "77").await;
        let signer = "bb".repeat(32);
        // The same member key twice: once lowercase, once in the uppercase
        // spelling validation accepts and stores as-is.
        insert_test_keyring_version(&pool, org_id, 1, &[&signer, &signer.to_uppercase()]).await;

        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select candidates with duplicate member keys");
        let matching: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == artifact.metadata.descriptor_core_hash
            })
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "repeated member keys must not duplicate the authorized legacy artifact"
        );
        assert!(matching[0].required);

        let single_body_len =
            signed_policy_artifact_policy_body(std::slice::from_ref(&matching[0].artifact))
                .unwrap()
                .len();
        let selected =
            select_signed_policy_artifacts_for_policy_body(candidates, single_body_len + 32)
                .unwrap();
        assert_eq!(
            selected.len(),
            1,
            "the repeated member key must not spuriously exhaust the serialized policy budget"
        );

        crate::test_support::drop_isolated_database("cap_pr187_duplicate_members", pool).await;
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
    async fn selector_drops_artifacts_withdrawn_by_signer_rotation() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap119_withdrawal_selector").await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_test_keyring_version(&pool, org_id, 1, &[&"bb".repeat(32)]).await;
        let current = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, current, "healthy", now).await;
        let current_artifact = insert_test_artifact(&pool, app_id, current, "31").await;
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

        crate::test_support::drop_isolated_database("cap119_withdrawal_selector", pool).await;
    }

    /// A legacy binding whose signer's artifacts were withdrawn must
    /// not be readmitted just because a newer non-withdrawn artifact under
    /// the same identity shares the binding's image_ref and init-data
    /// measurements. Equal measurements do not prove the binding belongs to
    /// that artifact; the fresh deployment authorizes through signed-policy
    /// candidates instead.
    #[tokio::test]
    async fn withdrawn_legacy_binding_is_not_readmitted_by_coincident_measurements() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_pr187_legacy_readmission").await;
        let subject = "https://github.com/acme/workload/.github/workflows/ci.yaml@refs/heads/main";
        let issuer = "https://token.actions.githubusercontent.com";
        let measurement: Vec<u8> = (0..32u8).collect();
        let image_ref = format!("ghcr.io/acme/workload@sha256:{}", hex::encode(&measurement));
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        let now = Utc::now();
        let withdrawn_hash: Vec<u8> = (0..32u8).collect();
        let fresh_hash: Vec<u8> = (1..33u8).collect();
        insert_signer_identity_artifact(
            &pool,
            org_id,
            app_id,
            (subject, issuer),
            &measurement,
            &withdrawn_hash,
            now,
        )
        .await;
        insert_measured_legacy_tls_binding(
            &pool,
            app_id,
            subject,
            issuer,
            &image_ref,
            &measurement,
        )
        .await;

        // Baseline: the live artifact admits the binding (no withdrawal).
        let admitted = load_legacy_tls_bindings(&pool)
            .await
            .expect("load admitted legacy tls bindings");
        assert_eq!(
            admitted.len(),
            1,
            "a never-withdrawn signer must keep its legacy binding admitted"
        );

        // A -> B -> A: the original artifact is withdrawn durably while the
        // binding still carries the identity and its original measurements.
        withdraw_test_artifact(&pool, &withdrawn_hash, app_id).await;

        // A newer accepted artifact under the same identity shares the
        // binding's exact image_ref and init-data hash but is a different
        // artifact. The binding must stay denied: coincident measurements
        // are not binding provenance.
        let fresh_artifact = insert_signer_identity_artifact(
            &pool,
            org_id,
            app_id,
            (subject, issuer),
            &measurement,
            &fresh_hash,
            now + chrono::Duration::seconds(1),
        )
        .await;
        let admitted = load_legacy_tls_bindings(&pool)
            .await
            .expect("load admitted legacy tls bindings after the rotate-back");
        assert!(
            admitted.is_empty(),
            "a fresh artifact with coincident measurements must not readmit the withdrawn binding, got {admitted:?}"
        );

        // The fresh signed deployment still authorizes through valid
        // signed-policy candidates.
        insert_test_keyring_version(&pool, org_id, 1, &[&"bb".repeat(32)]).await;
        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select candidates for the fresh deployment");
        assert!(
            candidates.iter().any(|candidate| {
                candidate.artifact.metadata.descriptor_core_hash
                    == fresh_artifact.metadata.descriptor_core_hash
            }),
            "the fresh signed artifact must remain selectable"
        );

        crate::test_support::drop_isolated_database("cap_pr187_legacy_readmission", pool).await;
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
    async fn legacy_authority_survives_while_the_only_durable_job_is_an_unreleased_hold() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
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

    fn legacy_kbs_test_config() -> KbsPolicyConfig {
        KbsPolicyConfig {
            namespace: "kbs-test".to_string(),
            configmap_name: "resource-policy".to_string(),
            policy_key: "policy.rego".to_string(),
            deployment_name: "trustee".to_string(),
            required: true,
            signed_policy_retention: 6,
            signed_policy_max_bytes: 900 * 1024,
        }
    }

    async fn insert_legacy_owner_binding(pool: &PgPool, app_id: Uuid, binding_key: &str) {
        sqlx::query(
            "INSERT INTO kbs_owner_bindings (
                 app_id, binding_key, repository, namespace, service_account,
                 tenant_instance_identity_hash
             ) VALUES ($1, $2, 'default', 'cap-legacy', 'cap-legacy-sa', $3)",
        )
        .bind(app_id)
        .bind(binding_key)
        .bind("ab".repeat(32))
        .execute(pool)
        .await
        .expect("insert legacy owner binding");
    }

    #[tokio::test]
    async fn rollout_waits_for_old_replicas_to_leave() {
        for signed in [false, true] {
            let mut fixture = KbsPolicyProvider::new(true);
            let token = if signed {
                "signed-publication"
            } else {
                "legacy-publication"
            };
            let hash = "ab".repeat(32);
            let mut annotations = serde_json::json!({
                POLICY_PUBLICATION_TOKEN_ANNOTATION: token,
            });
            if signed {
                annotations[POLICY_GENERATION_ANNOTATION] = serde_json::json!("1");
                annotations[POLICY_SHA256_ANNOTATION] = serde_json::json!(hash);
            }
            fixture.deployment["spec"]["template"]["metadata"]["annotations"] = annotations;
            fixture.deployment["status"]["replicas"] = serde_json::json!(2);
            fixture.deployment_gets_before_failure = Some(1);
            let provider = std::sync::Arc::new(tokio::sync::Mutex::new(fixture));
            let client = crate::test_support::kbs_policy_kube_client(provider.clone());
            let api = Api::<Deployment>::namespaced(client, "kbs-test");
            let pending = if signed {
                wait_for_deployment_policy_generation(&api, "trustee", 1, &hash, token, false).await
            } else {
                wait_for_legacy_publication(&api, "trustee", token).await
            };
            assert!(
                matches!(pending, Err(KbsPolicyError::Kube(_))),
                "the old ReplicaSet cannot satisfy publication readiness"
            );
            provider.lock().await.deployment["status"]["replicas"] = serde_json::json!(1);
            let ready = if signed {
                wait_for_deployment_policy_generation(&api, "trustee", 1, &hash, token, false).await
            } else {
                wait_for_legacy_publication(&api, "trustee", token).await
            };
            assert_eq!(ready.unwrap(), GenerationDecision::Current);
        }
    }

    #[tokio::test]
    async fn legacy_wait_rejects_another_publication() {
        let mut fixture = KbsPolicyProvider::new(true);
        fixture.deployment["spec"]["template"]["metadata"]["annotations"] = serde_json::json!({
            POLICY_PUBLICATION_TOKEN_ANNOTATION: "another-publication",
        });
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(fixture));
        let client = crate::test_support::kbs_policy_kube_client(provider);
        let api = Api::<Deployment>::namespaced(client, "kbs-test");
        assert_eq!(
            wait_for_legacy_publication(&api, "trustee", "expected-publication")
                .await
                .unwrap(),
            GenerationDecision::Superseded,
        );
    }

    #[tokio::test]
    async fn legacy_rollout_fails_closed_until_deployment_converges() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_fail_closed").await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_legacy_owner_binding(&pool, app_id, "legacy-owner").await;
        let config = legacy_kbs_test_config();
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        provider.lock().await.deployment_put_failures = usize::MAX;
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                assert!(reconcile_policy(&pool, Some(&config)).await.is_err());
                assert!(
                    provider.lock().await.configmap["data"]["policy.rego"]
                        .as_str()
                        .unwrap()
                        .contains("legacy-owner")
                );
                assert!(
                    reconcile_policy(&pool, Some(&config)).await.is_err(),
                    "an unchanged ConfigMap with an unconverged deployment marker must fail closed"
                );
                provider.lock().await.deployment_put_failures = 0;
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        let guard = provider.lock().await;
        assert_eq!(
            guard.configmap_replaces, 1,
            "recovery must reuse the persisted ConfigMap, not rewrite it"
        );
        assert_eq!(
            guard.deployment_replaces, 1,
            "converged passes must not rewrite the Trustee template"
        );
    }

    /// The legacy render records the publication obligation before any
    /// ConfigMap write whenever it carries signer identities (Codex review
    /// finding on #187): an unconfigured replica may only confirm a signer
    /// rotation while this durable evidence is absent, and a failed
    /// publication must not lose the evidence either.
    #[tokio::test]
    async fn legacy_render_with_tls_binding_records_publication_obligation() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_obligation").await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        assert!(
            !lock_legacy_publication_sentinel(&pool)
                .await
                .expect("lock publication sentinel on a fresh install")
                || !read_legacy_publication_obligation(&pool)
                    .await
                    .expect("read publication obligation on a fresh install"),
            "a fresh install starts without any legacy publication obligation"
        );
        insert_measured_legacy_tls_binding(
            &pool,
            app_id,
            "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
            "ghcr.io/enclava-labs/example@sha256:2222222222222222222222222222222222222222222222222222222222222222",
            &[0x22; 32],
        )
        .await;
        let config = legacy_kbs_test_config();
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        assert!(
            lock_legacy_publication_sentinel(&pool)
                .await
                .expect("lock publication sentinel after the legacy render")
                && read_legacy_publication_obligation(&pool)
                    .await
                    .expect("read publication obligation after the legacy render"),
            "a legacy render carrying signer identities must record the publication obligation"
        );
    }

    /// Finding-2 regression: the obligation is about policies that PIN a
    /// signer. A legacy render whose bindings carry no signer identity
    /// cannot authorize the rotated-out signer, so it must not record the
    /// obligation and must not fence rotations on an unconfigured replica.
    #[tokio::test]
    async fn legacy_render_without_signer_identity_records_no_publication_obligation() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_null_identity_obligation")
                .await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        // A measured binding that pins no signer (the pre-signer-identity
        // binding shape).
        sqlx::query(
            "INSERT INTO kbs_tls_bindings (
                 app_id, binding_key, repository, tag, namespace, service_account,
                 tenant_instance_identity_hash, image_digest, init_data_hash,
                 signer_identity_subject, signer_identity_issuer
             ) VALUES ($1, 'tls-null-identity', 'default', 'workload-secret-seed',
                 'cap-null-identity', 'cap-null-identity-sa', $2, $3, $4, NULL, NULL)",
        )
        .bind(app_id)
        .bind("22".repeat(32))
        .bind("ghcr.io/enclava-labs/example@sha256:2222222222222222222222222222222222222222222222222222222222222222")
        .bind(&[0x22u8; 32][..])
        .execute(&pool)
        .await
        .expect("insert null-identity legacy tls binding");
        let config = legacy_kbs_test_config();
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        assert!(
            !lock_legacy_publication_sentinel(&pool)
                .await
                .expect("lock sentinel after the null-identity render")
                || !read_legacy_publication_obligation(&pool)
                    .await
                    .expect("read publication obligation after the null-identity render"),
            "a legacy render that pins no signer must not record the publication obligation"
        );
    }

    #[tokio::test]
    async fn legacy_marker_match_still_requires_readiness_without_new_rollout() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_readiness").await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_legacy_owner_binding(&pool, app_id, "legacy-owner").await;
        let config = legacy_kbs_test_config();
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        provider.lock().await.deployment_gets_before_failure = Some(1);
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                assert!(reconcile_policy(&pool, Some(&config)).await.is_err());
                assert_eq!(provider.lock().await.deployment_replaces, 1);
                provider.lock().await.deployment_gets_before_failure = Some(1);
                assert!(reconcile_policy(&pool, Some(&config)).await.is_err());
                assert_eq!(provider.lock().await.deployment_replaces, 1);
                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        let guard = provider.lock().await;
        assert_eq!(
            guard.deployment_replaces, 1,
            "a readiness-only retry must not rewrite the Trustee template"
        );
    }

    #[tokio::test]
    async fn legacy_converged_passes_perform_no_recurring_writes() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_no_churn").await;
        let config = legacy_kbs_test_config();
        let mut fixture = KbsPolicyProvider::new(true);
        let policy = fixture.configmap["data"]["policy.rego"].as_str().unwrap();
        let policy = replace_tls_resource_bindings_block(policy, &[]).unwrap();
        let policy = replace_owner_bindings_block(&policy, &[]).unwrap();
        fixture.configmap["data"]["policy.rego"] = serde_json::json!(policy);
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(fixture));
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                reconcile_policy(&pool, Some(&config)).await.unwrap();

                // External metadata-only churn: resourceVersion, labels, and
                // an unrelated data key advance without a policy change, so
                // the converged publication must not rewrite anything.
                let mut guard = provider.lock().await;
                guard.configmap["metadata"]["resourceVersion"] = serde_json::json!("2");
                guard.configmap["metadata"]["labels"] = serde_json::json!({"team": "platform"});
                guard.configmap["data"]["unrelated.txt"] = serde_json::json!("noise");
                drop(guard);

                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        let guard = provider.lock().await;
        assert_eq!(
            guard.configmap_replaces, 1,
            "one adoption write to persist the publication nonce, then none"
        );
        assert_eq!(
            guard.deployment_replaces, 1,
            "one adoption rollout, then zero recurring Trustee rewrites"
        );
    }

    /// Adopting unchanged legacy bytes must persist a single-use publication
    /// event rather than leaning on the deterministic hash token (Codex
    /// review finding on #187): a pre-upgrade ConfigMap without a valid
    /// annotation gets a fresh nonce and a real rollout, so a Deployment that
    /// kept an older token for the same bytes cannot be mistaken for a
    /// healthy rollout of an intervening external publication.
    #[tokio::test]
    async fn legacy_adoption_persists_publication_nonce() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_adoption_nonce").await;
        let config = legacy_kbs_test_config();
        let mut fixture = KbsPolicyProvider::new(true);
        let policy = fixture.configmap["data"]["policy.rego"].as_str().unwrap();
        let policy = replace_tls_resource_bindings_block(policy, &[]).unwrap();
        let policy = replace_owner_bindings_block(&policy, &[]).unwrap();
        fixture.configmap["data"]["policy.rego"] = serde_json::json!(policy);
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(fixture));
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                // First adoption of the pre-upgrade ConfigMap: the bytes are
                // already correct but no publication event exists, so a
                // nonce must be persisted and rolled out.
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                {
                    let guard = provider.lock().await;
                    assert_eq!(guard.configmap_replaces, 1);
                    assert_eq!(guard.deployment_replaces, 1);
                    let annotation = guard.configmap["metadata"]["annotations"]
                        [POLICY_PUBLICATION_TOKEN_ANNOTATION]
                        .as_str()
                        .expect("adoption must persist a publication token annotation");
                    assert!(
                        annotation.starts_with("legacy:kbs-test/resource-policy/policy.rego:"),
                        "the persisted token must be namespaced to this policy body, got {annotation}"
                    );
                    let nonce = annotation.rsplit(':').next().unwrap();
                    assert!(
                        Uuid::parse_str(nonce).is_ok(),
                        "the persisted token must carry a fresh single-use nonce, got {annotation}"
                    );
                }

                // An external writer restores the original bytes but strips
                // the publication event (or leaves a malformed one): the
                // adoption must be re-observed with a fresh nonce and a real
                // rollout, never accepted via the deterministic token.
                {
                    let mut guard = provider.lock().await;
                    guard.configmap["metadata"]["resourceVersion"] = serde_json::json!("3");
                    guard.configmap["metadata"]["annotations"]
                        .as_object_mut()
                        .unwrap()
                        .remove(POLICY_PUBLICATION_TOKEN_ANNOTATION);
                }
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                {
                    let guard = provider.lock().await;
                    assert_eq!(
                        guard.configmap_replaces, 2,
                        "an adoption without a valid publication event must rewrite the ConfigMap"
                    );
                    assert_eq!(
                        guard.deployment_replaces, 2,
                        "the re-adoption must trigger a fresh Trustee rollout"
                    );
                }

                // Steady state: a valid event for these bytes stays put.
                reconcile_policy(&pool, Some(&config)).await.unwrap();
                let guard = provider.lock().await;
                assert_eq!(guard.configmap_replaces, 2);
                assert_eq!(guard.deployment_replaces, 2);
            })
            .await;
    }

    #[tokio::test]
    async fn legacy_rollout_reconverges_when_configmap_changes_mid_rollout() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_reconverge").await;
        let (_org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_legacy_owner_binding(&pool, app_id, "legacy-owner").await;
        let config = legacy_kbs_test_config();
        let mut fixture = KbsPolicyProvider::new(true);
        let mut replacement = fixture.configmap.clone();
        replacement["metadata"]["resourceVersion"] = serde_json::json!("external-rewrite");
        fixture.replace_configmap_on_next_deployment_get = Some(replacement);
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(fixture));
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                reconcile_policy(&pool, Some(&config)).await.unwrap();
            })
            .await;
        let guard = provider.lock().await;
        assert_eq!(
            guard.configmap_replaces, 2,
            "the externally replaced ConfigMap must be republished"
        );
        assert_eq!(
            guard.deployment_replaces, 2,
            "the new publication must trigger a fresh rollout"
        );
        assert!(
            guard.configmap["data"]["policy.rego"]
                .as_str()
                .unwrap()
                .contains("legacy-owner")
        );
    }

    #[tokio::test]
    async fn legacy_rollout_hands_off_to_signed_authority() {
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap187_legacy_signed_handoff").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_legacy_owner_binding(&pool, app_id, "legacy-owner").await;
        let config = legacy_kbs_test_config();
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        provider.lock().await.deployment_gets_before_failure = Some(1);
        let client = crate::test_support::kbs_policy_kube_client(provider.clone());
        crate::kbs::TEST_KUBE_CLIENT
            .scope(client, async {
                assert!(reconcile_policy(&pool, Some(&config)).await.is_err());

                let signer = "bb".repeat(32);
                insert_test_keyring_version(&pool, org_id, 1, &[&signer]).await;
                let deployment = Uuid::new_v4();
                insert_test_deployment(&pool, org_id, app_id, deployment, "healthy", Utc::now())
                    .await;
                let artifact = insert_test_artifact(&pool, app_id, deployment, "aa").await;
                sqlx::query(
                    "UPDATE kbs_signed_policy_reconciliation
                    SET desired_generation = 1
                  WHERE singleton",
                )
                .execute(&pool)
                .await
                .expect("activate signed policy mode");

                reconcile_policy(&pool, Some(&config)).await.unwrap();
                let guard = provider.lock().await;
                let body = guard.configmap["data"]["policy.rego"].as_str().unwrap();
                assert!(
                    body.contains(&artifact.metadata.descriptor_core_hash),
                    "the signed artifact set must replace the legacy Rego body"
                );
                let annotations = &guard.deployment["spec"]["template"]["metadata"]["annotations"];
                assert_eq!(
                    annotations["enclava.dev/cap-policy-generation"]
                        .as_str()
                        .unwrap(),
                    "1"
                );
            })
            .await;
    }

    #[tokio::test]
    async fn replacement_handoff_keeps_running_authority_required_until_healthy() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        // A signed replacement released from its hold whose apply has not
        // completed.
        let (signed_org, signed_app) = insert_test_app(&pool, "running").await;
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, signed_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, unsigned_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, held_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, legacy_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, stopped_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, deleting_org, 1, &["bb".repeat(32).as_str()]).await;
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
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, fresh_org, 1, &["bb".repeat(32).as_str()]).await;
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

    #[tokio::test]
    async fn deleting_app_keeps_authorization_only_while_teardown_pending() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        let (pending_org, pending_app) = insert_test_app(&pool, "deleting").await;

        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, pending_org, 1, &["bb".repeat(32).as_str()]).await;
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

        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, completed_org, 1, &["bb".repeat(32).as_str()]).await;
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

    fn teardown_budget_config(max_policy_bytes: usize) -> KbsPolicyConfig {
        KbsPolicyConfig {
            namespace: "cap-test".to_string(),
            configmap_name: "resource-policy".to_string(),
            policy_key: "resource-policy.rego".to_string(),
            deployment_name: "trustee".to_string(),
            required: false,
            signed_policy_retention: 6,
            signed_policy_max_bytes: max_policy_bytes,
        }
    }

    /// Codex security finding 4a27950: a delete whose teardown unit would
    /// overflow the shared byte budget must be refused up front — the
    /// fail-closed selector would otherwise wedge every app's policy
    /// convergence.
    #[tokio::test]
    async fn teardown_admission_refuses_a_unit_that_exceeds_the_shared_budget() {
        // The budget check sums required candidates across every app, so a
        // sibling test's live fixtures would shift the byte math; run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_over_budget").await;
        let now = Utc::now();

        // Mid-upgrade delete: the unit pins the last completed workload plus
        // the newer published generation, growing the required set by the
        // older artifact.
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The teardown unit loader and the deleting selector filter artifacts
        // by current keyring membership (issue #130), so the fixture signer
        // (bb repeated) must be a current member.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        let completed = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, completed, "healthy", now).await;
        let completed_artifact = insert_test_artifact(&pool, app_id, completed, "aa").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            completed,
            completed,
            Some((completed, &completed_artifact)),
        )
        .await;
        let published = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            published,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let published_artifact = insert_test_artifact(&pool, app_id, published, "bb").await;
        insert_failed_apply_job(&pool, org_id, app_id, published, &published_artifact, 7).await;
        mark_test_workload_published(&pool, published).await;

        let unit_len =
            signed_policy_artifact_policy_body(&dedup_signed_policy_artifacts_by_hash(vec![
                completed_artifact.clone(),
                published_artifact.clone(),
            ]))
            .expect("serialize projected teardown unit")
            .len();

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len)),
            app_id,
        )
        .await
        .expect("admit a teardown unit that fits the shared budget");
        assert!(
            fits,
            "a teardown unit that fits the shared byte budget must be admitted"
        );

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len - 1)),
            app_id,
        )
        .await
        .expect("refuse a teardown unit that exceeds the shared budget");
        assert!(
            !fits,
            "a teardown unit that would overflow the shared byte budget must be refused"
        );

        crate::test_support::drop_isolated_database("cap_teardown_over_budget", pool).await;
    }

    /// Other apps' pending teardown pins already occupy the budget: admitting
    /// another unit must count them instead of only checking this app in
    /// isolation.
    #[tokio::test]
    async fn teardown_admission_counts_other_apps_pending_pins() {
        // The budget check counts required candidates across every app, so
        // run on a per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_pin_bytes").await;
        let now = Utc::now();

        let (pin_org, pin_app) = insert_test_app(&pool, "deleting").await;
        // Both loaders filter by current keyring membership (issue #130):
        // the pin artifact stays authorized only while its fixture signer
        // (bb repeated) is a current member of the pin org's keyring.
        insert_test_keyring_version(&pool, pin_org, 1, &["bb".repeat(32).as_str()]).await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(pin_app)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");
        let pin_deployment = Uuid::new_v4();
        insert_test_deployment(&pool, pin_org, pin_app, pin_deployment, "healthy", now).await;
        let pin_artifact = insert_test_artifact(&pool, pin_app, pin_deployment, "cc").await;
        insert_test_job(
            &pool,
            pin_org,
            pin_app,
            pin_deployment,
            pin_deployment,
            Some((pin_deployment, &pin_artifact)),
        )
        .await;

        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        let completed = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, completed, "healthy", now).await;
        let completed_artifact = insert_test_artifact(&pool, app_id, completed, "aa").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            completed,
            completed,
            Some((completed, &completed_artifact)),
        )
        .await;
        let published = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            published,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let published_artifact = insert_test_artifact(&pool, app_id, published, "bb").await;
        insert_failed_apply_job(&pool, org_id, app_id, published, &published_artifact, 7).await;
        mark_test_workload_published(&pool, published).await;

        let unit_len =
            signed_policy_artifact_policy_body(&dedup_signed_policy_artifacts_by_hash(vec![
                completed_artifact,
                published_artifact,
            ]))
            .expect("serialize projected teardown unit")
            .len();
        let pin_len = signed_policy_artifact_policy_body(&[pin_artifact])
            .expect("serialize pending teardown pin")
            .len();

        // The applicant's own unit fits alone; the other app's pending pin
        // eats the headroom and must be counted.
        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len)),
            app_id,
        )
        .await
        .expect("weigh other apps' pending teardown pins");
        assert!(
            !fits,
            "another app's pending teardown pin must count against the shared byte budget"
        );

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(pin_len + unit_len)),
            app_id,
        )
        .await
        .expect("admit a teardown unit alongside existing pins");
        assert!(
            fits,
            "a teardown unit must be admitted once every required artifact fits"
        );

        crate::test_support::drop_isolated_database("cap_teardown_pin_bytes", pool).await;
    }

    /// A delete that does not grow the required set must never be refused —
    /// even an already-overflowed deployment has to be able to shrink back,
    /// and deleting a healthy app replaces its live authority with the same
    /// artifact.
    #[tokio::test]
    async fn teardown_admission_never_refuses_a_non_growing_delete() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The teardown unit loader and the deleting selector filter artifacts
        // by current keyring membership (issue #130), so the fixture signer
        // (bb repeated) must be a current member.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        let deployment_id = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, deployment_id, "healthy", now).await;
        let artifact = insert_test_artifact(&pool, app_id, deployment_id, "dd").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            deployment_id,
            deployment_id,
            Some((deployment_id, &artifact)),
        )
        .await;

        // A budget far below anything realistic: the unit replaces this app's
        // live required artifact byte for byte, so the required set cannot
        // grow and the delete must be admitted regardless.
        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(1)),
            app_id,
        )
        .await
        .expect("admit a delete that does not grow the required set");
        assert!(
            fits,
            "a delete that does not grow the required set must never be refused"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete non-growing delete fixture organization");
    }

    /// A deletion retry after the teardown already completed must bypass
    /// admission: the selector excludes apps with
    /// `workload_teardown_completed_at` set, so projecting the unit would
    /// phantom-409 the only operation that removes the app when the budget
    /// is tight.
    #[tokio::test]
    async fn teardown_admission_bypasses_completed_teardown_retries() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;
        // Keep the fixture signer (bb repeated) in the current keyring so the
        // completed-teardown artifacts remain eligible if the bypass regresses.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        sqlx::query(
            "UPDATE apps
                SET workload_teardown_required = true,
                    workload_teardown_completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("mark workload teardown completed");

        // Two historical teardown artifacts that would never fit a tiny
        // budget — exactly the phantom-pin scenario from review.
        let completed = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, completed, "healthy", now).await;
        let completed_artifact = insert_test_artifact(&pool, app_id, completed, "ee").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            completed,
            completed,
            Some((completed, &completed_artifact)),
        )
        .await;
        let published = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            published,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let published_artifact = insert_test_artifact(&pool, app_id, published, "ff").await;
        insert_failed_apply_job(&pool, org_id, app_id, published, &published_artifact, 9).await;
        mark_test_workload_published(&pool, published).await;

        let unit_len = signed_policy_artifact_policy_body(&[
            completed_artifact.clone(),
            published_artifact.clone(),
        ])
        .expect("serialize the would-be teardown unit")
        .len();

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len / 2)),
            app_id,
        )
        .await
        .expect("admission check on a completed teardown");
        assert!(
            fits,
            "a deletion retry after teardown completed must bypass budget admission"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete completed-teardown fixture organization");
    }

    /// Codex review on 0c678f57 (mixed legacy authority): the app still runs a
    /// pre-job healthy deployment while a later job-backed replacement failed
    /// after publishing its workload spec. The selector keeps BOTH artifacts
    /// required while deleting, so admission must project both — excluding
    /// every legacy row merely because an apply job exists undercounts the
    /// authority the delete will actually pin.
    #[tokio::test]
    async fn teardown_admission_counts_mixed_legacy_authority() {
        // The budget check sums required candidates across every app, so
        // run on a per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_mixed").await;
        let now = Utc::now();

        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The teardown unit loader filters both the job unit and the legacy
        // unit by current keyring membership (issue #130), so the fixture
        // signer (bb repeated) must be a current member.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        // The pre-job healthy workload: a deployment with no apply job rows.
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, app_id, legacy, "ee").await;
        // The failed job-backed replacement that still published its spec.
        let published = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            published,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let published_artifact = insert_test_artifact(&pool, app_id, published, "0f").await;
        insert_failed_apply_job(&pool, org_id, app_id, published, &published_artifact, 7).await;
        mark_test_workload_published(&pool, published).await;

        let unit_len =
            signed_policy_artifact_policy_body(&dedup_signed_policy_artifacts_by_hash(vec![
                legacy_artifact.clone(),
                published_artifact.clone(),
            ]))
            .expect("serialize the projected mixed teardown unit")
            .len();

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len)),
            app_id,
        )
        .await
        .expect("admit the full mixed legacy/job unit");
        assert!(
            fits,
            "the full mixed legacy/job teardown unit fits the shared byte budget"
        );

        let fits = teardown_unit_fits_signed_policy_budget(
            &pool,
            Some(&teardown_budget_config(unit_len - 1)),
            app_id,
        )
        .await
        .expect("refuse a mixed unit that exceeds the shared budget");
        assert!(
            !fits,
            "the legacy artifact must count against the projected teardown unit, \
             not disappear merely because an apply job exists"
        );

        crate::test_support::drop_isolated_database("cap_teardown_mixed", pool).await;
    }

    /// Selector-vs-projection regression: the admission projection must pin
    /// exactly the authority the deleting selector will require. Both sides
    /// filter by current-keyring deploy-role membership (case-insensitive)
    /// and drop withdrawn artifacts, and neither treats an unreleased
    /// customer-config hold as the newest operation — a drift in either
    /// predicate undercounts (teardown denied live authority) or inflates
    /// (phantom 409) the projected unit.
    async fn teardown_projection(pool: &PgPool, app_id: Uuid) -> HashSet<String> {
        load_teardown_policy_unit(pool, app_id)
            .await
            .expect("project teardown unit")
            .into_iter()
            .map(|artifact| artifact.metadata.descriptor_core_hash)
            .collect()
    }

    async fn deleting_selector_authority(pool: &PgPool, app_id: Uuid) -> HashSet<String> {
        load_signed_policy_candidates(pool, 1)
            .await
            .expect("load deleting selector candidates")
            .into_iter()
            .filter(|candidate| candidate.required)
            .filter(|candidate| candidate.artifact.metadata.app_id == app_id.to_string())
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash)
            .collect()
    }

    async fn assert_projection_matches_selector(pool: &PgPool, app_id: Uuid, label: &str) {
        assert_eq!(
            teardown_projection(pool, app_id).await,
            deleting_selector_authority(pool, app_id).await,
            "{label}: the teardown-unit projection must match the authority the deleting selector requires"
        );
    }

    async fn insert_teardown_pending_app(pool: &PgPool) -> (Uuid, Uuid) {
        let (org_id, app_id) = insert_test_app(pool, "deleting").await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(app_id)
            .execute(pool)
            .await
            .expect("mark workload teardown pending");
        (org_id, app_id)
    }

    /// A deleting app whose newest completed job-backed deployment carries
    /// the given signer. Returns the hash both sides must agree on.
    async fn insert_job_teardown_authority(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        signer: &str,
    ) -> crate::signing_service::SignedPolicyArtifact {
        let live = Uuid::new_v4();
        insert_test_deployment(pool, org_id, app_id, live, "healthy", Utc::now()).await;
        let artifact = insert_test_artifact_signed_by(pool, app_id, live, "aa", signer).await;
        insert_test_job(pool, org_id, app_id, live, live, Some((live, &artifact))).await;
        artifact
    }

    /// A deleting app whose only authority is a pre-job healthy deployment.
    async fn insert_legacy_teardown_authority(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        signer: &str,
    ) -> crate::signing_service::SignedPolicyArtifact {
        let legacy = Uuid::new_v4();
        insert_test_deployment(pool, org_id, app_id, legacy, "healthy", Utc::now()).await;
        insert_test_artifact_signed_by(pool, app_id, legacy, "aa", signer).await
    }

    async fn withdraw_fixture_artifact(
        pool: &PgPool,
        artifact: &crate::signing_service::SignedPolicyArtifact,
        app_id: Uuid,
    ) {
        sqlx::query(
            "INSERT INTO withdrawn_signer_artifacts (descriptor_core_hash, app_id)
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(hex::decode(&artifact.metadata.descriptor_core_hash).unwrap())
        .bind(app_id)
        .execute(pool)
        .await
        .expect("withdraw teardown artifact");
    }

    async fn delete_fixture_orgs(pool: &PgPool, orgs: &[Uuid]) {
        for org in orgs {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org)
                .execute(pool)
                .await
                .expect("delete selector-parity fixture organization");
        }
    }

    /// Job-backed teardown authority: for every keyring shape and withdrawal
    /// state, the projected unit must equal the required set the deleting
    /// selector admits.
    #[tokio::test]
    async fn teardown_unit_projection_matches_deleting_selector_for_job_authority() {
        let pool = crate::test_support::database_test_pool().await;
        let signer = "bb";

        // Missing keyring: nothing is authorized on either side.
        let (no_keyring_org, no_keyring_app) = insert_teardown_pending_app(&pool).await;
        insert_job_teardown_authority(&pool, no_keyring_org, no_keyring_app, signer).await;

        // Current member: both sides admit the artifact.
        let (current_org, current_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, current_org, 1, &[signer.repeat(32).as_str()]).await;
        let current_artifact =
            insert_job_teardown_authority(&pool, current_org, current_app, signer).await;

        // Rotated-out signer: version 2 drops bb, so both sides drop it.
        let (rotated_org, rotated_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, rotated_org, 1, &[signer.repeat(32).as_str()]).await;
        insert_test_keyring_version(&pool, rotated_org, 2, &["ab".repeat(32).as_str()]).await;
        insert_job_teardown_authority(&pool, rotated_org, rotated_app, signer).await;

        // Non-deploy role: a 'viewer' member never authorizes artifacts.
        let (viewer_org, viewer_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_with_roles(
            &pool,
            viewer_org,
            1,
            &[(signer.repeat(32).as_str(), "viewer")],
        )
        .await;
        insert_job_teardown_authority(&pool, viewer_org, viewer_app, signer).await;

        // Uppercase member pubkey: membership compares case-insensitively,
        // so both sides still admit the lowercase-signed artifact.
        let (upper_org, upper_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, upper_org, 1, &["BB".repeat(32).as_str()]).await;
        let upper_artifact =
            insert_job_teardown_authority(&pool, upper_org, upper_app, signer).await;

        // Withdrawn artifact: both sides must refuse it.
        let (withdrawn_org, withdrawn_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, withdrawn_org, 1, &[signer.repeat(32).as_str()]).await;
        let withdrawn_artifact =
            insert_job_teardown_authority(&pool, withdrawn_org, withdrawn_app, signer).await;
        withdraw_fixture_artifact(&pool, &withdrawn_artifact, withdrawn_app).await;

        assert_projection_matches_selector(&pool, no_keyring_app, "job authority without keyring")
            .await;
        assert_eq!(teardown_projection(&pool, no_keyring_app).await.len(), 0);
        assert_projection_matches_selector(&pool, current_app, "job authority with current member")
            .await;
        assert_eq!(
            teardown_projection(&pool, current_app).await,
            HashSet::from([current_artifact.metadata.descriptor_core_hash.clone()])
        );
        assert_projection_matches_selector(&pool, rotated_app, "job authority after rotation")
            .await;
        assert_eq!(teardown_projection(&pool, rotated_app).await.len(), 0);
        assert_projection_matches_selector(&pool, viewer_app, "job authority with non-deploy role")
            .await;
        assert_eq!(teardown_projection(&pool, viewer_app).await.len(), 0);
        assert_projection_matches_selector(&pool, upper_app, "job authority with uppercase member")
            .await;
        assert_eq!(
            teardown_projection(&pool, upper_app).await,
            HashSet::from([upper_artifact.metadata.descriptor_core_hash.clone()])
        );
        assert_projection_matches_selector(&pool, withdrawn_app, "job authority withdrawn").await;
        assert_eq!(teardown_projection(&pool, withdrawn_app).await.len(), 0);

        delete_fixture_orgs(
            &pool,
            &[
                no_keyring_org,
                current_org,
                rotated_org,
                viewer_org,
                upper_org,
                withdrawn_org,
            ],
        )
        .await;
    }

    /// Legacy (pre-job) teardown authority: same selector/projection parity
    /// on the legacy arm, plus an unreleased customer-config hold, which the
    /// selector excludes before ranking and the projection must too.
    #[tokio::test]
    async fn teardown_unit_projection_matches_deleting_selector_for_legacy_authority() {
        let pool = crate::test_support::database_test_pool().await;
        let signer = "bb";

        // Missing keyring.
        let (no_keyring_org, no_keyring_app) = insert_teardown_pending_app(&pool).await;
        insert_legacy_teardown_authority(&pool, no_keyring_org, no_keyring_app, signer).await;

        // Current member.
        let (current_org, current_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, current_org, 1, &[signer.repeat(32).as_str()]).await;
        let current_artifact =
            insert_legacy_teardown_authority(&pool, current_org, current_app, signer).await;

        // Rotated-out signer.
        let (rotated_org, rotated_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, rotated_org, 1, &[signer.repeat(32).as_str()]).await;
        insert_test_keyring_version(&pool, rotated_org, 2, &["ab".repeat(32).as_str()]).await;
        insert_legacy_teardown_authority(&pool, rotated_org, rotated_app, signer).await;

        // Non-deploy role.
        let (viewer_org, viewer_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_with_roles(
            &pool,
            viewer_org,
            1,
            &[(signer.repeat(32).as_str(), "viewer")],
        )
        .await;
        insert_legacy_teardown_authority(&pool, viewer_org, viewer_app, signer).await;

        // Uppercase member pubkey.
        let (upper_org, upper_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, upper_org, 1, &["BB".repeat(32).as_str()]).await;
        let upper_artifact =
            insert_legacy_teardown_authority(&pool, upper_org, upper_app, signer).await;

        // Withdrawn artifact.
        let (withdrawn_org, withdrawn_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, withdrawn_org, 1, &[signer.repeat(32).as_str()]).await;
        let withdrawn_artifact =
            insert_legacy_teardown_authority(&pool, withdrawn_org, withdrawn_app, signer).await;
        withdraw_fixture_artifact(&pool, &withdrawn_artifact, withdrawn_app).await;

        // Unreleased hold: the only apply job is held pending, so the
        // selector ranks nothing and the projection must be empty too.
        let (held_org, held_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, held_org, 1, &[signer.repeat(32).as_str()]).await;
        let held = Uuid::new_v4();
        insert_test_deployment(&pool, held_org, held_app, held, "healthy", Utc::now()).await;
        let held_artifact =
            insert_test_artifact_signed_by(&pool, held_app, held, "aa", signer).await;
        insert_test_job(
            &pool,
            held_org,
            held_app,
            held,
            held,
            Some((held, &held_artifact)),
        )
        .await;
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
        .expect("hold the teardown job");
        // Nonterminal deployments require a nonterminal durable job.
        sqlx::query("UPDATE deployments SET status = 'pending' WHERE id = $1")
            .bind(held)
            .execute(&pool)
            .await
            .expect("mark the held deployment pending after its durable job exists");

        // Released hold: the same job counts again on both sides.
        let (released_org, released_app) = insert_teardown_pending_app(&pool).await;
        insert_test_keyring_version(&pool, released_org, 1, &[signer.repeat(32).as_str()]).await;
        let released = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            released_org,
            released_app,
            released,
            "healthy",
            Utc::now(),
        )
        .await;
        let released_artifact =
            insert_test_artifact_signed_by(&pool, released_app, released, "aa", signer).await;
        insert_test_job(
            &pool,
            released_org,
            released_app,
            released,
            released,
            Some((released, &released_artifact)),
        )
        .await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() - interval '1 hour',
                    customer_config_released_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(released)
        .execute(&pool)
        .await
        .expect("release the teardown job hold");

        assert_projection_matches_selector(
            &pool,
            no_keyring_app,
            "legacy authority without keyring",
        )
        .await;
        assert_eq!(teardown_projection(&pool, no_keyring_app).await.len(), 0);
        assert_projection_matches_selector(
            &pool,
            current_app,
            "legacy authority with current member",
        )
        .await;
        assert_eq!(
            teardown_projection(&pool, current_app).await,
            HashSet::from([current_artifact.metadata.descriptor_core_hash.clone()])
        );
        assert_projection_matches_selector(&pool, rotated_app, "legacy authority after rotation")
            .await;
        assert_eq!(teardown_projection(&pool, rotated_app).await.len(), 0);
        assert_projection_matches_selector(
            &pool,
            viewer_app,
            "legacy authority with non-deploy role",
        )
        .await;
        assert_eq!(teardown_projection(&pool, viewer_app).await.len(), 0);
        assert_projection_matches_selector(
            &pool,
            upper_app,
            "legacy authority with uppercase member",
        )
        .await;
        assert_eq!(
            teardown_projection(&pool, upper_app).await,
            HashSet::from([upper_artifact.metadata.descriptor_core_hash.clone()])
        );
        assert_projection_matches_selector(&pool, withdrawn_app, "legacy authority withdrawn")
            .await;
        assert_eq!(teardown_projection(&pool, withdrawn_app).await.len(), 0);
        assert_projection_matches_selector(&pool, held_app, "unreleased hold").await;
        assert_eq!(teardown_projection(&pool, held_app).await.len(), 0);
        assert_projection_matches_selector(&pool, released_app, "released hold").await;
        assert_eq!(
            teardown_projection(&pool, released_app).await,
            HashSet::from([released_artifact.metadata.descriptor_core_hash.clone()])
        );

        delete_fixture_orgs(
            &pool,
            &[
                no_keyring_org,
                current_org,
                rotated_org,
                viewer_org,
                upper_org,
                withdrawn_org,
                held_org,
                released_org,
            ],
        )
        .await;
    }

    /// Codex review on 0c678f57 (over-budget republication): when the required
    /// set is already over budget but the live policy carries the app's full
    /// teardown unit, the delete must be able to proceed to teardown without
    /// demanding an impossible republication.
    #[tokio::test]
    async fn teardown_unit_already_published_checks_the_live_policy_body() {
        let pool = crate::test_support::database_test_pool().await;
        let now = Utc::now();

        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The production unit loader filters by current keyring membership
        // (issue #130); the fixture signer (bb repeated) must be a member or
        // load_teardown_policy_unit below returns an empty unit.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", now).await;
        let legacy_artifact = insert_test_artifact(&pool, app_id, legacy, "1e").await;
        let published = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            published,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        let published_artifact = insert_test_artifact(&pool, app_id, published, "2e").await;
        insert_failed_apply_job(&pool, org_id, app_id, published, &published_artifact, 7).await;
        mark_test_workload_published(&pool, published).await;

        let config = teardown_budget_config(1024 * 1024);
        let full_body =
            signed_policy_artifact_policy_body(&dedup_signed_policy_artifacts_by_hash(vec![
                legacy_artifact.clone(),
                published_artifact.clone(),
            ]))
            .expect("serialize the live policy body");
        let partial_body =
            signed_policy_artifact_policy_body(&dedup_signed_policy_artifacts_by_hash(vec![
                published_artifact.clone(),
            ]))
            .expect("serialize the partial policy body");

        let client_for = |policy: String, deployment_token: &'static str| {
            kube::Client::new(
                tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
                    let hash = hex::encode(Sha256::digest(policy.as_bytes()));
                    let annotations = serde_json::json!({
                        (POLICY_GENERATION_ANNOTATION): "7",
                        (POLICY_SHA256_ANNOTATION): hash,
                        (POLICY_PUBLICATION_TOKEN_ANNOTATION): "published",
                    });
                    let object = if request.uri().path().contains("deployments") {
                        serde_json::json!({
                            "apiVersion": "apps/v1", "kind": "Deployment",
                            "metadata": {"name": "trustee", "namespace": "cap-test"},
                            "spec": {"template": {"metadata": {"annotations": {
                                (POLICY_GENERATION_ANNOTATION): "7",
                                (POLICY_SHA256_ANNOTATION): hash,
                                (POLICY_PUBLICATION_TOKEN_ANNOTATION): deployment_token,
                            }}}}
                        })
                    } else {
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": {"name": "resource-policy", "namespace": "cap-test",
                                         "resourceVersion": "3", "annotations": annotations},
                            "data": {"resource-policy.rego": policy}
                        })
                    };
                    async move {
                        Ok::<_, std::io::Error>(axum::http::Response::new(
                            kube::client::Body::from(serde_json::to_vec(&object).unwrap()),
                        ))
                    }
                }),
                "default",
            )
        };

        // Exercise the production unit loader too: the publication predicate
        // must not silently pass because the app's teardown set is empty.
        let loaded_unit = dedup_signed_policy_artifacts_by_hash(
            load_teardown_policy_unit(&pool, app_id)
                .await
                .expect("load teardown unit"),
        );
        assert_eq!(
            loaded_unit.len(),
            2,
            "both teardown artifacts must be loaded"
        );
        assert!(signed_policy_body_covers_artifacts(
            &signed_policy_artifact_policy_body(&loaded_unit).expect("serialize loaded unit"),
            &[legacy_artifact.clone(), published_artifact.clone()],
        ));
        let unit = loaded_unit;
        let production_covers = teardown_unit_already_published(
            &pool,
            &config,
            client_for(partial_body.clone(), "published"),
            app_id,
        )
        .await
        .expect("check production loader against partial live policy");
        assert!(
            !production_covers,
            "a missing teardown artifact must fail closed through the production entry point"
        );
        let covers = teardown_unit_already_published_with_applied(
            &config,
            client_for(full_body.clone(), "published"),
            &unit,
            None,
        )
        .await
        .expect("check pending publication");
        assert!(
            !covers,
            "ConfigMap publication alone must not authorize teardown"
        );

        let full_hash = Sha256::digest(full_body.as_bytes()).to_vec();
        let applied = Some((7, full_hash));
        let covers = teardown_unit_already_published_with_applied(
            &config,
            client_for(full_body.clone(), "published"),
            &unit,
            applied.clone(),
        )
        .await
        .expect("check applied publication");
        assert!(
            covers,
            "applied full-unit policy must let the delete proceed"
        );

        let covers = teardown_unit_already_published_with_applied(
            &config,
            client_for(full_body.clone(), "stale"),
            &unit,
            applied.clone(),
        )
        .await
        .expect("check deployment publication token");
        assert!(!covers, "a different Trustee publication must fail closed");

        let covers = teardown_unit_already_published_with_applied(
            &config,
            client_for(partial_body.clone(), "published"),
            &unit,
            applied,
        )
        .await
        .expect("check partial policy body");
        assert!(!covers, "partial unit must still fail the delete");

        // The exact live body also covers a single-artifact unit, proving the
        // pure predicate handles the single-artifact body shape too.
        assert!(signed_policy_body_covers_artifacts(
            &full_body,
            std::slice::from_ref(&legacy_artifact),
        ));
        assert!(!signed_policy_body_covers_artifacts(
            "package authz\n# legacy rego\n",
            &[legacy_artifact],
        ));
        assert!(signed_policy_body_covers_artifacts("package authz", &[]));

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete already-published fixture organization");
    }

    #[tokio::test]
    async fn teardown_pending_authorization_survives_deployment_supersession() {
        // Asserts the exact size of the global candidate set, so run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_supersede").await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;

        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
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

        // Setup accepted, still pending, then superseded before apply.
        // No StatefulSet was written. The three rows share one transaction:
        // a nonterminal deployment requires its apply job at INSERT time,
        // while the job's artifact binding and the artifact's deployment
        // reference are deferred FKs.
        let pending = Uuid::new_v4();
        let mut pending_artifact = test_signed_policy_artifact("cd", 16);
        pending_artifact.metadata.descriptor_core_hash = unique_test_descriptor_hash("cd", pending);
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
            !hashes.contains(pending_artifact.metadata.descriptor_core_hash.as_str()),
            "a setup-accepted job superseded before publication wrote no spec"
        );
        assert_eq!(
            hashes.len(),
            1,
            "only the last applied workload stays authorized"
        );
        assert!(
            !hashes.contains(dead_artifact.metadata.descriptor_core_hash.as_str()),
            "a long-dead historical operation's artifact must not re-enter the policy"
        );

        crate::test_support::drop_isolated_database("cap_teardown_supersede", pool).await;
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
        // Asserts the exact size of the global candidate set, so run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_stacked").await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;

        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
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

        // Published a StatefulSet, then failed. That spec may still be the
        // one running. Setup acceptance alone is not this signal.
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
        mark_test_workload_published(&pool, apply_failed).await;
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

        // Newer generation reached setup accepted and failed before any
        // StatefulSet write. It must not suppress the published spec, and
        // it must not consume required policy budget.
        let latest_apply_failed = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            latest_apply_failed,
            "failed",
            now + chrono::Duration::seconds(2),
        )
        .await;
        set_test_setup_state(&pool, latest_apply_failed, "accepted").await;
        let latest_apply_failed_artifact =
            insert_test_artifact(&pool, app_id, latest_apply_failed, "ef").await;
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
        .bind(latest_apply_failed)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7u8; 32])
        .bind(hex::decode(&latest_apply_failed_artifact.metadata.descriptor_core_hash).unwrap())
        .execute(&pool)
        .await
        .expect("insert latest apply-failed apply job");

        let candidates = load_signed_policy_candidates(&pool, 6)
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
            "a published spec must stay authorized when a newer failure never wrote one"
        );
        assert!(
            !hashes.contains(
                latest_apply_failed_artifact
                    .metadata
                    .descriptor_core_hash
                    .as_str()
            ),
            "a setup-accepted failure that never published a spec must not be authorized"
        );
        assert!(
            !hashes.contains(setup_failed_artifact.metadata.descriptor_core_hash.as_str()),
            "a provable setup failure never wrote a workload spec and must stay excluded"
        );
        assert_eq!(hashes.len(), 2, "deletion authority must stay bounded");

        let retained = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select teardown authority at retention 1");
        let retained_hashes: HashSet<_> = retained
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert!(
            retained_hashes.contains(live_artifact.metadata.descriptor_core_hash.as_str())
                && retained_hashes
                    .contains(apply_failed_artifact.metadata.descriptor_core_hash.as_str()),
            "retention 1 must not drop either live teardown artifact: {retained_hashes:?}"
        );
        assert_eq!(retained_hashes.len(), 2);

        crate::test_support::drop_isolated_database("cap_teardown_stacked", pool).await;
    }

    #[tokio::test]
    async fn newer_published_spec_bounds_teardown_authority() {
        // Asserts the exact size of the global candidate set, so run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_bounded").await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
        sqlx::query("UPDATE apps SET workload_teardown_required = true WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark workload teardown pending");

        let live = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, live, "healthy", now).await;
        let live_artifact = insert_test_artifact(&pool, app_id, live, "11").await;
        insert_test_job(
            &pool,
            org_id,
            app_id,
            live,
            live,
            Some((live, &live_artifact)),
        )
        .await;

        let older = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, older, "failed", now).await;
        set_test_setup_state(&pool, older, "accepted").await;
        mark_test_workload_published(&pool, older).await;
        let older_artifact = insert_test_artifact(&pool, app_id, older, "22").await;
        insert_failed_apply_job(&pool, org_id, app_id, older, &older_artifact, 6).await;

        let newer = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            newer,
            "failed",
            now + chrono::Duration::seconds(1),
        )
        .await;
        set_test_setup_state(&pool, newer, "accepted").await;
        mark_test_workload_published(&pool, newer).await;
        let newer_artifact = insert_test_artifact(&pool, app_id, newer, "33").await;
        insert_failed_apply_job(&pool, org_id, app_id, newer, &newer_artifact, 7).await;

        // Highest generation, setup accepted, never published. Must not be
        // the row that wins, and must not be admitted.
        let unpublished = Uuid::new_v4();
        insert_test_deployment(
            &pool,
            org_id,
            app_id,
            unpublished,
            "failed",
            now + chrono::Duration::seconds(2),
        )
        .await;
        set_test_setup_state(&pool, unpublished, "accepted").await;
        let unpublished_artifact = insert_test_artifact(&pool, app_id, unpublished, "44").await;
        insert_failed_apply_job(&pool, org_id, app_id, unpublished, &unpublished_artifact, 8).await;

        let candidates = load_signed_policy_candidates(&pool, 1)
            .await
            .expect("select bounded teardown authority");
        let hashes: HashSet<_> = candidates
            .iter()
            .map(|candidate| candidate.artifact.metadata.descriptor_core_hash.as_str())
            .collect();
        assert!(hashes.contains(live_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(hashes.contains(newer_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(!hashes.contains(older_artifact.metadata.descriptor_core_hash.as_str()));
        assert!(!hashes.contains(unpublished_artifact.metadata.descriptor_core_hash.as_str()));
        assert_eq!(
            hashes.len(),
            2,
            "only the last completed workload and the newest publication"
        );

        crate::test_support::drop_isolated_database("cap_teardown_bounded", pool).await;
    }

    async fn insert_failed_apply_job(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        artifact: &crate::signing_service::SignedPolicyArtifact,
        payload_byte: u8,
    ) {
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
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![payload_byte; 32])
        .bind(hex::decode(&artifact.metadata.descriptor_core_hash).unwrap())
        .execute(pool)
        .await
        .expect("insert failed apply job");
    }

    #[tokio::test]
    async fn queued_supersessions_do_not_crowd_out_live_teardown_authority() {
        // Asserts the exact size of the global candidate set, so run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_queued").await;
        let now = Utc::now();
        let (org_id, app_id) = insert_test_app(&pool, "deleting").await;

        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;
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
            artifact.metadata.descriptor_core_hash =
                unique_test_descriptor_hash(&format!("{index:x}0"), queued);
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

        crate::test_support::drop_isolated_database("cap_teardown_queued", pool).await;
    }

    #[tokio::test]
    async fn unreleased_signed_customer_config_hold_defers_an_empty_policy() {
        // Asserts exact emptiness on the global hold-deferral probe and the
        // global candidate set, and sweeps every app's hold, so run on a
        // per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_signed_hold_deferral").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;

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
        artifact.metadata.descriptor_core_hash = unique_test_descriptor_hash("09", held);
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
        artifact2.metadata.descriptor_core_hash = unique_test_descriptor_hash("0b", held2);
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

        crate::test_support::drop_isolated_database("cap_signed_hold_deferral", pool).await;
    }

    #[tokio::test]
    async fn unrelated_unsigned_hold_does_not_defer_an_empty_policy() {
        // Asserts on the global hold-deferral probe, so run on a per-process
        // database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_unsigned_hold_probe").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;
        // The candidates query filters artifacts by current keyring
        // membership (issue #130), so the fixture org needs a keyring whose
        // member set still contains the fixture signer pubkey (test_signed_
        // policy_artifact signs with bb repeated 32 times) for its artifacts
        // to stay authorized.
        insert_test_keyring_version(&pool, org_id, 1, &["bb".repeat(32).as_str()]).await;

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

        crate::test_support::drop_isolated_database("cap_unsigned_hold_probe", pool).await;
    }

    #[tokio::test]
    async fn expired_signed_hold_preserves_legacy_policy_until_lifecycle_advances() {
        // Sweeps holds and bumps the kbs_signed_policy_reconciliation
        // singleton globally, so run on a per-process database.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap_teardown_hold_sweep").await;
        let (org_id, app_id) = insert_test_app(&pool, "running").await;

        // The still-running workload the hold preserved: a healthy legacy
        // deployment with no signed artifact row.
        let legacy = Uuid::new_v4();
        insert_test_deployment(&pool, org_id, app_id, legacy, "healthy", Utc::now()).await;

        // The first signed redeploy is held past its expiry so the sweeper
        // terminalizes it without ever applying the workload.
        let held = Uuid::new_v4();
        let mut artifact = test_signed_policy_artifact("0d", 16);
        artifact.metadata.descriptor_core_hash = unique_test_descriptor_hash("0d", held);
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

        let deferred = reconcile_pending_signed_policy_artifacts_with_client(
            &pool,
            &config,
            None,
            client.clone(),
        )
        .await;
        assert!(
            matches!(deferred, Err(KbsPolicyError::PublicationDeferredByHold)),
            "a hold must preserve the running legacy workload without falsely reporting publication success"
        );
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

        crate::test_support::drop_isolated_database("cap_teardown_hold_sweep", pool).await;
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
