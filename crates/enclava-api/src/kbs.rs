use std::collections::HashSet;

use chrono::{DateTime, Utc};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use enclava_engine::manifest::cc_init_data::compute_cc_init_data;
use enclava_engine::types::ConfidentialApp;

const DEFAULT_SIGNED_POLICY_RETENTION: i64 = 6;
const DEFAULT_SIGNED_POLICY_MAX_BYTES: usize = 900 * 1024;
const SIGNED_POLICY_SET_SCHEMA_VERSION: &str = "enclava-signed-policy-set-v2";

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
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
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
    app_artifact_rank: i64,
}

#[derive(Debug, Clone)]
struct SignedPolicyArtifactCandidate {
    artifact: crate::signing_service::SignedPolicyArtifact,
    required: bool,
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

    let client = kube::Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let mut data = cm.data.unwrap_or_default();
    let current_policy = data
        .get(&config.policy_key)
        .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
    if is_signed_policy_artifact_body(current_policy) {
        tracing::info!(
            namespace = %config.namespace,
            configmap = %config.configmap_name,
            "skipping legacy KBS marker reconciliation because Trustee policy is a signed artifact"
        );
        return Ok(());
    }
    let next_policy = replace_tls_resource_bindings_block(current_policy, &tls_bindings)?;
    let next_policy = replace_owner_bindings_block(&next_policy, &bindings)?;

    if next_policy != *current_policy {
        data.insert(config.policy_key.clone(), next_policy);
        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": config.configmap_name,
                "namespace": config.namespace,
            },
            "data": data,
        });
        let pp = PatchParams::apply("enclava-platform").force();
        cm_api
            .patch(&config.configmap_name, &pp, &Patch::Apply(&patch))
            .await?;
        restart_trustee_deployment(client, config).await?;
    }

    Ok(())
}

pub async fn reconcile_signed_policy_artifacts(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    extra_artifact: Option<&crate::signing_service::SignedPolicyArtifact>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Err(KbsPolicyError::NotConfigured);
    };

    let rows: Vec<SignedPolicyArtifactRow> = sqlx::query_as(
        r#"
        SELECT signed_policy_artifact, app_artifact_rank
        FROM (
            SELECT
                wa.signed_policy_artifact,
                d.created_at AS deployment_created_at,
                wa.created_at AS artifact_created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY d.app_id
                    ORDER BY d.created_at DESC, wa.created_at DESC
                ) AS app_artifact_rank
            FROM workload_artifacts wa
            JOIN deployments d ON d.id = wa.deploy_id AND d.app_id = wa.app_id
            WHERE d.status::text IN ('pending', 'applying', 'watching', 'healthy')
        ) ranked_active_artifacts
        WHERE app_artifact_rank <= $1
        ORDER BY app_artifact_rank ASC, deployment_created_at DESC, artifact_created_at DESC
        "#,
    )
    .bind(config.signed_policy_retention)
    .fetch_all(db)
    .await?;

    if rows.is_empty() && extra_artifact.is_none() {
        return Ok(());
    }

    let mut candidates = Vec::with_capacity(rows.len() + usize::from(extra_artifact.is_some()));
    if let Some(extra_artifact) = extra_artifact {
        candidates.push(SignedPolicyArtifactCandidate {
            artifact: extra_artifact.clone(),
            required: true,
        });
    }
    candidates.extend(
        rows.into_iter()
            .map(|row| {
                serde_json::from_value(row.signed_policy_artifact).map(|artifact| {
                    SignedPolicyArtifactCandidate {
                        artifact,
                        required: row.app_artifact_rank == 1,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    let candidate_count = candidates.len();
    let artifacts =
        select_signed_policy_artifacts_for_policy_body(candidates, config.signed_policy_max_bytes)?;

    let client = kube::Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let mut data = cm.data.unwrap_or_default();
    let next_policy = signed_policy_artifact_policy_body(&artifacts)?;
    tracing::info!(
        candidate_artifacts = candidate_count,
        selected_artifacts = artifacts.len(),
        policy_bytes = next_policy.len(),
        max_policy_bytes = config.signed_policy_max_bytes,
        "reconciled bounded signed KBS policy artifacts"
    );

    if data.get(&config.policy_key) != Some(&next_policy) {
        data.insert(config.policy_key.clone(), next_policy);
        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": config.configmap_name,
                "namespace": config.namespace,
            },
            "data": data,
        });
        let pp = PatchParams::apply("enclava-platform").force();
        cm_api
            .patch(&config.configmap_name, &pp, &Patch::Apply(&patch))
            .await?;
        restart_trustee_deployment(client, config).await?;
    }

    Ok(())
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
    let is_set = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .map(|artifacts| !artifacts.is_empty())
        .unwrap_or(false);
    is_single || is_set
}

async fn restart_trustee_deployment(
    client: kube::Client,
    config: &KbsPolicyConfig,
) -> Result<(), KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    let restarted_at: DateTime<Utc> = Utc::now();
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": config.deployment_name,
            "namespace": config.namespace,
        },
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "enclava.dev/cap-policy-restarted-at": restarted_at.to_rfc3339()
                    }
                }
            }
        }
    });
    let pp = PatchParams::apply("enclava-platform").force();
    deploy_api
        .patch(&config.deployment_name, &pp, &Patch::Apply(&patch))
        .await?;
    wait_for_deployment_ready(&deploy_api, &config.deployment_name).await?;
    Ok(())
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
}
