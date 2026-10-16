//! Deploy orchestrator: builds ConfidentialApp from DB state, calls engine, records result.

use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode as CommonUnlockMode};
use enclava_engine::apply::{
    engine::ApplyEngine,
    gateway::apply_gateway_resources,
    generation::MutationGeneration,
    namespace::apply_namespace,
    network_policy::apply_network_policy,
    orchestrator::{MANIFEST_HASH_ANNOTATION, manifest_hash},
    resources::{apply_namespaced_resource, apply_standard_resources},
    statefulset::apply_statefulset,
    types::{DeployPhase, DeployStatus as EngineDeployStatus},
    watch::watch_rollout,
};
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::types::{
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, EgressMode,
    LogEncryptionConfig, StorageSpec, WorkloadArtifactBinding, WorkloadSecurityProfile,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use sqlx::{PgPool, Postgres, Transaction};
use std::net::IpAddr;
use uuid::Uuid;

use crate::models::{App, AppContainer, AppResources, AppStatus};

const DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME: &str = "enclava-registry-auth";

/// The tenant image-pull secret name the cleanup sweep must delete from
/// adopted namespaces. Re-uses `configured_tenant_image_pull_secret_name`'s
/// env-derived value so the sweep always matches what apply published.
pub(crate) fn default_tenant_image_pull_secret_name_for_cleanup() -> String {
    configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string())
}
const TENANT_IMAGE_PULL_SECRET_NAME_ENV: &str = "TENANT_IMAGE_PULL_SECRET_NAME";
const TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV: &str = "TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES";
const PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV: &str = "CAP_PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS";
pub(crate) const PERSISTED_DEPLOYMENT_ERROR_MESSAGE: &str = "deployment_error";

#[derive(Debug, Clone)]
struct TenantImagePullSecretConfig {
    name: String,
    username: String,
    token: String,
    allowed_repositories: Vec<ImagePullRepositoryScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImagePullRepositoryScope {
    registry: String,
    repository: String,
    include_subrepositories: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct DeploymentOutcome {
    deploy_status: &'static str,
    app_status: &'static str,
    error_message: Option<String>,
    terminal: bool,
}

fn classify_rollout_result(
    result: Result<EngineDeployStatus, String>,
    previous_app_status: AppStatus,
    unlock_mode: crate::models::UnlockMode,
) -> DeploymentOutcome {
    match result {
        Ok(status) if status.phase == DeployPhase::Running => DeploymentOutcome {
            deploy_status: "healthy",
            app_status: "running",
            error_message: None,
            terminal: true,
        },
        Ok(status)
            if status.phase == DeployPhase::TimedOut
                && previous_app_status == AppStatus::Running
                && unlock_mode == crate::models::UnlockMode::Password =>
        {
            DeploymentOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_message: None,
                terminal: true,
            }
        }
        Ok(status)
            if status.phase == DeployPhase::TimedOut
                && previous_app_status == AppStatus::Creating
                && unlock_mode == crate::models::UnlockMode::Password =>
        {
            DeploymentOutcome {
                deploy_status: "watching",
                app_status: "creating",
                error_message: None,
                terminal: false,
            }
        }
        Ok(_) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE.to_string()),
            terminal: true,
        },
        Err(_) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE.to_string()),
            terminal: true,
        },
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn configured_tenant_image_pull_secret_name() -> Option<String> {
    if let Some(name) = env_nonempty(TENANT_IMAGE_PULL_SECRET_NAME_ENV) {
        return Some(name);
    }

    match (env_nonempty("GHCR_USERNAME"), env_nonempty("GHCR_TOKEN")) {
        (Some(_), Some(_)) => Some(DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string()),
        _ => None,
    }
}

fn tenant_image_pull_secret_config_from_env() -> Option<TenantImagePullSecretConfig> {
    let username = env_nonempty("GHCR_USERNAME")?;
    let token = env_nonempty("GHCR_TOKEN")?;
    let name = configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string());

    Some(TenantImagePullSecretConfig {
        name,
        username,
        token,
        allowed_repositories: tenant_image_pull_allowed_repositories_from_env(),
    })
}

fn tenant_image_pull_allowed_repositories_from_env() -> Vec<ImagePullRepositoryScope> {
    let Some(raw) = env_nonempty(TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV) else {
        return Vec::new();
    };
    raw.split(',')
        .filter_map(parse_image_pull_repository_scope)
        .collect()
}

fn parse_image_pull_repository_scope(raw: &str) -> Option<ImagePullRepositoryScope> {
    let mut value = raw.trim();
    if value.is_empty() {
        return None;
    }

    let include_subrepositories = value.ends_with("/*");
    if include_subrepositories {
        value = value.trim_end_matches("/*");
    }
    let value = value.trim_end_matches('/');
    let (registry, repository) = value.split_once('/')?;
    if registry.is_empty() || repository.is_empty() {
        return None;
    }

    Some(ImagePullRepositoryScope {
        registry: registry.to_string(),
        repository: repository.to_string(),
        include_subrepositories,
    })
}

fn tenant_image_pull_secret_config_for_containers(
    containers: &[Container],
) -> Option<TenantImagePullSecretConfig> {
    let config = tenant_image_pull_secret_config_from_env()?;
    if tenant_image_pull_secret_applies_to_containers(containers, &config) {
        return Some(config);
    }

    tracing::warn!(
        secret = %config.name,
        allowed_repositories = ?config.allowed_repositories,
        "tenant image pull secret not attached because workload images are outside configured repository scope"
    );
    None
}

fn tenant_image_pull_secret_applies_to_containers(
    containers: &[Container],
    config: &TenantImagePullSecretConfig,
) -> bool {
    if containers.is_empty() {
        return false;
    }
    if config.allowed_repositories.is_empty() {
        return true;
    }

    containers.iter().all(|container| {
        config
            .allowed_repositories
            .iter()
            .any(|scope| image_matches_repository_scope(&container.image, scope))
    })
}

fn image_matches_repository_scope(image: &ImageRef, scope: &ImagePullRepositoryScope) -> bool {
    if image.registry() != scope.registry {
        return false;
    }
    if image.repository() == scope.repository {
        return true;
    }
    scope.include_subrepositories
        && image
            .repository()
            .strip_prefix(&scope.repository)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn public_internet_egress_excluded_cidrs_from_env() -> Vec<String> {
    let Some(raw) = env_nonempty(PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV) else {
        return Vec::new();
    };
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            match normalize_ipv4_cidr(entry) {
                Some(cidr) => Some(cidr),
                None => {
                    tracing::warn!(
                        env = PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV,
                        cidr = entry,
                        "ignoring invalid public internet egress exclusion CIDR"
                    );
                    None
                }
            }
        })
        .collect()
}

fn normalize_ipv4_cidr(value: &str) -> Option<String> {
    let (addr, bits) = value.split_once('/')?;
    let bits = bits.trim().parse::<u8>().ok()?;
    if bits > 32 {
        return None;
    }
    let IpAddr::V4(addr) = addr.trim().parse::<IpAddr>().ok()? else {
        return None;
    };
    Some(format!("{addr}/{bits}"))
}

fn should_reconcile_global_signed_policy_artifacts(
    signed_policy_artifact_present: bool,
    _attestation: &AttestationConfig,
) -> bool {
    signed_policy_artifact_present
}

fn generate_tenant_image_pull_secret(
    namespace: &str,
    config: &TenantImagePullSecretConfig,
) -> Secret {
    use base64::Engine as _;

    let auth = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", config.username, config.token));
    let docker_config_json = serde_json::json!({
        "auths": {
            "ghcr.io": {
                "username": config.username,
                "password": config.token,
                "auth": auth,
            }
        }
    })
    .to_string();

    let mut string_data = std::collections::BTreeMap::new();
    string_data.insert(".dockerconfigjson".to_string(), docker_config_json);

    Secret {
        metadata: ObjectMeta {
            name: Some(config.name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        string_data: Some(string_data),
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        ..Default::default()
    }
}

async fn apply_all_with_tenant_image_pull_secret(
    engine: &ApplyEngine,
    pool: &sqlx::PgPool,
    deployment_id: Uuid,
    manifests: &enclava_engine::manifest::GeneratedManifests,
    manifest_hash: &str,
    image_pull_secret_config: Option<&TenantImagePullSecretConfig>,
    generation: MutationGeneration,
) -> Result<(), DeployError> {
    let ns_name = manifests
        .namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| {
            enclava_engine::apply::engine::ApplyError::NamespaceNotReady(
                "namespace has no name".to_string(),
            )
        })?;

    apply_namespace(engine, &manifests.namespace, generation).await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    if let Some(config) = image_pull_secret_config {
        let secret = generate_tenant_image_pull_secret(ns_name, config);
        apply_namespaced_resource(engine, ns_name, &secret, generation).await?;
        tracing::info!(
            namespace = %ns_name,
            secret = %config.name,
            "tenant image pull secret applied"
        );
    }

    apply_standard_resources(engine, manifests, generation).await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    apply_network_policy(engine, ns_name, &manifests.network_policy, generation).await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
        generation,
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 4/5: Gateway API resources applied");

    let mut sts = manifests.statefulset.clone();
    sts.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            MANIFEST_HASH_ANNOTATION.to_string(),
            manifest_hash.to_string(),
        );

    // Codex P1: creation-specific evidence for the PVC sweep. Stamped
    // immediately before the StatefulSet step is attempted (the final
    // apply phase). Under Retain/Retain the controller attaches no PVC
    // ownerReferences, so this stamp — not apply_started_at (which
    // precedes KBS reconciliation and every Kubernetes write) — is the
    // earliest point a claim of this workload's lineage could exist: a
    // tenant-created same-named claim predates it and is never swept.
    // First-writer-wins (COALESCE) so a retry of a partially-failed apply
    // does not advance the bound past claims the first attempt created.
    sqlx::query(
        "UPDATE deployments
            SET sts_apply_started_at = COALESCE(sts_apply_started_at, clock_timestamp())
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(pool)
    .await?;
    // Conservative workload-apply evidence. The StatefulSet write is the
    // first operation that can replace the TEE, so the settling guard's
    // marker is stamped at ITS entry -- not at the multi-resource apply's
    // entry (a namespace/standard-resource/gateway failure never touched
    // the workload and must not count as a rollout) and not after the SSA
    // response (a request Kubernetes accepted but whose response was lost
    // to a timeout or connection error must still count). Idempotent
    // re-applies keep the first stamp time.
    sqlx::query(
        "UPDATE deployments
            SET apply_committed_at = COALESCE(apply_committed_at, clock_timestamp())
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(pool)
    .await?;
    let sts_live = apply_statefulset(engine, ns_name, &sts, generation).await?;
    // Persist the server-reported UID and creationTimestamp of the
    // StatefulSet object this apply produced (the POST/SSA response — not
    // a pre-call stamp). This is the identity the claim sweep matches
    // ownerReferences against. Grok P2: only persist when the RESPONSE
    // itself carries CAP creation evidence (the same gate the sweep uses):
    // an SSA patch of a PRE-EXISTING StatefulSet returns that set's UID,
    // and recording it would let the claim sweep treat a tenant's set as
    // proven CAP lineage. First-writer-wins keeps a retry from advancing
    // the record past claims the first attempt created.
    if crate::deployment_failure_cleanup::is_cap_created_generation_leftover(
        &sts_live,
        generation.get(),
    ) {
        if let (Some(uid), Some(created)) = (
            sts_live.metadata.uid.as_deref(),
            sts_live
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| ts.0.to_string())
                .and_then(|raw| raw.parse::<chrono::DateTime<chrono::Utc>>().ok()),
        ) && let Err(error) = crate::deployment_failure_cleanup::persist_sts_provenance(
            pool,
            None,
            deployment_id,
            uid,
            created,
            None,
        )
        .await
        {
            tracing::warn!(
                deployment_id = %deployment_id,
                error = %error,
                "could not persist StatefulSet provenance; PVC sweep will require a live sts observation (fail closed)"
            );
        }
    } else {
        // No CAP creation evidence on the response (e.g. an SSA patch of a
        // pre-existing set, or a mutating admission rewrote the creation
        // annotation): recording this UID would forge claim-deletion
        // authority. The sweep's no-window path stays fail-closed.
        tracing::warn!(
            deployment_id = %deployment_id,
            namespace = %ns_name,
            "StatefulSet apply response lacks CAP creation evidence; not recording provenance"
        );
    }
    tracing::info!(
        namespace = %ns_name,
        manifest_hash = %manifest_hash,
        "step 5/5: StatefulSet applied"
    );

    tracing::info!(namespace = %ns_name, "apply_all complete");
    Ok(())
}

/// The SNI (backend-tag, host) pairs a deployment of this app publishes,
/// derived from the authoritative app row exactly as
/// `build_confidential_app_from_rows` derives its `DomainSpec`: the TEE host
/// falls back to the platform domain when `tee_domain` is null, and an empty
/// custom domain is skipped. Apply and failed-apply cleanup both build their
/// route lists from this helper so they can never diverge.
pub(crate) fn app_route_hosts(app: &App) -> Vec<(crate::edge::BackendTag, String)> {
    let mut hosts = vec![
        (crate::edge::BackendTag::App, app.domain.clone()),
        (
            crate::edge::BackendTag::Tee,
            match app.tee_domain.as_deref() {
                Some(tee_domain) if !tee_domain.is_empty() => tee_domain.to_string(),
                // build_confidential_app_from_rows falls back to the platform
                // domain when tee_domain is null, and apply publishes that
                // route unconditionally.
                _ => app.domain.clone(),
            },
        ),
    ];
    if let Some(custom_domain) = app.custom_domain.as_deref()
        && !custom_domain.is_empty()
    {
        hosts.push((crate::edge::BackendTag::App, custom_domain.to_string()));
    }
    hosts
}

pub struct ApplyDeploymentManifestsRequest {
    pub pool: PgPool,
    pub app: App,
    pub snapshot: DeploymentApplySnapshot,
    pub engine: ApplyEngine,
    pub fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims,
    pub deployment_id: Uuid,
    pub attestation_config: Option<AttestationConfig>,
    pub kbs_policy_config: Option<crate::kbs::KbsPolicyConfig>,
    pub edge_config_generation: i64,
    pub kubernetes_mutation_generation: i64,
    pub api_signing_pubkey: String,
    pub api_url: String,
    pub workload_artifact_binding: Option<WorkloadArtifactBinding>,
    pub signed_policy_artifact: Option<crate::signing_service::SignedPolicyArtifact>,
    pub local_workload_artifacts_json: Option<String>,
    pub local_trustee_policy_json: Option<String>,
    pub sigstore_material: Vec<u8>,
    pub provenance_oci_material: Vec<u8>,
    pub log_encryption: Option<LogEncryptionConfig>,
}

/// Immutable database-row inputs captured for one queued deployment apply.
///
/// The API can accept another deployment while this one waits for the apply
/// semaphore. Keeping these rows on the queued request prevents a later
/// deployment from changing the manifest rendered for this deployment ID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeploymentApplySnapshot {
    pub containers: Vec<AppContainer>,
    pub resources: AppResources,
}

impl DeploymentApplySnapshot {
    pub fn new(containers: Vec<AppContainer>, resources: AppResources) -> Self {
        Self {
            containers,
            resources,
        }
    }
}

/// Authoritative database rows used while validating an existing app
/// deployment. Acceptance locks and compares this snapshot before committing
/// any candidate changes.
#[derive(Debug, Clone)]
pub(crate) struct ExistingAppAuthoritySnapshot {
    app_updated_at: chrono::DateTime<chrono::Utc>,
    containers: Vec<AppContainer>,
    resources: AppResources,
}

impl ExistingAppAuthoritySnapshot {
    pub(crate) fn new(
        app_updated_at: chrono::DateTime<chrono::Utc>,
        containers: Vec<AppContainer>,
        resources: AppResources,
    ) -> Self {
        Self {
            app_updated_at,
            containers,
            resources,
        }
    }

    pub(crate) fn app_id(&self) -> Uuid {
        self.resources.app_id
    }
}

pub(crate) async fn lock_and_verify_existing_app_authority(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
) -> Result<bool, sqlx::Error> {
    verify_existing_app_authority_rows(tx, app_id, expected, true).await
}

/// Compare the accepted app/runtime rows while the caller holds the app
/// advisory lane, without taking row locks. Durable workers use this form
/// because manifest application updates app/deployment status through other
/// pooled connections while the advisory lane remains held. Taking a row lock
/// here would make the worker wait on itself.
pub(crate) async fn verify_existing_app_authority(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
) -> Result<bool, sqlx::Error> {
    verify_existing_app_authority_rows(tx, app_id, expected, false).await
}

async fn verify_existing_app_authority_rows(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
    lock_rows: bool,
) -> Result<bool, sqlx::Error> {
    let app_query = if lock_rows {
        "SELECT updated_at FROM apps WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT updated_at FROM apps WHERE id = $1"
    };
    let current_updated_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(app_query)
        .bind(app_id)
        .fetch_optional(&mut **tx)
        .await?;
    if current_updated_at != Some(expected.app_updated_at) {
        return Ok(false);
    }

    let containers_query = if lock_rows {
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id FOR UPDATE"
    } else {
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id"
    };
    let current_containers: Vec<AppContainer> = sqlx::query_as(containers_query)
        .bind(app_id)
        .fetch_all(&mut **tx)
        .await?;
    let mut expected_containers = expected.containers.clone();
    expected_containers.sort_by_key(|container| container.id);
    if current_containers != expected_containers {
        return Ok(false);
    }

    let resources_query = if lock_rows {
        "SELECT * FROM app_resources WHERE app_id = $1 FOR UPDATE"
    } else {
        "SELECT * FROM app_resources WHERE app_id = $1"
    };
    let current_resources: Option<AppResources> = sqlx::query_as(resources_query)
        .bind(app_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(current_resources.as_ref() == Some(&expected.resources))
}

#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("no containers defined for app")]
    NoContainers,
    #[error("image parse error: {0}")]
    ImageParse(String),
    #[error("image must have a digest: {0}")]
    NoDigest(String),
    #[error("engine validation error: {0}")]
    Validation(String),
    #[error(
        "deploy runtime is not configured: set ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE"
    )]
    MissingAttestationConfig,
    #[error("Kubernetes apply error: {0}")]
    Apply(#[from] enclava_engine::apply::engine::ApplyError),
    #[error("app is not deployed: {0}")]
    NotDeployed(String),
    #[error("KBS policy error: {0}")]
    KbsPolicy(#[from] crate::kbs::KbsPolicyError),
    #[error("edge route error: {0}")]
    EdgeRoute(#[from] crate::edge::EdgeRouteError),
    #[error("durable mutation fence error: {0}")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
}

impl DeployError {
    /// Return a bounded code safe for persistence and operator logs.
    pub(crate) fn public_code(&self) -> &'static str {
        match self {
            Self::Db(_) => "database_error",
            Self::NoContainers => "no_containers",
            Self::ImageParse(_) => "image_parse_error",
            Self::NoDigest(_) => "image_digest_required",
            Self::Validation(_) => "deployment_validation_error",
            Self::MissingAttestationConfig => "deploy_runtime_not_configured",
            Self::Apply(error) => error.public_code(),
            Self::NotDeployed(_) => "app_not_deployed",
            Self::KbsPolicy(_) => "kbs_policy_error",
            Self::EdgeRoute(_) => "edge_route_error",
            Self::Mutation(_) => "mutation_fence_error",
        }
    }
}

fn persisted_deployment_error(error_message: Option<&str>) -> Option<&'static str> {
    error_message.map(|_| PERSISTED_DEPLOYMENT_ERROR_MESSAGE)
}

pub(crate) fn serialize_workload_command(
    command: &[String],
) -> Result<Option<String>, serde_json::Error> {
    if command.is_empty() {
        Ok(None)
    } else {
        serde_json::to_string(command).map(Some)
    }
}

pub(crate) fn descriptor_primary_port(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Option<i32> {
    descriptor
        .oci_runtime_spec
        .ports
        .first()
        .and_then(|port| i32::try_from(port.container_port).ok())
}

pub(crate) fn descriptor_storage_paths(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Vec<String> {
    descriptor
        .oci_runtime_spec
        .mounts
        .iter()
        .filter(|mount| {
            mount.mount_type == "kubernetes-volume-subpath"
                || mount.source.starts_with("state-mount:")
        })
        .map(|mount| mount.destination.clone())
        .filter(|path| path != "/state")
        .collect()
}

fn deserialize_workload_command(command: Option<&str>) -> Option<Vec<String>> {
    let raw = command?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    match serde_json::from_str::<Vec<String>>(trimmed) {
        Ok(argv) if !argv.is_empty() => Some(argv),
        Ok(_) => None,
        Err(_) => Some(vec![raw.to_string()]),
    }
}

fn parse_workload_security_profile(
    value: Option<&str>,
) -> Result<WorkloadSecurityProfile, DeployError> {
    value
        .unwrap_or("restricted")
        .parse()
        .map_err(DeployError::Validation)
}

pub(crate) fn set_primary_descriptor_runtime(
    app: &mut ConfidentialApp,
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) {
    let command = &descriptor.oci_runtime_spec.args;
    let port = descriptor_primary_port(descriptor).and_then(|port| u16::try_from(port).ok());
    let storage_paths = descriptor_storage_paths(descriptor);

    for container in app.containers.iter_mut().filter(|c| c.is_primary) {
        if !command.is_empty() {
            container.command = Some(command.to_vec());
        }
        if let Some(port) = port {
            container.port = Some(port);
        }
        container.storage_paths = storage_paths.clone();
    }
}

/// Build a ConfidentialApp spec from database state.
/// This is the bridge between the API's data model and the engine's input type.
pub async fn build_confidential_app(
    pool: &PgPool,
    app: &App,
    deployment_id: Uuid,
    attestation_config: &AttestationConfig,
    api_signing_pubkey: &str,
    api_url: &str,
) -> Result<ConfidentialApp, DeployError> {
    let containers_rows: Vec<AppContainer> =
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(pool)
            .await?;

    if containers_rows.is_empty() {
        return Err(DeployError::NoContainers);
    }

    let resources: AppResources = sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
        .bind(app.id)
        .fetch_one(pool)
        .await?;

    build_confidential_app_from_rows(
        app,
        deployment_id,
        attestation_config,
        api_signing_pubkey,
        api_url,
        &containers_rows,
        &resources,
    )
}

/// Build a `ConfidentialApp` from an immutable snapshot of database rows.
///
/// Deployment request validation uses this helper to render a candidate spec
/// before any requested app or container changes are persisted.
pub(crate) fn build_confidential_app_from_rows(
    app: &App,
    deployment_id: Uuid,
    attestation_config: &AttestationConfig,
    api_signing_pubkey: &str,
    api_url: &str,
    containers_rows: &[AppContainer],
    resources: &AppResources,
) -> Result<ConfidentialApp, DeployError> {
    if containers_rows.is_empty() {
        return Err(DeployError::NoContainers);
    }

    let mut containers = Vec::new();
    for row in containers_rows {
        let mut image =
            ImageRef::parse(&row.image_ref).map_err(|e| DeployError::ImageParse(e.to_string()))?;
        if let Some(d) = row.image_digest.as_ref() {
            // The digest is authoritative: render the digest-pinned name with
            // any tag stripped, so the cc-init render matches the signed
            // descriptor's registry/repository@digest even when the request
            // carried a tag (#210 review).
            image = ImageRef::parse(&format!(
                "{}/{}@{}",
                image.registry(),
                image.repository(),
                d
            ))
            .map_err(|e| DeployError::ImageParse(e.to_string()))?;
        }

        let storage_paths = row.storage_paths.clone().unwrap_or_default();

        containers.push(Container {
            name: row.name.clone(),
            image,
            port: row.port.map(|p| p as u16),
            command: deserialize_workload_command(row.command.as_deref()),
            env: std::collections::HashMap::new(),
            storage_paths,
            workload_security_profile: parse_workload_security_profile(
                row.workload_security_profile.as_deref(),
            )?,
            is_primary: row.is_primary,
        });
    }

    let unlock_mode = match app.unlock_mode {
        crate::models::UnlockMode::Auto => CommonUnlockMode::Auto,
        crate::models::UnlockMode::Password => CommonUnlockMode::Password,
    };
    let egress_mode = app.egress_mode.parse::<EgressMode>().map_err(|error| {
        DeployError::Validation(format!(
            "stored egress_mode for app {} is invalid: {error}",
            app.name
        ))
    })?;

    let mut storage = StorageSpec::new(&resources.app_data_size, &resources.tls_data_size);
    // Set bind mounts from the primary container
    if let Some(primary) = containers_rows.iter().find(|c| c.is_primary) {
        let paths = primary.storage_paths.clone().unwrap_or_default();
        storage.app_data.bind_mounts = paths
            .iter()
            .map(|path| {
                let subdir = path.strip_prefix('/').unwrap_or(path).replace('/', "-");
                BindMount {
                    source: format!("/data/{subdir}"),
                    destination: path.clone(),
                }
            })
            .collect();
    }

    let image_pull_secret_name =
        tenant_image_pull_secret_config_for_containers(&containers).map(|config| config.name);

    Ok(ConfidentialApp {
        app_id: app.id,
        deployment_id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        image_pull_secret_name,
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers,
        storage,
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey: api_signing_pubkey.to_string(),
        api_url: api_url.to_string(),
        resources: ResourceLimits {
            cpu: resources.cpu_limit.clone(),
            memory: resources.memory_limit.clone(),
        },
        attestation: attestation_config.clone(),
        egress_mode,
        public_internet_egress_excluded_cidrs: public_internet_egress_excluded_cidrs_from_env(),
        allow_internal_egress: crate::routes::apps::internal_egress_allowlist_enabled()
            && app.egress_allowlist.0.iter().any(|rule| {
                !crate::routes::apps::egress_allowlist_host_audit_reasons(&rule.host).is_empty()
            }),
        egress_allowlist: app.egress_allowlist.0.clone(),
        log_encryption: None,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    })
}

pub(crate) async fn latest_deployment_id_for_app(
    pool: &PgPool,
    app_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let deployment_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT deployment.id
           FROM deployments AS deployment
           LEFT JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
          ORDER BY (apply_job.generation IS NOT NULL) DESC,
                   apply_job.generation DESC NULLS LAST,
                   deployment.created_at DESC,
                   deployment.id DESC
          LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await?;
    Ok(deployment_id.unwrap_or_else(Uuid::nil))
}

pub(crate) const DEPLOYMENT_SUPERSEDED_ERROR: &str = "deployment_superseded";

#[derive(Debug, thiserror::Error)]
pub(crate) enum SupersedeDeploymentError {
    #[error("an unexpired deployment mutation is still in progress")]
    Busy,
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

fn app_deployment_lane_key(app_id: Uuid) -> i64 {
    let (high, low) = app_id.as_u64_pair();
    (high ^ low) as i64
}

/// Serialize deployment acceptance, manifest application, and terminal result
/// publication for one app across every API replica.
///
/// A 64-bit advisory key collision can only serialize unrelated apps; it
/// cannot allow two operations for the same app to overlap.
pub(crate) async fn lock_app_deployment_lane(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(app_deployment_lane_key(app_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Mark accepted-but-incomplete deployments as superseded before inserting a
/// newer deployment for the same app. The caller must hold the app deployment
/// lane for the surrounding transaction.
pub(crate) async fn supersede_incomplete_deployments(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
) -> Result<u64, SupersedeDeploymentError> {
    // Config tokens are app-scoped, so supersession cannot cancel a CLI's
    // writes. Keep its live hold exclusive; deletion may still stop the app.
    let active_mutation: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM deployment_apply_jobs AS job
               JOIN deployments AS deployment ON deployment.id = job.deployment_id
              WHERE job.app_id = $1
                AND job.locked_until >= clock_timestamp()
                AND (
                    job.state IN ('setting_up', 'cleaning_up')
                    OR (
                        job.state = 'running'
                        AND deployment.status IN (
                            'pending'::deploy_status_enum,
                            'applying'::deploy_status_enum
                        )
                    )
                )
         ) OR EXISTS (
             SELECT 1
               FROM deployment_apply_jobs AS job
               JOIN apps AS app ON app.id = job.app_id
              WHERE job.app_id = $1
                AND job.customer_config_hold
                AND job.customer_config_released_at IS NULL
                AND job.state = 'setup_pending'
                AND job.customer_config_hold_until > clock_timestamp()
                AND app.status <> 'deleting'::app_status_enum
         )",
    )
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await?;
    if active_mutation {
        return Err(SupersedeDeploymentError::Busy);
    }
    // Stop every queued or leased operation before terminalizing its
    // deployment. A worker that already holds a lease must acquire the same
    // app lane before any setup/apply/cleanup side effect, so once this update
    // commits it can only observe a lost lease / terminal generation.
    sqlx::query(
        "UPDATE deployment_apply_jobs
         SET state = 'failed',
             lock_token = NULL,
             locked_until = NULL,
             next_attempt_at = clock_timestamp(),
             last_error_code = $1,
             updated_at = clock_timestamp()
         WHERE app_id = $2
           AND state IN (
               'setup_pending', 'setting_up',
               'cleanup_pending', 'cleaning_up',
               'pending', 'running'
           )",
    )
    .bind(DEPLOYMENT_SUPERSEDED_ERROR)
    .bind(app_id)
    .execute(&mut **tx)
    .await?;

    let result = sqlx::query(
        "UPDATE deployments
         SET status = 'failed'::deploy_status_enum,
             error_message = $1,
             completed_at = clock_timestamp()
         WHERE app_id = $2
           AND status::text IN ('pending', 'applying', 'watching')",
    )
    .bind(DEPLOYMENT_SUPERSEDED_ERROR)
    .bind(app_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

pub(crate) async fn deployment_is_active_for_apply(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM deployments AS deployment
             JOIN apps AS app ON app.id = deployment.app_id
             WHERE deployment.id = $1
               AND deployment.app_id = $2
               -- A worker can die after idempotent SSA apply and before its
               -- rollout watcher publishes a terminal result. Reclaiming a
               -- watching generation must re-apply and re-watch it; treating
               -- it as inactive would complete the job while stranding the
               -- deployment forever in watching.
               AND deployment.status::text IN ('pending', 'applying', 'watching')
               AND app.status <> 'deleting'::app_status_enum
         )",
    )
    .bind(deployment_id)
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await
}

/// Publish a rollout observation only while it still belongs to the active
/// watching deployment and exact manifest hash. A newer acceptance first
/// supersedes the old row under the same app deployment lane, so a late old
/// watcher becomes a no-op for both deployment and app status.
#[cfg(test)]
pub(crate) struct DeploymentResultUpdate<'a> {
    pub app_id: Uuid,
    pub deployment_id: Uuid,
    pub deploy_status: &'a str,
    pub expected_manifest_hash: &'a str,
    pub app_status: &'a str,
    pub error_code: Option<&'a str>,
    pub terminal: bool,
}

#[cfg(test)]
pub(crate) async fn record_deployment_result_if_current(
    pool: &PgPool,
    update: DeploymentResultUpdate<'_>,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_app_deployment_lane(&mut tx, update.app_id).await?;

    let result = sqlx::query(
        "UPDATE deployments
         SET status = $1::deploy_status_enum,
             error_message = $2,
             completed_at = CASE WHEN $3 THEN clock_timestamp() ELSE completed_at END
         WHERE id = $4
           AND app_id = $5
           AND status = 'watching'::deploy_status_enum
           AND manifest_hash = $6",
    )
    .bind(update.deploy_status)
    .bind(update.error_code)
    .bind(update.terminal)
    .bind(update.deployment_id)
    .bind(update.app_id)
    .bind(update.expected_manifest_hash)
    .execute(&mut *tx)
    .await?;

    let recorded = result.rows_affected() == 1;
    if recorded {
        sqlx::query(
            "UPDATE apps
             SET status = $1::app_status_enum,
                 updated_at = clock_timestamp()
             WHERE id = $2",
        )
        .bind(update.app_status)
        .bind(update.app_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(recorded)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use enclava_common::descriptor::{
        Capabilities, DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources,
        SecurityContext, Sidecars, SignerIdentity,
    };

    fn test_attestation_config() -> AttestationConfig {
        AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
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
        }
    }

    fn queued_apply_app() -> App {
        let now = chrono::Utc::now();
        App {
            id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            name: "queued-app".to_string(),
            namespace: "cap-queued-app".to_string(),
            instance_id: "queued-app-instance".to_string(),
            tenant_id: "8f346820".to_string(),
            service_account: "cap-queued-app-sa".to_string(),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: crate::models::UnlockMode::Password,
            domain: "queued-app.8f346820.enclava.dev".to_string(),
            tee_domain: Some("queued-app.8f346820.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: AppStatus::Creating,
            signer_identity_subject: Some("https://github.com/acme/app".to_string()),
            signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            signer_identity_set_at: Some(now),
            source_provider: Some("github".to_string()),
            source_repository: Some("acme/app".to_string()),
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    fn queued_apply_snapshot(digest_byte: char) -> DeploymentApplySnapshot {
        let app = queued_apply_app();
        let digest = format!("sha256:{}", digest_byte.to_string().repeat(64));
        DeploymentApplySnapshot::new(
            vec![AppContainer {
                id: uuid::Uuid::new_v4(),
                app_id: app.id,
                name: "web".to_string(),
                image_ref: "ghcr.io/acme/app:latest".to_string(),
                image_digest: Some(digest),
                port: Some(8080),
                command: None,
                storage_paths: Some(vec!["/data".to_string()]),
                workload_security_profile: Some("restricted".to_string()),
                is_primary: true,
            }],
            AppResources {
                app_id: app.id,
                cpu_limit: "1".to_string(),
                memory_limit: "1Gi".to_string(),
                app_data_size: "5Gi".to_string(),
                tls_data_size: "2Gi".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn queued_apply_renders_its_captured_rows_after_later_state_changes() {
        let app = queued_apply_app();
        let first_snapshot = queued_apply_snapshot('a');
        let later_snapshot = queued_apply_snapshot('b');
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let queued_gate = gate.clone();
        let queued_app = app.clone();
        let queued = tokio::spawn(async move {
            let _permit = queued_gate.acquire().await.expect("queue remains open");
            build_confidential_app_from_rows(
                &queued_app,
                uuid::Uuid::new_v4(),
                &test_attestation_config(),
                "api-signing-key",
                "https://api.enclava.dev",
                &first_snapshot.containers,
                &first_snapshot.resources,
            )
            .expect("captured apply snapshot")
        });

        tokio::task::yield_now().await;
        let later = build_confidential_app_from_rows(
            &app,
            uuid::Uuid::new_v4(),
            &test_attestation_config(),
            "api-signing-key",
            "https://api.enclava.dev",
            &later_snapshot.containers,
            &later_snapshot.resources,
        )
        .expect("later apply snapshot");
        gate.add_permits(1);
        let first = queued.await.expect("queued renderer");

        assert_eq!(
            first.containers[0].image.digest(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(
            later.containers[0].image.digest(),
            format!("sha256:{}", "b".repeat(64))
        );
    }

    #[test]
    fn tagged_rows_render_the_digest_pinned_name() {
        let app = queued_apply_app();
        let snapshot = queued_apply_snapshot('c');
        let rendered = build_confidential_app_from_rows(
            &app,
            uuid::Uuid::new_v4(),
            &test_attestation_config(),
            "api-signing-key",
            "https://api.enclava.dev",
            &snapshot.containers,
            &snapshot.resources,
        )
        .expect("render");
        // A stored tag must not leak into the rendered name: the signed
        // descriptor binds registry/repository@digest (#210 review).
        assert_eq!(
            rendered.containers[0].image.digest_ref(),
            format!("ghcr.io/acme/app@sha256:{}", "c".repeat(64))
        );
    }

    #[test]
    fn password_redeploy_timeout_stays_healthy_for_manual_unlock() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Running,
            crate::models::UnlockMode::Password,
        );

        assert_eq!(
            outcome,
            DeploymentOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_message: None,
                terminal: true,
            }
        );
    }

    #[test]
    fn auto_redeploy_timeout_still_fails() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Running,
            crate::models::UnlockMode::Auto,
        );

        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE)
        );
    }

    #[test]
    fn deployment_error_persistence_discards_plaintext() {
        const SENSITIVE_ERROR: &str =
            "kubernetes response included customer-secret-name and private-config";

        let persisted = persisted_deployment_error(Some(SENSITIVE_ERROR));
        assert_eq!(persisted, Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE));
        assert!(!persisted.unwrap().contains("customer-secret-name"));
        assert_eq!(persisted_deployment_error(None), None);

        let error = DeployError::Apply(enclava_engine::apply::engine::ApplyError::RolloutFailed(
            SENSITIVE_ERROR.to_string(),
        ));
        assert_eq!(error.public_code(), "rollout_failed");
        assert!(!error.public_code().contains("customer-secret-name"));

        let mutation_error =
            DeployError::Mutation(crate::mutation_leases::MutationLeaseError::Busy);
        assert_eq!(mutation_error.public_code(), "mutation_fence_error");
        assert_eq!(
            crate::deployment_jobs::DeploymentJobError::from(mutation_error).code(),
            "mutation_fence_error"
        );
    }

    #[test]
    fn password_create_timeout_stays_watchable_for_initial_claim() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Creating,
            crate::models::UnlockMode::Password,
        );

        assert_eq!(
            outcome,
            DeploymentOutcome {
                deploy_status: "watching",
                app_status: "creating",
                error_message: None,
                terminal: false,
            }
        );
    }

    #[test]
    fn tenant_image_pull_secret_uses_dockerconfigjson_shape() {
        let config = TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_fake".to_string(),
            allowed_repositories: Vec::new(),
        };

        let secret = generate_tenant_image_pull_secret("tenant-ns", &config);
        let string_data = secret.string_data.as_ref().unwrap();
        let docker_config: serde_json::Value =
            serde_json::from_str(string_data.get(".dockerconfigjson").unwrap()).unwrap();

        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("enclava-registry-auth")
        );
        assert_eq!(secret.metadata.namespace.as_deref(), Some("tenant-ns"));
        assert_eq!(
            secret.type_.as_deref(),
            Some("kubernetes.io/dockerconfigjson")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["username"].as_str(),
            Some("cap-bot")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["password"].as_str(),
            Some("ghp_fake")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["auth"].as_str(),
            Some("Y2FwLWJvdDpnaHBfZmFrZQ==")
        );
    }

    fn pull_secret_config(
        allowed_repositories: Vec<ImagePullRepositoryScope>,
    ) -> TenantImagePullSecretConfig {
        TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_fake".to_string(),
            allowed_repositories,
        }
    }

    fn test_container(image_ref: &str) -> Container {
        Container {
            name: "web".to_string(),
            image: ImageRef::parse(image_ref).unwrap(),
            port: Some(8080),
            command: None,
            env: std::collections::HashMap::new(),
            storage_paths: Vec::new(),
            workload_security_profile: WorkloadSecurityProfile::Restricted,
            is_primary: true,
        }
    }

    #[test]
    fn tenant_image_pull_scope_parses_exact_and_prefix_repositories() {
        assert_eq!(
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template"),
            Some(ImagePullRepositoryScope {
                registry: "ghcr.io".to_string(),
                repository: "enclava-ai/private-template".to_string(),
                include_subrepositories: false,
            })
        );
        assert_eq!(
            parse_image_pull_repository_scope(" ghcr.io/enclava-ai/templates/* "),
            Some(ImagePullRepositoryScope {
                registry: "ghcr.io".to_string(),
                repository: "enclava-ai/templates".to_string(),
                include_subrepositories: true,
            })
        );
        assert!(parse_image_pull_repository_scope("ghcr.io").is_none());
    }

    #[test]
    fn tenant_image_pull_secret_without_scope_preserves_global_fallback() {
        let config = pull_secret_config(Vec::new());
        let containers = vec![test_container(
            "ghcr.io/tenant/private-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )];

        assert!(tenant_image_pull_secret_applies_to_containers(
            &containers,
            &config
        ));
    }

    #[test]
    fn tenant_image_pull_secret_scope_requires_every_container_to_match() {
        let config = pull_secret_config(vec![
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template").unwrap(),
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
        ]);
        let allowed = vec![
            test_container(
                "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            test_container(
                "ghcr.io/enclava-ai/templates/ssh@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ];
        let mixed = vec![
            test_container(
                "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            test_container(
                "ghcr.io/tenant/private-app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
        ];

        assert!(tenant_image_pull_secret_applies_to_containers(
            &allowed, &config
        ));
        assert!(!tenant_image_pull_secret_applies_to_containers(
            &mixed, &config
        ));
    }

    #[test]
    fn signed_deploy_with_local_artifacts_still_reconciles_global_kbs_policy() {
        let mut attestation = test_attestation_config();
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));

        attestation.local_workload_artifacts_json = Some("{\"bundle\":true}".to_string());
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));

        attestation.local_trustee_policy_json = Some("{\"policy\":true}".to_string());
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));
        assert!(!should_reconcile_global_signed_policy_artifacts(
            false,
            &attestation
        ));
    }

    fn customer_app_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "8f346820".to_string(),
            app_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "customer-app".to_string(),
            deploy_id: uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap(),
            nonce: [1; 32],
            app_domain: "customer-app.8f346820.enclava.dev".to_string(),
            tee_domain: "customer-app.8f346820.tee.enclava.dev".to_string(),
            custom_domains: Vec::new(),
            namespace: "cap-demo-org-customer-app".to_string(),
            service_account: "cap-customer-app-sa".to_string(),
            identity_hash: [2; 32],
            image_ref:
                "ghcr.io/acme/customer-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject:
                    "https://github.com/acme/customer-app/.github/workflows/docker.yaml@refs/heads/main"
                        .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/usr/local/bin/enclava-wait-exec".to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![EnvVar {
                    name: "APP_SEED_PATH".to_string(),
                    value: "/run/enclava/seeds/app/seed".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3338,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![
                    Mount {
                        source: "state-mount".to_string(),
                        destination: "/state".to_string(),
                        mount_type: "kubernetes-volume".to_string(),
                        options: vec!["rw".to_string()],
                    },
                    Mount {
                        source: "state-mount:data".to_string(),
                        destination: "/data".to_string(),
                        mount_type: "kubernetes-volume-subpath".to_string(),
                        options: vec!["rw".to_string()],
                    },
                ],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                caddy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            independent_verification: true,
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-demo-org-customer-app-customer-app-owner/seed-encrypted"
                .to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "test".to_string(),
            expected_agent_policy_hash: [5; 32],
            expected_cc_init_data_hash: [6; 32],
            expected_kbs_policy_hash: [7; 32],
        }
    }

    #[test]
    fn signed_descriptor_runtime_fields_match_descriptor_expectations() {
        let descriptor = customer_app_descriptor();

        assert_eq!(
            serialize_workload_command(&descriptor.oci_runtime_spec.args).unwrap(),
            Some("[\"/usr/local/bin/app\"]".to_string())
        );
        assert_eq!(descriptor_primary_port(&descriptor), Some(3338));
        assert_eq!(
            descriptor_storage_paths(&descriptor),
            vec!["/data".to_string()]
        );
    }

    #[test]
    fn descriptor_runtime_overrides_stale_primary_container_fields() {
        let descriptor = customer_app_descriptor();
        let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: Vec::new(),
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
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
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

        set_primary_descriptor_runtime(&mut app, &descriptor);

        let primary = app.primary_container().unwrap();
        assert_eq!(
            primary.command,
            Some(vec!["/usr/local/bin/app".to_string()])
        );
        assert_eq!(primary.port, Some(3338));
        assert_eq!(primary.storage_paths, vec!["/data".to_string()]);
    }

    #[test]
    fn signed_descriptor_without_subpath_mounts_clears_stale_storage_paths() {
        let mut descriptor = customer_app_descriptor();
        descriptor
            .oci_runtime_spec
            .mounts
            .retain(|mount| mount.destination == "/state");
        let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: vec!["/data".to_string()],
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
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
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

        set_primary_descriptor_runtime(&mut app, &descriptor);

        assert!(descriptor_storage_paths(&descriptor).is_empty());
        assert!(app.primary_container().unwrap().storage_paths.is_empty());
    }

    /// A Kubernetes API double with configurable readiness and an empty pod list.
    fn rollout_client(ready: bool) -> kube::Client {
        rollout_client_with(1, 1, i32::from(ready))
    }

    fn rollout_client_with(
        generation: i64,
        observed_generation: i64,
        ready_replicas: i32,
    ) -> kube::Client {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        kube::Client::new(
            service_fn(move |request: Request<Body>| async move {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let path = request.uri().path().to_string();
                let _ = request.into_body().collect().await;
                let value = if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "items": [],
                    })
                } else {
                    serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "metadata": {
                            "name": "queued-app",
                            "namespace": "cap-queued-app",
                            "generation": generation,
                        },
                        "spec": { "replicas": 1 },
                        "status": {
                            "observedGeneration": observed_generation,
                            "replicas": ready_replicas,
                            "readyReplicas": ready_replicas,
                            "currentReplicas": ready_replicas,
                            "updatedReplicas": ready_replicas,
                        },
                    })
                };
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(200)
                        .body(Body::from(serde_json::to_vec(&value).unwrap()))
                        .unwrap(),
                )
            }),
            "default",
        )
    }

    fn rollout_test_engine() -> ApplyEngine {
        ApplyEngine::new(
            rollout_client(false),
            enclava_engine::apply::types::ApplyConfig {
                rollout_timeout: std::time::Duration::from_secs(600),
                poll_interval: std::time::Duration::from_millis(5),
                ..enclava_engine::apply::types::ApplyConfig::default()
            },
        )
    }

    fn expired_rollout_anchor(budget: std::time::Duration) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
            - chrono::Duration::from_std(budget).unwrap()
            - chrono::Duration::seconds(1)
    }

    /// The base budget an initialized redeploy would carry: no fresh claim
    /// contributes the first-boot allowance.
    fn initialized_redeploy_budget() -> std::time::Duration {
        rollout_test_engine()
            .config()
            .rollout_timeout_for_storage(
                "2Ti",
                "2Ti",
                enclava_engine::apply::orchestrator::FreshVolumeClaims::NONE,
            )
            .expect("fixture rollout budget")
    }

    /// The budget a first render that must freshly initialize both volumes
    /// would record with its watching marker.
    fn fresh_initialization_budget(
        app_data_size: &str,
        tls_data_size: &str,
    ) -> std::time::Duration {
        rollout_test_engine()
            .config()
            .rollout_timeout_for_storage(
                app_data_size,
                tls_data_size,
                enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            )
            .expect("fixture rollout budget")
    }

    #[tokio::test]
    async fn rollout_watch_slice_returns_nonterminal_while_budget_remains() {
        // An owner-waiting workload must release its worker slot between
        // observation slices instead of holding it for the full rollout
        // timeout.
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            rollout_test_engine(),
            "slice-manifest".to_string(),
            chrono::Utc::now(),
            fresh_initialization_budget("32Mi", "32Mi"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
        assert_eq!(outcome.manifest_hash, "slice-manifest");
    }

    #[tokio::test]
    async fn rollout_watch_respects_anchored_cumulative_deadline() {
        // A restarted observer anchors at `observing_since`: once the
        // cumulative rollout budget is spent, the slice ends immediately and
        // returns the engine timeout classification instead of restarting a
        // fresh initialization budget.
        let mut auto_app = queued_apply_app();
        auto_app.unlock_mode = crate::models::UnlockMode::Auto;
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            auto_app,
            rollout_test_engine(),
            "deadline-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
    }

    #[tokio::test]
    async fn initialized_redeploy_expires_at_base_budget() {
        // A redeploy whose volumes are already initialized carries only the
        // base rollout budget. A 2 Ti manifest must NOT inherit a
        // multi-hour first-boot allowance: once the recorded base budget is
        // spent, the cumulative deadline ends the rollout normally.
        let mut app = queued_apply_app();
        app.unlock_mode = crate::models::UnlockMode::Auto;
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "initialized-redeploy-manifest".to_string(),
            expired_rollout_anchor(initialized_redeploy_budget()),
            initialized_redeploy_budget(),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
    }

    #[tokio::test]
    async fn resumed_observer_keeps_recorded_budget() {
        // The budget persisted with the watching marker is the deadline.
        // Simulating a restart where live pod/volume state has changed, the
        // resumed observer must reuse the recorded value: a record smaller
        // than any size-derived budget still expires, a record larger than
        // one still keeps observing. Neither recomputes.
        let mut expired_app = queued_apply_app();
        expired_app.unlock_mode = crate::models::UnlockMode::Auto;
        let recorded_small = std::time::Duration::from_secs(1);
        let expired = DeploymentRollout::observe_only(
            expired_app,
            rollout_test_engine(),
            "resumed-expired-manifest".to_string(),
            expired_rollout_anchor(recorded_small),
            recorded_small,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(expired.deploy_status, "failed");
        assert!(expired.terminal);

        let mut waiting_app = queued_apply_app();
        waiting_app.unlock_mode = crate::models::UnlockMode::Auto;
        let waiting = DeploymentRollout::observe_only(
            waiting_app,
            rollout_test_engine(),
            "resumed-waiting-manifest".to_string(),
            chrono::Utc::now() - chrono::Duration::minutes(30),
            fresh_initialization_budget("2Ti", "2Ti"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(waiting.deploy_status, "watching");
        assert!(!waiting.terminal);
        assert_eq!(waiting.error_code, None);
    }

    #[tokio::test]
    async fn rollout_watch_observes_late_owner_unlock_after_deadline() {
        let engine = ApplyEngine::new(
            rollout_client(true),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            engine,
            "late-unlock-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "healthy");
        assert_eq!(outcome.app_status, "running");
        assert!(outcome.terminal);
    }

    #[tokio::test]
    async fn rollout_watch_password_timeout_stays_nonterminal_for_owner_wait() {
        // Password-mode creates classify an exhausted rollout budget as a
        // continuing owner wait, but the observation slice still returns
        // promptly so the worker slot is released between probes.
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            rollout_test_engine(),
            "password-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
    }

    #[tokio::test]
    async fn rollout_watch_password_timeout_stays_nonterminal_for_failed_app_redeploy() {
        // The job payload freezes the app snapshot at accept time, so a
        // redeploy of a previously-failed app carries status "failed". The
        // apply already persisted "creating" for the new rollout; the stale
        // snapshot must not terminalize a legitimate owner wait.
        let mut app = queued_apply_app();
        app.status = AppStatus::Failed;
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "password-redeploy-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
    }

    fn settled_statefulset(
        generation: i64,
        observed: i64,
        desired: i32,
        ready: i32,
        current: i32,
        updated: i32,
    ) -> k8s_openapi::api::apps::v1::StatefulSet {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "app", "namespace": "cap-app", "generation": generation},
            "spec": {"replicas": desired},
            "status": {
                "observedGeneration": observed,
                "readyReplicas": ready,
                "currentReplicas": current,
                "updatedReplicas": updated,
            },
        }))
        .expect("statefulset settling fixture")
    }

    #[test]
    fn statefulset_rollout_settled_matches_the_rollout_completion_criterion() {
        // Fully converged: the controller has observed the current
        // generation and every replica matches the latest spec.
        assert!(statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 1, 1, 1
        )));
        // The controller has not observed the newest applied generation:
        // a failed rollout's spec is still being reconciled and its
        // controller can still replace the TEE.
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 2, 1, 1, 1, 1
        )));
        // The replacement is not up yet: the workload is mid-swap even
        // though the controller caught up with the generation.
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 0, 1, 1
        )));
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 1, 1, 0
        )));
        // A scaled-down workload has no TEE that could be replaced.
        assert!(statefulset_rollout_settled(&settled_statefulset(
            3, 3, 0, 0, 0, 0
        )));
    }

    #[tokio::test]
    async fn supersession_serializes_customer_config_delivery() {
        let pool = crate::test_support::database_test_pool().await;
        let (app, deployment_id, _, _) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() + interval '1 hour',
                    next_attempt_at = 'infinity'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("arm config delivery hold");

        for (scenario, blocked) in [
            ("active", true),
            ("expired", false),
            ("released", false),
            ("deleting", false),
        ] {
            let mut tx = pool.begin().await.expect("begin supersession scenario");
            lock_app_deployment_lane(&mut tx, app.id).await.unwrap();
            if scenario == "expired" {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET customer_config_hold_until = clock_timestamp() - interval '1 second'
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            if scenario == "released" {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET customer_config_released_at = clock_timestamp(),
                            next_attempt_at = clock_timestamp()
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            if scenario == "deleting" {
                sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
                    .bind(app.id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let result = supersede_incomplete_deployments(&mut tx, app.id).await;
            if blocked {
                assert!(matches!(result, Err(SupersedeDeploymentError::Busy)));
                let state: String = sqlx::query_scalar(
                    "SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
                assert_eq!(state, "setup_pending");
            } else {
                assert_eq!(result.expect(scenario), 1);
            }
            tx.rollback().await.unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn workload_rollout_settled_reads_the_live_generation() {
        let converged = ApplyEngine::new(
            rollout_client(true),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&converged, "cap-queued-app", "queued-app")
                .await
                .expect("probe converged workload"),
            Some(true)
        );

        let converging = ApplyEngine::new(
            rollout_client(false),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&converging, "cap-queued-app", "queued-app")
                .await
                .expect("probe converging workload"),
            Some(false)
        );
    }

    #[tokio::test]
    async fn workload_rollout_settled_rejects_an_unobserved_generation() {
        // observedGeneration behind metadata.generation: the controller has
        // not caught up to the newest applied spec yet, so the failed
        // rollout is still reconciling even though the replica counts look
        // ready. The probe must read both fields through the client.
        let lagging = ApplyEngine::new(
            rollout_client_with(3, 2, 1),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&lagging, "cap-queued-app", "queued-app")
                .await
                .expect("probe lagging workload"),
            Some(false)
        );
    }

    #[tokio::test]
    async fn workload_rollout_settled_distinguishes_a_missing_workload() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| async move {
                let _ = request.into_body().collect().await;
                let status = serde_json::json!({
                    "apiVersion": "v1", "kind": "Status",
                    "status": "Failure", "reason": "NotFound",
                    "message": "absent", "code": 404,
                });
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(404)
                        .body(Body::from(serde_json::to_vec(&status).unwrap()))
                        .unwrap(),
                )
            }),
            "default",
        );
        let engine = ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default());
        assert_eq!(
            workload_rollout_settled(&engine, "cap-absent-app", "absent-app")
                .await
                .expect("probe missing workload"),
            None
        );
    }

    #[tokio::test]
    async fn large_volume_initialization_keeps_observing_after_base_deadline() {
        // The recorded first-boot budget extends past the base deadline: 30
        // minutes into observation a fresh 2 Ti render is still watching.
        let mut app = queued_apply_app();
        app.unlock_mode = crate::models::UnlockMode::Auto;
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "initializing-manifest".to_string(),
            chrono::Utc::now() - chrono::Duration::minutes(30),
            fresh_initialization_budget("2Ti", "2Gi"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
        assert_eq!(outcome.error_code, None);
    }

    /// Kubernetes API double for `ingress_restart_verdict`: exact-path GET
    /// responses, 404 `Status` for anything absent — the same shape the real
    /// API server returns to `get`/`get_opt`.
    struct GateCluster {
        responses: std::collections::HashMap<String, (u16, serde_json::Value)>,
    }

    impl GateCluster {
        fn empty() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
            }
        }

        /// A live StatefulSet plus both claims created at a fixed timestamp.
        fn deployed(namespace: &str, workload: &str) -> Self {
            let mut cluster = Self::empty();
            cluster.put(
                format!("/apis/apps/v1/namespaces/{namespace}/statefulsets/{workload}"),
                200,
                serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": workload, "namespace": namespace},
                }),
            );
            cluster.with_claims(namespace, workload, &["state", "tls-state"]);
            cluster
        }

        fn with_claims(&mut self, namespace: &str, workload: &str, vcts: &[&str]) {
            for vct in vcts {
                let claim_name = format!("{vct}-{workload}-0");
                self.put(
                    format!("/api/v1/namespaces/{namespace}/persistentvolumeclaims/{claim_name}"),
                    200,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PersistentVolumeClaim",
                        "metadata": {
                            "name": claim_name,
                            "namespace": namespace,
                            "creationTimestamp": "2025-01-01T00:00:00Z",
                        },
                    }),
                );
            }
        }

        /// Ordinal-0 pod created AFTER both claims (strict whole-second
        /// ordering satisfied), mounting both claims, with configurable
        /// readiness — a still-formatting initializer reports `ready=false`.
        fn with_pod(&mut self, namespace: &str, workload: &str, ready: bool) {
            let pod_name = format!("{workload}-0");
            let state_claim = format!("state-{workload}-0");
            let tls_claim = format!("tls-state-{workload}-0");
            let ready_status = if ready { "True" } else { "False" };
            self.put(
                format!("/api/v1/namespaces/{namespace}/pods/{pod_name}"),
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": pod_name,
                        "namespace": namespace,
                        "creationTimestamp": "2025-01-01T00:01:00Z",
                    },
                    "spec": {
                        "containers": [],
                        "volumes": [
                            {"name": "state",
                             "persistentVolumeClaim": {"claimName": state_claim}},
                            {"name": "tls-state",
                             "persistentVolumeClaim": {"claimName": tls_claim}},
                        ],
                    },
                    "status": {
                        "conditions": [{
                            "type": "Ready",
                            "status": ready_status,
                        }],
                    },
                }),
            );
        }

        fn put(&mut self, path: String, status: u16, body: serde_json::Value) {
            self.responses.insert(path, (status, body));
        }

        fn client(self) -> kube::Client {
            use axum::http::{Request, Response};
            use http_body_util::BodyExt;
            use kube::client::Body;
            use tower::service_fn;

            kube::Client::new(
                service_fn(move |request: Request<Body>| {
                    let responses = self.responses.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        let _ = request.into_body().collect().await;
                        let (status, body) = responses.get(&path).cloned().unwrap_or_else(|| {
                            (
                                404,
                                serde_json::json!({
                                    "apiVersion": "v1",
                                    "kind": "Status",
                                    "status": "Failure",
                                    "reason": "NotFound",
                                    "code": 404,
                                    "message": format!("{path} not found"),
                                }),
                            )
                        });
                        Ok::<_, std::io::Error>(
                            Response::builder()
                                .status(status)
                                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                .unwrap(),
                        )
                    }
                }),
                "default",
            )
        }
    }

    fn gate_engine(cluster: GateCluster) -> ApplyEngine {
        ApplyEngine::new(
            cluster.client(),
            enclava_engine::apply::types::ApplyConfig::default(),
        )
    }

    #[tokio::test]
    async fn ingress_restart_not_deployed_without_statefulset() {
        // No StatefulSet: nothing to restart, so the predeploy verify keeps
        // its DNS-only path. The probe must not provision or wait.
        let engine = gate_engine(GateCluster::empty());
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("404 StatefulSet lookup is a verdict, not an error");
        assert_eq!(verdict, IngressRestartVerdict::NotDeployed);
    }

    #[tokio::test]
    async fn ingress_restart_ready_when_live_pod_proves_both_claims() {
        // Exact ordinal-0 Ready pod, created after both claims, mounting both:
        // the restart only re-opens initialized volumes under the base budget.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", true);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Ready);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_when_claim_missing() {
        // The tls-state claim is gone: a restart lands the replacement pod on
        // a never-formatted device under the base deadline — refuse, never
        // wait longer under the shared fences.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", true);
        cluster
            .responses
            .remove("/api/v1/namespaces/cap-app/persistentvolumeclaims/tls-state-app-0");
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_while_initializer_not_ready() {
        // Live pod mounting both claims but not yet Ready: enclava-init may
        // still be scanning/formatting — a restart now could strand a
        // partially formatted volume.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", false);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_without_live_pod() {
        // Claims exist but the ordinal-0 pod is absent (evicted/scaled): no
        // live proof of completed initialization, fail closed.
        let cluster = GateCluster::deployed("cap-app", "app");
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn terminal_failed_deployment_cannot_admit_restart_of_live_unready_pod() {
        // A 'failed' deployment row is terminal — the DB guard passes it —
        // but the pod it left behind is still mid first-boot. The verdict
        // consults live cluster state only, so it must refuse regardless of
        // the recorded status.
        let pool = crate::test_support::database_test_pool().await;
        let (app, deployment_id, _, _) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        sqlx::query("UPDATE deployments SET status = 'failed'::deploy_status_enum WHERE id = $1")
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("record terminal deployment status");

        let mut cluster = GateCluster::deployed(&app.namespace, &app.name);
        cluster.with_pod(&app.namespace, &app.name, false);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, &app.namespace, &app.name)
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("clean up fixture");
    }
}

/// Project a worker's deployment status transition. Two evidence-preserving
/// quirks (devin 🔴 round-6 follow-up): the `watching` transition stamps
/// `observing_since` as the observation anchor, AND a transition AWAY from a
/// `watching` row keeps that stamp — the legacy re-apply path (a pre-0047
/// watched row has NULL `observing_since`; `claim_rollout_observation` cannot
/// resume it and re-applies) demotes `watching` -> `applying` here, and that
/// demotion is the moment the row proves it already served a watched
/// generation. Without the stamp the later failure publisher would see a
/// NULL-`observing_since` partial apply and arm retryable cleanup whose sweep
/// can then remove the routes and namespace under the still-live workload.
pub async fn set_deployment_status(
    pool: &PgPool,
    deployment_id: Uuid,
    status: &str,
    manifest_hash: Option<&str>,
    error_message: Option<&str>,
    terminal: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE deployments
         SET status = $1::deploy_status_enum,
             manifest_hash = COALESCE($2, manifest_hash),
             error_message = $3,
             completed_at = CASE WHEN $4 THEN now() ELSE completed_at END,
             observing_since = CASE
                 WHEN $1 = 'watching' OR status = 'watching'
                     THEN COALESCE(observing_since, clock_timestamp())
                 ELSE observing_since
             END,
             apply_started_at = CASE
                 WHEN $1 = 'applying' THEN COALESCE(apply_started_at, clock_timestamp())
                 ELSE apply_started_at
             END
         WHERE id = $5",
    )
    .bind(status)
    .bind(manifest_hash)
    .bind(persisted_deployment_error(error_message))
    .bind(terminal)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn set_app_status(pool: &PgPool, app_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
    // This is a nonterminal worker projection, not a change to accepted app
    // authority. Advancing updated_at here would make a reclaimed durable job
    // reject its own immutable payload after a crash between apply phases.
    sqlx::query("UPDATE apps SET status = $1::app_status_enum WHERE id = $2")
        .bind(status)
        .bind(app_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Whether a domain-triggered tenant-ingress restart may proceed.
///
/// `NotDeployed`: the workload StatefulSet does not exist yet, so there is
/// nothing to restart — the caller keeps the DNS-only predeploy path.
///
/// `Ready`: a live StatefulSet exists and both persistent claims are proven
/// initialized by the exact live Ready ordinal-0 pod, so the restart only
/// re-opens finished volumes under the base rollout deadline.
///
/// `Unproven`: a live StatefulSet exists but at least one claim is missing,
/// terminating, or not proven initialized — restarting could kill a still
/// formatting first-boot pod or strand a fresh claim under the base wait,
/// so the caller must conflict before any domain effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRestartVerdict {
    NotDeployed,
    Ready,
    Unproven,
}

/// Probe live Kubernetes state before a domain mutation may restart the
/// workload pod. Deployment-row status is NOT consulted: 'failed'/'healthy'
/// rows cannot prove a first-boot formatter is finished, so only the shared
/// live-proof inspector admits the restart. Lookup errors propagate (fail
/// closed) and never admit.
pub async fn ingress_restart_verdict(
    engine: &ApplyEngine,
    namespace: &str,
    workload: &str,
) -> Result<IngressRestartVerdict, DeployError> {
    if !statefulset_exists(engine, namespace, workload).await? {
        return Ok(IngressRestartVerdict::NotDeployed);
    }
    let fresh = enclava_engine::apply::orchestrator::inspect_fresh_volume_claims(
        engine,
        namespace,
        workload,
        enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
    )
    .await
    .map_err(DeployError::Apply)?;
    if fresh.app_data || fresh.tls_data {
        Ok(IngressRestartVerdict::Unproven)
    } else {
        Ok(IngressRestartVerdict::Ready)
    }
}

/// Re-render and SSA-apply only the tenant-ingress ConfigMap for an app.
///
/// Used when domain-only state changes (e.g. a custom-domain verification)
/// must reach the running pod's Caddyfile without a full redeploy. Caddy
/// inside the pod runs `caddy run` with no live config-watch sidecar, so this
/// function applies the new Caddyfile, triggers a StatefulSet rollout restart,
/// and waits for the replacement pod to become ready before returning.
///
/// Callers MUST obtain `IngressRestartVerdict::Ready` (or `NotDeployed` for
/// the DNS-only path) from [`ingress_restart_verdict`] before invoking this:
/// it does not re-check initialization, and the rollout wait below assumes
/// the restart only re-opens already-initialized volumes.
///
/// Returns `DeployError::NotDeployed` when the app has no live StatefulSet yet.
pub async fn reapply_tenant_ingress(
    pool: &PgPool,
    app: &App,
    attestation_config: Option<&AttestationConfig>,
    api_signing_pubkey: &str,
    api_url: &str,
    mutation: &crate::mutation_leases::AppMutationLease,
    kubernetes_mutation_generation: i64,
) -> Result<(), DeployError> {
    let Some(attestation_config) = attestation_config else {
        return Err(DeployError::MissingAttestationConfig);
    };

    let deployment_id = latest_deployment_id_for_app(pool, app.id).await?;
    let app_spec = build_confidential_app(
        pool,
        app,
        deployment_id,
        attestation_config,
        api_signing_pubkey,
        api_url,
    )
    .await?;
    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    let cm = enclava_engine::manifest::ingress::generate_ingress_configmap(&app_spec);

    let engine = ApplyEngine::try_default().await?;
    // Domain-only reapply: the pod restart re-opens existing volumes, so the
    // base rollout budget applies — the fresh-initialization allowance is
    // reserved for renders that provision a new claim.
    let rollout_timeout = engine.config().rollout_timeout;
    ensure_statefulset_exists(&engine, &app_spec.namespace, &app_spec.name).await?;
    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    enclava_engine::apply::resources::apply_namespaced_resource(
        &engine,
        &app_spec.namespace,
        &cm,
        generation,
    )
    .await?;
    restart_statefulset_for_ingress(&engine, &app_spec.namespace, &app_spec.name, generation)
        .await?;

    let status = watch_rollout(
        &engine,
        &app_spec.namespace,
        &app_spec.name,
        rollout_timeout,
    )
    .await?;
    if status.phase != DeployPhase::Running {
        return Err(enclava_engine::apply::engine::ApplyError::RolloutFailed(
            status
                .message
                .unwrap_or_else(|| format!("tenant ingress rollout ended in {:?}", status.phase)),
        )
        .into());
    }

    Ok(())
}

async fn statefulset_exists(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<bool, DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match api.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
        Err(e) => Err(enclava_engine::apply::engine::ApplyError::Kube(e).into()),
    }
}

/// Probe under the app deployment lane: terminal SQL rows cannot prove a
/// Kubernetes controller stopped replacing the TEE. `None` means no live
/// workload exists, so recovery must not wait for config delivery to it.
pub async fn workload_rollout_settled(
    engine: &ApplyEngine,
    namespace: &str,
    workload_name: &str,
) -> Result<Option<bool>, DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match api.get(workload_name).await {
        Ok(sts)
            if sts
                .spec
                .as_ref()
                .and_then(|spec| spec.replicas)
                .unwrap_or(1)
                <= 0 =>
        {
            Ok(None)
        }
        Ok(sts) => Ok(Some(statefulset_rollout_settled(&sts))),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
        Err(e) => Err(enclava_engine::apply::engine::ApplyError::Kube(e).into()),
    }
}

/// Whether a live StatefulSet is fully converged: the controller has
/// observed the current generation and every replica matches the latest
/// spec. Anything less means the cluster may still replace the workload's
/// pod — including past any SQL settling window, because a controller never
/// abandons an applied generation. A scaled-down workload (`desired == 0`)
/// has no TEE that could be replaced.
pub fn statefulset_rollout_settled(sts: &k8s_openapi::api::apps::v1::StatefulSet) -> bool {
    let status = sts.status.as_ref();
    let generation = sts.metadata.generation.unwrap_or(0);
    let observed_generation = status.and_then(|s| s.observed_generation).unwrap_or(0);
    let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let ready = status.and_then(|s| s.ready_replicas).unwrap_or(0);
    let current = status.and_then(|s| s.current_replicas).unwrap_or(0);
    let updated = status.and_then(|s| s.updated_replicas).unwrap_or(0);
    if desired <= 0 {
        return true;
    }
    observed_generation >= generation
        && ready >= desired
        && current >= desired
        && updated >= desired
}

async fn ensure_statefulset_exists(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<(), DeployError> {
    if statefulset_exists(engine, namespace, name).await? {
        Ok(())
    } else {
        Err(DeployError::NotDeployed(format!(
            "StatefulSet {namespace}/{name} not found"
        )))
    }
}

async fn restart_statefulset_for_ingress(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    generation: MutationGeneration,
) -> Result<(), DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "cap.enclava.dev/tenant-ingress-restarted-at": chrono::Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    });
    enclava_engine::apply::generation::apply_existing_partial(
        &api,
        name,
        &patch,
        generation,
        &engine.config().field_manager,
    )
    .await?;

    tracing::info!(
        namespace = %namespace,
        statefulset = %name,
        "triggered tenant ingress rollout restart"
    );

    Ok(())
}

/// One rollout-observation slice. A durable watcher owns no mutation fence, so
/// this bound is also the maximum time a waiting workload keeps a worker slot
/// before the job is released for the next dispatch.
const ROLLOUT_OBSERVATION_SLICE: std::time::Duration = std::time::Duration::from_secs(90);

/// A rollout handle returned after Kubernetes accepted the rendered manifests.
///
/// Callers must await [`DeploymentRollout::watch`]. Durable deployment workers
/// publish each observed outcome under their job lease, so a replacement API
/// process resumes observation after a crash without re-applying manifests.
pub struct DeploymentRollout {
    app: App,
    engine: ApplyEngine,
    namespace: String,
    workload_name: String,
    pub(crate) manifest_hash: String,
    observing_since: chrono::DateTime<chrono::Utc>,
    observation_slice: std::time::Duration,
    /// Cumulative budget recorded by the watching transition. Resumed
    /// observers reuse this value verbatim rather than recomputing it from
    /// changing live cluster state.
    pub(crate) rollout_timeout: std::time::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRolloutOutcome {
    pub deploy_status: &'static str,
    pub app_status: &'static str,
    pub error_code: Option<&'static str>,
    pub terminal: bool,
    pub manifest_hash: String,
}

impl DeploymentRollout {
    /// Read-only rollout observer for a generation whose durable deployment
    /// row is already `watching`. It shares the recorded manifest hash, the
    /// anchored observation window, and the `rollout_timeout` budget that was
    /// computed once before this generation's first provider apply and
    /// persisted with the watching transition — resumed observation never
    /// recomputes it from changing live pod or volume state. Performs no
    /// provider mutation.
    pub(crate) fn observe_only(
        app: App,
        engine: ApplyEngine,
        manifest_hash: String,
        observing_since: chrono::DateTime<chrono::Utc>,
        rollout_timeout: std::time::Duration,
    ) -> Result<Self, DeployError> {
        let namespace = app.namespace.clone();
        let workload_name = app.name.clone();
        Ok(Self {
            app,
            engine,
            namespace,
            workload_name,
            manifest_hash,
            observing_since,
            observation_slice: ROLLOUT_OBSERVATION_SLICE,
            rollout_timeout,
        })
    }

    #[cfg(test)]
    fn with_observation_slice(mut self, slice: std::time::Duration) -> Self {
        self.observation_slice = slice;
        self
    }

    /// Observe Kubernetes only, in one bounded slice. The durable job owner
    /// publishes this outcome after atomically revalidating its lease. When
    /// the slice elapses while cumulative rollout budget remains, the outcome
    /// is a nonterminal `watching` so the worker releases its slot and the
    /// job resumes observation on the next dispatch. The total
    /// `rollout_timeout` is anchored at `observing_since`, so restarted
    /// observation cannot extend a rollout deadline forever.
    pub async fn watch(self) -> DeploymentRolloutOutcome {
        // `self.app` is the snapshot frozen into the job payload at accept
        // time. `apply_deployment_manifests` has already persisted status
        // "creating" for this rollout, so a pre-existing terminal "failed"
        // must not drive classification: a redeployed failed app is creating
        // again, and password-mode owner wait must stay nonterminal rather
        // than terminalizing on the stale snapshot.
        let previous_app_status = match self.app.status {
            AppStatus::Failed => AppStatus::Creating,
            status => status,
        };
        let unlock_mode = self.app.unlock_mode;
        let total = self.rollout_timeout;
        let elapsed = chrono::Utc::now()
            .signed_duration_since(self.observing_since)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let remaining = total.saturating_sub(elapsed);
        // Owner wait is deliberately nonterminal. Keep observing after its
        // initial budget expires so a later unlock can still become healthy.
        let owner_wait = unlock_mode == crate::models::UnlockMode::Password
            && previous_app_status == AppStatus::Creating;
        let slice = if owner_wait && remaining.is_zero() {
            self.observation_slice
        } else {
            remaining.min(self.observation_slice)
        };
        let result = match tokio::time::timeout(
            slice,
            watch_rollout(&self.engine, &self.namespace, &self.workload_name, total),
        )
        .await
        {
            Ok(result) => result.map_err(|error| error.public_code().to_string()),
            Err(_) if remaining > self.observation_slice => {
                // Slice elapsed with rollout budget remaining: return a
                // nonterminal observation so the worker frees its slot.
                return DeploymentRolloutOutcome {
                    deploy_status: "watching",
                    app_status: app_status_label(previous_app_status),
                    error_code: None,
                    terminal: false,
                    manifest_hash: self.manifest_hash,
                };
            }
            // The cumulative rollout budget is exhausted; preserve the engine
            // timeout classification for this generation.
            Err(_) => Ok(EngineDeployStatus::timed_out(&format!(
                "rollout did not complete within {total:?}"
            ))),
        };
        let outcome = classify_rollout_result(result, previous_app_status, unlock_mode);
        DeploymentRolloutOutcome {
            deploy_status: outcome.deploy_status,
            app_status: outcome.app_status,
            error_code: (outcome.deploy_status == "failed").then_some("deployment_rollout_failed"),
            terminal: outcome.terminal,
            manifest_hash: self.manifest_hash,
        }
    }
}

fn app_status_label(status: AppStatus) -> &'static str {
    match status {
        AppStatus::Creating => "creating",
        AppStatus::Running => "running",
        AppStatus::Stopped => "stopped",
        AppStatus::Failed => "failed",
        AppStatus::Deleting => "deleting",
    }
}

/// Apply manifests and return durable rollout-observation context.
pub async fn apply_deployment_manifests(
    request: ApplyDeploymentManifestsRequest,
    mutation: &crate::mutation_leases::AppMutationLease,
) -> Result<Option<DeploymentRollout>, DeployError> {
    let ApplyDeploymentManifestsRequest {
        pool,
        app,
        snapshot,
        engine,
        fresh_volume_claims,
        deployment_id,
        attestation_config,
        kbs_policy_config,
        edge_config_generation,
        kubernetes_mutation_generation,
        api_signing_pubkey,
        api_url,
        workload_artifact_binding,
        signed_policy_artifact,
        local_workload_artifacts_json,
        local_trustee_policy_json,
        sigstore_material,
        provenance_oci_material,
        log_encryption,
    } = request;
    let attestation_config = attestation_config.ok_or(DeployError::MissingAttestationConfig)?;

    let mut app_spec = build_confidential_app_from_rows(
        &app,
        deployment_id,
        &attestation_config,
        &api_signing_pubkey,
        &api_url,
        &snapshot.containers,
        &snapshot.resources,
    )?;
    app_spec.workload_artifact_binding = workload_artifact_binding;
    app_spec.log_encryption = log_encryption;
    if let (Some(workload_artifacts), Some(trustee_policy)) = (
        local_workload_artifacts_json.as_ref(),
        local_trustee_policy_json.as_ref(),
    ) {
        app_spec.attestation.local_workload_artifacts_json = Some(workload_artifacts.clone());
        app_spec.attestation.local_trustee_policy_json = Some(trustee_policy.clone());
    }
    if let Some(signed_policy_artifact) = signed_policy_artifact.as_ref() {
        let policy_sha256: [u8; 32] = hex::decode(&signed_policy_artifact.agent_policy_sha256)
            .map_err(|err| DeployError::Validation(format!("agent_policy_sha256: {err}")))?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                DeployError::Validation(format!(
                    "agent_policy_sha256 must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
        app_spec.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
            policy_text: signed_policy_artifact.agent_policy_text.clone(),
            policy_sha256,
            genpolicy_version_pin: signed_policy_artifact
                .metadata
                .genpolicy_version_pin
                .clone(),
        });
    }

    app_spec.attestation.verification_material = Some(build_verification_material(
        &app_spec,
        local_workload_artifacts_json.as_deref().unwrap_or_default(),
        local_trustee_policy_json.as_deref().unwrap_or_default(),
        &sigstore_material,
        &provenance_oci_material,
    )?);

    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    // Reuse the under-fence verdict the worker reinspected immediately
    // before this call: reading again here could terminalize a transient
    // lookup failure after provider writes already began.
    enclava_engine::apply::orchestrator::enforce_floor_on_claims(&app_spec, fresh_volume_claims)?;
    let rollout_timeout = engine
        .config()
        .rollout_timeout_for_storage(
            &app_spec.storage.app_data.size,
            &app_spec.storage.tls_data.size,
            fresh_volume_claims,
        )
        .map_err(DeployError::Validation)?;

    let tenant_image_pull_secret_config =
        tenant_image_pull_secret_config_for_containers(&app_spec.containers);
    let manifests = generate_all_manifests(&app_spec);
    let hash = manifest_hash(&manifests);
    set_deployment_status(&pool, deployment_id, "applying", Some(&hash), None, false).await?;
    set_app_status(&pool, app.id, "creating").await?;
    if signed_policy_artifact.is_some() {
        if should_reconcile_global_signed_policy_artifacts(true, &app_spec.attestation) {
            // Acceptance already advanced the durable desired generation in
            // the same transaction that persisted this artifact.  Converge
            // that generation here while the caller holds the global KBS
            // mutation fence; do not enqueue a second generation.
            crate::kbs::reconcile_pending_signed_policy_artifacts(
                &pool,
                kbs_policy_config.as_ref(),
            )
            .await?;
        } else {
            tracing::info!(
                app_id = %app.id,
                deployment_id = %deployment_id,
                "signed deployment did not request global KBS policy aggregate reconciliation"
            );
        }
    } else {
        crate::kbs::ensure_owner_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::ensure_tls_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::reconcile_policy(&pool, kbs_policy_config.as_ref()).await?;
    }

    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    // The floor verdict was already derived from live PVC evidence before
    // the first provider write above; provisioned sub-floor claims pass
    // through unchanged.

    apply_all_with_tenant_image_pull_secret(
        &engine,
        &pool,
        deployment_id,
        &manifests,
        &hash,
        tenant_image_pull_secret_config.as_ref(),
        generation,
    )
    .await?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .fetch_one(&pool)
        .await?;
    // Host list shared with failed-apply cleanup
    // (`crate::deployment_failure_cleanup`) so publication and removal can
    // never diverge.
    let app_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 443).await?;
    let tee_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 8081).await?;
    let mut routes = Vec::with_capacity(3);
    for (tag, host) in crate::deploy::app_route_hosts(&app) {
        let backend = crate::edge::backend_name_for(&org_slug, &app_spec.name, tag)?;
        let target = match tag {
            crate::edge::BackendTag::App => &app_target,
            crate::edge::BackendTag::Tee => &tee_target,
        };
        routes.push(crate::edge::SniRoute::new(&host, &backend, target)?);
    }
    crate::edge::ensure_haproxy_routes(&pool, &edge_config, Some(edge_config_generation), &routes)
        .await?;

    Ok(Some(DeploymentRollout {
        app,
        engine,
        namespace: app_spec.namespace.clone(),
        workload_name: app_spec.name.clone(),
        manifest_hash: hash,
        observing_since: chrono::Utc::now(),
        observation_slice: ROLLOUT_OBSERVATION_SLICE,
        rollout_timeout,
    }))
}

fn build_verification_material(
    app: &enclava_engine::types::ConfidentialApp,
    workload_artifacts_json: &str,
    trustee_policy_json: &str,
    sigstore_material: &[u8],
    provenance_oci_material: &[u8],
) -> Result<Vec<u8>, DeployError> {
    let cc_init_data = enclava_engine::manifest::cc_init_data::build_toml(app);
    let fields = [
        ("cc_init_data_toml", cc_init_data.as_bytes(), 196_608),
        (
            "workload_artifacts_json",
            workload_artifacts_json.as_bytes(),
            196_608,
        ),
        (
            "trustee_policy_json",
            trustee_policy_json.as_bytes(),
            49_152,
        ),
        ("sigstore_material", sigstore_material, 196_608),
        ("provenance_oci_material", provenance_oci_material, 311_296),
    ];
    if fields.iter().any(|(_, value, limit)| value.len() > *limit) {
        return Err(DeployError::Validation(
            "verification material field exceeds v1 limit".into(),
        ));
    }
    let records = fields
        .iter()
        .map(|(label, value, _)| (*label, *value))
        .collect::<Vec<_>>();
    let material = enclava_common::canonical::ce_v1_bytes(&records);
    if material.len() > enclava_engine::manifest::verification_material::MAX_BYTES {
        return Err(DeployError::Validation(
            "verification material exceeds 700 KiB".into(),
        ));
    }
    Ok(material)
}
