//! Deploy orchestrator: builds ConfidentialApp from DB state, calls engine, records result.

use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode as CommonUnlockMode};
use enclava_engine::apply::{
    engine::ApplyEngine,
    gateway::apply_gateway_resources,
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
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec,
    WorkloadArtifactBinding,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{App, AppContainer, AppResources, AppStatus};

const DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME: &str = "enclava-registry-auth";
const TENANT_IMAGE_PULL_SECRET_NAME_ENV: &str = "TENANT_IMAGE_PULL_SECRET_NAME";

#[derive(Debug, Clone)]
struct TenantImagePullSecretConfig {
    name: String,
    username: String,
    token: String,
}

#[derive(Debug, PartialEq, Eq)]
struct DeploymentOutcome {
    deploy_status: &'static str,
    app_status: &'static str,
    error_message: Option<String>,
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
            }
        }
        Ok(status) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: status
                .message
                .or_else(|| Some(format!("{:?}", status.phase))),
        },
        Err(err) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: Some(err),
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
    })
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
    manifests: &enclava_engine::manifest::GeneratedManifests,
    manifest_hash: &str,
    image_pull_secret_config: Option<&TenantImagePullSecretConfig>,
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

    apply_namespace(engine, &manifests.namespace).await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    if let Some(config) = image_pull_secret_config {
        let secret = generate_tenant_image_pull_secret(ns_name, config);
        apply_namespaced_resource(engine, ns_name, &secret).await?;
        tracing::info!(
            namespace = %ns_name,
            secret = %config.name,
            "tenant image pull secret applied"
        );
    }

    apply_standard_resources(engine, manifests).await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    apply_network_policy(engine, ns_name, &manifests.network_policy).await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
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

    apply_statefulset(engine, ns_name, &sts).await?;
    tracing::info!(
        namespace = %ns_name,
        manifest_hash = %manifest_hash,
        "step 5/5: StatefulSet applied"
    );

    tracing::info!(namespace = %ns_name, "apply_all complete");
    Ok(())
}

pub struct ApplyDeploymentManifestsRequest {
    pub pool: PgPool,
    pub app: App,
    pub deployment_id: Uuid,
    pub attestation_config: Option<AttestationConfig>,
    pub kbs_policy_config: Option<crate::kbs::KbsPolicyConfig>,
    pub api_signing_pubkey: String,
    pub api_url: String,
    pub runtime_profile: Option<enclava_engine::types::ConfidentialRuntimeProfile>,
    pub workload_artifact_binding: Option<WorkloadArtifactBinding>,
    pub signed_policy_artifact: Option<crate::signing_service::SignedPolicyArtifact>,
    pub local_workload_artifacts_json: Option<String>,
    pub local_trustee_policy_json: Option<String>,
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

    let mut containers = Vec::new();
    for row in &containers_rows {
        let image_str = row
            .image_digest
            .as_ref()
            .map(|d| {
                format!(
                    "{}@{}",
                    row.image_ref.split('@').next().unwrap_or(&row.image_ref),
                    d
                )
            })
            .unwrap_or_else(|| row.image_ref.clone());

        let image =
            ImageRef::parse(&image_str).map_err(|e| DeployError::ImageParse(e.to_string()))?;

        let storage_paths = row.storage_paths.clone().unwrap_or_default();

        containers.push(Container {
            name: row.name.clone(),
            image,
            port: row.port.map(|p| p as u16),
            command: deserialize_workload_command(row.command.as_deref()),
            env: std::collections::HashMap::new(),
            storage_paths,
            is_primary: row.is_primary,
        });
    }

    let unlock_mode = match app.unlock_mode {
        crate::models::UnlockMode::Auto => CommonUnlockMode::Auto,
        crate::models::UnlockMode::Password => CommonUnlockMode::Password,
    };

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

    Ok(ConfidentialApp {
        app_id: app.id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        image_pull_secret_name: configured_tenant_image_pull_secret_name(),
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
            cpu: resources.cpu_limit,
            memory: resources.memory_limit,
        },
        runtime_profile: enclava_engine::types::ConfidentialRuntimeProfile::default(),
        gpu: None,
        attestation: attestation_config.clone(),
        egress_allowlist: app.egress_allowlist.0.clone(),
        workload_artifact_binding: None,
        generated_agent_policy: None,
    })
}

/// Record a deployment result in the database.
pub async fn record_deployment_result(
    pool: &PgPool,
    deployment_id: Uuid,
    status: &str,
    manifest_hash: Option<&str>,
    error_message: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE deployments
         SET status = $1::deploy_status_enum,
             manifest_hash = $2,
             error_message = $3,
             completed_at = now()
         WHERE id = $4",
    )
    .bind(status)
    .bind(manifest_hash)
    .bind(error_message)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(())
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
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
        }
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
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("rollout did not complete within 600s")
        );
    }

    #[test]
    fn password_create_timeout_still_fails() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Creating,
            crate::models::UnlockMode::Password,
        );

        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("rollout did not complete within 600s")
        );
    }

    #[test]
    fn tenant_image_pull_secret_uses_dockerconfigjson_shape() {
        let config = TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_fake".to_string(),
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
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-demo-org-customer-app-owner".to_string(),
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
            runtime_profile: enclava_engine::types::ConfidentialRuntimeProfile::default(),
            gpu: None,
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
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
            },
            egress_allowlist: Vec::new(),
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
            runtime_profile: enclava_engine::types::ConfidentialRuntimeProfile::default(),
            gpu: None,
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
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
            },
            egress_allowlist: Vec::new(),
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

        set_primary_descriptor_runtime(&mut app, &descriptor);

        assert!(descriptor_storage_paths(&descriptor).is_empty());
        assert!(app.primary_container().unwrap().storage_paths.is_empty());
    }
}

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
             completed_at = CASE WHEN $4 THEN now() ELSE completed_at END
         WHERE id = $5",
    )
    .bind(status)
    .bind(manifest_hash)
    .bind(error_message)
    .bind(terminal)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn set_app_status(pool: &PgPool, app_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE apps SET status = $1::app_status_enum, updated_at = now() WHERE id = $2")
        .bind(status)
        .bind(app_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Re-render and SSA-apply only the tenant-ingress ConfigMap for an app.
///
/// Used when domain-only state changes (e.g. a custom-domain verification)
/// must reach the running pod's Caddyfile without a full redeploy. Caddy
/// inside the pod runs `caddy run` with no live config-watch sidecar, so this
/// function applies the new Caddyfile, triggers a StatefulSet rollout restart,
/// and waits for the replacement pod to become ready before returning.
///
/// Returns `DeployError::NotDeployed` when the app has no live StatefulSet yet.
pub async fn reapply_tenant_ingress(
    pool: &PgPool,
    app: &App,
    attestation_config: Option<&AttestationConfig>,
    api_signing_pubkey: &str,
    api_url: &str,
) -> Result<(), DeployError> {
    let Some(attestation_config) = attestation_config else {
        return Err(DeployError::MissingAttestationConfig);
    };

    let app_spec =
        build_confidential_app(pool, app, attestation_config, api_signing_pubkey, api_url).await?;
    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    let cm = enclava_engine::manifest::ingress::generate_ingress_configmap(&app_spec);

    let engine = ApplyEngine::try_default().await?;
    ensure_statefulset_exists(&engine, &app_spec.namespace, &app_spec.name).await?;
    enclava_engine::apply::resources::apply_namespaced_resource(&engine, &app_spec.namespace, &cm)
        .await?;
    restart_statefulset_for_ingress(&engine, &app_spec.namespace, &app_spec.name).await?;

    let status = watch_rollout(&engine, &app_spec.namespace, &app_spec.name).await?;
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

async fn ensure_statefulset_exists(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<(), DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match api.get(name).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Err(DeployError::NotDeployed(format!(
            "StatefulSet {namespace}/{name} not found"
        ))),
        Err(e) => Err(enclava_engine::apply::engine::ApplyError::Kube(e).into()),
    }
}

async fn restart_statefulset_for_ingress(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<(), DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;
    use kube::api::{Patch, PatchParams};

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let patch = serde_json::json!({
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
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(enclava_engine::apply::engine::ApplyError::Kube)?;

    tracing::info!(
        namespace = %namespace,
        statefulset = %name,
        "triggered tenant ingress rollout restart"
    );

    Ok(())
}

/// Apply manifests before returning the deploy response, then continue rollout
/// monitoring in the background so CLI/API calls are not held for TEE boot.
pub async fn apply_deployment_manifests(
    request: ApplyDeploymentManifestsRequest,
) -> Result<(), DeployError> {
    let ApplyDeploymentManifestsRequest {
        pool,
        app,
        deployment_id,
        attestation_config,
        kbs_policy_config,
        api_signing_pubkey,
        api_url,
        runtime_profile,
        workload_artifact_binding,
        signed_policy_artifact,
        local_workload_artifacts_json,
        local_trustee_policy_json,
    } = request;
    let attestation_config = attestation_config.ok_or(DeployError::MissingAttestationConfig)?;
    let mut app_spec = build_confidential_app(
        &pool,
        &app,
        &attestation_config,
        &api_signing_pubkey,
        &api_url,
    )
    .await?;
    if let Some(runtime_profile) = runtime_profile {
        app_spec.runtime_profile = runtime_profile;
    }
    app_spec.workload_artifact_binding = workload_artifact_binding;
    if let (Some(workload_artifacts), Some(trustee_policy)) =
        (local_workload_artifacts_json, local_trustee_policy_json)
    {
        app_spec.attestation.local_workload_artifacts_json = Some(workload_artifacts);
        app_spec.attestation.local_trustee_policy_json = Some(trustee_policy);
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

    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    let tenant_image_pull_secret_config = tenant_image_pull_secret_config_from_env();
    let manifests = generate_all_manifests(&app_spec);
    let hash = manifest_hash(&manifests);
    set_deployment_status(&pool, deployment_id, "applying", Some(&hash), None, false).await?;
    set_app_status(&pool, app.id, "creating").await?;

    if let Some(signed_policy_artifact) = signed_policy_artifact.as_ref() {
        if should_reconcile_global_signed_policy_artifacts(true, &app_spec.attestation) {
            crate::kbs::reconcile_signed_policy_artifacts(
                &pool,
                kbs_policy_config.as_ref(),
                Some(signed_policy_artifact),
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

    let engine = ApplyEngine::try_default().await?;
    apply_all_with_tenant_image_pull_secret(
        &engine,
        &manifests,
        &hash,
        tenant_image_pull_secret_config.as_ref(),
    )
    .await?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .fetch_one(&pool)
        .await?;
    let app_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 443).await?;
    let tee_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 8081).await?;
    let app_backend =
        crate::edge::backend_name_for(&org_slug, &app_spec.name, crate::edge::BackendTag::App)?;
    let tee_backend =
        crate::edge::backend_name_for(&org_slug, &app_spec.name, crate::edge::BackendTag::Tee)?;
    let mut routes = vec![
        crate::edge::SniRoute::new(&app_spec.domain.platform_domain, &app_backend, &app_target)?,
        crate::edge::SniRoute::new(&app_spec.domain.tee_domain, &tee_backend, &tee_target)?,
    ];
    if let Some(custom) = app_spec.domain.custom_domain.as_deref()
        && !custom.is_empty()
    {
        routes.push(crate::edge::SniRoute::new(
            custom,
            &app_backend,
            &app_target,
        )?);
    }
    crate::edge::ensure_haproxy_routes(&pool, &edge_config, &routes).await?;
    set_deployment_status(&pool, deployment_id, "watching", Some(&hash), None, false).await?;

    tokio::spawn(async move {
        let previous_app_status = app.status;
        let unlock_mode = app.unlock_mode;
        let result = watch_rollout(&engine, &app_spec.namespace, &app_spec.name)
            .await
            .map_err(|e| e.to_string());
        let outcome = classify_rollout_result(result, previous_app_status, unlock_mode);

        if let Err(e) = record_deployment_result(
            &pool,
            deployment_id,
            outcome.deploy_status,
            Some(&hash),
            outcome.error_message.as_deref(),
        )
        .await
        {
            tracing::error!(deployment_id = %deployment_id, error = %e, "failed to record deployment result");
        }

        if let Err(e) = set_app_status(&pool, app.id, outcome.app_status).await {
            tracing::error!(app_id = %app.id, error = %e, "failed to update app status");
        }
    });

    Ok(())
}
