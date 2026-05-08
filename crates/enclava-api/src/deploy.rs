//! Deploy orchestrator: builds ConfidentialApp from DB state, calls engine, records result.

use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode};
use enclava_engine::apply::{
    engine::ApplyEngine,
    orchestrator::{apply_all, manifest_hash},
    types::DeployPhase,
    watch::watch_rollout,
};
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::types::{
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec,
    WorkloadArtifactBinding,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{App, AppContainer, AppResources};

pub struct ApplyDeploymentManifestsRequest {
    pub pool: PgPool,
    pub app: App,
    pub deployment_id: Uuid,
    pub attestation_config: Option<AttestationConfig>,
    pub kbs_policy_config: Option<crate::kbs::KbsPolicyConfig>,
    pub api_signing_pubkey: String,
    pub api_url: String,
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
            command: row.command.as_ref().map(|c| vec![c.clone()]),
            env: std::collections::HashMap::new(),
            storage_paths,
            is_primary: row.is_primary,
        });
    }

    let unlock_mode = match app.unlock_mode {
        crate::models::UnlockMode::Auto => UnlockMode::Auto,
        crate::models::UnlockMode::Password => UnlockMode::Password,
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
                    source: format!("/data/{}", subdir),
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
        attestation: attestation_config.clone(),
        egress_allowlist: Vec::new(),
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

    let manifests = generate_all_manifests(&app_spec);
    let hash = manifest_hash(&manifests);
    set_deployment_status(&pool, deployment_id, "applying", Some(&hash), None, false).await?;
    set_app_status(&pool, app.id, "creating").await?;

    if signed_policy_artifact.is_some() {
        crate::kbs::reconcile_signed_policy_artifacts(
            &pool,
            kbs_policy_config.as_ref(),
            signed_policy_artifact.as_ref(),
        )
        .await?;
    } else {
        // Backward-compatible path for unsigned deployments only. Signed
        // deployments must use the signing-service envelope as Trustee's
        // authoritative policy body.
        crate::kbs::ensure_owner_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::ensure_tls_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::reconcile_policy(&pool, kbs_policy_config.as_ref()).await?;
    }

    let engine = ApplyEngine::try_default().await?;
    apply_all(&engine, &manifests).await?;
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
        let result = watch_rollout(&engine, &app_spec.namespace, &app_spec.name).await;
        let (deploy_status, app_status, error_message) = match result {
            Ok(status) if status.phase == DeployPhase::Running => ("healthy", "running", None),
            Ok(status) => (
                "failed",
                "failed",
                status
                    .message
                    .or_else(|| Some(format!("{:?}", status.phase))),
            ),
            Err(e) => ("failed", "failed", Some(e.to_string())),
        };

        if let Err(e) = record_deployment_result(
            &pool,
            deployment_id,
            deploy_status,
            Some(&hash),
            error_message.as_deref(),
        )
        .await
        {
            tracing::error!(deployment_id = %deployment_id, error = %e, "failed to record deployment result");
        }

        if let Err(e) = set_app_status(&pool, app.id, app_status).await {
            tracing::error!(app_id = %app.id, error = %e, "failed to update app status");
        }
    });

    Ok(())
}
