use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::{App, Deployment};
use crate::source_provider::{SourceProvider, validate_source_context};
use crate::state::AppState;

fn deploy_blocked_response(
    status: StatusCode,
    reason: &str,
    message: String,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "error": "deploy_blocked",
            "reason": reason,
            "message": message,
        })),
    )
}

fn dns_error_response(error: crate::dns::DnsError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &error {
        crate::dns::DnsError::OutsideManagedZone(_) => StatusCode::BAD_REQUEST,
        crate::dns::DnsError::HostnameInUse { .. } => StatusCode::CONFLICT,
        crate::dns::DnsError::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
        crate::dns::DnsError::Cloudflare(_)
        | crate::dns::DnsError::Http(_)
        | crate::dns::DnsError::Db(_) => StatusCode::BAD_GATEWAY,
    };

    (
        status,
        Json(serde_json::json!({"error": error.to_string()})),
    )
}

pub(crate) fn signing_error_response(
    error: crate::signing_service::SigningServiceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::signing_service::SigningServiceError;

    let status = match &error {
        SigningServiceError::PartialBlobs
        | SigningServiceError::ArtifactWithoutBlobs
        | SigningServiceError::Blob(_)
        | SigningServiceError::Mismatch(_)
        | SigningServiceError::InvalidSignature => StatusCode::BAD_REQUEST,
        SigningServiceError::Upstream { .. } | SigningServiceError::Http(_) => {
            StatusCode::BAD_GATEWAY
        }
        SigningServiceError::InvalidUrl(_)
        | SigningServiceError::InvalidTimeout(_)
        | SigningServiceError::Db(_)
        | SigningServiceError::Serde(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(serde_json::json!({"error": error.to_string()})),
    )
}

pub(crate) fn customer_signed_deploy_required(
    attestation: Option<&enclava_engine::types::AttestationConfig>,
    signing_service_configured: bool,
) -> bool {
    signing_service_configured
        || attestation
            .map(|cfg| {
                cfg.trustee_policy_read_available
                    || cfg.signing_service_pubkey_hex.is_some()
                    || cfg.platform_trustee_policy_pubkey_hex.is_some()
            })
            .unwrap_or(false)
}

pub(crate) fn select_local_signed_artifact_delivery(
    attestation: &mut enclava_engine::types::AttestationConfig,
) {
    attestation.trustee_policy_read_available = true;
    attestation.local_workload_artifacts_json = Some("{}".to_string());
    attestation.local_trustee_policy_json = Some("{}".to_string());
}

pub(crate) async fn resolve_signed_policy_artifact(
    state: &AppState,
    artifacts: &crate::signing_service::DeploymentSigningArtifacts,
    provided_artifact: Option<String>,
    signing_service_pubkey_hex: Option<&str>,
) -> Result<crate::signing_service::SignedPolicyArtifact, (StatusCode, Json<serde_json::Value>)> {
    artifacts
        .validate_customer_authority(&state.db)
        .await
        .map_err(signing_error_response)?;
    let signing_service_pubkey_hex = signing_service_pubkey_hex.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "platform signing-service pubkey required for signed_policy_artifact verification"
        })),
    ))?;
    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "canonical policy validation requires the platform signing service"
        })),
    ))?;

    let generated = signing_service
        .agent_policy(&crate::signing_service::AgentPolicyRequest {
            descriptor: artifacts.descriptor.clone(),
        })
        .await
        .map_err(signing_error_response)?;

    if let Some(provided_artifact) = provided_artifact {
        let mut artifact =
            crate::signing_service::decode_optional_policy_artifact(Some(provided_artifact))
                .map_err(signing_error_response)?
                .ok_or_else(|| {
                    signing_error_response(
                        crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
                    )
                })?;
        if artifacts
            .validate_signed_artifact(&artifact, signing_service_pubkey_hex)
            .is_ok()
        {
            artifacts
                .validate_canonical_agent_policy(&artifact, &generated)
                .map_err(signing_error_response)?;
            artifacts
                .attach_customer_authority(&mut artifact)
                .map_err(signing_error_response)?;
            return Ok(artifact);
        }
    }

    let mut artifact = signing_service
        .sign(&artifacts.sign_request())
        .await
        .map_err(signing_error_response)?;
    artifacts
        .validate_signed_artifact(&artifact, signing_service_pubkey_hex)
        .map_err(signing_error_response)?;
    artifacts
        .validate_canonical_agent_policy(&artifact, &generated)
        .map_err(signing_error_response)?;
    artifacts
        .attach_customer_authority(&mut artifact)
        .map_err(signing_error_response)?;
    Ok(artifact)
}

/// Pick the right cosign `VerificationPolicy` for a stored signer identity.
///
/// GitHub Actions OIDC subjects are URLs that contain `@` after the workflow
/// path (e.g. `https://github.com/me/repo/.github/workflows/build.yml@refs/heads/main`),
/// so the URL prefix must be checked before the `@`-as-email heuristic.
fn classify_signer_identity(subject: &str, issuer: &str) -> crate::cosign::VerificationPolicy {
    if subject.starts_with("https://") || subject.starts_with("http://") {
        crate::cosign::VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: subject.to_string(),
            fulcio_issuer: issuer.to_string(),
        }
    } else if subject.contains('@') {
        crate::cosign::VerificationPolicy::FulcioEmailIdentity {
            email: subject.to_string(),
            fulcio_issuer: issuer.to_string(),
        }
    } else {
        crate::cosign::VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: subject.to_string(),
            fulcio_issuer: issuer.to_string(),
        }
    }
}

#[cfg(test)]
#[path = "deployments/tests/classifier.rs"]
mod classifier_tests;

/// Parse memory string like "1Gi", "8Gi" to f64 in GiB with validation.
fn parse_memory_gi(s: &str) -> Result<f64, String> {
    if s.is_empty() {
        return Err("memory value cannot be empty".to_string());
    }

    let (value_str, unit) = if let Some(stripped) = s.strip_suffix("Gi") {
        (stripped, "Gi")
    } else if let Some(stripped) = s.strip_suffix("Mi") {
        (stripped, "Mi")
    } else if let Some(stripped) = s.strip_suffix("GiB") {
        (stripped, "GiB")
    } else if let Some(stripped) = s.strip_suffix("MiB") {
        (stripped, "MiB")
    } else {
        // No unit suffix, assume GiB
        (s, "GiB")
    };

    let value: f64 = value_str
        .parse()
        .map_err(|_| format!("invalid memory value: {}", value_str))?;

    if value <= 0.0 {
        return Err("memory value must be positive".to_string());
    }

    let value_gi = match unit {
        "Gi" | "GiB" => Ok(value),
        "Mi" | "MiB" => Ok(value / 1024.0),
        _ => Err(format!("unsupported memory unit: {}", unit)),
    }?;
    if value_gi > 1024.0 {
        return Err("memory value too large (max 1024Gi)".to_string());
    }
    Ok(value_gi)
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub image: String,
    #[serde(default)]
    pub container_name: Option<String>,
    #[serde(default)]
    pub resources: Option<DeployResources>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub source_provider: Option<SourceProvider>,
    #[serde(default)]
    pub source_repository: Option<String>,
    #[serde(default)]
    pub customer_descriptor_blob: Option<String>,
    #[serde(default)]
    pub org_keyring_blob: Option<String>,
    #[serde(default)]
    pub signed_policy_artifact: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeployResources {
    pub cpu: Option<String>,
    pub memory: Option<String>,
    pub storage: Option<String>,
}

fn resource_value(resources: &[enclava_common::descriptor::EnvVar], name: &str) -> Option<String> {
    resources
        .iter()
        .find(|resource| resource.name == name)
        .map(|resource| resource.value.clone())
}

fn descriptor_deploy_resources(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Option<DeployResources> {
    descriptor_deploy_resources_from_limits(&descriptor.oci_runtime_spec.resources.limits)
}

fn descriptor_deploy_resources_from_limits(
    limits: &[enclava_common::descriptor::EnvVar],
) -> Option<DeployResources> {
    let cpu = resource_value(limits, "cpu");
    let memory = resource_value(limits, "memory");
    if cpu.is_none() && memory.is_none() {
        return None;
    }
    Some(DeployResources {
        cpu,
        memory,
        storage: None,
    })
}

fn merge_signed_descriptor_resources(
    requested: Option<DeployResources>,
    signing_artifacts: Option<&crate::signing_service::DeploymentSigningArtifacts>,
) -> Result<Option<DeployResources>, String> {
    let Some(descriptor_resources) =
        signing_artifacts.and_then(|artifacts| descriptor_deploy_resources(&artifacts.descriptor))
    else {
        return Ok(requested);
    };

    let Some(requested) = requested else {
        return Ok(Some(descriptor_resources));
    };

    if let (Some(requested_cpu), Some(descriptor_cpu)) = (
        requested.cpu.as_deref(),
        descriptor_resources.cpu.as_deref(),
    ) && requested_cpu != descriptor_cpu
    {
        return Err(format!(
            "requested cpu {requested_cpu} conflicts with signed descriptor cpu {descriptor_cpu}"
        ));
    }
    if let (Some(requested_memory), Some(descriptor_memory)) = (
        requested.memory.as_deref(),
        descriptor_resources.memory.as_deref(),
    ) && requested_memory != descriptor_memory
    {
        return Err(format!(
            "requested memory {requested_memory} conflicts with signed descriptor memory {descriptor_memory}"
        ));
    }

    Ok(Some(DeployResources {
        cpu: descriptor_resources.cpu.or(requested.cpu),
        memory: descriptor_resources.memory.or(requested.memory),
        storage: requested.storage,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct AgentPolicyRequest {
    pub descriptor: enclava_common::descriptor::DeploymentDescriptor,
}

#[derive(Debug, Serialize)]
pub struct AgentPolicyResponse {
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
}

#[derive(Debug, Serialize)]
pub struct RollbackResponse {
    pub deployment_id: Uuid,
    pub rolled_back_to: Uuid,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct DeploymentResponse {
    pub deployment_id: Uuid,
    pub app_id: Uuid,
    pub app_domain: String,
    pub trigger: String,
    pub status: String,
    pub image_digest: Option<String>,
    pub cosign_verified: bool,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl DeploymentResponse {
    fn from_deployment(d: Deployment, app: &App) -> Self {
        let app_domain = app
            .custom_domain
            .clone()
            .unwrap_or_else(|| app.domain.clone());
        Self {
            deployment_id: d.id,
            app_id: d.app_id,
            app_domain,
            trigger: format!("{:?}", d.trigger).to_lowercase(),
            status: format!("{:?}", d.status).to_lowercase(),
            image_digest: d.image_digest,
            cosign_verified: d.cosign_verified,
            error_message: d.error_message,
            created_at: d.created_at,
            completed_at: d.completed_at,
        }
    }
}

mod generic;
use generic::json_error;
pub use generic::{
    GenericConfigTokenResponse, GenericDeploymentApp, GenericDeploymentRequest,
    GenericDeploymentResponse, GenericDeploymentSecurity, GenericDeploymentSigning,
    GenericDeploymentSource, GenericDeploymentWorkload, create_generic_deployment,
    generate_agent_policy, generic_config_token, get_generic_deployment,
};
#[cfg(test)]
use generic::{ensure_idempotent_retry_matches, validate_external_id};
/// POST /apps/{name}/deploy -- deploy or update an app.
pub async fn deploy(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeploymentResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    if let (Some(provider), Some(repository)) =
        (body.source_provider, body.source_repository.as_deref())
    {
        let subject = app.signer_identity_subject.as_deref().ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "app has no pinned signer identity; set one before deploying",
            )
        })?;
        let issuer = app.signer_identity_issuer.as_deref().ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "app has no pinned signer identity; set one before deploying",
            )
        })?;
        validate_source_context(provider, repository, &body.image, subject, issuer)
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, e.to_string()))?;
    } else if body.source_provider.is_some() || body.source_repository.is_some() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "source_provider and source_repository must be provided together",
        ));
    }

    let signing_artifacts = crate::signing_service::decode_optional_blobs(
        body.customer_descriptor_blob.clone(),
        body.org_keyring_blob.clone(),
    )
    .map_err(signing_error_response)?;
    let effective_resources =
        merge_signed_descriptor_resources(body.resources.clone(), signing_artifacts.as_ref())
            .map_err(|message| json_error(StatusCode::BAD_REQUEST, message))?;
    if body.signed_policy_artifact.is_some() && signing_artifacts.is_none() {
        return Err(signing_error_response(
            crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
        ));
    }
    if customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && signing_artifacts.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed policy deployments require customer_descriptor_blob and org_keyring_blob; use a current enclava CLI to sign the deployment descriptor before deploy"
            })),
        ));
    }

    // Resolve image tag to digest
    let image_ref = enclava_common::image::ImageRef::parse(&body.image).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let image_digest = if image_ref.has_digest() {
        image_ref.digest().to_string()
    } else {
        crate::registry::resolve_image_digest(&state.registry_client, &image_ref)
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": format!("failed to resolve image tag: {}", e)}),
                    ),
                )
            })?
    };

    // Build the per-app verification policy from the app's pinned signer
    // identity. Apps without a pinned identity cannot deploy.
    let policy = match (
        app.signer_identity_subject.as_deref(),
        app.signer_identity_issuer.as_deref(),
    ) {
        (Some(subject), Some(issuer)) if !subject.is_empty() && !issuer.is_empty() => {
            classify_signer_identity(subject, issuer)
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "app has no pinned signer identity; set one before deploying"
                })),
            ));
        }
    };

    let verified = crate::cosign::verify_image(&body.image, &image_digest, &policy)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("cosign verification failed: {}", e)})),
            )
        })?;

    // Enforce core entitlement resource limits.
    if let Some(ref resources) = effective_resources {
        let org: crate::models::Organization =
            sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
                .bind(auth.org_id)
                .fetch_one(&state.db)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "database error"})),
                    )
                })?;

        let entitlement_class = org.entitlement_class.clone();
        let decision = crate::entitlements::entitlement_decision_for_org(
            &state.db,
            auth.org_id,
            &entitlement_class,
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
        if !decision.deploy_allowed {
            return Err(deploy_blocked_response(
                StatusCode::FORBIDDEN,
                decision
                    .deploy_block_reason
                    .as_deref()
                    .unwrap_or("entitlement_blocked"),
                format!("Org entitlement class {entitlement_class} does not allow deploys"),
            ));
        }
        let limits = decision.limits.ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "unknown entitlement class"})),
        ))?;

        if let Some(ref cpu) = resources.cpu {
            let requested: f64 = cpu.parse().unwrap_or(0.0);
            let allowed: f64 = limits.max_cpu.parse().unwrap_or(0.0);
            if requested > allowed {
                return Err(deploy_blocked_response(
                    StatusCode::FORBIDDEN,
                    "entitlement_cpu_limit",
                    format!(
                        "Org entitlement class {entitlement_class} allows max {} CPU, requested {cpu}. Increase the entitlement class or lower the requested CPU.",
                        limits.max_cpu
                    ),
                ));
            }
        }

        if let Some(ref memory) = resources.memory {
            let requested = parse_memory_gi(memory).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e})),
                )
            })?;
            let allowed = parse_memory_gi(&limits.max_memory).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "invalid entitlement memory limit"})),
                )
            })?;
            if requested > allowed {
                return Err(deploy_blocked_response(
                    StatusCode::FORBIDDEN,
                    "entitlement_memory_limit",
                    format!(
                        "Org entitlement class {entitlement_class} allows max {} memory, requested {memory}. Increase the entitlement class or lower the requested memory.",
                        limits.max_memory
                    ),
                ));
            }
        }

        sqlx::query(
            "UPDATE app_resources
                SET cpu_limit = COALESCE($1, cpu_limit),
                    memory_limit = COALESCE($2, memory_limit),
                    app_data_size = COALESCE($3, app_data_size)
              WHERE app_id = $4",
        )
        .bind(resources.cpu.as_deref())
        .bind(resources.memory.as_deref())
        .bind(resources.storage.as_deref())
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    }

    // Fetch provenance attestation and SBOM if available (non-fatal if missing)
    let (provenance, sbom) =
        crate::cosign::fetch_attestations(&state.http_client, &body.image, &image_digest)
            .await
            .unwrap_or((None, None));

    let container_name = body.container_name.as_deref().unwrap_or("web");
    let signed_workload_command = match signing_artifacts.as_ref() {
        Some(artifacts) => {
            crate::deploy::serialize_workload_command(&artifacts.descriptor.oci_runtime_spec.args)
                .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "command serialization error"})),
                )
            })?
        }
        None => None,
    };
    let signed_container_port = signing_artifacts
        .as_ref()
        .and_then(|artifacts| crate::deploy::descriptor_primary_port(&artifacts.descriptor));
    let signed_storage_paths = signing_artifacts
        .as_ref()
        .map(|artifacts| crate::deploy::descriptor_storage_paths(&artifacts.descriptor));
    let container_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_containers WHERE app_id = $1 AND name = $2)",
    )
    .bind(app.id)
    .bind(container_name)
    .fetch_one(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    if container_exists {
        sqlx::query(
            "UPDATE app_containers
             SET image_ref = $1,
                 image_digest = $2,
                 command = COALESCE($3, command),
                 port = COALESCE($4, port),
                 storage_paths = COALESCE($5, storage_paths)
             WHERE app_id = $6 AND name = $7",
        )
        .bind(&body.image)
        .bind(Some(&image_digest))
        .bind(signed_workload_command.as_ref())
        .bind(signed_container_port)
        .bind(signed_storage_paths.as_ref())
        .bind(app.id)
        .bind(container_name)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    } else {
        sqlx::query(
            "INSERT INTO app_containers (id, app_id, name, image_ref, image_digest, command, port, storage_paths, is_primary)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)",
        )
        .bind(Uuid::new_v4())
        .bind(app.id)
        .bind(container_name)
        .bind(&body.image)
        .bind(Some(&image_digest))
        .bind(signed_workload_command.as_ref())
        .bind(signed_container_port)
        .bind(signed_storage_paths.as_ref())
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    }

    let mut workload_artifact_binding = None;
    let mut signed_policy_artifact = None;
    if let Some(artifacts) = signing_artifacts.as_ref() {
        let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
        artifacts
            .validate_deployment_inputs(&app, &image_digest, &api_signing_pubkey)
            .map_err(signing_error_response)?;
        let attestation = state.attestation.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "signed deployment artifacts require attestation runtime configuration"
            })),
        ))?;
        let signing_service_pubkey_hex = attestation.signing_service_pubkey_hex.as_deref();
        let mut app_spec = crate::deploy::build_confidential_app(
            &state.db,
            &app,
            attestation,
            &api_signing_pubkey,
            &state.api_url,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
        let binding = artifacts.binding();
        app_spec.workload_artifact_binding = Some(binding.clone());

        let signed = resolve_signed_policy_artifact(
            &state,
            artifacts,
            body.signed_policy_artifact.clone(),
            signing_service_pubkey_hex,
        )
        .await?;
        app_spec.generated_agent_policy = Some(
            artifacts
                .generated_agent_policy(&signed)
                .map_err(signing_error_response)?,
        );
        select_local_signed_artifact_delivery(&mut app_spec.attestation);
        let (_encoded, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        let expected_cc_init_data_hash =
            hex::encode(artifacts.descriptor.expected_cc_init_data_hash);
        if expected_cc_init_data_hash != cc_init_data_hash {
            if let Ok(path) = std::env::var("ENCLAVA_DEBUG_CC_INIT_MISMATCH_TOML_PATH") {
                let actual_toml = enclava_engine::manifest::cc_init_data::build_toml(&app_spec);
                if let Err(error) = std::fs::write(&path, actual_toml) {
                    tracing::warn!(
                        path = %path,
                        error = %error,
                        "failed to write debug cc_init_data mismatch TOML"
                    );
                }
            }
            tracing::warn!(
                expected_cc_init_data_hash = %expected_cc_init_data_hash,
                actual_cc_init_data_hash = %cc_init_data_hash,
                namespace = %app_spec.namespace,
                service_account = %app_spec.service_account,
                platform_domain = %app_spec.domain.platform_domain,
                custom_domain = ?app_spec.domain.custom_domain,
                attestation_proxy_image = ?app_spec.attestation.proxy_image,
                caddy_image = ?app_spec.attestation.caddy_image,
                caddy_tls_mode = ?app_spec.attestation.caddy_tls_mode,
                tls_certificate_broker_url = ?app_spec.attestation.tls_certificate_broker_url,
                local_workload_artifacts = app_spec.attestation.local_workload_artifacts_json.is_some(),
                local_trustee_policy = app_spec.attestation.local_trustee_policy_json.is_some(),
                generated_agent_policy_sha256 = %hex::encode(app_spec.generated_agent_policy.as_ref().map(|policy| policy.policy_sha256).unwrap_or([0; 32])),
                descriptor_core_hash = %hex::encode(binding.descriptor_core_hash),
                "signed deployment cc_init_data hash mismatch"
            );
        }
        artifacts
            .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
            .map_err(signing_error_response)?;
        workload_artifact_binding = Some(binding);
        signed_policy_artifact = Some(signed);
    }

    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
    let source_provider = body.source_provider.map(SourceProvider::as_str);
    let spec_snapshot = serde_json::json!({
        "app_name": app.name,
        "namespace": app.namespace,
        "instance_id": app.instance_id,
        "image": body.image,
        "image_digest": &image_digest,
        "container_name": container_name,
        "resources": effective_resources,
        "external_id": &body.external_id,
        "source_provider": source_provider,
        "source_repository": &body.source_repository,
        "signed_descriptor_core_hash": signing_artifacts
            .as_ref()
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
    });

    // Create deployment record. cosign_verified is set from the actual
    // verification result, not hardcoded.
    let cosign_verified = true;
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, cosign_verified, provenance_attestation, sbom, external_id, source_provider, source_repository)
         VALUES ($1, $2, $3, 'api', $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&spec_snapshot)
    .bind(Some(&image_digest))
    .bind(cosign_verified)
    .bind(&provenance)
    .bind(&sbom)
    .bind(body.external_id.as_deref())
    .bind(source_provider)
    .bind(body.source_repository.as_deref())
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("idx_deployments_org_external_id") {
            json_error(
                StatusCode::CONFLICT,
                "deployment with external_id already exists in this org",
            )
        } else {
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
        }
    })?;

    if let (Some(artifacts), Some(signed)) =
        (signing_artifacts.as_ref(), signed_policy_artifact.as_ref())
    {
        crate::signing_service::persist_workload_artifacts(
            &state.db, app.id, deploy_id, artifacts, signed,
        )
        .await
        .map_err(signing_error_response)?;
    }

    // Audit the image signer and, when present, the signed descriptor hash
    // persisted for workload-attested artifact fetches.
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.deploy', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "image": &body.image,
        "deployment_id": deploy_id,
        "signer_subject": verified.signer_subject,
        "signer_issuer": verified.signer_issuer,
        "rekor_log_index": verified.rekor_log_index,
        "descriptor_core_hash": signing_artifacts
            .as_ref()
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
    }))
    .execute(&state.db)
    .await;

    let tee_domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    crate::dns::ensure_dns_pair(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
        &app.domain,
        tee_domain,
    )
    .await
    .map_err(dns_error_response)?;

    if let Some(custom_domain) = app.custom_domain.as_ref() {
        crate::dns::record_custom_domain(&state.db, app.id, custom_domain)
            .await
            .map_err(dns_error_response)?;
    }

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let local_verification_artifacts =
        match (signing_artifacts.as_ref(), signed_policy_artifact.as_ref()) {
            (Some(artifacts), Some(signed)) => Some((
                crate::signing_service::workload_artifacts_json(artifacts, signed)
                    .map_err(signing_error_response)?,
                crate::signing_service::trustee_policy_json(signed)
                    .map_err(signing_error_response)?,
            )),
            _ => None,
        };
    let db = state.db.clone();
    let attestation = state.attestation.clone();
    let kbs_policy = state.kbs_policy.clone();
    let api_url = state.api_url.clone();
    let apply_app = app.clone();
    let apply_permits = state.deployment_apply_permits.clone();
    let (local_workload_artifacts_json, local_trustee_policy_json) =
        local_verification_artifacts.unzip();
    let signed_descriptor = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.clone());
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                let error_message = format!("deployment apply limiter closed: {}", e);
                let _ = crate::deploy::set_deployment_status(
                    &db,
                    deploy_id,
                    "failed",
                    None,
                    Some(&error_message),
                    true,
                )
                .await;
                let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
                tracing::error!(
                    app_id = %apply_app.id,
                    deployment_id = %deploy_id,
                    error = %error_message,
                    "failed to acquire deployment apply permit"
                );
                return;
            }
        };

        if let Err(e) = crate::deploy::apply_deployment_manifests(
            crate::deploy::ApplyDeploymentManifestsRequest {
                pool: db.clone(),
                app: apply_app.clone(),
                deployment_id: deploy_id,
                attestation_config: attestation,
                kbs_policy_config: kbs_policy,
                api_signing_pubkey,
                api_url,
                workload_artifact_binding,
                signed_policy_artifact,
                signed_descriptor,
                local_workload_artifacts_json,
                local_trustee_policy_json,
            },
        )
        .await
        {
            let error_message = e.to_string();
            let _ = crate::deploy::set_deployment_status(
                &db,
                deploy_id,
                "failed",
                None,
                Some(&error_message),
                true,
            )
            .await;
            let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
            tracing::error!(
                app_id = %apply_app.id,
                deployment_id = %deploy_id,
                error = %error_message,
                "failed to apply deployment manifests"
            );
        }
    });

    let deployment: Deployment = sqlx::query_as("SELECT * FROM deployments WHERE id = $1")
        .bind(deploy_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(DeploymentResponse::from_deployment(deployment, &app)),
    ))
}

/// GET /apps/{name}/deployments -- deployment history.
pub async fn deployment_history(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<Vec<DeploymentResponse>>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let deployments: Vec<Deployment> = sqlx::query_as(
        "SELECT * FROM deployments WHERE app_id = $1 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(app.id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok(Json(
        deployments
            .into_iter()
            .map(|d| DeploymentResponse::from_deployment(d, &app))
            .collect(),
    ))
}

mod rollback;
pub use rollback::rollback;
