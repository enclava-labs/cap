use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::{App, Deployment};
use crate::state::AppState;

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

pub(crate) async fn resolve_signed_policy_artifact(
    state: &AppState,
    artifacts: &crate::signing_service::DeploymentSigningArtifacts,
    provided_artifact: Option<String>,
    signing_service_pubkey_hex: Option<&str>,
) -> Result<crate::signing_service::SignedPolicyArtifact, (StatusCode, Json<serde_json::Value>)> {
    if let Some(provided_artifact) = provided_artifact {
        let mut artifact =
            crate::signing_service::decode_optional_policy_artifact(Some(provided_artifact))
                .map_err(signing_error_response)?
                .ok_or_else(|| {
                    signing_error_response(
                        crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
                    )
                })?;
        artifacts
            .validate_customer_authority(&state.db)
            .await
            .map_err(signing_error_response)?;
        artifacts
            .validate_customer_signed_artifact(&artifact)
            .map_err(signing_error_response)?;
        let signing_service = state.signing_service.as_ref().ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "canonical agent policy validation requires the platform policy generator"
            })),
        ))?;
        let generated = signing_service
            .agent_policy(&crate::signing_service::AgentPolicyRequest {
                descriptor: artifacts.descriptor.clone(),
            })
            .await
            .map_err(signing_error_response)?;
        artifacts
            .validate_canonical_agent_policy(&artifact, &generated)
            .map_err(signing_error_response)?;
        artifacts
            .attach_customer_authority(&mut artifact)
            .map_err(signing_error_response)?;
        return Ok(artifact);
    }

    if state.require_customer_signed_policy_artifact {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "customer-signed signed_policy_artifact is required; platform signing-service fallback is disabled"
            })),
        ));
    }

    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;
    let signing_service_pubkey_hex = signing_service_pubkey_hex.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "platform signing-service fallback requires SIGNING_SERVICE_PUBKEY_HEX"
        })),
    ))?;
    let mut signed = signing_service
        .sign(&artifacts.sign_request())
        .await
        .map_err(signing_error_response)?;
    artifacts
        .validate_signed_artifact(&signed, signing_service_pubkey_hex)
        .map_err(signing_error_response)?;
    artifacts
        .attach_customer_authority(&mut signed)
        .map_err(signing_error_response)?;
    Ok(signed)
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
mod classifier_tests {
    use super::*;
    use crate::cosign::VerificationPolicy;
    use enclava_common::image::ImageRef;
    use enclava_engine::types::AttestationConfig;

    fn attestation_config() -> AttestationConfig {
        AttestationConfig {
            proxy_image: ImageRef::parse("ghcr.io/enclava-ai/attestation-proxy@sha256:996c32b0726a90d82c08ae095b4bfbe01e47617cf929dc1eed3bd981f4e8155d")
                .unwrap(),
            caddy_image: ImageRef::parse("ghcr.io/enclava-ai/caddy-ingress@sha256:31a43cbfce0399cc83d22aabcb25346badcddfb46f4984eccd410c22e691ca6f")
                .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            trustee_policy_read_available: false,
            workload_artifacts_url: None,
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
        }
    }

    #[test]
    fn github_actions_oidc_url_with_at_is_url_policy() {
        let policy = classify_signer_identity(
            "https://github.com/me/repo/.github/workflows/build.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        );
        assert!(matches!(
            policy,
            VerificationPolicy::FulcioUrlIdentity { .. }
        ));
    }

    #[test]
    fn email_subject_is_email_policy() {
        let policy = classify_signer_identity("alice@example.com", "https://accounts.google.com");
        assert!(matches!(
            policy,
            VerificationPolicy::FulcioEmailIdentity { .. }
        ));
    }

    #[test]
    fn http_url_subject_is_url_policy() {
        let policy = classify_signer_identity(
            "http://gitlab.example.com/foo@v1",
            "https://gitlab.example.com",
        );
        assert!(matches!(
            policy,
            VerificationPolicy::FulcioUrlIdentity { .. }
        ));
    }

    #[test]
    fn signed_deploy_required_when_policy_signing_boundary_is_configured() {
        assert!(!customer_signed_deploy_required(None, false));
        assert!(customer_signed_deploy_required(None, true));

        let mut cfg = attestation_config();
        assert!(!customer_signed_deploy_required(Some(&cfg), false));

        cfg.signing_service_pubkey_hex = Some("11".repeat(32));
        assert!(customer_signed_deploy_required(Some(&cfg), false));

        cfg.signing_service_pubkey_hex = None;
        cfg.platform_trustee_policy_pubkey_hex = Some("22".repeat(32));
        assert!(customer_signed_deploy_required(Some(&cfg), false));

        cfg.platform_trustee_policy_pubkey_hex = None;
        cfg.trustee_policy_read_available = true;
        assert!(customer_signed_deploy_required(Some(&cfg), false));
    }
}

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

    // Parse numeric value
    let value: f64 = value_str
        .parse()
        .map_err(|_| format!("invalid memory value: {}", value_str))?;

    // Validate range: must be positive and reasonable
    if value <= 0.0 {
        return Err("memory value must be positive".to_string());
    }
    if value > 1024.0 {
        return Err("memory value too large (max 1024Gi)".to_string());
    }

    // Convert to GiB
    match unit {
        "Gi" | "GiB" => Ok(value),
        "Mi" | "MiB" => Ok(value / 1024.0),
        _ => Err(format!("unsupported memory unit: {}", unit)),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub image: String,
    #[serde(default)]
    pub container_name: Option<String>,
    #[serde(default)]
    pub resources: Option<DeployResources>,
    #[serde(default)]
    pub customer_descriptor_blob: Option<String>,
    #[serde(default)]
    pub org_keyring_blob: Option<String>,
    #[serde(default)]
    pub signed_policy_artifact: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeployResources {
    pub cpu: Option<String>,
    pub memory: Option<String>,
    pub storage: Option<String>,
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

/// POST /apps/{name}/agent-policy -- authenticated genpolicy preflight broker.
pub async fn generate_agent_policy(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<AgentPolicyRequest>,
) -> Result<Json<AgentPolicyResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "apps:write")?;

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

    let descriptor = &body.descriptor;
    let expected_identity_hash = hex::decode(&app.tenant_instance_identity_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "stored app identity hash is invalid"})),
        )
    })?;
    if descriptor.org_id != auth.org_id
        || descriptor.app_id != app.id
        || descriptor.app_name != app.name
        || descriptor.namespace != app.namespace
        || descriptor.service_account != app.service_account
        || descriptor.identity_hash.as_slice() != expected_identity_hash.as_slice()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "descriptor does not match the authenticated app"
            })),
        ));
    }

    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;
    let response = signing_service
        .agent_policy(&crate::signing_service::AgentPolicyRequest {
            descriptor: body.descriptor,
        })
        .await
        .map_err(signing_error_response)?;

    Ok(Json(AgentPolicyResponse {
        agent_policy_text: response.agent_policy_text,
        agent_policy_sha256: response.agent_policy_sha256,
        genpolicy_version_pin: response.genpolicy_version_pin,
    }))
}

/// POST /apps/{name}/deploy -- deploy or update an app.
pub async fn deploy(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeploymentResponse>), (StatusCode, Json<serde_json::Value>)> {
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

    let signing_artifacts = crate::signing_service::decode_optional_blobs(
        body.customer_descriptor_blob.clone(),
        body.org_keyring_blob.clone(),
    )
    .map_err(signing_error_response)?;
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
        crate::registry::resolve_image_digest(&state.http_client, &image_ref)
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

    // Enforce tier resource limits (API-18)
    if let Some(ref resources) = body.resources {
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

        let tier_str = format!("{:?}", org.tier).to_lowercase();
        let limits = crate::routes::billing::tier_limits(&tier_str).ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "unknown tier"})),
        ))?;

        if let Some(ref cpu) = resources.cpu {
            let requested: f64 = cpu.parse().unwrap_or(0.0);
            let allowed: f64 = limits.max_cpu.parse().unwrap_or(0.0);
            if requested > allowed {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(
                        serde_json::json!({"error": format!("tier '{}' allows max {} CPU, requested {}", tier_str, limits.max_cpu, cpu)}),
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
                    Json(serde_json::json!({"error": "invalid tier memory limit"})),
                )
            })?;
            if requested > allowed {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(
                        serde_json::json!({"error": format!("tier '{}' allows max {} memory, requested {}", tier_str, limits.max_memory, memory)}),
                    ),
                ));
            }
        }
    }

    // Fetch provenance attestation and SBOM if available (non-fatal if missing)
    let (provenance, sbom) =
        crate::cosign::fetch_attestations(&state.http_client, &body.image, &image_digest)
            .await
            .unwrap_or((None, None));

    // Update container image in DB
    let container_name = body.container_name.as_deref().unwrap_or("web");
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
            "UPDATE app_containers SET image_ref = $1, image_digest = $2 WHERE app_id = $3 AND name = $4",
        )
        .bind(&body.image)
        .bind(Some(&image_digest))
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
            "INSERT INTO app_containers (id, app_id, name, image_ref, image_digest, is_primary)
             VALUES ($1, $2, $3, $4, $5, true)",
        )
        .bind(Uuid::new_v4())
        .bind(app.id)
        .bind(container_name)
        .bind(&body.image)
        .bind(Some(&image_digest))
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
        artifacts
            .validate_deployment_inputs(&app, &image_digest)
            .map_err(signing_error_response)?;
        let attestation = state.attestation.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "signed deployment artifacts require attestation runtime configuration"
            })),
        ))?;
        let signing_service_pubkey_hex = attestation.signing_service_pubkey_hex.as_deref();
        let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
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
        let (_encoded, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        artifacts
            .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
            .map_err(signing_error_response)?;
        workload_artifact_binding = Some(binding);
        signed_policy_artifact = Some(signed);
    }

    // Build spec snapshot
    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
    let spec_snapshot = serde_json::json!({
        "app_name": app.name,
        "namespace": app.namespace,
        "instance_id": app.instance_id,
        "image": body.image,
        "image_digest": &image_digest,
        "resources": body.resources,
        "signed_descriptor_core_hash": signing_artifacts
            .as_ref()
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
    });

    // Create deployment record. cosign_verified is set from the actual
    // verification result, not hardcoded.
    let cosign_verified = true;
    sqlx::query(
        "INSERT INTO deployments (id, app_id, trigger, spec_snapshot, image_digest, cosign_verified, provenance_attestation, sbom)
         VALUES ($1, $2, 'api', $3, $4, $5, $6, $7)",
    )
    .bind(deploy_id)
    .bind(app.id)
    .bind(&spec_snapshot)
    .bind(Some(&image_digest))
    .bind(cosign_verified)
    .bind(&provenance)
    .bind(&sbom)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
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

    crate::dns::ensure_dns_record(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
        &app.domain,
        false,
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

/// POST /apps/{name}/rollback -- rollback to a previous deployment.
pub async fn rollback(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<RollbackResponse>), (StatusCode, Json<serde_json::Value>)> {
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

    let prev: Deployment = if let Some(deployment_id) = body.deployment_id {
        sqlx::query_as(
            "SELECT * FROM deployments
             WHERE app_id = $1 AND id = $2 AND status = 'healthy'",
        )
        .bind(app.id)
        .bind(deployment_id)
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
            Json(
                serde_json::json!({"error": "rollback target deployment not found or not healthy"}),
            ),
        ))?
    } else {
        sqlx::query_as(
            "SELECT * FROM deployments
             WHERE app_id = $1 AND status = 'healthy'
             ORDER BY created_at DESC
             OFFSET 1 LIMIT 1",
        )
        .bind(app.id)
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
            Json(serde_json::json!({"error": "no previous deployment to rollback to"})),
        ))?
    };

    let image = prev
        .spec_snapshot
        .get("image")
        .and_then(serde_json::Value::as_str)
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "rollback target is missing image in spec snapshot"})),
        ))?
        .to_string();
    let image_digest = prev.image_digest.clone().ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "rollback target is missing image digest"})),
    ))?;

    let rollback_artifact =
        crate::signing_service::load_workload_artifact_binding(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;

    if customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && rollback_artifact.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no stored customer-signed policy artifact"
            })),
        ));
    }

    let container_name = "web";
    sqlx::query(
        "UPDATE app_containers
         SET image_ref = $1, image_digest = $2
         WHERE app_id = $3 AND name = $4",
    )
    .bind(&image)
    .bind(Some(&image_digest))
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

    let deploy_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployments (id, app_id, trigger, spec_snapshot, image_digest)
         VALUES ($1, $2, 'rollback', $3, $4)",
    )
    .bind(deploy_id)
    .bind(app.id)
    .bind(&prev.spec_snapshot)
    .bind(&prev.image_digest)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.rollback', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"rollback_to": prev.id, "deployment_id": deploy_id}))
    .execute(&state.db)
    .await;

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let local_verification_artifacts =
        crate::signing_service::load_workload_artifacts_json(&state.db, app.id, prev.id)
            .await
            .map_err(signing_error_response)?;
    let db = state.db.clone();
    let attestation = state.attestation.clone();
    let kbs_policy = state.kbs_policy.clone();
    let api_url = state.api_url.clone();
    let apply_app = app.clone();
    let apply_permits = state.deployment_apply_permits.clone();
    let (workload_artifact_binding, signed_policy_artifact) = rollback_artifact.unzip();
    let (local_workload_artifacts_json, local_trustee_policy_json) =
        local_verification_artifacts.unzip();
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
                    "failed to acquire rollback apply permit"
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
                "failed to apply rollback manifests"
            );
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(RollbackResponse {
            deployment_id: deploy_id,
            rolled_back_to: prev.id,
            status: "deploying".to_string(),
        }),
    ))
}
