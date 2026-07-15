use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use enclava_common::log_encryption::public_key_sha256;
use enclava_engine::types::{LogEncryptionConfig, WorkloadSecurityProfile};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{middleware::AuthContext, scopes};
use crate::models::{App, AppContainer, Deployment};
use crate::source_provider::{SourceProvider, validate_source_context};
use crate::state::AppState;

const PLATFORM_MANAGED_SSH_RELAY_CAPS: &[&str] =
    &["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];
const ROOTFUL_SUDO_CAPS: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETGID",
    "SETUID",
    "AUDIT_WRITE",
];
const LOG_ENCRYPTION_ALGORITHM_X25519_HPKE_V1: &str = "x25519-hpke-v1";

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
    attestation.local_workload_artifacts_json = Some("{}".to_string());
    attestation.local_trustee_policy_json = Some("{}".to_string());
}

pub(crate) async fn resolve_signed_policy_artifact(
    state: &AppState,
    artifacts: &crate::signing_service::DeploymentSigningArtifacts,
    provided_artifact: Option<String>,
    signing_service_pubkey_hex: Option<&str>,
    log_encryption: Option<LogEncryptionConfig>,
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
            log_encryption: log_encryption.clone(),
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
        .sign(&artifacts.sign_request(log_encryption))
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
        .map_err(|_| format!("invalid memory value: {value_str}"))?;

    if value <= 0.0 {
        return Err("memory value must be positive".to_string());
    }

    let gib = match unit {
        "Gi" | "GiB" => Ok(value),
        "Mi" | "MiB" => Ok(value / 1024.0),
        _ => Err(format!("unsupported memory unit: {unit}")),
    }?;
    if gib > 1024.0 {
        return Err("memory value too large (max 1024Gi)".to_string());
    }
    Ok(gib)
}

fn validate_workload_security_profile(
    value: Option<&str>,
) -> Result<WorkloadSecurityProfile, (StatusCode, Json<serde_json::Value>)> {
    value
        .unwrap_or("restricted")
        .parse::<WorkloadSecurityProfile>()
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))
}

fn signed_descriptor_profile(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Option<WorkloadSecurityProfile> {
    let sec = &descriptor.oci_runtime_spec.security_context;
    let caps = &descriptor.oci_runtime_spec.capabilities;
    let drops_all = caps.drop.iter().any(|cap| cap.eq_ignore_ascii_case("ALL"));
    let legacy_unset_security = sec.run_as_user == 0
        && sec.run_as_group == 0
        && !sec.read_only_root_fs
        && !sec.allow_privilege_escalation
        && !sec.privileged
        && caps.add.is_empty()
        && caps.drop.is_empty();
    let restricted = sec.run_as_user == 10001
        && sec.run_as_group == 10001
        && sec.read_only_root_fs
        && !sec.allow_privilege_escalation
        && !sec.privileged
        && drops_all
        && caps.add.is_empty();
    if legacy_unset_security || restricted {
        return Some(WorkloadSecurityProfile::Restricted);
    }

    let relay = sec.run_as_user == 0
        && sec.run_as_group == 0
        && sec.read_only_root_fs
        && !sec.allow_privilege_escalation
        && !sec.privileged
        && drops_all
        && caps.add.len() == PLATFORM_MANAGED_SSH_RELAY_CAPS.len()
        && PLATFORM_MANAGED_SSH_RELAY_CAPS.iter().all(|required| {
            caps.add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        });
    if relay {
        return Some(WorkloadSecurityProfile::PlatformManagedSshRelay);
    }

    let rootful_sudo = sec.run_as_user == 0
        && sec.run_as_group == 0
        && !sec.read_only_root_fs
        && sec.allow_privilege_escalation
        && !sec.privileged
        && drops_all
        && caps.add.len() == ROOTFUL_SUDO_CAPS.len()
        && ROOTFUL_SUDO_CAPS.iter().all(|required| {
            caps.add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        });
    if rootful_sudo {
        Some(WorkloadSecurityProfile::RootfulSudo)
    } else {
        None
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
    #[serde(default)]
    pub workload_security_profile: Option<String>,
    #[serde(default)]
    pub log_encryption: Option<LogEncryptionConfig>,
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
    #[serde(default)]
    pub log_encryption: Option<LogEncryptionConfig>,
}

#[derive(Debug, Serialize)]
pub struct AgentPolicyResponse {
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_encryption: Option<LogEncryptionConfig>,
}

fn validate_log_encryption_config(
    value: Option<LogEncryptionConfig>,
) -> Result<Option<LogEncryptionConfig>, (StatusCode, Json<serde_json::Value>)> {
    let Some(config) = value else {
        return Ok(None);
    };
    if config.algorithm != LOG_ENCRYPTION_ALGORITHM_X25519_HPKE_V1 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "unsupported log_encryption.algorithm",
        ));
    }
    if config.key_id.trim().is_empty()
        || config.key_id.len() > 128
        || !config
            .key_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid log_encryption.key_id",
        ));
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(config.public_key_base64url.as_bytes())
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid log_encryption.public_key"))?;
    if public_key.len() != 32 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid log_encryption.public_key length",
        ));
    }
    let expected_hash = public_key_sha256(&public_key);
    if config.public_key_sha256 != expected_hash {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "log_encryption.public_key_sha256 mismatch",
        ));
    }
    Ok(Some(config))
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
    let workload_security_profile =
        validate_workload_security_profile(body.workload_security_profile.as_deref())?;
    let log_encryption = validate_log_encryption_config(body.log_encryption.clone())?;

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
    if body.signed_policy_artifact.is_some() && signing_artifacts.is_none() {
        return Err(signing_error_response(
            crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
        ));
    }
    if let Some(artifacts) = signing_artifacts.as_ref() {
        let signed_profile = signed_descriptor_profile(&artifacts.descriptor).ok_or_else(|| {
            signing_error_response(crate::signing_service::SigningServiceError::Mismatch(
                "workload_security_profile".into(),
            ))
        })?;
        if signed_profile != workload_security_profile {
            return Err(signing_error_response(
                crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".into(),
                ),
            ));
        }
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
    // Fetch the app's current containers into memory and compute the candidate
    // container state that this deploy *would* persist. We validate the signed
    // artifacts against this candidate before writing it to the database, so a
    // rejected deploy cannot mutate app_containers (image/command/port/storage
    // paths/workload security profile) for the app.
    let existing_containers: Vec<AppContainer> =
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;
    let existing_container = existing_containers
        .iter()
        .find(|c| c.name == container_name)
        .cloned();
    let (candidate_container, is_new_container) = compute_candidate_container(
        &CandidateContainerInputs {
            app_id: app.id,
            container_name,
            image: &body.image,
            image_digest: &image_digest,
            workload_security_profile: workload_security_profile.as_str(),
            signed_workload_command: signed_workload_command.clone(),
            signed_container_port,
            signed_storage_paths: signed_storage_paths.clone(),
        },
        existing_container.as_ref(),
    );
    // Candidate row set for validation: drop the stale same-named container and
    // splice in the candidate, keeping the is_primary DESC ordering used by
    // build_confidential_app_from_containers' primary lookup.
    let candidate_containers = splice_candidate_containers(
        existing_containers,
        candidate_container.clone(),
        container_name,
    );

    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
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
        let mut app_spec = crate::deploy::build_confidential_app_from_containers(
            &state.db,
            &app,
            deploy_id,
            attestation,
            &api_signing_pubkey,
            &state.api_url,
            &candidate_containers,
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
        app_spec.log_encryption = log_encryption.clone();

        let signed = resolve_signed_policy_artifact(
            &state,
            artifacts,
            body.signed_policy_artifact.clone(),
            signing_service_pubkey_hex,
            log_encryption.clone(),
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

    // Persist the validated container state only after signed-artifact
    // validation has passed, so a rejected deploy cannot mutate app_containers.
    if !is_new_container {
        sqlx::query(
            "UPDATE app_containers
             SET image_ref = $1,
                 image_digest = $2,
                 command = $3,
                 port = $4,
                 storage_paths = $5,
                 workload_security_profile = $6
             WHERE app_id = $7 AND name = $8",
        )
        .bind(&candidate_container.image_ref)
        .bind(&candidate_container.image_digest)
        .bind(&candidate_container.command)
        .bind(candidate_container.port)
        .bind(&candidate_container.storage_paths)
        .bind(candidate_container.workload_security_profile.as_deref())
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
            "INSERT INTO app_containers (id, app_id, name, image_ref, image_digest, command, port, storage_paths, workload_security_profile, is_primary)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(candidate_container.id)
        .bind(app.id)
        .bind(&candidate_container.name)
        .bind(&candidate_container.image_ref)
        .bind(&candidate_container.image_digest)
        .bind(&candidate_container.command)
        .bind(candidate_container.port)
        .bind(&candidate_container.storage_paths)
        .bind(candidate_container.workload_security_profile.as_deref())
        .bind(candidate_container.is_primary)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    }

    let source_provider = body.source_provider.map(SourceProvider::as_str);
    let spec_snapshot = serde_json::json!({
        "app_name": app.name,
        "namespace": app.namespace,
        "instance_id": app.instance_id,
        "image": body.image,
        "image_digest": &image_digest,
        "container_name": container_name,
        "resources": body.resources,
        "external_id": &body.external_id,
        "source_provider": source_provider,
        "source_repository": &body.source_repository,
        "signed_descriptor_core_hash": signing_artifacts
            .as_ref()
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
        "workload_security_profile": workload_security_profile.as_str(),
        "log_encryption": &log_encryption,
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
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                let error_message = format!("deployment apply limiter closed: {e}");
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
                log_encryption,
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

/// Build the candidate `app_containers` row a deploy *would* persist, without
/// touching the database.
///
/// Returns `(candidate, is_new)`. When `existing` is `Some` the candidate
/// mirrors the previous `UPDATE ... COALESCE` semantics: signed-descriptor
/// fields override the stored value, and any field the descriptor leaves unset
/// is retained from the existing row. When `existing` is `None` the candidate
/// is a fresh primary container matching the prior `INSERT`.
///
/// Computing this in memory lets the deploy handler run signed-artifact
/// validation against the post-deploy container state *before* persisting it,
/// so a rejected deploy cannot mutate `app_containers`.
fn compute_candidate_container(
    inputs: &CandidateContainerInputs,
    existing: Option<&AppContainer>,
) -> (AppContainer, bool) {
    match existing {
        Some(existing) => {
            let candidate = AppContainer {
                image_ref: inputs.image.to_string(),
                image_digest: Some(inputs.image_digest.to_string()),
                // COALESCE semantics: a signed descriptor overrides, otherwise
                // keep the existing value (mirrors the prior UPDATE query).
                command: inputs
                    .signed_workload_command
                    .clone()
                    .or_else(|| existing.command.clone()),
                port: inputs.signed_container_port.or(existing.port),
                storage_paths: inputs
                    .signed_storage_paths
                    .clone()
                    .or_else(|| existing.storage_paths.clone()),
                workload_security_profile: Some(inputs.workload_security_profile.to_string()),
                ..existing.clone()
            };
            (candidate, false)
        }
        None => {
            let candidate = AppContainer {
                id: Uuid::new_v4(),
                app_id: inputs.app_id,
                name: inputs.container_name.to_string(),
                image_ref: inputs.image.to_string(),
                image_digest: Some(inputs.image_digest.to_string()),
                command: inputs.signed_workload_command.clone(),
                port: inputs.signed_container_port,
                storage_paths: inputs.signed_storage_paths.clone(),
                workload_security_profile: Some(inputs.workload_security_profile.to_string()),
                is_primary: true,
            };
            (candidate, true)
        }
    }
}

/// Deploy-supplied values used to compute a candidate `app_containers` row.
struct CandidateContainerInputs<'a> {
    app_id: Uuid,
    container_name: &'a str,
    image: &'a str,
    image_digest: &'a str,
    workload_security_profile: &'a str,
    signed_workload_command: Option<String>,
    signed_container_port: Option<i32>,
    signed_storage_paths: Option<Vec<String>>,
}

/// Replace the same-named container in `existing` with `candidate` and return
/// the resulting row set ordered by `is_primary` descending, matching the
/// ordering `build_confidential_app_from_containers` relies on for its primary
/// lookup.
fn splice_candidate_containers(
    mut existing: Vec<AppContainer>,
    candidate: AppContainer,
    container_name: &str,
) -> Vec<AppContainer> {
    existing.retain(|c| c.name != container_name);
    existing.insert(0, candidate);
    existing.sort_by_key(|c| std::cmp::Reverse(c.is_primary));
    existing
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateContainerInputs, LOG_ENCRYPTION_ALGORITHM_X25519_HPKE_V1, LogEncryptionConfig,
        StatusCode, compute_candidate_container, parse_memory_gi, splice_candidate_containers,
        validate_log_encryption_config,
    };
    use crate::models::AppContainer;
    use uuid::Uuid;

    fn existing_primary_container() -> AppContainer {
        AppContainer {
            id: Uuid::nil(),
            app_id: Uuid::nil(),
            name: "web".to_string(),
            image_ref: "registry/old:tag".to_string(),
            image_digest: None,
            port: Some(8080),
            command: Some(r#"["/old-start"]"#.to_string()),
            storage_paths: Some(vec!["/old-data".to_string()]),
            workload_security_profile: Some("baseline".to_string()),
            is_primary: true,
        }
    }

    /// Build candidate inputs for a deploy of the given container name.
    fn candidate_inputs(name: &str) -> CandidateContainerInputs<'_> {
        CandidateContainerInputs {
            app_id: Uuid::nil(),
            container_name: name,
            image: "registry/new:tag",
            image_digest: "sha256:deadbeef",
            workload_security_profile: "baseline",
            signed_workload_command: None,
            signed_container_port: None,
            signed_storage_paths: None,
        }
    }

    fn valid_log_encryption_config() -> LogEncryptionConfig {
        LogEncryptionConfig {
            algorithm: LOG_ENCRYPTION_ALGORITHM_X25519_HPKE_V1.to_string(),
            key_id: "logs-prod".to_string(),
            public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
        }
    }

    #[test]
    fn parse_memory_gi_validates_after_unit_conversion() {
        assert_eq!(parse_memory_gi("8Gi").expect("8Gi"), 8.0);
        assert_eq!(parse_memory_gi("8192Mi").expect("8192Mi"), 8.0);
        assert_eq!(parse_memory_gi("1048576Mi").expect("1024Gi in Mi"), 1024.0);
        assert!(parse_memory_gi("1048577Mi").is_err());
    }

    #[test]
    fn log_encryption_config_accepts_public_x25519_key_metadata() {
        let config = valid_log_encryption_config();
        let validated = validate_log_encryption_config(Some(config.clone()))
            .expect("valid log encryption config")
            .expect("config returned");
        assert_eq!(validated, config);
    }

    #[test]
    fn log_encryption_config_rejects_hash_mismatch() {
        let mut config = valid_log_encryption_config();
        config.public_key_sha256 = "00".repeat(32);
        let (status, body) =
            validate_log_encryption_config(Some(config)).expect_err("hash mismatch rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "log_encryption.public_key_sha256 mismatch");
    }

    #[test]
    fn log_encryption_config_rejects_unknown_algorithm() {
        let mut config = valid_log_encryption_config();
        config.algorithm = "plaintext".to_string();
        let (status, body) =
            validate_log_encryption_config(Some(config)).expect_err("algorithm rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["error"], "unsupported log_encryption.algorithm");
    }

    #[test]
    fn candidate_container_marks_new_rows_and_sets_primary() {
        let inputs = candidate_inputs("web");
        let (candidate, is_new) = compute_candidate_container(&inputs, None);
        assert!(is_new);
        assert!(candidate.is_primary);
        assert_eq!(candidate.image_ref, "registry/new:tag");
        assert_eq!(candidate.image_digest.as_deref(), Some("sha256:deadbeef"));
        assert_eq!(
            candidate.workload_security_profile.as_deref(),
            Some("baseline")
        );
        // No signed descriptor and no existing row: remaining optional fields are unset.
        assert!(candidate.command.is_none());
        assert!(candidate.port.is_none());
        assert!(candidate.storage_paths.is_none());
    }

    #[test]
    fn candidate_container_for_existing_row_is_not_new_and_keeps_identity() {
        let existing = existing_primary_container();
        let mut inputs = candidate_inputs(&existing.name);
        inputs.workload_security_profile = "restricted";
        let (candidate, is_new) = compute_candidate_container(&inputs, Some(&existing));
        // Updating an existing row is not a new insert.
        assert!(!is_new);
        // Identity fields are carried over from the existing row.
        assert_eq!(candidate.id, existing.id);
        assert_eq!(candidate.app_id, existing.app_id);
        assert_eq!(candidate.name, existing.name);
        assert_eq!(candidate.is_primary, existing.is_primary);
        // The deploy always supplies the image + digest and the security profile.
        assert_eq!(candidate.image_ref, "registry/new:tag");
        assert_eq!(candidate.image_digest.as_deref(), Some("sha256:deadbeef"));
        assert_eq!(
            candidate.workload_security_profile.as_deref(),
            Some("restricted")
        );
    }

    #[test]
    fn candidate_container_coalesces_signed_descriptor_over_existing_values() {
        let existing = existing_primary_container();
        let mut inputs = candidate_inputs(&existing.name);
        inputs.workload_security_profile = "restricted";
        inputs.signed_workload_command = Some(r#"["/new-start","--flag"]"#.to_string());
        inputs.signed_container_port = Some(9000);
        inputs.signed_storage_paths = Some(vec!["/new-data".to_string()]);
        let (candidate, _) = compute_candidate_container(&inputs, Some(&existing));
        // A signed descriptor overrides every field it sets.
        assert_eq!(
            candidate.command.as_deref(),
            Some(r#"["/new-start","--flag"]"#)
        );
        assert_eq!(candidate.port, Some(9000));
        assert_eq!(
            candidate.storage_paths.as_deref(),
            Some(&["/new-data".to_string()][..])
        );
    }

    #[test]
    fn candidate_container_retains_existing_values_without_signed_descriptor() {
        // Regression guard for the bug: a deploy that carries no signed
        // descriptor must compute a candidate whose command/port/storage paths
        // fall back to the existing stored values (COALESCE semantics). Because
        // validation now runs against this candidate *before* the write, a
        // rejected deploy leaves app_containers untouched.
        let existing = existing_primary_container();
        let inputs = candidate_inputs(&existing.name);
        let (candidate, _) = compute_candidate_container(&inputs, Some(&existing));
        assert_eq!(candidate.command, existing.command);
        assert_eq!(candidate.port, existing.port);
        assert_eq!(candidate.storage_paths, existing.storage_paths);
    }

    #[test]
    fn splice_candidate_replaces_same_named_container_and_orders_primary_first() {
        let mut sidecar = existing_primary_container();
        sidecar.name = "worker".to_string();
        sidecar.is_primary = false;
        let existing = vec![sidecar.clone(), existing_primary_container()];

        let inputs = candidate_inputs("web");
        let (candidate, _) =
            compute_candidate_container(&inputs, existing.iter().find(|c| c.name == "web"));
        let spliced = splice_candidate_containers(existing, candidate, "web");

        // Both containers present, no duplication of the deployed name.
        assert_eq!(spliced.len(), 2);
        assert_eq!(spliced.iter().filter(|c| c.name == "web").count(), 1);
        assert_eq!(spliced.iter().filter(|c| c.name == "worker").count(), 1);
        // The replaced primary container is the new candidate (new image).
        let deployed = spliced.iter().find(|c| c.name == "web").unwrap();
        assert_eq!(deployed.image_ref, "registry/new:tag");
        // is_primary DESC ordering: primary container sorts first.
        assert!(spliced[0].is_primary);
        assert!(!spliced[1].is_primary);
    }

    #[test]
    fn splice_candidate_appends_new_container_preserving_ordering() {
        // Deploying a brand-new container name keeps any existing rows. A new
        // container is always marked primary (matching the original INSERT),
        // so the sort orders both primary rows ahead of any non-primary row.
        let existing = vec![existing_primary_container()];
        let inputs = candidate_inputs("worker");
        let (candidate, _) = compute_candidate_container(&inputs, None);
        assert!(candidate.is_primary);
        let spliced = splice_candidate_containers(existing, candidate, "worker");

        assert_eq!(spliced.len(), 2);
        // Both containers are primary; the candidate is spliced in first.
        assert!(spliced.iter().all(|c| c.is_primary));
        assert!(spliced.iter().any(|c| c.name == "web"));
        assert!(spliced.iter().any(|c| c.name == "worker"));
    }

    #[test]
    fn splice_candidate_orders_non_primary_after_primary() {
        // A non-primary candidate (e.g. an existing sidecar being re-deployed)
        // sorts after any primary container.
        let mut sidecar = existing_primary_container();
        sidecar.id = Uuid::new_v4();
        sidecar.name = "worker".to_string();
        sidecar.is_primary = false;
        let existing = vec![existing_primary_container(), sidecar.clone()];

        let inputs = candidate_inputs("worker");
        let mut candidate =
            compute_candidate_container(&inputs, existing.iter().find(|c| c.name == "worker")).0;
        candidate.is_primary = false;
        let spliced = splice_candidate_containers(existing, candidate, "worker");

        assert_eq!(spliced.len(), 2);
        // Primary container sorts first.
        assert!(spliced[0].is_primary);
        assert_eq!(spliced[0].name, "web");
        // Non-primary candidate sorts after.
        assert!(!spliced[1].is_primary);
        assert_eq!(spliced[1].name, "worker");
    }
}
