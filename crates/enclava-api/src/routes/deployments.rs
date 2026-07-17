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
use crate::deployment_jobs::{
    DEPLOYMENT_SETUP_CLEANUP_PENDING, DEPLOYMENT_SETUP_DNS_PENDING, DEPLOYMENT_SETUP_STATE,
    DeploymentApplyJobPayload,
};
use crate::models::{App, AppContainer, AppResources, Deployment};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppMutation {
    None,
    UpdateGenericMetadata,
    Insert,
}

fn deployment_setup_incomplete(deployment: &Deployment) -> bool {
    matches!(
        deployment
            .spec_snapshot
            .get(DEPLOYMENT_SETUP_STATE)
            .and_then(serde_json::Value::as_str),
        Some(DEPLOYMENT_SETUP_DNS_PENDING | DEPLOYMENT_SETUP_CLEANUP_PENDING)
    )
}

async fn insert_transaction_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    app_id: Uuid,
    user_id: Uuid,
    action: &str,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(org_id)
    .bind(app_id)
    .bind(user_id)
    .bind(action)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

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

    deploy_app_candidate(auth, state, app, body, AppMutation::None).await
}

async fn deploy_app_candidate(
    auth: AuthContext,
    state: AppState,
    app: App,
    body: DeployRequest,
    app_mutation: AppMutation,
) -> Result<(StatusCode, Json<DeploymentResponse>), (StatusCode, Json<serde_json::Value>)> {
    let workload_security_profile =
        validate_workload_security_profile(body.workload_security_profile.as_deref())?;
    let log_encryption = validate_log_encryption_config(body.log_encryption.clone())?;

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

    let mut candidate_containers: Vec<AppContainer> = if app_mutation == AppMutation::Insert {
        Vec::new()
    } else {
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?
    };
    let app_resources: AppResources = if app_mutation == AppMutation::Insert {
        AppResources {
            app_id: app.id,
            cpu_limit: "1".to_string(),
            memory_limit: "1Gi".to_string(),
            app_data_size: "5Gi".to_string(),
            tls_data_size: "2Gi".to_string(),
        }
    } else {
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app.id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?
    };
    let candidate_container = if let Some(container) = candidate_containers
        .iter_mut()
        .find(|row| row.name == container_name)
    {
        container.image_ref = body.image.clone();
        container.image_digest = Some(image_digest.clone());
        if signed_workload_command.is_some() {
            container.command = signed_workload_command.clone();
        }
        if signed_container_port.is_some() {
            container.port = signed_container_port;
        }
        if signed_storage_paths.is_some() {
            container.storage_paths = signed_storage_paths.clone();
        }
        container.workload_security_profile = Some(workload_security_profile.as_str().to_string());
        container.clone()
    } else {
        let container = AppContainer {
            id: Uuid::new_v4(),
            app_id: app.id,
            name: container_name.to_string(),
            image_ref: body.image.clone(),
            image_digest: Some(image_digest.clone()),
            port: signed_container_port,
            command: signed_workload_command.clone(),
            storage_paths: signed_storage_paths.clone(),
            workload_security_profile: Some(workload_security_profile.as_str().to_string()),
            is_primary: true,
        };
        candidate_containers.push(container.clone());
        container
    };

    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
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
        let mut app_spec = crate::deploy::build_confidential_app_from_rows(
            &app,
            deploy_id,
            attestation,
            &api_signing_pubkey,
            &state.api_url,
            &candidate_containers,
            &app_resources,
        )
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
        signed_policy_artifact = Some(signed);
    }

    // Signed inputs and their rendered cc-init hash are now validated against
    // the immutable candidate. Only then perform external image verification.
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

    // Fetch provenance attestation and SBOM if available (non-fatal if missing).
    let (provenance, sbom) =
        crate::cosign::fetch_attestations(&state.http_client, &body.image, &image_digest)
            .await
            .unwrap_or((None, None));

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
        "setup_state": DEPLOYMENT_SETUP_DNS_PENDING,
    });

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let apply_payload = DeploymentApplyJobPayload::new(
        app.clone(),
        crate::deploy::DeploymentApplySnapshot::new(
            candidate_containers.clone(),
            app_resources.clone(),
        ),
        state.attestation.clone(),
        api_signing_pubkey,
        state.api_url.clone(),
        signing_artifacts.as_ref().map(|_| deploy_id),
        signing_artifacts
            .as_ref()
            .map(|artifacts| artifacts.descriptor_core_hash),
        log_encryption,
        app_mutation == AppMutation::Insert,
    );

    // No requested app/container state has been persisted before this point.
    // Commit every accepted deployment row and its app/container changes as a
    // single unit so any database error rolls the candidate back completely.
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    match app_mutation {
        AppMutation::None => {}
        AppMutation::UpdateGenericMetadata => {
            let result = sqlx::query(
                "UPDATE apps
                    SET source_provider = $1,
                        source_repository = $2,
                        signer_identity_subject = $3,
                        signer_identity_issuer = $4,
                        signer_identity_set_at = COALESCE(signer_identity_set_at, now()),
                        egress_allowlist = $5,
                        egress_mode = $6,
                        updated_at = now()
                  WHERE id = $7
                    AND updated_at = $8",
            )
            .bind(app.source_provider.as_deref())
            .bind(app.source_repository.as_deref())
            .bind(app.signer_identity_subject.as_deref())
            .bind(app.signer_identity_issuer.as_deref())
            .bind(&app.egress_allowlist)
            .bind(&app.egress_mode)
            .bind(app.id)
            .bind(app.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
            if result.rows_affected() != 1 {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "app metadata changed while deployment was validating; retry the deployment",
                ));
            }
        }
        AppMutation::Insert => {
            sqlx::query(
                "INSERT INTO apps (
                    id, org_id, name, namespace, instance_id, tenant_id, service_account,
                    bootstrap_owner_pubkey_hash, tenant_instance_identity_hash, unlock_mode,
                    domain, tee_domain, custom_domain, status, signer_identity_subject,
                    signer_identity_issuer, signer_identity_set_at, source_provider,
                    source_repository, egress_allowlist, egress_mode, created_at, updated_at
                 )
                 VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum,
                    $11, $12, $13, $14::app_status_enum, $15, $16, $17, $18,
                    $19, $20, $21, $22, $23
                 )",
            )
            .bind(app.id)
            .bind(app.org_id)
            .bind(&app.name)
            .bind(&app.namespace)
            .bind(&app.instance_id)
            .bind(&app.tenant_id)
            .bind(&app.service_account)
            .bind(&app.bootstrap_owner_pubkey_hash)
            .bind(&app.tenant_instance_identity_hash)
            .bind(app.unlock_mode)
            .bind(&app.domain)
            .bind(app.tee_domain.as_deref())
            .bind(app.custom_domain.as_deref())
            .bind(app.status)
            .bind(app.signer_identity_subject.as_deref())
            .bind(app.signer_identity_issuer.as_deref())
            .bind(app.signer_identity_set_at)
            .bind(app.source_provider.as_deref())
            .bind(app.source_repository.as_deref())
            .bind(&app.egress_allowlist)
            .bind(&app.egress_mode)
            .bind(app.created_at)
            .bind(app.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                if error.to_string().contains("duplicate key")
                    || error.to_string().contains("unique")
                {
                    json_error(StatusCode::CONFLICT, "app name already taken in this org")
                } else {
                    json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
                }
            })?;
            sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
                .bind(app.id)
                .execute(&mut *tx)
                .await
                .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

            insert_transaction_audit(
                &mut tx,
                auth.org_id,
                app.id,
                auth.user_id,
                "app.create",
                serde_json::json!({
                "name": &app.name,
                "unlock_mode": format!("{:?}", app.unlock_mode).to_lowercase(),
                "egress_allowlist": &app.egress_allowlist.0,
                "egress_mode": &app.egress_mode,
                }),
            )
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
        }
    }

    sqlx::query(
        "INSERT INTO app_containers (
            id, app_id, name, image_ref, image_digest, command, port,
            storage_paths, workload_security_profile, is_primary
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (app_id, name) DO UPDATE SET
            image_ref = EXCLUDED.image_ref,
            image_digest = EXCLUDED.image_digest,
            command = EXCLUDED.command,
            port = EXCLUDED.port,
            storage_paths = EXCLUDED.storage_paths,
            workload_security_profile = EXCLUDED.workload_security_profile",
    )
    .bind(candidate_container.id)
    .bind(candidate_container.app_id)
    .bind(&candidate_container.name)
    .bind(&candidate_container.image_ref)
    .bind(candidate_container.image_digest.as_deref())
    .bind(candidate_container.command.as_deref())
    .bind(candidate_container.port)
    .bind(candidate_container.storage_paths.as_ref())
    .bind(candidate_container.workload_security_profile.as_deref())
    .bind(candidate_container.is_primary)
    .execute(&mut *tx)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

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
    .execute(&mut *tx)
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
            &mut *tx, app.id, deploy_id, artifacts, signed,
        )
        .await
        .map_err(signing_error_response)?;
    }

    let setup_job = crate::deployment_jobs::insert_setup_job(&mut tx, deploy_id, &apply_payload)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    // Audit the image signer and, when present, the signed descriptor hash
    // persisted for workload-attested artifact fetches.
    insert_transaction_audit(
        &mut tx,
        auth.org_id,
        app.id,
        auth.user_id,
        "app.deploy",
        serde_json::json!({
            "image": &body.image,
            "deployment_id": deploy_id,
            "signer_subject": verified.signer_subject,
            "signer_issuer": verified.signer_issuer,
            "rekor_log_index": verified.rekor_log_index,
            "descriptor_core_hash": signing_artifacts
                .as_ref()
                .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
        }),
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    tx.commit()
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    match crate::deployment_jobs::process_setup_job(&state, setup_job).await {
        Ok(()) => {}
        Err(crate::deployment_jobs::DeploymentJobError::Dns(error)) => {
            return Err(dns_error_response(error));
        }
        Err(error) => {
            tracing::error!(
                app_id = %app.id,
                deployment_id = %deploy_id,
                error_code = error.code(),
                "durable deployment setup did not complete"
            );
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
            ));
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect deployment regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate deployment regression database");
        pool
    }

    async fn insert_setup_test_app(pool: &sqlx::PgPool) -> App {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("setup-test-{suffix}");
        let app_name = format!("app-{}", &suffix[..12]);
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(org_name)
        .bind(&suffix[..8])
        .execute(pool)
        .await
        .expect("insert setup test organization");
        sqlx::query(
            "INSERT INTO apps (
                id, org_id, name, namespace, instance_id, tenant_id,
                service_account, bootstrap_owner_pubkey_hash,
                tenant_instance_identity_hash, domain, tee_domain
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(&app_name)
        .bind(format!("cap-{app_name}"))
        .bind(format!("instance-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-{app_name}-sa"))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("{app_name}.{}.enclava.dev", &suffix[..8]))
        .bind(format!("{app_name}.{}.tee.enclava.dev", &suffix[..8]))
        .execute(pool)
        .await
        .expect("insert setup test app");
        sqlx::query_as("SELECT * FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load setup test app")
    }

    async fn delete_setup_test_org(pool: &sqlx::PgPool, org_id: Uuid) {
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(pool)
            .await
            .expect("delete setup test organization");
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

    #[tokio::test]
    async fn malformed_rollback_artifact_fails_before_container_or_deployment_commit() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        let target_id = Uuid::new_v4();
        let original_image = format!("ghcr.io/acme/original@sha256:{}", "aa".repeat(32));
        sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("insert rollback test resources");
        sqlx::query(
            "INSERT INTO app_containers (
                id, app_id, name, image_ref, image_digest,
                workload_security_profile, is_primary
             )
             VALUES ($1, $2, 'web', $3, $4, 'restricted', true)",
        )
        .bind(Uuid::new_v4())
        .bind(app.id)
        .bind(&original_image)
        .bind(format!("sha256:{}", "aa".repeat(32)))
        .execute(&pool)
        .await
        .expect("insert rollback test container");
        sqlx::query(
            "INSERT INTO deployments (
                id, org_id, app_id, trigger, status, spec_snapshot, image_digest
             )
             VALUES ($1, $2, $3, 'api', 'healthy', $4, $5)",
        )
        .bind(target_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(serde_json::json!({
            "image": &original_image,
            "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
        }))
        .bind(format!("sha256:{}", "aa".repeat(32)))
        .execute(&pool)
        .await
        .expect("insert healthy rollback target");
        sqlx::query(
            "INSERT INTO workload_artifacts (
                descriptor_core_hash, app_id, deploy_id, descriptor_payload,
                descriptor_signature, descriptor_signing_key_id,
                org_keyring_payload, org_keyring_signature, signed_policy_artifact
             )
             VALUES ($1, $2, $3, '{}'::jsonb, $4, 'malformed', '{}'::jsonb, $5, '{}'::jsonb)",
        )
        .bind(app.id.as_bytes().repeat(2))
        .bind(app.id)
        .bind(target_id)
        .bind(vec![0u8; 64])
        .bind(vec![0u8; 64])
        .execute(&pool)
        .await
        .expect("insert malformed rollback artifact");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.attestation = None;
        state.require_customer_signed_policy_artifact = false;
        let auth = crate::auth::middleware::AuthContext {
            user_id: Uuid::new_v4(),
            org_id: app.org_id,
            org_name: "rollback-test".to_string(),
            role: crate::models::Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let error = rollback(
            auth,
            State(state),
            Path(app.name.clone()),
            Json(RollbackRequest {
                deployment_id: Some(target_id),
            }),
        )
        .await
        .expect_err("malformed rollback artifact rejected");
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);

        let persisted_image: String = sqlx::query_scalar(
            "SELECT image_ref FROM app_containers WHERE app_id = $1 AND name = 'web'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("load unchanged rollback container");
        assert_eq!(persisted_image, original_image);
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count rollback deployments");
        assert_eq!(deployment_count, 1);
        let job_count: i64 = sqlx::query_scalar(
            "SELECT count(*)
               FROM deployment_apply_jobs j
               JOIN deployments d ON d.id = j.deployment_id
              WHERE d.app_id = $1",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count rollback apply jobs");
        assert_eq!(job_count, 0);

        delete_setup_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn audit_insert_failure_aborts_the_candidate_transaction() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        let suffix = app.id.simple().to_string();
        let function_name = format!("cap_test_block_audit_{suffix}");
        let trigger_name = format!("cap_test_block_audit_trigger_{suffix}");
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.app_id = '{}'::uuid THEN
                 RAISE EXCEPTION 'forced audit failure';
               END IF;
               RETURN NEW;
             END
             $$",
            app.id
        ))
        .execute(&pool)
        .await
        .expect("create audit failure function");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE INSERT ON audit_log
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .expect("create audit failure trigger");

        let mut tx = pool.begin().await.expect("begin candidate transaction");
        sqlx::query("UPDATE organizations SET display_name = 'must-roll-back' WHERE id = $1")
            .bind(app.org_id)
            .execute(&mut *tx)
            .await
            .expect("mutate candidate transaction");
        let audit_error = insert_transaction_audit(
            &mut tx,
            app.org_id,
            app.id,
            Uuid::new_v4(),
            "app.deploy",
            serde_json::json!({"deployment_id": Uuid::new_v4()}),
        )
        .await
        .expect_err("audit failure must propagate");
        assert!(audit_error.to_string().contains("forced audit failure"));
        tx.rollback().await.expect("roll back rejected candidate");

        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM organizations WHERE id = $1")
                .bind(app.org_id)
                .fetch_one(&pool)
                .await
                .expect("load rolled-back organization");
        assert_eq!(display_name, None);

        sqlx::query(&format!("DROP TRIGGER {trigger_name} ON audit_log"))
            .execute(&pool)
            .await
            .expect("drop audit failure trigger");
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .expect("drop audit failure function");
        delete_setup_test_org(&pool, app.org_id).await;
    }
}
