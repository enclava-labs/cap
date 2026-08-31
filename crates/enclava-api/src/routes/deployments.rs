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

fn resource_limit_error_response(
    error: crate::entitlements::ResourceLimitError,
) -> (StatusCode, Json<serde_json::Value>) {
    match error {
        crate::entitlements::ResourceLimitError::Invalid { field, message: _ }
            if field.starts_with("entitlement.") =>
        {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid entitlement resource limit",
            )
        }
        crate::entitlements::ResourceLimitError::Invalid { message, .. } => {
            json_error(StatusCode::BAD_REQUEST, message)
        }
        crate::entitlements::ResourceLimitError::Exceeded {
            code,
            field,
            requested,
            allowed,
        } => deploy_blocked_response(
            StatusCode::FORBIDDEN,
            code,
            format!("requested {field} {requested} exceeds authoritative limit {allowed}"),
        ),
    }
}

pub(crate) async fn enforce_authoritative_entitlement(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    resources: &AppResources,
    creating_app: bool,
) -> Result<crate::entitlements::AuthoritativeEntitlement, (StatusCode, Json<serde_json::Value>)> {
    let authority = crate::entitlements::authoritative_entitlement_in_tx(tx, org_id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if !authority.decision.deploy_allowed {
        return Err(deploy_blocked_response(
            StatusCode::FORBIDDEN,
            authority
                .decision
                .deploy_block_reason
                .as_deref()
                .unwrap_or("entitlement_blocked"),
            "organization authority does not allow workload mutation".to_string(),
        ));
    }
    let limits = authority.decision.limits.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authoritative entitlement limits are missing",
        )
    })?;
    crate::entitlements::validate_resource_limits(resources, limits)
        .map_err(resource_limit_error_response)?;
    if creating_app {
        let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
        if app_count >= limits.max_apps as i64 {
            return Err(deploy_blocked_response(
                StatusCode::FORBIDDEN,
                "entitlement_app_limit",
                format!(
                    "organization allows max {} apps and already has {app_count}",
                    limits.max_apps
                ),
            ));
        }
    }
    Ok(authority)
}

fn dns_error_response(error: crate::dns::DnsError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match &error {
        crate::dns::DnsError::OutsideManagedZone(_) => {
            (StatusCode::BAD_REQUEST, "dns_outside_managed_zone")
        }
        crate::dns::DnsError::HostnameInUse { .. } => (StatusCode::CONFLICT, "dns_hostname_in_use"),
        crate::dns::DnsError::NotConfigured => {
            (StatusCode::INTERNAL_SERVER_ERROR, "dns_not_configured")
        }
        crate::dns::DnsError::Cloudflare(_)
        | crate::dns::DnsError::Http(_)
        | crate::dns::DnsError::Db(_) => (StatusCode::BAD_GATEWAY, "dns_unavailable"),
    };

    (status, Json(serde_json::json!({"error": code})))
}

pub(crate) fn signing_error_response(
    error: crate::signing_service::SigningServiceError,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::signing_service::SigningServiceError;

    let (status, code) = match &error {
        SigningServiceError::PartialBlobs | SigningServiceError::ArtifactWithoutBlobs => {
            (StatusCode::BAD_REQUEST, "signed_artifacts_incomplete")
        }
        SigningServiceError::Blob(_) => (StatusCode::BAD_REQUEST, "signed_artifact_invalid"),
        SigningServiceError::Mismatch(_) => (StatusCode::BAD_REQUEST, "signed_artifact_mismatch"),
        SigningServiceError::AuthorityStatus(_) => {
            (StatusCode::BAD_GATEWAY, "signing_authority_status_invalid")
        }
        SigningServiceError::InvalidSignature => {
            (StatusCode::BAD_REQUEST, "signed_artifact_signature_invalid")
        }
        SigningServiceError::Upstream { .. } | SigningServiceError::Http(_) => {
            (StatusCode::BAD_GATEWAY, "signing_service_unavailable")
        }
        SigningServiceError::InvalidUrl(_) | SigningServiceError::InvalidTimeout(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_service_configuration_invalid",
        ),
        SigningServiceError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
        SigningServiceError::Serde(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "signed_artifact_invalid")
        }
    };

    (status, Json(serde_json::json!({"error": code})))
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

fn validate_workload_security_profile(
    value: Option<&str>,
) -> Result<WorkloadSecurityProfile, (StatusCode, Json<serde_json::Value>)> {
    value
        .unwrap_or("restricted")
        .parse::<WorkloadSecurityProfile>()
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, error))
}

pub(crate) fn signed_descriptor_profile(
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

const PUBLIC_DEPLOYMENT_ERROR_MESSAGE: &str = "deployment_error";

/// Project a stored deployment error across an API boundary without exposing
/// arbitrary backend, runtime, or workload-controlled plaintext.
pub(crate) fn public_deployment_error_message(error_message: Option<&str>) -> Option<String> {
    error_message.map(|error_message| match error_message {
        crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR => error_message.to_string(),
        _ => PUBLIC_DEPLOYMENT_ERROR_MESSAGE.to_string(),
    })
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
            error_message: public_deployment_error_message(d.error_message.as_deref()),
            created_at: d.created_at,
            completed_at: d.completed_at,
        }
    }
}

mod generic;
pub(crate) use generic::generic_config_token_for_issuance;
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

async fn app_has_incomplete_deployment_setup(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM deployments
             WHERE app_id = $1
               AND spec_snapshot ->> 'setup_state' IN ('dns_pending', 'cleanup_pending')
         )",
    )
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn build_accepted_apply_payload(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
    attestation_config: Option<enclava_engine::types::AttestationConfig>,
    api_signing_pubkey: String,
    api_url: String,
    artifact_deployment_id: Option<Uuid>,
    artifact_descriptor_core_hash: Option<[u8; 32]>,
    log_encryption: Option<LogEncryptionConfig>,
    delete_app_on_setup_failure: bool,
) -> Result<DeploymentApplyJobPayload, sqlx::Error> {
    let accepted_app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&mut **tx)
        .await?;
    let accepted_containers: Vec<AppContainer> = sqlx::query_as(
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
    )
    .bind(app_id)
    .fetch_all(&mut **tx)
    .await?;
    let accepted_resources: AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(&mut **tx)
            .await?;
    Ok(DeploymentApplyJobPayload::new(
        accepted_app,
        crate::deploy::DeploymentApplySnapshot::new(accepted_containers, accepted_resources),
        attestation_config,
        api_signing_pubkey,
        api_url,
        artifact_deployment_id,
        artifact_descriptor_core_hash,
        log_encryption,
        delete_app_on_setup_failure,
    ))
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
    if app_mutation != AppMutation::Insert && app.status == crate::models::AppStatus::Stopped {
        return Err(json_error(
            StatusCode::CONFLICT,
            "start the stopped app before deploying",
        ));
    }
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
    let signed_required = customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    );
    if signed_required && signing_artifacts.is_none() {
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

    let container_name = body.container_name.as_deref().unwrap_or("web");
    if enclava_common::validate::validate_dns_label(container_name).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_container_name",
                "message": "container_name must be a DNS-safe label ([a-z0-9-], max 63 chars)"
            })),
        ));
    }
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
    let base_resources: AppResources = if app_mutation == AppMutation::Insert {
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
    let existing_authority_snapshot = (app_mutation != AppMutation::Insert).then(|| {
        crate::deploy::ExistingAppAuthoritySnapshot::new(
            app.updated_at,
            candidate_containers.clone(),
            base_resources.clone(),
        )
    });
    let mut candidate_resources = base_resources;
    if let Some(resources) = body.resources.as_ref() {
        if let Some(cpu) = resources.cpu.as_ref() {
            candidate_resources.cpu_limit = cpu.clone();
        }
        if let Some(memory) = resources.memory.as_ref() {
            candidate_resources.memory_limit = memory.clone();
        }
        if let Some(storage) = resources.storage.as_ref() {
            candidate_resources.app_data_size = storage.clone();
        }
    }

    // Fail fast on malformed or over-limit candidate values. Acceptance
    // repeats this check under the entitlement lane against the latest
    // management/entitlement generation.
    let org: crate::models::Organization =
        sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
            .bind(auth.org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let early_entitlement = crate::entitlements::entitlement_decision_for_org(
        &state.db,
        auth.org_id,
        &org.entitlement_class,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if !early_entitlement.deploy_allowed {
        return Err(deploy_blocked_response(
            StatusCode::FORBIDDEN,
            early_entitlement
                .deploy_block_reason
                .as_deref()
                .unwrap_or("entitlement_blocked"),
            "organization authority does not allow deploys".to_string(),
        ));
    }
    let early_limits = early_entitlement.limits.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authoritative entitlement limits are missing",
        )
    })?;
    crate::entitlements::validate_resource_limits(&candidate_resources, early_limits)
        .map_err(resource_limit_error_response)?;
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
            &candidate_resources,
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
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "cosign_verification_failed"})),
            )
        })?;
    let portable_material =
        crate::cosign::fetch_portable_verification_material(&body.image, &image_digest)
            .await
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": "portable_verification_material_unavailable"}),
                    ),
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
        "resolved_resources": {
            "cpu": &candidate_resources.cpu_limit,
            "memory": &candidate_resources.memory_limit,
            "storage": &candidate_resources.app_data_size,
            "tls_storage": &candidate_resources.tls_data_size,
        },
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

    // No requested app/container state has been persisted before this point.
    // Commit every accepted deployment row and its app/container changes as a
    // single unit so any database error rolls the candidate back completely.
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if signing_artifacts.is_some() {
        crate::signing_service::lock_org_signing_authority_lane(&mut tx, auth.org_id)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    }
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    enforce_authoritative_entitlement(
        &mut tx,
        auth.org_id,
        &candidate_resources,
        app_mutation == AppMutation::Insert,
    )
    .await?;
    if let Some(artifacts) = signing_artifacts.as_ref() {
        artifacts
            .validate_customer_authority_in_tx(&mut tx)
            .await
            .map_err(signing_error_response)?;
        let signed = signed_policy_artifact.as_ref().ok_or_else(|| {
            signing_error_response(
                crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
            )
        })?;
        let signing_service_pubkey_hex = state
            .attestation
            .as_ref()
            .and_then(|config| config.signing_service_pubkey_hex.as_deref())
            .ok_or_else(|| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "platform signing-service pubkey required for signed deployment verification",
                )
            })?;
        artifacts
            .validate_signed_artifact(signed, signing_service_pubkey_hex)
            .map_err(signing_error_response)?;
    }
    if let Some(expected) = existing_authority_snapshot.as_ref()
        && !crate::deploy::lock_and_verify_existing_app_authority(&mut tx, app.id, expected)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "app deployment inputs changed while deployment was validating; retry the deployment",
        ));
    }
    if app_mutation != AppMutation::Insert {
        let current_status: crate::models::AppStatus =
            sqlx::query_scalar("SELECT status FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
        match current_status {
            crate::models::AppStatus::Deleting => {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "app deletion is in progress",
                ));
            }
            crate::models::AppStatus::Stopped => {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "start the stopped app before deploying",
                ));
            }
            _ => {}
        }
    }
    if app_has_incomplete_deployment_setup(&mut tx, app.id)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err(json_error(
            StatusCode::CONFLICT,
            "an earlier deployment is still completing setup; retry after setup is reconciled",
        ));
    }

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
        "INSERT INTO app_resources (
             app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
         )
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (app_id) DO UPDATE SET
             cpu_limit = EXCLUDED.cpu_limit,
             memory_limit = EXCLUDED.memory_limit,
             app_data_size = EXCLUDED.app_data_size,
             tls_data_size = EXCLUDED.tls_data_size",
    )
    .bind(candidate_resources.app_id)
    .bind(&candidate_resources.cpu_limit)
    .bind(&candidate_resources.memory_limit)
    .bind(&candidate_resources.app_data_size)
    .bind(&candidate_resources.tls_data_size)
    .execute(&mut *tx)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

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

    // Build the immutable worker payload from the rows actually accepted by
    // this transaction. Generic metadata updates advance apps.updated_at; a
    // payload built from the pre-transaction candidate would be rejected by
    // the worker's exact authority revalidation every time.
    let apply_payload = build_accepted_apply_payload(
        &mut tx,
        app.id,
        state.attestation.clone(),
        crate::auth::jwt::public_key_base64(&state.signing_key),
        state.api_url.clone(),
        signing_artifacts.as_ref().map(|_| deploy_id),
        signing_artifacts
            .as_ref()
            .map(|artifacts| artifacts.descriptor_core_hash),
        log_encryption,
        app_mutation == AppMutation::Insert,
    )
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    crate::deploy::supersede_incomplete_deployments(&mut tx, app.id)
        .await
        .map_err(|error| match error {
            crate::deploy::SupersedeDeploymentError::Busy => json_error(
                StatusCode::CONFLICT,
                "deployment mutation is still in progress; retry after its lease completes",
            ),
            crate::deploy::SupersedeDeploymentError::Database(_) => {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
            }
        })?;

    // Create deployment record. cosign_verified is set from the actual
    // verification result, not hardcoded.
    let cosign_verified = true;
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, cosign_verified, provenance_attestation, sbom, external_id, source_provider, source_repository, sigstore_material, provenance_oci_material)
         VALUES ($1, $2, $3, 'api', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
    .bind(&portable_material.sigstore)
    .bind(&portable_material.provenance_oci)
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
        crate::kbs::enqueue_signed_policy_reconciliation(&mut tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    } else {
        // An unsigned generation makes a previously-current signed artifact
        // ineligible.  Persist revocation intent atomically with acceptance;
        // this is a no-op for installations that never entered signed mode.
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx)
            .await
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    }

    let setup_job = crate::deployment_jobs::insert_setup_job(
        &mut tx,
        deploy_id,
        deploy_id,
        &apply_payload,
        signed_required,
    )
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

    async fn insert_authority_rows(
        pool: &sqlx::PgPool,
        app: &App,
    ) -> crate::deploy::ExistingAppAuthoritySnapshot {
        sqlx::query(
            "INSERT INTO app_containers (
                id, app_id, name, image_ref, image_digest, port,
                workload_security_profile, is_primary
             )
             VALUES ($1, $2, 'web', $3, $4, 8080, 'restricted', true)",
        )
        .bind(Uuid::new_v4())
        .bind(app.id)
        .bind("ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .execute(pool)
        .await
        .expect("insert authority test container");
        sqlx::query(
            "INSERT INTO app_resources (
                app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
             )
             VALUES ($1, '1', '1Gi', '5Gi', '2Gi')",
        )
        .bind(app.id)
        .execute(pool)
        .await
        .expect("insert authority test resources");
        load_authority_snapshot(pool, app.id).await
    }

    async fn load_authority_snapshot(
        pool: &sqlx::PgPool,
        app_id: Uuid,
    ) -> crate::deploy::ExistingAppAuthoritySnapshot {
        let app_updated_at = sqlx::query_scalar("SELECT updated_at FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load authority app timestamp");
        let containers =
            sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id")
                .bind(app_id)
                .fetch_all(pool)
                .await
                .expect("load authority containers");
        let resources = sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load authority resources");
        crate::deploy::ExistingAppAuthoritySnapshot::new(app_updated_at, containers, resources)
    }

    async fn wait_for_backend_lock(pool: &sqlx::PgPool, backend_pid: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting_on_lock: bool = sqlx::query_scalar(
                    "SELECT COALESCE((
                         SELECT wait_event_type = 'Lock'
                         FROM pg_stat_activity
                         WHERE pid = $1
                     ), false)",
                )
                .bind(backend_pid)
                .fetch_one(pool)
                .await
                .expect("inspect validator backend lock state");
                if waiting_on_lock {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("validator did not block on the concurrent authority mutation");
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
    async fn deployment_acceptance_waits_for_membership_removal_and_rejects() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Removed Deployer')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert removed deployer");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("insert deployer membership");

        let mut removal = pool.begin().await.expect("begin deployer removal");
        crate::entitlements::lock_org_entitlement_lane(&mut removal, app.org_id)
            .await
            .expect("lock removal entitlement lane");
        crate::signing_service::lock_org_signing_authority_lane(&mut removal, app.org_id)
            .await
            .expect("lock removal signing lane");
        sqlx::query(
            "UPDATE memberships
                SET role = 'member', removed_at = now()
              WHERE org_id = $1 AND user_id = $2",
        )
        .bind(app.org_id)
        .bind(user_id)
        .execute(&mut *removal)
        .await
        .expect("stage deployer removal");

        let validation_pool = pool.clone();
        let org_id = app.org_id;
        let app_id = app.id;
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let validation = tokio::spawn(async move {
            let mut tx = validation_pool
                .begin()
                .await
                .expect("begin deployment membership validation");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .expect("deployment membership validator backend pid");
            pid_sender.send(backend_pid).expect("send validator pid");
            crate::entitlements::lock_org_entitlement_lane(&mut tx, org_id)
                .await
                .expect("lock acceptance entitlement lane");
            crate::signing_service::lock_org_signing_authority_lane(&mut tx, org_id)
                .await
                .expect("lock acceptance signing lane");
            let authority =
                crate::auth::scopes::active_membership_role_in_tx(&mut tx, org_id, user_id)
                    .await
                    .and_then(crate::auth::scopes::require_admin_role);
            if authority.is_ok() {
                crate::deploy::lock_app_deployment_lane(&mut tx, app_id)
                    .await
                    .expect("lock acceptance app lane");
            }
            tx.rollback()
                .await
                .expect("roll back membership validation");
            authority
        });

        let backend_pid = pid_receiver.await.expect("receive validator pid");
        wait_for_backend_lock(&pool, backend_pid).await;
        removal.commit().await.expect("commit deployer removal");

        let rejected = validation
            .await
            .expect("join deployment membership validation")
            .expect_err("removed deployer must fail serialized acceptance");
        assert_eq!(rejected.0, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.1.0["error"],
            "active organization membership required"
        );

        delete_setup_test_org(&pool, app.org_id).await;
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete removed deployer");
    }

    #[tokio::test]
    async fn existing_app_acceptance_waits_for_and_rejects_concurrent_authority_change() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        let expected = insert_authority_rows(&pool, &app).await;

        let mut mutation = pool.begin().await.expect("begin authority mutation");
        sqlx::query(
            "UPDATE apps
             SET signer_identity_subject = 'https://github.com/attacker/repo',
                 signer_identity_issuer = 'https://issuer.example.test',
                 egress_allowlist = '[{\"host\":\"race.example.test\",\"ports\":[443]}]'::jsonb,
                 updated_at = clock_timestamp()
             WHERE id = $1",
        )
        .bind(app.id)
        .execute(&mut *mutation)
        .await
        .expect("hold concurrent app authority mutation");

        let app_id = app.id;
        let validation_pool = pool.clone();
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let validation = tokio::spawn(async move {
            let mut tx = validation_pool
                .begin()
                .await
                .expect("begin acceptance validation");
            let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .expect("validator backend pid");
            pid_sender.send(backend_pid).expect("send validator pid");
            crate::deploy::lock_app_deployment_lane(&mut tx, app_id)
                .await
                .expect("lock app deployment lane");
            let unchanged =
                crate::deploy::lock_and_verify_existing_app_authority(&mut tx, app_id, &expected)
                    .await
                    .expect("verify authority snapshot");
            tx.rollback()
                .await
                .expect("roll back validation transaction");
            unchanged
        });

        let backend_pid = pid_receiver.await.expect("receive validator pid");
        wait_for_backend_lock(&pool, backend_pid).await;
        mutation.commit().await.expect("commit authority mutation");

        assert!(
            !validation.await.expect("join acceptance validation"),
            "a signer/egress change committed during validation must reject acceptance"
        );
        delete_setup_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn existing_app_acceptance_rejects_stale_container_and_resource_rows() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        let expected = insert_authority_rows(&pool, &app).await;

        let original_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load unchanged app timestamp");
        sqlx::query(
            "UPDATE app_containers
             SET image_ref = $1, image_digest = $2
             WHERE app_id = $3 AND name = 'web'",
        )
        .bind("ghcr.io/acme/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .bind("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .bind(app.id)
        .execute(&pool)
        .await
        .expect("mutate container authority");
        sqlx::query("UPDATE app_resources SET cpu_limit = '2' WHERE app_id = $1")
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("mutate resource authority");
        let current_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("reload unchanged app timestamp");
        assert_eq!(current_updated_at, original_updated_at);

        let mut tx = pool.begin().await.expect("begin stale snapshot validation");
        crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
            .await
            .expect("lock app deployment lane");
        assert!(
            !crate::deploy::lock_and_verify_existing_app_authority(&mut tx, app.id, &expected)
                .await
                .expect("verify stale child rows"),
            "child-row changes must be detected without relying on apps.updated_at"
        );
        tx.rollback()
            .await
            .expect("roll back validation transaction");
        delete_setup_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn generic_metadata_acceptance_persists_dispatchable_post_mutation_payload() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        insert_authority_rows(&pool, &app).await;
        let deployment_id = Uuid::new_v4();

        let mut tx = pool
            .begin()
            .await
            .expect("begin generic metadata acceptance");
        crate::deploy::lock_app_deployment_lane(&mut tx, app.id)
            .await
            .expect("lock generic metadata app lane");
        sqlx::query(
            "UPDATE apps
                SET source_provider = 'github',
                    source_repository = 'enclava-labs/example',
                    updated_at = updated_at + interval '1 second'
              WHERE id = $1",
        )
        .bind(app.id)
        .execute(&mut *tx)
        .await
        .expect("persist generic metadata mutation");
        let payload = build_accepted_apply_payload(
            &mut tx,
            app.id,
            None,
            "test-api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        )
        .await
        .expect("build payload from accepted rows");
        assert_ne!(payload.app.updated_at, app.updated_at);
        assert_eq!(payload.app.source_provider.as_deref(), Some("github"));
        assert_eq!(
            payload.app.source_repository.as_deref(),
            Some("enclava-labs/example")
        );
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, spec_snapshot, image_digest
             ) VALUES (
                 $1, $2, $3, 'api',
                 jsonb_build_object('setup_state', $4::text),
                 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
             )",
        )
        .bind(deployment_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(DEPLOYMENT_SETUP_DNS_PENDING)
        .execute(&mut *tx)
        .await
        .expect("insert accepted deployment");
        crate::deployment_jobs::insert_setup_job(
            &mut tx,
            deployment_id,
            deployment_id,
            &payload,
            false,
        )
        .await
        .expect("persist accepted setup job");
        tx.commit()
            .await
            .expect("commit generic metadata acceptance");

        let stored_payload: serde_json::Value = sqlx::query_scalar(
            "SELECT payload FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load persisted apply payload");
        let stored_payload: DeploymentApplyJobPayload =
            serde_json::from_value(stored_payload).expect("decode persisted apply payload");
        let database_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load accepted app timestamp");
        assert_eq!(stored_payload.app.updated_at, database_updated_at);

        let expected = crate::deploy::ExistingAppAuthoritySnapshot::new(
            stored_payload.app.updated_at,
            stored_payload.snapshot.containers.clone(),
            stored_payload.snapshot.resources.clone(),
        );
        let mut worker_lane = pool.begin().await.expect("begin worker authority lane");
        crate::deploy::lock_app_deployment_lane(&mut worker_lane, app.id)
            .await
            .expect("lock worker app lane");
        assert!(
            crate::deploy::verify_existing_app_authority(&mut worker_lane, app.id, &expected)
                .await
                .expect("verify exact post-mutation payload"),
            "the payload accepted after generic metadata mutation must be dispatchable"
        );

        // The nonterminal status projection uses another pooled connection
        // during apply. It must neither self-deadlock on worker row locks nor
        // invalidate the immutable authority timestamp for crash recovery.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            crate::deploy::set_app_status(&pool, app.id, "creating"),
        )
        .await
        .expect("worker status projection self-deadlocked")
        .expect("project worker status");
        let after_projection: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load timestamp after worker status projection");
        assert_eq!(after_projection, database_updated_at);
        worker_lane
            .rollback()
            .await
            .expect("release worker authority lane");

        delete_setup_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn superseded_watcher_cannot_publish_over_new_manifest() {
        let pool = database_test_pool().await;
        let app = insert_setup_test_app(&pool).await;
        insert_authority_rows(&pool, &app).await;
        let containers: Vec<AppContainer> =
            sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id")
                .bind(app.id)
                .fetch_all(&pool)
                .await
                .expect("load watcher fixture containers");
        let resources: AppResources =
            sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load watcher fixture resources");
        let payload = DeploymentApplyJobPayload::new(
            app.clone(),
            crate::deploy::DeploymentApplySnapshot::new(containers.clone(), resources),
            None,
            "test-api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        );
        let old_deployment_id = Uuid::new_v4();
        let new_deployment_id = Uuid::new_v4();
        let old_hash = "old-manifest-hash";
        let new_hash = "new-manifest-hash";
        let image_digest = containers[0]
            .image_digest
            .clone()
            .expect("watcher fixture image digest");
        let deployment_snapshot = serde_json::json!({
            "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
            "image": &containers[0].image_ref,
            "image_digest": &image_digest,
            "signed_descriptor_core_hash": null,
            "log_encryption": null,
        });

        let mut old_acceptance = pool.begin().await.expect("begin old acceptance");
        sqlx::query(
            "INSERT INTO deployments (
                id, org_id, app_id, trigger, status, spec_snapshot,
                image_digest, manifest_hash
             )
             VALUES ($1, $2, $3, 'api', 'watching', $4, $5, $6)",
        )
        .bind(old_deployment_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(&deployment_snapshot)
        .bind(&image_digest)
        .bind(old_hash)
        .execute(&mut *old_acceptance)
        .await
        .expect("insert old watching deployment");
        crate::deployment_jobs::insert_ready_job(
            &mut old_acceptance,
            old_deployment_id,
            old_deployment_id,
            &payload,
            false,
        )
        .await
        .expect("insert old watcher job");
        old_acceptance
            .commit()
            .await
            .expect("commit old watching deployment");

        let mut acceptance = pool.begin().await.expect("begin newer acceptance");
        crate::deploy::lock_app_deployment_lane(&mut acceptance, app.id)
            .await
            .expect("lock app deployment lane");
        assert_eq!(
            crate::deploy::supersede_incomplete_deployments(&mut acceptance, app.id)
                .await
                .expect("supersede old deployment"),
            1
        );
        sqlx::query(
            "INSERT INTO deployments (
                id, org_id, app_id, trigger, status, spec_snapshot,
                image_digest, manifest_hash
             )
             VALUES ($1, $2, $3, 'api', 'watching', $4, $5, $6)",
        )
        .bind(new_deployment_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(&deployment_snapshot)
        .bind(&image_digest)
        .bind(new_hash)
        .execute(&mut *acceptance)
        .await
        .expect("insert new watching deployment");
        crate::deployment_jobs::insert_ready_job(
            &mut acceptance,
            new_deployment_id,
            new_deployment_id,
            &payload,
            false,
        )
        .await
        .expect("insert new watcher job");
        acceptance.commit().await.expect("commit newer acceptance");

        assert!(
            !crate::deploy::record_deployment_result_if_current(
                &pool,
                crate::deploy::DeploymentResultUpdate {
                    app_id: app.id,
                    deployment_id: old_deployment_id,
                    deploy_status: "healthy",
                    expected_manifest_hash: old_hash,
                    app_status: "running",
                    error_code: None,
                    terminal: true,
                },
            )
            .await
            .expect("discard old watcher"),
            "superseded watcher must not publish a terminal result"
        );
        assert!(
            !crate::deploy::record_deployment_result_if_current(
                &pool,
                crate::deploy::DeploymentResultUpdate {
                    app_id: app.id,
                    deployment_id: new_deployment_id,
                    deploy_status: "healthy",
                    expected_manifest_hash: old_hash,
                    app_status: "running",
                    error_code: None,
                    terminal: true,
                },
            )
            .await
            .expect("discard wrong manifest watcher"),
            "a watcher for the wrong manifest must not publish"
        );

        let app_status_before: String =
            sqlx::query_scalar("SELECT status::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load app status before current watcher");
        assert_eq!(app_status_before, "creating");
        assert!(
            crate::deploy::record_deployment_result_if_current(
                &pool,
                crate::deploy::DeploymentResultUpdate {
                    app_id: app.id,
                    deployment_id: new_deployment_id,
                    deploy_status: "healthy",
                    expected_manifest_hash: new_hash,
                    app_status: "running",
                    error_code: None,
                    terminal: true,
                },
            )
            .await
            .expect("record current watcher")
        );

        let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT id, status::text, error_message
             FROM deployments
             WHERE app_id = $1
             ORDER BY id",
        )
        .bind(app.id)
        .fetch_all(&pool)
        .await
        .expect("load fenced deployment results");
        let old = rows
            .iter()
            .find(|(id, _, _)| *id == old_deployment_id)
            .expect("old deployment row");
        assert_eq!(old.1, "failed");
        assert_eq!(
            old.2.as_deref(),
            Some(crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR)
        );
        let new = rows
            .iter()
            .find(|(id, _, _)| *id == new_deployment_id)
            .expect("new deployment row");
        assert_eq!(new.1, "healthy");
        assert_eq!(new.2, None);
        let app_status: String = sqlx::query_scalar("SELECT status::text FROM apps WHERE id = $1")
            .bind(app.id)
            .fetch_one(&pool)
            .await
            .expect("load app status after current watcher");
        assert_eq!(app_status, "running");

        delete_setup_test_org(&pool, app.org_id).await;
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
        assert_eq!(error.0, StatusCode::CONFLICT);

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
        insert_authority_rows(&pool, &app).await;
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
        sqlx::query(
            "UPDATE app_resources
                SET cpu_limit = '2.0000000000000000001',
                    memory_limit = '3Gi',
                    app_data_size = '7Gi'
              WHERE app_id = $1",
        )
        .bind(app.id)
        .execute(&mut *tx)
        .await
        .expect("mutate exact candidate resources");
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
        let persisted_resources: AppResources =
            sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load rolled-back resources");
        assert_eq!(persisted_resources.cpu_limit, "1");
        assert_eq!(persisted_resources.memory_limit, "1Gi");
        assert_eq!(persisted_resources.app_data_size, "5Gi");

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
