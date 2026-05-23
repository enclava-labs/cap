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
    // Signed descriptor hashes must commit to the same artifact delivery mode
    // that apply uses. The actual JSON is persisted later; only the local file
    // URLs are embedded in cc_init_data.
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
mod classifier_tests {
    use super::*;
    use crate::cosign::VerificationPolicy;
    use crate::models::{App, AppStatus, DeployStatus, Deployment, Role, Trigger, UnlockMode};
    use enclava_common::image::ImageRef;
    use enclava_engine::types::AttestationConfig;

    fn idempotency_app() -> App {
        App {
            id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            org_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
            name: "customer-app".to_string(),
            namespace: "cap-test-customer-app".to_string(),
            instance_id: "test-customer-app".to_string(),
            tenant_id: "test".to_string(),
            service_account: "cap-customer-app-sa".to_string(),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: UnlockMode::Auto,
            domain: "customer-app.test.enclava.dev".to_string(),
            tee_domain: Some("customer-app.test.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: AppStatus::Creating,
            signer_identity_subject: Some(
                "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
            ),
            signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            signer_identity_set_at: Some(chrono::Utc::now()),
            source_provider: Some("github".to_string()),
            source_repository: Some("acme/confidential-app".to_string()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn idempotency_deployment(app: &App) -> Deployment {
        Deployment {
            id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
            org_id: Some(app.org_id),
            app_id: app.id,
            trigger: Trigger::Api,
            status: DeployStatus::Pending,
            spec_snapshot: serde_json::json!({
                "app_name": app.name,
                "namespace": app.namespace,
                "instance_id": app.instance_id,
                "image": "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "container_name": "app",
                "resources": null,
                "external_id": "deploy-123",
                "source_provider": "github",
                "source_repository": "acme/confidential-app",
            }),
            manifest_hash: None,
            image_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            error_message: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
            cosign_verified: true,
            provenance_attestation: None,
            sbom: None,
            external_id: Some("deploy-123".to_string()),
            source_provider: Some("github".to_string()),
            source_repository: Some("acme/confidential-app".to_string()),
        }
    }

    fn idempotency_request(app_name: &str) -> GenericDeploymentRequest {
        GenericDeploymentRequest {
            external_id: Some("deploy-123".to_string()),
            app: GenericDeploymentApp {
                name: app_name.to_string(),
                create_if_missing: true,
                unlock_mode: "auto".to_string(),
                bootstrap_pubkey_hash: None,
            },
            source: GenericDeploymentSource {
                provider: SourceProvider::GitHub,
                repository: "acme/confidential-app".to_string(),
            },
            workload: GenericDeploymentWorkload {
                image: "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                container_name: Some("app".to_string()),
                resources: None,
            },
            signing: GenericDeploymentSigning {
                subject: "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            security: GenericDeploymentSecurity::default(),
        }
    }

    fn attestation_config() -> AttestationConfig {
        AttestationConfig {
            proxy_image: ImageRef::parse("ghcr.io/enclava-ai/attestation-proxy@sha256:996c32b0726a90d82c08ae095b4bfbe01e47617cf929dc1eed3bd981f4e8155d")
                .unwrap(),
            caddy_image: ImageRef::parse("ghcr.io/enclava-ai/caddy-ingress@sha256:31a43cbfce0399cc83d22aabcb25346badcddfb46f4984eccd410c22e691ca6f")
                .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
            trustee_policy_read_available: false,
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

    #[test]
    fn signed_deploy_hash_validation_uses_local_artifact_delivery_mode() {
        let mut cfg = attestation_config();
        cfg.trustee_policy_read_available = true;
        cfg.workload_artifacts_url = Some("https://api.example.test/workload-artifacts".into());
        cfg.trustee_policy_url = Some("https://kbs.example.test/resource-policy/body".into());

        select_local_signed_artifact_delivery(&mut cfg);

        assert_eq!(cfg.local_workload_artifacts_json.as_deref(), Some("{}"));
        assert_eq!(cfg.local_trustee_policy_json.as_deref(), Some("{}"));
    }

    #[test]
    fn idempotent_retry_requires_same_deployment_payload() {
        let app = idempotency_app();
        let deployment = idempotency_deployment(&app);

        ensure_idempotent_retry_matches(&deployment, &app, &idempotency_request(&app.name))
            .unwrap();

        let err = ensure_idempotent_retry_matches(
            &deployment,
            &app,
            &idempotency_request("different-app"),
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(
            err.1.0["error"].as_str(),
            Some("external_id already exists with different app.name")
        );
    }

    #[test]
    fn external_id_rejects_empty_or_padded_values() {
        validate_external_id(Some("deploy-123")).unwrap();

        for value in ["", " deploy-123", "deploy-123 "] {
            let err = validate_external_id(Some(value)).unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn cap_core_source_has_no_product_specific_deployment_customizations() {
        let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let needles = [
            ["her", "mes"].concat(),
            ["secret", "_", "agent"].concat(),
            ["nut", "shell"].concat(),
        ];
        let mut findings = Vec::new();
        scan_rs_files_for_needles(&source_dir, &needles, &mut findings);

        assert!(
            findings.is_empty(),
            "CAP core source contains product-specific deployment customizations: {findings:?}"
        );
    }

    fn scan_rs_files_for_needles(
        dir: &std::path::Path,
        needles: &[String],
        findings: &mut Vec<String>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                scan_rs_files_for_needles(&path, needles, findings);
                continue;
            }
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                continue;
            }
            let contents = std::fs::read_to_string(&path).unwrap();
            let normalized = contents.to_ascii_lowercase();
            for needle in needles {
                if normalized.contains(needle) {
                    findings.push(format!("{} contains {}", path.display(), needle));
                }
            }
        }
    }

    #[tokio::test]
    async fn deploy_rejects_member_before_database_access() {
        let result = deploy(
            crate::test_support::auth_context(Role::Member, &[]),
            State(crate::test_support::lazy_state()),
            Path("demo".to_string()),
            Json(DeployRequest {
                image: "ghcr.io/example/demo:latest".to_string(),
                container_name: None,
                resources: None,
                external_id: None,
                source_provider: None,
                source_repository: None,
                customer_descriptor_blob: None,
                org_keyring_blob: None,
                signed_policy_artifact: None,
            }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("member deploy unexpectedly passed authorization"),
            Err(err) => err,
        };

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rollback_rejects_unscoped_api_key_before_database_access() {
        let result = rollback(
            crate::test_support::auth_context(Role::Admin, &["apps:read"]),
            State(crate::test_support::lazy_state()),
            Path("demo".to_string()),
            Json(RollbackRequest {
                deployment_id: Some(Uuid::new_v4()),
            }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("unscoped rollback unexpectedly passed authorization"),
            Err(err) => err,
        };

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn generic_config_token_rejects_unscoped_api_key_before_database_access() {
        let result = generic_config_token(
            crate::test_support::auth_context(Role::Admin, &["apps:read"]),
            State(crate::test_support::lazy_state()),
            Path(Uuid::new_v4()),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("unscoped generic config token unexpectedly passed authorization"),
            Err(err) => err,
        };

        assert_eq!(err.0, StatusCode::FORBIDDEN);
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

#[derive(Debug, Deserialize)]
pub struct GenericDeploymentRequest {
    #[serde(default)]
    pub external_id: Option<String>,
    pub app: GenericDeploymentApp,
    pub source: GenericDeploymentSource,
    pub workload: GenericDeploymentWorkload,
    pub signing: GenericDeploymentSigning,
    #[serde(default)]
    pub security: GenericDeploymentSecurity,
}

#[derive(Debug, Deserialize)]
pub struct GenericDeploymentApp {
    pub name: String,
    #[serde(default)]
    pub create_if_missing: bool,
    #[serde(default = "default_generic_unlock_mode")]
    pub unlock_mode: String,
    #[serde(default)]
    pub bootstrap_pubkey_hash: Option<String>,
}

fn default_generic_unlock_mode() -> String {
    "password".to_string()
}

#[derive(Debug, Deserialize)]
pub struct GenericDeploymentSource {
    pub provider: SourceProvider,
    pub repository: String,
}

#[derive(Debug, Deserialize)]
pub struct GenericDeploymentWorkload {
    pub image: String,
    #[serde(default)]
    pub container_name: Option<String>,
    #[serde(default)]
    pub resources: Option<DeployResources>,
}

#[derive(Debug, Deserialize)]
pub struct GenericDeploymentSigning {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GenericDeploymentSecurity {
    #[serde(default)]
    pub customer_descriptor_blob: Option<String>,
    #[serde(default)]
    pub org_keyring_blob: Option<String>,
    #[serde(default)]
    pub signed_policy_artifact: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenericDeploymentResponse {
    pub deployment_id: Uuid,
    pub app_name: String,
    pub app_domain: String,
    pub tee_url: Option<String>,
    pub image: Option<String>,
    pub image_digest: Option<String>,
    pub source_provider: Option<String>,
    pub source_repository: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct GenericConfigTokenResponse {
    pub deployment_id: Uuid,
    pub token: String,
    pub tee_url: String,
    pub expires_in_seconds: u64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl GenericDeploymentResponse {
    fn from_deployment(deployment: Deployment, app: &App) -> Self {
        let app_domain = app
            .custom_domain
            .clone()
            .unwrap_or_else(|| app.domain.clone());
        let tee_url = app
            .tee_domain
            .as_ref()
            .map(|domain| format!("https://{domain}"));
        let image = deployment
            .spec_snapshot
            .get("image")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Self {
            deployment_id: deployment.id,
            app_name: app.name.clone(),
            app_domain,
            tee_url,
            image,
            image_digest: deployment.image_digest,
            source_provider: deployment
                .source_provider
                .or_else(|| app.source_provider.clone()),
            source_repository: deployment
                .source_repository
                .or_else(|| app.source_repository.clone()),
            status: format!("{:?}", deployment.status).to_lowercase(),
            error_message: deployment.error_message,
            created_at: deployment.created_at,
            completed_at: deployment.completed_at,
        }
    }
}

fn json_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": message.into()})))
}

/// POST /apps/{name}/agent-policy -- authenticated genpolicy preflight broker.
pub async fn generate_agent_policy(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<AgentPolicyRequest>,
) -> Result<Json<AgentPolicyResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

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

/// POST /deployments -- generic provider-aware deployment entrypoint.
pub async fn create_generic_deployment(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<GenericDeploymentRequest>,
) -> Result<(StatusCode, Json<GenericDeploymentResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    validate_external_id(body.external_id.as_deref())?;

    validate_source_context(
        body.source.provider,
        &body.source.repository,
        &body.workload.image,
        &body.signing.subject,
        &body.signing.issuer,
    )
    .map_err(|e| json_error(StatusCode::BAD_REQUEST, e.to_string()))?;

    if let Some(external_id) = body.external_id.as_deref()
        && let Some((deployment, app)) =
            fetch_deployment_by_external_id(&state, auth.org_id, external_id).await?
    {
        ensure_idempotent_retry_matches(&deployment, &app, &body)?;
        return Ok((
            StatusCode::OK,
            Json(GenericDeploymentResponse::from_deployment(deployment, &app)),
        ));
    }

    let app = match fetch_app_by_name(&state, auth.org_id, &body.app.name).await? {
        Some(app) => {
            ensure_generic_app_metadata(
                &state,
                app,
                body.source.provider,
                &body.source.repository,
                &body.signing.subject,
                &body.signing.issuer,
            )
            .await?
        }
        None if body.app.create_if_missing => {
            let create = crate::routes::apps::CreateAppRequest {
                name: body.app.name.clone(),
                unlock_mode: body.app.unlock_mode.clone(),
                bootstrap_pubkey_hash: body.app.bootstrap_pubkey_hash.clone(),
                signer_identity_subject: Some(body.signing.subject.clone()),
                signer_identity_issuer: Some(body.signing.issuer.clone()),
                source_provider: Some(body.source.provider),
                source_repository: Some(body.source.repository.clone()),
            };
            let (_, Json(created)) =
                crate::routes::apps::create_app(auth.clone(), State(state.clone()), Json(create))
                    .await?;
            fetch_app_by_name(&state, auth.org_id, &created.name)
                .await?
                .ok_or_else(|| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        }
        None => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "app not found; set app.create_if_missing to true to create it",
            ));
        }
    };

    let deploy_request = DeployRequest {
        image: body.workload.image,
        container_name: body.workload.container_name,
        resources: body.workload.resources,
        external_id: body.external_id,
        source_provider: Some(body.source.provider),
        source_repository: Some(body.source.repository),
        customer_descriptor_blob: body.security.customer_descriptor_blob,
        org_keyring_blob: body.security.org_keyring_blob,
        signed_policy_artifact: body.security.signed_policy_artifact,
    };
    let org_id = auth.org_id;
    let (status, Json(deployed)) = deploy(
        auth,
        State(state.clone()),
        Path(app.name.clone()),
        Json(deploy_request),
    )
    .await?;
    let (deployment, app) = fetch_deployment_with_app(&state, org_id, deployed.deployment_id)
        .await?
        .ok_or_else(|| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok((
        status,
        Json(GenericDeploymentResponse::from_deployment(deployment, &app)),
    ))
}

/// GET /deployments/{deployment_id} -- generic deployment status/details.
pub async fn get_generic_deployment(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> Result<Json<GenericDeploymentResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;
    let (deployment, app) = fetch_deployment_with_app(&state, auth.org_id, deployment_id)
        .await?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "deployment not found"))?;

    Ok(Json(GenericDeploymentResponse::from_deployment(
        deployment, &app,
    )))
}

/// POST /deployments/{deployment_id}/config-token -- generic config-token bridge.
pub async fn generic_config_token(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> Result<Json<GenericConfigTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_admin(&auth)?;
    scopes::require_scope(&auth, "config:write")?;

    let (_deployment, app) = fetch_deployment_with_app(&state, auth.org_id, deployment_id)
        .await?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "deployment not found"))?;
    let Json(token) =
        crate::routes::config::issue_config_token_route(auth, State(state), Path(app.name.clone()))
            .await?;

    Ok(Json(GenericConfigTokenResponse {
        deployment_id,
        token: token.token,
        tee_url: token.tee_url,
        expires_in_seconds: token.expires_in_seconds,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(token.expires_in_seconds as i64),
    }))
}

async fn fetch_app_by_name(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
) -> Result<Option<App>, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(org_id)
        .bind(app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))
}

async fn fetch_app_by_id(
    state: &AppState,
    org_id: Uuid,
    app_id: Uuid,
) -> Result<App, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(app_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "app not found"))
}

async fn fetch_deployment_with_app(
    state: &AppState,
    org_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<(Deployment, App)>, (StatusCode, Json<serde_json::Value>)> {
    let Some(deployment) = sqlx::query_as::<_, Deployment>(
        "SELECT d.*
           FROM deployments d
           JOIN apps a ON a.id = d.app_id
          WHERE d.id = $1
            AND a.org_id = $2",
    )
    .bind(deployment_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    else {
        return Ok(None);
    };
    let app = fetch_app_by_id(state, org_id, deployment.app_id).await?;
    Ok(Some((deployment, app)))
}

async fn fetch_deployment_by_external_id(
    state: &AppState,
    org_id: Uuid,
    external_id: &str,
) -> Result<Option<(Deployment, App)>, (StatusCode, Json<serde_json::Value>)> {
    let Some(deployment) = sqlx::query_as::<_, Deployment>(
        "SELECT d.*
           FROM deployments d
           JOIN apps a ON a.id = d.app_id
          WHERE a.org_id = $1
            AND d.external_id = $2
          ORDER BY d.created_at DESC
          LIMIT 1",
    )
    .bind(org_id)
    .bind(external_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    else {
        return Ok(None);
    };
    let app = fetch_app_by_id(state, org_id, deployment.app_id).await?;
    Ok(Some((deployment, app)))
}

fn validate_external_id(
    external_id: Option<&str>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(external_id) = external_id else {
        return Ok(());
    };
    if external_id.trim() != external_id || external_id.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "external_id must not be empty or padded with whitespace",
        ));
    }
    Ok(())
}

fn ensure_idempotent_retry_matches(
    deployment: &Deployment,
    app: &App,
    body: &GenericDeploymentRequest,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if app.name != body.app.name {
        return Err(idempotency_conflict("app.name"));
    }
    let expected_provider = body.source.provider.as_str();
    let existing_provider = deployment
        .source_provider
        .as_deref()
        .or(app.source_provider.as_deref());
    if existing_provider != Some(expected_provider) {
        return Err(idempotency_conflict("source.provider"));
    }
    let existing_repository = deployment
        .source_repository
        .as_deref()
        .or(app.source_repository.as_deref());
    if existing_repository != Some(body.source.repository.as_str()) {
        return Err(idempotency_conflict("source.repository"));
    }
    if app.signer_identity_subject.as_deref() != Some(body.signing.subject.as_str()) {
        return Err(idempotency_conflict("signing.subject"));
    }
    if app.signer_identity_issuer.as_deref() != Some(body.signing.issuer.as_str()) {
        return Err(idempotency_conflict("signing.issuer"));
    }
    if deployment
        .spec_snapshot
        .get("image")
        .and_then(serde_json::Value::as_str)
        != Some(body.workload.image.as_str())
    {
        return Err(idempotency_conflict("workload.image"));
    }
    let requested_container = body.workload.container_name.as_deref().unwrap_or("web");
    let existing_container = deployment
        .spec_snapshot
        .get("container_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("web");
    if existing_container != requested_container {
        return Err(idempotency_conflict("workload.container_name"));
    }
    let existing_resources = deployment
        .spec_snapshot
        .get("resources")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let requested_resources =
        serde_json::to_value(&body.workload.resources).unwrap_or(serde_json::Value::Null);
    if existing_resources != requested_resources {
        return Err(idempotency_conflict("workload.resources"));
    }
    Ok(())
}

fn idempotency_conflict(field: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    json_error(
        StatusCode::CONFLICT,
        format!("external_id already exists with different {field}"),
    )
}

async fn ensure_generic_app_metadata(
    state: &AppState,
    app: App,
    provider: SourceProvider,
    repository: &str,
    subject: &str,
    issuer: &str,
) -> Result<App, (StatusCode, Json<serde_json::Value>)> {
    let provider_str = provider.as_str();
    if let Some(existing) = app.source_provider.as_deref()
        && existing != provider_str
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "app source_provider does not match deployment source provider",
        ));
    }
    if let Some(existing) = app.source_repository.as_deref()
        && existing != repository
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "app source_repository does not match deployment source repository",
        ));
    }
    match (
        app.signer_identity_subject.as_deref(),
        app.signer_identity_issuer.as_deref(),
    ) {
        (Some(existing_subject), Some(existing_issuer))
            if existing_subject == subject && existing_issuer == issuer => {}
        (None, None) => {}
        _ => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "app pinned signer identity does not match deployment signing identity",
            ));
        }
    }

    sqlx::query_as(
        "UPDATE apps
            SET source_provider = $1,
                source_repository = $2,
                signer_identity_subject = $3,
                signer_identity_issuer = $4,
                signer_identity_set_at = COALESCE(signer_identity_set_at, now()),
                updated_at = now()
          WHERE id = $5
          RETURNING *",
    )
    .bind(provider_str)
    .bind(repository)
    .bind(subject)
    .bind(issuer)
    .bind(app.id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))
}

/// POST /apps/{name}/deploy -- deploy or update an app.
pub async fn deploy(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeploymentResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

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

    // Build spec snapshot
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
        "resources": body.resources,
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

/// POST /apps/{name}/rollback -- rollback to a previous deployment.
pub async fn rollback(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<RollbackResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

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
    let rollback_descriptor =
        crate::signing_service::load_workload_descriptor(&state.db, app.id, prev.id)
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
                "error": "rollback target has no stored signed policy artifact"
            })),
        ));
    }

    let rollback_workload_command = match rollback_descriptor.as_ref() {
        Some(descriptor) => crate::deploy::serialize_workload_command(
            &descriptor.oci_runtime_spec.args,
        )
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "command serialization error"})),
            )
        })?,
        None => None,
    };
    let rollback_container_port = rollback_descriptor
        .as_ref()
        .and_then(crate::deploy::descriptor_primary_port);
    let rollback_storage_paths = rollback_descriptor
        .as_ref()
        .map(crate::deploy::descriptor_storage_paths);
    if customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && rollback_workload_command.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "rollback target has no signed workload command"
            })),
        ));
    }

    let container_name = "web";
    sqlx::query(
        "UPDATE app_containers
         SET image_ref = $1,
             image_digest = $2,
             command = COALESCE($3, command),
             port = COALESCE($4, port),
             storage_paths = COALESCE($5, storage_paths)
         WHERE app_id = $6 AND name = $7",
    )
    .bind(&image)
    .bind(Some(&image_digest))
    .bind(rollback_workload_command.as_ref())
    .bind(rollback_container_port)
    .bind(rollback_storage_paths.as_ref())
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
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest, source_provider, source_repository)
         VALUES ($1, $2, $3, 'rollback', $4, $5, $6, $7)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&prev.spec_snapshot)
    .bind(&prev.image_digest)
    .bind(prev.source_provider.as_deref())
    .bind(prev.source_repository.as_deref())
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
