use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Duration;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::jwt::{
    SignerRotationTokenInput, issue_signer_rotation_token, verify_signer_rotation_token,
};
use crate::auth::middleware::{AuthContext, ManagementOrigin};
use crate::auth::scopes;
use crate::models::{App, AppStatus};
use crate::source_provider::{
    SourceProvider, validate_signing_identity, validate_source_repository,
};
use crate::state::{AppState, CapManagementMode};
use enclava_engine::types::{EgressMode, EgressRule};
use sqlx::types::Json as SqlJson;

/// Helper function for consistent internal server error responses
fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
}

/// Bounded diagnostics for app deletion failures.
///
/// Deletion dependencies can embed tenant-controlled hostnames, namespaces,
/// response bodies, and upstream error messages in their `Display`
/// implementations. Keep both the public response and operator diagnostics
/// on this fixed allowlist instead of formatting those source errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppDeleteFailure {
    TeardownToken,
    TeardownEndpoint,
    DnsNotConfigured,
    DnsOutsideManagedZone,
    DnsHostnameInUse,
    DnsUnavailable,
    EdgeBackend,
    EdgeRoute,
    Namespace,
    KbsOwnerBinding,
    KbsTlsBinding,
    KbsPolicy,
}

impl AppDeleteFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::TeardownToken => "app_delete_teardown_token_failed",
            Self::TeardownEndpoint => "app_delete_teardown_unavailable",
            Self::DnsNotConfigured => "app_delete_dns_not_configured",
            Self::DnsOutsideManagedZone => "app_delete_dns_outside_managed_zone",
            Self::DnsHostnameInUse => "app_delete_dns_hostname_in_use",
            Self::DnsUnavailable => "app_delete_dns_unavailable",
            Self::EdgeBackend => "app_delete_edge_backend_invalid",
            Self::EdgeRoute => "app_delete_edge_unavailable",
            Self::Namespace => "app_delete_namespace_unavailable",
            Self::KbsOwnerBinding => "app_delete_kbs_owner_binding_failed",
            Self::KbsTlsBinding => "app_delete_kbs_tls_binding_failed",
            Self::KbsPolicy => "app_delete_kbs_policy_failed",
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::TeardownToken | Self::DnsNotConfigured | Self::EdgeBackend => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::DnsOutsideManagedZone => StatusCode::BAD_REQUEST,
            Self::DnsHostnameInUse => StatusCode::CONFLICT,
            Self::TeardownEndpoint
            | Self::DnsUnavailable
            | Self::EdgeRoute
            | Self::Namespace
            | Self::KbsOwnerBinding
            | Self::KbsTlsBinding
            | Self::KbsPolicy => StatusCode::BAD_GATEWAY,
        }
    }
}

fn app_delete_failure<T>(
    app_id: Uuid,
    failure: AppDeleteFailure,
    _source: T,
) -> (StatusCode, Json<serde_json::Value>) {
    let status = failure.status();
    let code = failure.code();
    tracing::warn!(
        app_id = %app_id,
        status = status.as_u16(),
        code,
        "app deletion step failed"
    );
    (status, Json(serde_json::json!({"error": code})))
}

fn app_delete_dns_failure(
    app_id: Uuid,
    source: crate::dns::DnsError,
) -> (StatusCode, Json<serde_json::Value>) {
    let failure = match &source {
        crate::dns::DnsError::NotConfigured => AppDeleteFailure::DnsNotConfigured,
        crate::dns::DnsError::OutsideManagedZone(_) => AppDeleteFailure::DnsOutsideManagedZone,
        crate::dns::DnsError::HostnameInUse { .. } => AppDeleteFailure::DnsHostnameInUse,
        crate::dns::DnsError::Cloudflare(_)
        | crate::dns::DnsError::Http(_)
        | crate::dns::DnsError::Db(_) => AppDeleteFailure::DnsUnavailable,
    };
    app_delete_failure(app_id, failure, source)
}

fn deploy_blocked_response(reason: &str, message: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "deploy_blocked",
            "reason": reason,
            "message": message,
        })),
    )
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

pub(crate) async fn ensure_management_write_allowed(
    state: &AppState,
    auth: &AuthContext,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    match (state.management_mode, auth.management_origin) {
        (CapManagementMode::Standalone, ManagementOrigin::Public)
        | (CapManagementMode::PaasManaged, ManagementOrigin::PaasInternal) => Ok(()),
        (CapManagementMode::Standalone, ManagementOrigin::PaasInternal) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "standalone_instance",
                "message": "Standalone CAP instances do not accept PaaS internal management writes"
            })),
        )),
        (CapManagementMode::PaasManaged, ManagementOrigin::Public) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "paas_managed_instance",
                "message": "This CAP instance is managed by PaaS; management writes must use PaaS internal routes"
            })),
        )),
    }
}

async fn delete_tenant_namespace(
    api: kube::Api<k8s_openapi::api::core::v1::Namespace>,
    namespace: &str,
    generation: enclava_engine::apply::generation::MutationGeneration,
) -> Result<(), enclava_engine::apply::engine::ApplyError> {
    delete_tenant_namespace_with_timeouts(
        api,
        namespace,
        generation,
        std::time::Duration::from_secs(120),
        std::time::Duration::from_secs(150),
    )
    .await
}

async fn delete_tenant_namespace_with_timeouts(
    api: kube::Api<k8s_openapi::api::core::v1::Namespace>,
    namespace: &str,
    generation: enclava_engine::apply::generation::MutationGeneration,
    convergence_timeout: std::time::Duration,
    operation_timeout: std::time::Duration,
) -> Result<(), enclava_engine::apply::engine::ApplyError> {
    let delete_and_wait = async {
        enclava_engine::apply::generation::delete_resource(
            &api,
            namespace,
            generation,
            kube::api::DeleteParams::default(),
        )
        .await?;

        let deadline = tokio::time::Instant::now() + convergence_timeout;
        loop {
            match api.get(namespace).await {
                Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
                Ok(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Ok(_) => {
                    return Err(
                        enclava_engine::apply::engine::ApplyError::CleanupStepFailed {
                            step: "delete_namespace".to_string(),
                            detail: "namespace deletion did not converge".to_string(),
                        },
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    };

    // A Kubernetes read can hang beyond the convergence deadline. Bound the
    // entire provider operation so this path fails closed while the pre-armed
    // resource fence remains at infinity for operator reconciliation.
    tokio::time::timeout(operation_timeout, delete_and_wait)
        .await
        .map_err(
            |_| enclava_engine::apply::engine::ApplyError::CleanupStepFailed {
                step: "delete_namespace".to_string(),
                detail: "namespace deletion provider operation timed out".to_string(),
            },
        )?
}

fn workload_teardown_instance_id(app: &App) -> String {
    format!("{}-{}", app.namespace, app.name)
}

fn requires_workload_teardown(status: AppStatus) -> bool {
    matches!(status, AppStatus::Running | AppStatus::Deleting)
}

async fn request_workload_teardown(
    state: &AppState,
    auth: &AuthContext,
    app: &App,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !requires_workload_teardown(app.status) {
        tracing::info!(
            app_id = %app.id,
            status = ?app.status,
            code = "app_delete_teardown_not_required",
            "skipping workload teardown endpoint for non-running app"
        );
        return Ok(());
    }

    let token = crate::auth::jwt::issue_config_token(
        &state.signing_key,
        auth.user_id,
        auth.org_id,
        app.id,
        &workload_teardown_instance_id(app),
        vec!["teardown".to_string()],
    )
    .map_err(|error| app_delete_failure(app.id, AppDeleteFailure::TeardownToken, error))?;

    let domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    let url = format!(
        "https://{}/.well-known/confidential/teardown",
        domain.trim_end_matches('/')
    );
    let response = match state
        .tee_http_client
        .post(&url)
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            let _ = app_delete_failure(app.id, AppDeleteFailure::TeardownEndpoint, "unreachable");
            return Ok(());
        }
    };

    if response.status().is_success() {
        return Ok(());
    }

    let _ = app_delete_failure(
        app.id,
        AppDeleteFailure::TeardownEndpoint,
        response.status().as_u16(),
    );
    Ok(())
}

/// Comprehensive app name validation
pub(crate) fn validate_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 63 {
        return Err("app name must be between 1 and 63 characters".to_string());
    }

    // Reserved names (Kubernetes system names)
    let reserved = [
        "kubernetes",
        "kube",
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "default",
        "kube-service-account",
        "kube-root-ca",
        "config",
        "health",
        "status",
        "metrics",
        "prometheus",
        "grafana",
    ];
    if reserved.contains(&name) {
        return Err(format!("'{name}' is a reserved name"));
    }

    // Character validation (Kubernetes DNS-1123 subdomain)
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "app name must contain only lowercase letters, digits, and hyphens".to_string(),
        );
    }

    // Must start and end with alphanumeric
    if !name.chars().next().unwrap().is_ascii_alphanumeric()
        || !name.chars().last().unwrap().is_ascii_alphanumeric()
    {
        return Err("app name must start and end with a letter or digit".to_string());
    }

    if name.contains("--") {
        return Err("app name cannot contain consecutive hyphens".to_string());
    }

    // No leading/trailing hyphens (already covered by alphanumeric check)
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    #[serde(default = "default_unlock_mode")]
    pub unlock_mode: String,
    /// For password-mode: hex SHA256 of the user's bootstrap claim public key.
    /// Required when unlock_mode is "password".
    #[serde(default)]
    pub bootstrap_pubkey_hash: Option<String>,
    /// Cosign Fulcio identity subject (e.g. an email or workload identity URI).
    /// Optional at create-time; Phase 9 wires the validation/requirement.
    #[serde(default)]
    pub signer_identity_subject: Option<String>,
    /// Cosign Fulcio issuer URL. Optional at create-time; Phase 9 wires it in.
    #[serde(default)]
    pub signer_identity_issuer: Option<String>,
    /// Source provider that owns the workload repository.
    #[serde(default)]
    pub source_provider: Option<SourceProvider>,
    /// Provider-local repository path, e.g. owner/repo or group/subgroup/project.
    #[serde(default)]
    pub source_repository: Option<String>,
    /// Per-app FQDN egress allowlist rendered into the tenant Cilium policy.
    #[serde(default)]
    pub egress_allowlist: Vec<CreateEgressAllowRule>,
    /// Tenant egress posture. Defaults to restricted.
    #[serde(default = "default_egress_mode")]
    pub egress_mode: String,
}

fn default_unlock_mode() -> String {
    "password".to_string()
}

pub(crate) fn default_egress_mode() -> String {
    EgressMode::Restricted.as_str().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEgressAllowRule {
    pub host: String,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressAllowlistAuditReason {
    Localhost,
    Metadata,
    KubernetesService,
    InternalDnsSuffix,
    RebindingHelper,
}

pub(crate) fn validate_egress_allowlist(
    rules: &[CreateEgressAllowRule],
) -> Result<Vec<EgressRule>, String> {
    rules
        .iter()
        .map(|rule| {
            let host = rule.host.as_str();
            if host.trim() != host {
                return Err(
                    "egress_allowlist host must not have surrounding whitespace".to_string()
                );
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Err(
                    "egress_allowlist host must be a DNS hostname, not an IP address".to_string(),
                );
            }
            enclava_common::validate::validate_fqdn(host)
                .map_err(|e| format!("invalid egress_allowlist host: {e}"))?;
            audit_egress_allowlist_host(host);

            let ports = rule.ports.clone().unwrap_or_else(|| vec![443]);
            if ports.is_empty() || ports.contains(&0) {
                return Err("egress_allowlist ports must be between 1 and 65535".to_string());
            }

            Ok(EgressRule {
                host: host.to_string(),
                ports,
            })
        })
        .collect()
}

fn audit_egress_allowlist_host(host: &str) {
    let reasons = egress_allowlist_host_audit_reasons(host);
    if reasons.is_empty() {
        return;
    }

    tracing::warn!(
        host = %host,
        reasons = ?reasons,
        "egress_allowlist host matched internal/rebinding audit pattern; accepting in warn-only mode"
    );
}

pub(crate) fn egress_allowlist_host_audit_reasons(host: &str) -> Vec<EgressAllowlistAuditReason> {
    let host = host.to_ascii_lowercase();
    let mut reasons = Vec::new();

    if host == "localhost" || host.ends_with(".localhost") {
        add_egress_audit_reason(&mut reasons, EgressAllowlistAuditReason::Localhost);
    }
    if host == "metadata" || host == "metadata.google.internal" || host.starts_with("metadata.") {
        add_egress_audit_reason(&mut reasons, EgressAllowlistAuditReason::Metadata);
    }
    if host == "kubernetes.default.svc"
        || host == "kubernetes.default.svc.cluster.local"
        || host.ends_with(".svc")
        || host.ends_with(".svc.cluster.local")
    {
        add_egress_audit_reason(&mut reasons, EgressAllowlistAuditReason::KubernetesService);
    }
    if host.ends_with(".cluster.local")
        || host.ends_with(".internal")
        || host.ends_with(".local")
        || host.ends_with(".localdomain")
    {
        add_egress_audit_reason(&mut reasons, EgressAllowlistAuditReason::InternalDnsSuffix);
    }
    if host.ends_with(".nip.io")
        || host.ends_with(".sslip.io")
        || host.ends_with(".localtest.me")
        || host.ends_with(".lvh.me")
    {
        add_egress_audit_reason(&mut reasons, EgressAllowlistAuditReason::RebindingHelper);
    }

    reasons
}

fn add_egress_audit_reason(
    reasons: &mut Vec<EgressAllowlistAuditReason>,
    reason: EgressAllowlistAuditReason,
) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

pub(crate) fn validate_egress_mode(value: &str) -> Result<EgressMode, String> {
    value.parse()
}

#[derive(Debug, Serialize)]
pub struct AppResponse {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub instance_id: String,
    pub service_account: String,
    pub bootstrap_owner_pubkey_hash: String,
    pub tenant_instance_identity_hash: String,
    pub domain: String,
    pub tee_domain: Option<String>,
    pub custom_domain: Option<String>,
    pub unlock_mode: String,
    pub status: String,
    pub signer_identity_subject: Option<String>,
    pub signer_identity_issuer: Option<String>,
    pub source_provider: Option<String>,
    pub source_repository: Option<String>,
    pub egress_mode: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<App> for AppResponse {
    fn from(a: App) -> Self {
        Self {
            id: a.id,
            name: a.name,
            namespace: a.namespace,
            instance_id: a.instance_id,
            service_account: a.service_account,
            bootstrap_owner_pubkey_hash: a.bootstrap_owner_pubkey_hash,
            tenant_instance_identity_hash: a.tenant_instance_identity_hash,
            domain: a.domain,
            tee_domain: a.tee_domain,
            custom_domain: a.custom_domain,
            unlock_mode: format!("{:?}", a.unlock_mode).to_lowercase(),
            status: format!("{:?}", a.status).to_lowercase(),
            signer_identity_subject: a.signer_identity_subject,
            signer_identity_issuer: a.signer_identity_issuer,
            source_provider: a.source_provider,
            source_repository: a.source_repository,
            egress_mode: a.egress_mode,
            created_at: a.created_at,
        }
    }
}

fn validate_source_metadata(
    provider: Option<SourceProvider>,
    repository: Option<&str>,
    signer_subject: Option<&str>,
    signer_issuer: Option<&str>,
) -> Result<(), String> {
    match (provider, repository) {
        (None, None) => Ok(()),
        (Some(provider), Some(repository)) => {
            if let (Some(subject), Some(issuer)) = (signer_subject, signer_issuer) {
                validate_signing_identity(provider, repository, subject, issuer)
                    .map_err(|e| e.to_string())
            } else {
                validate_source_repository(provider, repository).map_err(|e| e.to_string())
            }
        }
        _ => Err("source_provider and source_repository must be provided together".to_string()),
    }
}

/// Derive identity fields per OID-1 and OID-6.
pub(crate) fn derive_identity(
    org_name: &str,
    app_id: Uuid,
    app_name: &str,
    unlock_mode: &str,
    user_pubkey_hash: Option<&str>,
) -> Result<(String, String, String, String, String, String), String> {
    let tenant_id = org_name.to_string();
    let app_id_short = &app_id.to_string()[..8];
    let instance_id = format!("{tenant_id}-{app_id_short}");
    let namespace = format!("cap-{org_name}-{app_name}");
    let service_account = format!("cap-{app_name}-sa");

    let bootstrap_owner_pubkey_hash = match unlock_mode {
        "password" => {
            let hash =
                user_pubkey_hash.ok_or("bootstrap_pubkey_hash required for password mode")?;
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("bootstrap_pubkey_hash must be 64 hex characters".to_string());
            }
            hash.to_lowercase()
        }
        "auto" => {
            // Platform generates Ed25519 keypair for auto-unlock apps
            let keypair = SigningKey::generate(&mut OsRng);
            let pubkey_bytes = keypair.verifying_key().to_bytes();
            let hash = Sha256::digest(pubkey_bytes);
            hex::encode(hash)
        }
        _ => return Err(format!("invalid unlock_mode: {unlock_mode}")),
    };

    let identity_hash = enclava_common::crypto::compute_identity_hash(
        &tenant_id,
        &instance_id,
        &bootstrap_owner_pubkey_hash,
    );

    Ok((
        tenant_id,
        instance_id,
        namespace,
        service_account,
        bootstrap_owner_pubkey_hash,
        identity_hash,
    ))
}

/// Validate an app creation request and construct the row that would be
/// inserted, without mutating persistent state.
///
/// Generic deployment uses this candidate while validating signed artifacts;
/// the row is inserted only when the deployment itself is ready to commit.
pub(crate) async fn prepare_app_candidate(
    state: &AppState,
    auth: &AuthContext,
    body: &CreateAppRequest,
) -> Result<App, (StatusCode, Json<serde_json::Value>)> {
    validate_app_name(&body.name).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
    })?;
    validate_source_metadata(
        body.source_provider,
        body.source_repository.as_deref(),
        body.signer_identity_subject.as_deref(),
        body.signer_identity_issuer.as_deref(),
    )
    .map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
    })?;
    let egress_allowlist = validate_egress_allowlist(&body.egress_allowlist).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
    })?;
    let egress_mode = validate_egress_mode(&body.egress_mode).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
    })?;

    let org: crate::models::Organization =
        sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
            .bind(auth.org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| internal_server_error())?;
    let entitlement_class = org.entitlement_class.clone();
    let decision = crate::entitlements::entitlement_decision_for_org(
        &state.db,
        auth.org_id,
        &entitlement_class,
    )
    .await
    .map_err(|_| internal_server_error())?;
    if !decision.deploy_allowed {
        return Err(deploy_blocked_response(
            decision
                .deploy_block_reason
                .as_deref()
                .unwrap_or("entitlement_blocked"),
            format!("Org entitlement class {entitlement_class} does not allow app creation"),
        ));
    }
    let limits = decision.limits.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "unknown entitlement class"})),
    ))?;
    let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps WHERE org_id = $1")
        .bind(auth.org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| internal_server_error())?;
    if app_count >= limits.max_apps as i64 {
        return Err(deploy_blocked_response(
            "entitlement_app_limit",
            format!(
                "Org entitlement class {entitlement_class} allows max {} apps, you have {app_count}. Increase the entitlement class or delete an app.",
                limits.max_apps
            ),
        ));
    }

    let app_id = Uuid::new_v4();
    let (tenant_id, instance_id, namespace, service_account, pubkey_hash, identity_hash) =
        derive_identity(
            &auth.org_name,
            app_id,
            &body.name,
            &body.unlock_mode,
            body.bootstrap_pubkey_hash.as_deref(),
        )
        .map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
        })?;
    let app_host =
        enclava_common::hostnames::app_hostname(&body.name, &org.cust_slug, &state.platform_domain)
            .map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("invalid app hostname: {error}")
                    })),
                )
            })?;
    let tee_host = enclava_common::hostnames::tee_hostname(
        &body.name,
        &org.cust_slug,
        &state.tee_domain_suffix,
    )
    .map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("invalid tee hostname: {error}")
            })),
        )
    })?;
    let unlock_mode = match body.unlock_mode.as_str() {
        "auto" => crate::models::UnlockMode::Auto,
        "password" => crate::models::UnlockMode::Password,
        _ => unreachable!("derive_identity validates unlock_mode"),
    };
    let now = chrono::Utc::now();

    Ok(App {
        id: app_id,
        org_id: auth.org_id,
        name: body.name.clone(),
        namespace,
        instance_id,
        tenant_id,
        service_account,
        bootstrap_owner_pubkey_hash: pubkey_hash,
        tenant_instance_identity_hash: identity_hash,
        unlock_mode,
        domain: app_host,
        tee_domain: Some(tee_host),
        custom_domain: None,
        status: AppStatus::Creating,
        signer_identity_subject: body.signer_identity_subject.clone(),
        signer_identity_issuer: body.signer_identity_issuer.clone(),
        signer_identity_set_at: (body.signer_identity_subject.is_some()
            || body.signer_identity_issuer.is_some())
        .then_some(now),
        source_provider: body
            .source_provider
            .map(SourceProvider::as_str)
            .map(str::to_string),
        source_repository: body.source_repository.clone(),
        egress_allowlist: SqlJson(egress_allowlist),
        egress_mode: egress_mode.as_str().to_string(),
        created_at: now,
        updated_at: now,
    })
}

/// POST /apps -- create a new app.
pub async fn create_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    ensure_management_write_allowed(&state, &auth).await?;
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;

    let app_candidate = prepare_app_candidate(&state, &auth, &body).await?;
    let app_id = app_candidate.id;
    let resources = crate::models::AppResources {
        app_id,
        cpu_limit: "1".to_string(),
        memory_limit: "1Gi".to_string(),
        app_data_size: "5Gi".to_string(),
        tls_data_size: "2Gi".to_string(),
    };

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::routes::deployments::enforce_authoritative_entitlement(
        &mut tx,
        auth.org_id,
        &resources,
        true,
    )
    .await?;

    let result = sqlx::query(
        "INSERT INTO apps (id, org_id, name, namespace, instance_id, tenant_id,
        service_account, bootstrap_owner_pubkey_hash, tenant_instance_identity_hash,
         unlock_mode, domain, tee_domain,
         signer_identity_subject, signer_identity_issuer, signer_identity_set_at,
        source_provider, source_repository, egress_allowlist, egress_mode)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
    )
    .bind(app_id)
    .bind(app_candidate.org_id)
    .bind(&app_candidate.name)
    .bind(&app_candidate.namespace)
    .bind(&app_candidate.instance_id)
    .bind(&app_candidate.tenant_id)
    .bind(&app_candidate.service_account)
    .bind(&app_candidate.bootstrap_owner_pubkey_hash)
    .bind(&app_candidate.tenant_instance_identity_hash)
    .bind(app_candidate.unlock_mode)
    .bind(&app_candidate.domain)
    .bind(app_candidate.tee_domain.as_deref())
    .bind(app_candidate.signer_identity_subject.as_deref())
    .bind(app_candidate.signer_identity_issuer.as_deref())
    .bind(app_candidate.signer_identity_set_at)
    .bind(app_candidate.source_provider.as_deref())
    .bind(app_candidate.source_repository.as_deref())
    .bind(&app_candidate.egress_allowlist)
    .bind(&app_candidate.egress_mode)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "app name already taken in this org"})),
            ));
        }
        return Err(internal_server_error());
    }

    sqlx::query(
        "INSERT INTO app_resources (
             app_id, cpu_limit, memory_limit, app_data_size, tls_data_size
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(resources.app_id)
    .bind(&resources.cpu_limit)
    .bind(&resources.memory_limit)
    .bind(&resources.app_data_size)
    .bind(&resources.tls_data_size)
    .execute(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?;

    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail)
         VALUES ($1, $2, $3, 'app.create', $4)",
    )
    .bind(auth.org_id)
    .bind(app_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "name": &body.name,
        "unlock_mode": &body.unlock_mode,
        "egress_allowlist": &app_candidate.egress_allowlist.0,
        "egress_mode": &app_candidate.egress_mode
    }))
    .execute(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?;

    tx.commit().await.map_err(|_| internal_server_error())?;

    let mut dns_mutation = match crate::mutation_leases::claim(
        &state,
        app_id,
        "app_create_dns",
        app_id,
        false,
        vec![
            crate::mutation_leases::ResourceFence::dns(&app_candidate.domain),
            crate::mutation_leases::ResourceFence::dns(
                app_candidate
                    .tee_domain
                    .as_deref()
                    .unwrap_or(&app_candidate.domain),
            ),
        ],
    )
    .await
    {
        Ok(mutation) => mutation,
        Err(error) => {
            // No provider future has been polled. Remove the pristine create
            // transaction under the app lane so a hostname-fence conflict or
            // closed admission queue cannot strand an undeployable name.
            let mut compensation = state
                .db
                .begin()
                .await
                .map_err(|_| internal_server_error())?;
            crate::deploy::lock_app_deployment_lane(&mut compensation, app_id)
                .await
                .map_err(|_| internal_server_error())?;
            let deleted = sqlx::query(
                "DELETE FROM apps AS app
                  WHERE app.id = $1
                    AND app.org_id = $2
                    AND app.status = 'creating'::app_status_enum
                    AND NOT EXISTS (
                        SELECT 1 FROM deployments WHERE app_id = app.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM dns_records WHERE app_id = app.id
                    )",
            )
            .bind(app_id)
            .bind(auth.org_id)
            .execute(&mut *compensation)
            .await
            .map_err(|_| internal_server_error())?;
            if deleted.rows_affected() != 1 {
                return Err(internal_server_error());
            }
            compensation
                .commit()
                .await
                .map_err(|_| internal_server_error())?;
            return Err(match error {
                crate::mutation_leases::MutationLeaseError::Busy => (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": "app mutation already in progress"})),
                ),
                _ => internal_server_error(),
            });
        }
    };

    // Reacquire and hold the app generation lane across legacy DNS setup.
    // Deletion and deployment acceptance use the same lane, so neither can
    // remove or supersede this app between the provider side effect and its
    // compensating database decision.
    let mut dns_lane = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::deploy::lock_app_deployment_lane(&mut dns_lane, app_id)
        .await
        .map_err(|_| internal_server_error())?;
    let setup_allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM apps
              WHERE id = $1
                AND org_id = $2
                AND status <> 'deleting'::app_status_enum
         )",
    )
    .bind(app_id)
    .bind(auth.org_id)
    .fetch_one(&mut *dns_lane)
    .await
    .map_err(|_| internal_server_error())?;
    if !setup_allowed {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "app creation was superseded"})),
        ));
    }

    if state.dns.is_some() {
        dns_mutation
            .arm_resource_scope_until_reconciled("dns_hostname")
            .await
            .map_err(|_| internal_server_error())?;
    }

    let dns_setup = dns_mutation
        .guard_provider_in_tx(
            &mut dns_lane,
            crate::dns::ensure_dns_pair(
                &state.db,
                &state.http_client,
                state.dns.as_ref(),
                app_id,
                &app_candidate.domain,
                app_candidate
                    .tee_domain
                    .as_deref()
                    .unwrap_or(&app_candidate.domain),
            ),
        )
        .await
        .map_err(|_| internal_server_error())?;
    if let Err(e) = dns_setup {
        // A provider POST can be accepted while its response is lost. An
        // immediate lookup may still be empty while that request is queued,
        // so cleanup success is not proof that no late record can appear.
        // Keep the failed app as durable reconciliation authority and retain
        // the hostname generations through quarantine; DELETE retries perform
        // provider discovery by hostname before the app can disappear.
        let _cleanup_result = dns_mutation
            .guard_provider_in_tx(
                &mut dns_lane,
                crate::dns::delete_managed_dns_pair_by_hostname(
                    &state.db,
                    &state.http_client,
                    state.dns.as_ref(),
                    app_id,
                    &app_candidate.domain,
                    app_candidate
                        .tee_domain
                        .as_deref()
                        .unwrap_or(&app_candidate.domain),
                ),
            )
            .await
            .map_err(|_| internal_server_error())?;
        dns_mutation
            .assert_current_in_tx(&mut dns_lane)
            .await
            .map_err(|_| internal_server_error())?;
        dns_mutation
            .retain_resource_scope_until_reconciled_in_tx(&mut dns_lane, "dns_hostname")
            .await
            .map_err(|_| internal_server_error())?;
        sqlx::query(
            "UPDATE apps
                SET status = 'failed'::app_status_enum,
                    updated_at = clock_timestamp()
              WHERE id = $1 AND org_id = $2",
        )
        .bind(app_id)
        .bind(auth.org_id)
        .execute(&mut *dns_lane)
        .await
        .map_err(|_| internal_server_error())?;
        dns_lane
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Err(dns_error_response(e));
    }
    dns_mutation
        .finish_in_tx(&mut dns_lane)
        .await
        .map_err(|_| internal_server_error())?;
    dns_lane
        .commit()
        .await
        .map_err(|_| internal_server_error())?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok((StatusCode::CREATED, Json(app.into())))
}

/// GET /apps -- list apps in the current org.
pub async fn list_apps(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<AppResponse>>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let apps: Vec<App> = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 ORDER BY name")
        .bind(auth.org_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok(Json(apps.into_iter().map(Into::into).collect()))
}

/// GET /apps/{name} -- app details.
pub async fn get_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<AppResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    Ok(Json(app.into()))
}

/// DELETE /apps/{name} -- ordered teardown.
pub async fn delete_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_admin(&auth)?;
    scopes::require_scope(&auth, "apps:write")?;
    ensure_management_write_allowed(&state, &auth).await?;
    crate::edge::require_haproxy_integration_enabled().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "tenant edge integration unavailable"})),
        )
    })?;

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

    let mut delete_resources = vec![
        crate::mutation_leases::ResourceFence::dns(&app.domain),
        crate::mutation_leases::ResourceFence::edge(&app.domain),
        crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
        crate::mutation_leases::ResourceFence::kbs_policy(),
        crate::mutation_leases::ResourceFence::edge_config(),
    ];
    let tracked_dns_hostnames: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| internal_server_error())?;
    for hostname in &tracked_dns_hostnames {
        delete_resources.push(crate::mutation_leases::ResourceFence::dns(hostname));
        delete_resources.push(crate::mutation_leases::ResourceFence::edge(hostname));
    }
    if let Some(tee_domain) = app.tee_domain.as_deref() {
        delete_resources.push(crate::mutation_leases::ResourceFence::dns(tee_domain));
        delete_resources.push(crate::mutation_leases::ResourceFence::edge(tee_domain));
    }
    if let Some(custom_domain) = app.custom_domain.as_deref() {
        delete_resources.push(crate::mutation_leases::ResourceFence::dns(custom_domain));
        delete_resources.push(crate::mutation_leases::ResourceFence::edge(custom_domain));
    }
    let mut delete_mutation =
        crate::mutation_leases::claim(&state, app.id, "app_delete", app.id, true, delete_resources)
            .await
            .map_err(|error| match error {
                crate::mutation_leases::MutationLeaseError::Busy => (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": "app mutation already in progress"})),
                ),
                _ => internal_server_error(),
            })?;
    let edge_config_generation = delete_mutation
        .resource_generation(&crate::mutation_leases::ResourceFence::edge_config())
        .ok_or_else(internal_server_error)?;
    let kubernetes_mutation_generation = delete_mutation
        .resource_generation(&crate::mutation_leases::ResourceFence::new(
            "kubernetes_namespace",
            &app.namespace,
        ))
        .ok_or_else(internal_server_error)?;

    // Persist the durable deleting phase before any external teardown. A retry
    // therefore repeats the workload wipe even if token issuance or a later
    // provider step failed. The same transaction terminalizes every queued or
    // leased deployment generation before releasing the app lane.
    let mut phase_tx = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut phase_tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut phase_tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut phase_tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut phase_tx, app.id)
        .await
        .map_err(|_| internal_server_error())?;
    let phase_app: Option<App> =
        sqlx::query_as("SELECT * FROM apps WHERE id = $1 AND org_id = $2 FOR UPDATE")
            .bind(app.id)
            .bind(auth.org_id)
            .fetch_optional(&mut *phase_tx)
            .await
            .map_err(|_| internal_server_error())?;
    let Some(phase_app) = phase_app else {
        phase_tx
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Ok(StatusCode::NO_CONTENT);
    };
    let current_dns_hostnames: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname")
            .bind(phase_app.id)
            .fetch_all(&mut *phase_tx)
            .await
            .map_err(|_| internal_server_error())?;
    if phase_app.domain != app.domain
        || phase_app.tee_domain != app.tee_domain
        || phase_app.custom_domain != app.custom_domain
        || phase_app.namespace != app.namespace
        || phase_app.name != app.name
        || current_dns_hostnames != tracked_dns_hostnames
    {
        delete_mutation
            .finish_in_tx(&mut phase_tx)
            .await
            .map_err(|_| internal_server_error())?;
        phase_tx
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "app resource authority changed; retry deletion"})),
        ));
    }
    sqlx::query(
        "UPDATE apps
            SET status = 'deleting'::app_status_enum,
                updated_at = clock_timestamp()
          WHERE id = $1",
    )
    .bind(phase_app.id)
    .execute(&mut *phase_tx)
    .await
    .map_err(|_| internal_server_error())?;
    match crate::deploy::supersede_incomplete_deployments(&mut phase_tx, phase_app.id).await {
        Ok(_) => {}
        Err(crate::deploy::SupersedeDeploymentError::Busy) => {
            // A deployment mutation is still in progress, so this delete is
            // known-not-applied: only the in-transaction `status = 'deleting'`
            // transition ran, and it is discarded by the rollback below. The
            // delete mutation lease must be released too — leaving it abandoned
            // (Drop only stops the heartbeat; the lock rows persist until
            // quarantine expiry) would block a same-key retry from re-claiming
            // until then, turning the cancel disposition into a self-inflicted
            // busy loop on this app's own abandoned lease.
            phase_tx
                .rollback()
                .await
                .map_err(|_| internal_server_error())?;
            delete_mutation
                .finish()
                .await
                .map_err(|_| internal_server_error())?;
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "deployment mutation is still in progress"})),
            ));
        }
        Err(crate::deploy::SupersedeDeploymentError::Database(_)) => {
            return Err(internal_server_error());
        }
    }
    let signed_policy_revocation =
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut phase_tx)
            .await
            .map_err(|_| internal_server_error())?
            .is_some();
    phase_tx
        .commit()
        .await
        .map_err(|_| internal_server_error())?;

    if signed_policy_revocation {
        delete_mutation
            .guard_provider(crate::kbs::reconcile_pending_signed_policy_artifacts(
                &state.db,
                state.kbs_policy.as_ref(),
                state.runtime_authority,
            ))
            .await
            .map_err(|_| internal_server_error())?
            .map_err(|error| {
                app_delete_failure(phase_app.id, AppDeleteFailure::KbsPolicy, error)
            })?;
    }

    // Hold the generation lane across all external teardown steps. Workers and
    // new deployment acceptance either finish before this point or observe the
    // committed deleting phase and fail closed.
    let mut delete_lane = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::deploy::lock_app_deployment_lane(&mut delete_lane, phase_app.id)
        .await
        .map_err(|_| internal_server_error())?;
    let deleting_app: Option<App> =
        sqlx::query_as("SELECT * FROM apps WHERE id = $1 AND org_id = $2")
            .bind(phase_app.id)
            .bind(auth.org_id)
            .fetch_optional(&mut *delete_lane)
            .await
            .map_err(|_| internal_server_error())?;
    let Some(deleting_app) = deleting_app else {
        delete_lane
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Ok(StatusCode::NO_CONTENT);
    };
    if deleting_app.status != AppStatus::Deleting {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "app deletion phase is invalid"})),
        ));
    }

    delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            request_workload_teardown(&state, &auth, &deleting_app),
        )
        .await
        .map_err(|_| internal_server_error())??;

    if state.dns.is_some() {
        delete_mutation
            .arm_resource_scope_until_reconciled("dns_hostname")
            .await
            .map_err(|_| internal_server_error())?;
    }
    let tracked_dns_cleanup = delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            crate::dns::delete_all_dns_records_for_app(
                &state.db,
                &state.http_client,
                state.dns.as_ref(),
                deleting_app.id,
            ),
        )
        .await
        .map_err(|_| internal_server_error())?;
    if let Err(error) = tracked_dns_cleanup {
        delete_mutation
            .retain_resource_scope_until_reconciled_in_tx(&mut delete_lane, "dns_hostname")
            .await
            .map_err(|_| internal_server_error())?;
        delete_lane
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Err(app_delete_dns_failure(deleting_app.id, error));
    }
    let expected_dns_cleanup = delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            crate::dns::delete_managed_dns_pair_by_hostname(
                &state.db,
                &state.http_client,
                state.dns.as_ref(),
                deleting_app.id,
                &deleting_app.domain,
                deleting_app
                    .tee_domain
                    .as_deref()
                    .unwrap_or(&deleting_app.domain),
            ),
        )
        .await
        .map_err(|_| internal_server_error())?;
    if let Err(error) = expected_dns_cleanup {
        delete_mutation
            .retain_resource_scope_until_reconciled_in_tx(&mut delete_lane, "dns_hostname")
            .await
            .map_err(|_| internal_server_error())?;
        delete_lane
            .commit()
            .await
            .map_err(|_| internal_server_error())?;
        return Err(app_delete_dns_failure(deleting_app.id, error));
    }
    delete_mutation
        .release_confirmed_resource_scope("dns_hostname")
        .await
        .map_err(|_| internal_server_error())?;
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(auth.org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    let app_backend =
        crate::edge::backend_name_for(&org_slug, &deleting_app.name, crate::edge::BackendTag::App)
            .map_err(|error| {
                app_delete_failure(deleting_app.id, AppDeleteFailure::EdgeBackend, error)
            })?;
    let tee_backend =
        crate::edge::backend_name_for(&org_slug, &deleting_app.name, crate::edge::BackendTag::Tee)
            .map_err(|error| {
                app_delete_failure(deleting_app.id, AppDeleteFailure::EdgeBackend, error)
            })?;
    let mut routes_to_remove: Vec<(String, String)> =
        vec![(app_backend.clone(), deleting_app.domain.clone())];
    if let Some(t) = deleting_app.tee_domain.as_deref() {
        routes_to_remove.push((tee_backend.clone(), t.to_string()));
    }
    if let Some(c) = deleting_app.custom_domain.as_deref() {
        routes_to_remove.push((app_backend.clone(), c.to_string()));
    }
    // Include every provider-tracked hostname, not only current app columns.
    // A failed custom-domain replacement can leave the old hostname tracked
    // even though `apps.custom_domain` already points elsewhere.
    for hostname in &tracked_dns_hostnames {
        let backend = if deleting_app.tee_domain.as_deref() == Some(hostname.as_str()) {
            tee_backend.clone()
        } else {
            app_backend.clone()
        };
        routes_to_remove.push((backend, hostname.clone()));
    }
    routes_to_remove.sort();
    routes_to_remove.dedup();
    delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            crate::edge::remove_haproxy_routes(
                &state.db,
                &crate::edge::EdgeRouteConfig::from_env(),
                state.runtime_authority,
                Some(edge_config_generation),
                &routes_to_remove,
            ),
        )
        .await
        .map_err(|_| internal_server_error())?
        .map_err(|error| app_delete_failure(deleting_app.id, AppDeleteFailure::EdgeRoute, error))?;

    let kubernetes_mutation_generation =
        enclava_engine::apply::generation::MutationGeneration::with_authority(
            kubernetes_mutation_generation,
            state.runtime_authority.epoch,
            state.runtime_authority.restore_generation,
        )
        .map_err(|_| internal_server_error())?;
    let kubernetes_client = kube::Client::try_default()
        .await
        .map_err(|error| app_delete_failure(deleting_app.id, AppDeleteFailure::Namespace, error))?;
    let kubernetes_namespaces: kube::Api<k8s_openapi::api::core::v1::Namespace> =
        kube::Api::all(kubernetes_client);
    delete_mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await
        .map_err(|_| internal_server_error())?;
    delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            delete_tenant_namespace(
                kubernetes_namespaces,
                &deleting_app.namespace,
                kubernetes_mutation_generation,
            ),
        )
        .await
        .map_err(|_| internal_server_error())?
        .map_err(|error| app_delete_failure(deleting_app.id, AppDeleteFailure::Namespace, error))?;
    delete_mutation
        .release_confirmed_resource_scope("kubernetes_namespace")
        .await
        .map_err(|_| internal_server_error())?;
    crate::kbs::soft_delete_owner_binding(&state.db, deleting_app.id)
        .await
        .map_err(|error| {
            app_delete_failure(deleting_app.id, AppDeleteFailure::KbsOwnerBinding, error)
        })?;
    crate::kbs::soft_delete_tls_binding(&state.db, state.kbs_policy.as_ref(), deleting_app.id)
        .await
        .map_err(|error| {
            app_delete_failure(deleting_app.id, AppDeleteFailure::KbsTlsBinding, error)
        })?;
    delete_mutation
        .guard_provider_in_tx(
            &mut delete_lane,
            crate::kbs::reconcile_policy(
                &state.db,
                state.kbs_policy.as_ref(),
                state.runtime_authority,
            ),
        )
        .await
        .map_err(|_| internal_server_error())?
        .map_err(|error| app_delete_failure(deleting_app.id, AppDeleteFailure::KbsPolicy, error))?;

    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action)
         VALUES ($1, $2, $3, 'app.delete')",
    )
    .bind(auth.org_id)
    .bind(deleting_app.id)
    .bind(auth.user_id)
    .execute(&mut *delete_lane)
    .await
    .map_err(|_| internal_server_error())?;
    delete_mutation
        .finish_in_tx(&mut delete_lane)
        .await
        .map_err(|_| internal_server_error())?;
    sqlx::query("DELETE FROM apps WHERE id = $1 AND status = 'deleting'::app_status_enum")
        .bind(deleting_app.id)
        .execute(&mut *delete_lane)
        .await
        .map_err(|_| internal_server_error())?;
    delete_lane
        .commit()
        .await
        .map_err(|_| internal_server_error())?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RotateSignerRequest {
    pub subject: String,
    pub issuer: String,
    /// Required when rotating a signer (replacing an existing identity).
    /// Optional when initially setting a signer on an app that has none --
    /// in that case we treat the call as a first-time set, not a rotation,
    /// so users created before signer-on-create shipped can self-recover.
    #[serde(default)]
    pub email_confirmation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignerRotationTokenRequest {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Serialize)]
pub struct SignerRotationTokenResponse {
    pub token: String,
    pub expires_in_seconds: u64,
}

const SIGNER_ROTATION_TOKEN_TTL_SECONDS: u64 = 600;

/// POST /apps/{name}/signer/rotation-token -- issue a short-lived token that
/// authorizes exactly one signer rotation from the currently pinned identity
/// to the requested identity. Session auth only; API keys cannot mint these
/// human-confirmation tokens.
pub async fn issue_signer_rotation_token_route(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<SignerRotationTokenRequest>,
) -> Result<Json<SignerRotationTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_owner(&auth)?;
    scopes::require_scope(&auth, "apps:write")?;

    if auth.api_key.is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "session authentication required for signer rotation token"
            })),
        ));
    }
    ensure_management_write_allowed(&state, &auth).await?;
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;

    let subject = body.subject.trim().to_string();
    let issuer = body.issuer.trim().to_string();
    if subject.is_empty() || issuer.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "subject and issuer are required"})),
        ));
    }

    let app_lookup: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_server_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app_lookup.id)
        .await
        .map_err(|_| internal_server_error())?;
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_owner_role(current_role)?;
    let app: App = sqlx::query_as(
        "SELECT * FROM apps
          WHERE id = $1
            AND org_id = $2
            AND name = $3
            AND status <> 'deleting'::app_status_enum
          FOR UPDATE",
    )
    .bind(app_lookup.id)
    .bind(auth.org_id)
    .bind(&app_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?
    .ok_or((
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "app signer authority is unavailable"})),
    ))?;

    let previous_subject = app
        .signer_identity_subject
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let previous_issuer = app
        .signer_identity_issuer
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let (previous_subject, previous_issuer) = match (previous_subject, previous_issuer) {
        (Some(subject), Some(issuer)) => (subject, issuer),
        (None, None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "signer identity is not set; use initial signer set first"
                })),
            ));
        }
        _ => {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "app signer identity is incomplete"})),
            ));
        }
    };

    let input = SignerRotationTokenInput {
        user_id: auth.user_id,
        org_id: auth.org_id,
        app_id: app.id,
        previous_subject,
        previous_issuer,
        new_subject: subject,
        new_issuer: issuer,
    };
    let token = issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &input,
        Duration::seconds(SIGNER_ROTATION_TOKEN_TTL_SECONDS as i64),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({"error": format!("failed to issue signer rotation token: {e}")}),
            ),
        )
    })?;

    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.signer.rotation_token.issue', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "previous_subject": input.previous_subject,
        "previous_issuer":  input.previous_issuer,
        "new_subject":      input.new_subject,
        "new_issuer":       input.new_issuer,
        "expires_in_seconds": SIGNER_ROTATION_TOKEN_TTL_SECONDS,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?;
    tx.commit().await.map_err(|_| internal_server_error())?;

    Ok(Json(SignerRotationTokenResponse {
        token,
        expires_in_seconds: SIGNER_ROTATION_TOKEN_TTL_SECONDS,
    }))
}

/// PATCH /apps/{name}/signer -- rotate the per-app cosign / Fulcio identity.
/// Owner-only. Requires an email confirmation token tied to the requesting
/// user's verified email address.
pub async fn rotate_signer(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<RotateSignerRequest>,
) -> Result<Json<AppResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_owner(&auth)?;
    scopes::require_scope(&auth, "apps:write")?;
    ensure_management_write_allowed(&state, &auth).await?;
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;

    let subject = body.subject.trim().to_string();
    let issuer = body.issuer.trim().to_string();
    if subject.is_empty() || issuer.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "subject and issuer are required"})),
        ));
    }

    let app_lookup: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_server_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| internal_server_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, auth.org_id)
        .await
        .map_err(|_| internal_server_error())?;
    crate::deploy::lock_app_deployment_lane(&mut tx, app_lookup.id)
        .await
        .map_err(|_| internal_server_error())?;
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, auth.org_id, auth.user_id)
            .await?;
    crate::auth::scopes::require_owner_role(current_role)?;
    let app: App = sqlx::query_as(
        "SELECT * FROM apps
          WHERE id = $1
            AND org_id = $2
            AND name = $3
            AND status <> 'deleting'::app_status_enum
          FOR UPDATE",
    )
    .bind(app_lookup.id)
    .bind(auth.org_id)
    .bind(&app_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?
    .ok_or((
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "app signer authority is unavailable"})),
    ))?;

    let previous_subject = app.signer_identity_subject.clone();
    let previous_issuer = app.signer_identity_issuer.clone();

    let is_initial_set = previous_subject.is_none() && previous_issuer.is_none();
    let confirmation_token = body
        .email_confirmation_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());

    if !is_initial_set && confirmation_token.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "email_confirmation_token is required for signer rotation"}),
            ),
        ));
    }

    if !is_initial_set {
        let expected = SignerRotationTokenInput {
            user_id: auth.user_id,
            org_id: auth.org_id,
            app_id: app.id,
            previous_subject: previous_subject.clone().unwrap_or_default(),
            previous_issuer: previous_issuer.clone().unwrap_or_default(),
            new_subject: subject.clone(),
            new_issuer: issuer.clone(),
        };
        verify_signer_rotation_token(
            state.hmac_key.as_ref(),
            confirmation_token.expect("checked above"),
            &expected,
        )
        .map_err(|_| {
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "invalid email_confirmation_token"})),
            )
        })?;
    }

    sqlx::query(
        "UPDATE apps
         SET signer_identity_subject = $1,
             signer_identity_issuer  = $2,
             signer_identity_set_at  = now(),
             updated_at              = now()
         WHERE id = $3",
    )
    .bind(&subject)
    .bind(&issuer)
    .bind(app.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?;

    // Audit. TODO(phase-2): the rotated signer_identity must be re-rendered
    // into the KBS Rego policy for this app once the Phase 2 policy
    // templates land.
    let action = if is_initial_set {
        "app.signer.set"
    } else {
        "app.signer.rotate"
    };
    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(action)
    .bind(serde_json::json!({
        "previous_subject": previous_subject,
        "previous_issuer":  previous_issuer,
        "new_subject":      &subject,
        "new_issuer":       &issuer,
        "initial_set":      is_initial_set,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|_| internal_server_error())?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| internal_server_error())?;
    tx.commit().await.map_err(|_| internal_server_error())?;

    Ok(Json(app.into()))
}

#[cfg(test)]
#[path = "apps/tests/mod.rs"]
mod tests;
