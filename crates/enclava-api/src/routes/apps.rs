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
use crate::models::App;
use crate::source_provider::{
    SourceProvider, validate_signing_identity, validate_source_repository,
};
use crate::state::{AppState, CapManagementMode};

/// Helper function for consistent internal server error responses
fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
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

async fn delete_tenant_namespace(namespace: &str) -> Result<(), kube::Error> {
    let client = kube::Client::try_default().await?;
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);
    match api
        .delete(namespace, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

fn workload_teardown_instance_id(app: &App) -> String {
    format!("{}-{}", app.namespace, app.name)
}

async fn request_workload_teardown(
    state: &AppState,
    auth: &AuthContext,
    app: &App,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let token = crate::auth::jwt::issue_config_token(
        &state.signing_key,
        auth.user_id,
        auth.org_id,
        app.id,
        &workload_teardown_instance_id(app),
        vec!["teardown".to_string()],
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to issue teardown token: {e}")})),
        )
    })?;

    let domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    let url = format!(
        "https://{}/.well-known/confidential/teardown",
        domain.trim_end_matches('/')
    );
    let response = state
        .tee_http_client
        .post(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "failed to contact workload teardown endpoint",
                    "detail": e.to_string(),
                })),
            )
        })?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let status_code = status.as_u16();
    let body = response.text().await.unwrap_or_default();
    Err((
        if matches!(status_code, 409 | 423) {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_GATEWAY
        },
        Json(serde_json::json!({
            "error": "workload teardown failed",
            "status": status_code,
            "body": body,
        })),
    ))
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
}

fn default_unlock_mode() -> String {
    "password".to_string()
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

/// POST /apps -- create a new app.
pub async fn create_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    ensure_management_write_allowed(&state, &auth).await?;

    validate_app_name(&body.name).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    validate_source_metadata(
        body.source_provider,
        body.source_repository.as_deref(),
        body.signer_identity_subject.as_deref(),
        body.signer_identity_issuer.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;

    // Enforce core entitlement app limit.
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
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

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
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
        })?;

    let app_host =
        enclava_common::hostnames::app_hostname(&body.name, &org.cust_slug, &state.platform_domain)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("invalid app hostname: {e}")})),
                )
            })?;
    let tee_host = enclava_common::hostnames::tee_hostname(
        &body.name,
        &org.cust_slug,
        &state.tee_domain_suffix,
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid tee hostname: {e}")})),
        )
    })?;

    let signer_set_at =
        if body.signer_identity_subject.is_some() || body.signer_identity_issuer.is_some() {
            Some(chrono::Utc::now())
        } else {
            None
        };

    let result = sqlx::query(
        "INSERT INTO apps (id, org_id, name, namespace, instance_id, tenant_id,
        service_account, bootstrap_owner_pubkey_hash, tenant_instance_identity_hash,
         unlock_mode, domain, tee_domain,
         signer_identity_subject, signer_identity_issuer, signer_identity_set_at,
         source_provider, source_repository)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11, $12, $13, $14, $15, $16, $17)",
    )
    .bind(app_id)
    .bind(auth.org_id)
    .bind(&body.name)
    .bind(&namespace)
    .bind(&instance_id)
    .bind(&tenant_id)
    .bind(&service_account)
    .bind(&pubkey_hash)
    .bind(&identity_hash)
    .bind(&body.unlock_mode)
    .bind(&app_host)
    .bind(&tee_host)
    .bind(body.signer_identity_subject.as_deref())
    .bind(body.signer_identity_issuer.as_deref())
    .bind(signer_set_at)
    .bind(body.source_provider.map(SourceProvider::as_str))
    .bind(body.source_repository.as_deref())
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "app name already taken in this org"})),
            ));
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("database error: {}", e)})),
        ));
    }

    // Insert default resources
    sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
        .bind(app_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    if let Err(e) = crate::dns::ensure_dns_pair(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app_id,
        &app_host,
        &tee_host,
    )
    .await
    {
        let _ = sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&state.db)
            .await;
        return Err(dns_error_response(e));
    }

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.create', $4)",
    )
    .bind(auth.org_id)
    .bind(app_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"name": &body.name, "unlock_mode": &body.unlock_mode}))
    .execute(&state.db)
    .await;

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

    request_workload_teardown(&state, &auth, &app).await?;

    // Mark as deleting after workload-owned KBS material has been removed.
    sqlx::query("UPDATE apps SET status = 'deleting', updated_at = now() WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    crate::dns::delete_all_dns_records_for_app(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
    )
    .await
    .map_err(dns_error_response)?;

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
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::App).map_err(
            |e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("invalid app name: {}", e)})),
                )
            },
        )?;
    let tee_backend =
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::Tee).map_err(
            |e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("invalid app name: {}", e)})),
                )
            },
        )?;
    let mut routes_to_remove: Vec<(String, String)> =
        vec![(app_backend.clone(), app.domain.clone())];
    if let Some(t) = app.tee_domain.as_deref() {
        routes_to_remove.push((tee_backend, t.to_string()));
    }
    if let Some(c) = app.custom_domain.as_deref() {
        routes_to_remove.push((app_backend, c.to_string()));
    }
    crate::edge::remove_haproxy_routes(
        &state.db,
        &crate::edge::EdgeRouteConfig::from_env(),
        &routes_to_remove,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(
                serde_json::json!({"error": format!("failed to remove tenant edge route: {}", e)}),
            ),
        )
    })?;

    delete_tenant_namespace(&app.namespace).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("failed to delete tenant namespace: {}", e)})),
        )
    })?;

    crate::kbs::soft_delete_owner_binding(&state.db, app.id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("failed to remove KBS owner binding: {}", e)})),
            )
        })?;
    crate::kbs::soft_delete_tls_binding(&state.db, state.kbs_policy.as_ref(), app.id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("failed to remove KBS TLS binding: {}", e)})),
            )
        })?;
    crate::kbs::reconcile_policy(&state.db, state.kbs_policy.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({"error": format!("failed to reconcile KBS policy: {}", e)}),
                ),
            )
        })?;

    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app.id)
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
        "INSERT INTO audit_log (org_id, app_id, user_id, action) VALUES ($1, $2, $3, 'app.delete')",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await;

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

    let subject = body.subject.trim().to_string();
    let issuer = body.issuer.trim().to_string();
    if subject.is_empty() || issuer.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "subject and issuer are required"})),
        ));
    }

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_server_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
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

    let _ = sqlx::query(
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
    .execute(&state.db)
    .await;

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

    let subject = body.subject.trim().to_string();
    let issuer = body.issuer.trim().to_string();
    if subject.is_empty() || issuer.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "subject and issuer are required"})),
        ));
    }

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_server_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
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
    .execute(&state.db)
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
    let _ = sqlx::query(
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
    .execute(&state.db)
    .await;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| internal_server_error())?;

    Ok(Json(app.into()))
}

#[cfg(test)]
#[path = "apps/tests/mod.rs"]
mod tests;
