use super::*;

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
    #[serde(default)]
    pub egress_allowlist: Vec<crate::routes::apps::CreateEgressAllowRule>,
    #[serde(default = "crate::routes::apps::default_egress_mode")]
    pub egress_mode: String,
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
    #[serde(default)]
    pub workload_security_profile: Option<String>,
    #[serde(default)]
    pub log_encryption: Option<LogEncryptionConfig>,
}

#[derive(Debug, Serialize)]
pub struct GenericDeploymentResponse {
    pub deployment_id: Uuid,
    pub app_id: Uuid,
    pub app_name: String,
    pub app_domain: String,
    pub tee_url: Option<String>,
    pub image: Option<String>,
    pub image_digest: Option<String>,
    pub source_provider: Option<String>,
    pub source_repository: Option<String>,
    pub status: String,
    /// Current status of the app that owns this deployment.
    ///
    /// This is intentionally distinct from `status`, which describes the
    /// requested deployment and may refer to an older deployment.
    pub app_status: String,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct GenericConfigTokenResponse {
    pub deployment_id: Uuid,
    pub token: String,
    pub tee_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_resolve_ip: Option<std::net::IpAddr>,
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
            app_id: app.id,
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
            app_status: format!("{:?}", app.status).to_lowercase(),
            error_message: deployment.error_message,
            created_at: deployment.created_at,
            completed_at: deployment.completed_at,
        }
    }
}

pub(super) fn json_error(
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

    let log_encryption = validate_log_encryption_config(body.log_encryption.clone())?;
    let descriptor = body.descriptor;
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
            descriptor,
            log_encryption: log_encryption.clone(),
        })
        .await
        .map_err(signing_error_response)?;

    Ok(Json(AgentPolicyResponse {
        agent_policy_text: response.agent_policy_text,
        agent_policy_sha256: response.agent_policy_sha256,
        genpolicy_version_pin: response.genpolicy_version_pin,
        log_encryption,
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

    let normalized_egress_allowlist =
        crate::routes::apps::validate_egress_allowlist(&body.app.egress_allowlist)
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    let normalized_egress_mode = crate::routes::apps::validate_egress_mode(&body.app.egress_mode)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;

    let app = match fetch_app_by_name(&state, auth.org_id, &body.app.name).await? {
        Some(app) => {
            ensure_generic_app_metadata(
                &state,
                app,
                GenericAppMetadata {
                    provider: body.source.provider,
                    repository: &body.source.repository,
                    subject: &body.signing.subject,
                    issuer: &body.signing.issuer,
                    egress_allowlist: &normalized_egress_allowlist,
                    egress_mode: normalized_egress_mode,
                },
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
                egress_allowlist: body.app.egress_allowlist.clone(),
                egress_mode: normalized_egress_mode.as_str().to_string(),
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
        workload_security_profile: body.security.workload_security_profile,
        log_encryption: body.security.log_encryption.clone(),
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
        tee_resolve_ip: token.tee_resolve_ip,
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

pub(super) fn validate_external_id(
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

pub(super) fn ensure_idempotent_retry_matches(
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
    let requested_egress =
        crate::routes::apps::validate_egress_allowlist(&body.app.egress_allowlist)
            .map_err(|_| idempotency_conflict("app.egress_allowlist"))?;
    if app.egress_allowlist.0 != requested_egress {
        return Err(idempotency_conflict("app.egress_allowlist"));
    }
    let requested_egress_mode = crate::routes::apps::validate_egress_mode(&body.app.egress_mode)
        .map_err(|_| idempotency_conflict("app.egress_mode"))?;
    if app.egress_mode != requested_egress_mode.as_str() {
        return Err(idempotency_conflict("app.egress_mode"));
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
    let existing_profile = deployment
        .spec_snapshot
        .get("workload_security_profile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("restricted");
    let requested_profile = body
        .security
        .workload_security_profile
        .as_deref()
        .unwrap_or("restricted");
    if existing_profile != requested_profile {
        return Err(idempotency_conflict("security.workload_security_profile"));
    }
    let existing_log_encryption = deployment
        .spec_snapshot
        .get("log_encryption")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let requested_log_encryption =
        serde_json::to_value(&body.security.log_encryption).unwrap_or(serde_json::Value::Null);
    if existing_log_encryption != requested_log_encryption {
        return Err(idempotency_conflict("security.log_encryption"));
    }
    Ok(())
}

fn idempotency_conflict(field: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    json_error(
        StatusCode::CONFLICT,
        format!("external_id already exists with different {field}"),
    )
}

struct GenericAppMetadata<'a> {
    provider: SourceProvider,
    repository: &'a str,
    subject: &'a str,
    issuer: &'a str,
    egress_allowlist: &'a [enclava_engine::types::EgressRule],
    egress_mode: enclava_engine::types::EgressMode,
}

async fn ensure_generic_app_metadata(
    state: &AppState,
    app: App,
    metadata: GenericAppMetadata<'_>,
) -> Result<App, (StatusCode, Json<serde_json::Value>)> {
    let provider_str = metadata.provider.as_str();
    if let Some(existing) = app.source_provider.as_deref()
        && existing != provider_str
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "app source_provider does not match deployment source provider",
        ));
    }
    if let Some(existing) = app.source_repository.as_deref()
        && existing != metadata.repository
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
            if existing_subject == metadata.subject && existing_issuer == metadata.issuer => {}
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
                egress_allowlist = $5,
                egress_mode = $6,
                updated_at = now()
          WHERE id = $7
          RETURNING *",
    )
    .bind(provider_str)
    .bind(metadata.repository)
    .bind(metadata.subject)
    .bind(metadata.issuer)
    .bind(sqlx::types::Json(metadata.egress_allowlist.to_vec()))
    .bind(metadata.egress_mode.as_str())
    .bind(app.id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error"))
}
