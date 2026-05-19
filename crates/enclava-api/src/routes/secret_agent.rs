//! Secret Agent hosted-Hermes provisioning compatibility API.
//!
//! Secret Agent deliberately has a smaller model than CAP: it asks for one
//! hosted Hermes deployment and expects CAP to return stable refs and a public
//! workspace URL. These routes translate that request into CAP's native
//! authenticated org/app/deploy/config-token model.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::auth::scopes;
use crate::models::{App, Deployment};
use crate::routes::{apps, config, deployments};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SecretAgentCreateDeploymentRequest {
    pub account_id: Uuid,
    pub deployment_id: Uuid,
    pub tier_id: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub workload_ref: Option<String>,
    #[serde(default)]
    pub manifest_ref: Option<String>,
    pub signer_identity_subject: String,
    pub signer_identity_issuer: String,
}

#[derive(Debug, Serialize)]
pub struct SecretAgentDeploymentResponse {
    pub deployment_id: Uuid,
    pub status: String,
    pub bootstrap_state: String,
    pub tracking_id: Option<String>,
    pub app_ref: Option<String>,
    pub deployment_ref: Option<String>,
    pub domain_ref: Option<String>,
    pub hermes_workspace_url: Option<String>,
    pub image_ref: Option<String>,
    pub manifest_ref: Option<String>,
    pub attestation_ref: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretAgentConfigTokenResponse {
    pub deployment_id: Uuid,
    pub token: String,
    pub tee_url: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// POST /v1/deployments -- Secret Agent creates a hosted Hermes CAP app.
pub async fn create_deployment(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<SecretAgentCreateDeploymentRequest>,
) -> Result<(StatusCode, Json<SecretAgentDeploymentResponse>), (StatusCode, Json<serde_json::Value>)>
{
    scopes::require_app_write(&auth)?;

    let image = body
        .image
        .as_deref()
        .or(body.workload_ref.as_deref())
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "image is required"})),
        ))?;

    if let Some(existing) =
        find_secret_agent_deployment(&state, auth.org_id, body.deployment_id).await?
    {
        return Ok((
            StatusCode::OK,
            Json(response_from_parts(
                body.deployment_id,
                &existing.app,
                Some(&existing.deployment),
                Some(image.to_string()),
                body.manifest_ref,
                Some("attestation-policy:cap-native".to_string()),
            )),
        ));
    }

    let app_name = secret_agent_app_name(body.deployment_id);
    let app = match fetch_app(&state, auth.org_id, &app_name).await? {
        Some(app) => app,
        None => {
            let create = apps::CreateAppRequest {
                name: app_name.clone(),
                unlock_mode: "auto".to_string(),
                bootstrap_pubkey_hash: None,
                signer_identity_subject: Some(body.signer_identity_subject.clone()),
                signer_identity_issuer: Some(body.signer_identity_issuer.clone()),
            };
            let (_, Json(created)) =
                apps::create_app(auth.clone(), State(state.clone()), Json(create)).await?;
            fetch_app(&state, auth.org_id, &created.name)
                .await?
                .ok_or_else(internal_server_error)?
        }
    };

    let deploy = deployments::DeployRequest {
        image: image.to_string(),
        container_name: Some("hermes-gateway".to_string()),
        resources: None,
        customer_descriptor_blob: None,
        org_keyring_blob: None,
        signed_policy_artifact: None,
    };
    let (_, Json(deployed)) = deployments::deploy(
        auth,
        State(state.clone()),
        Path(app.name.clone()),
        Json(deploy),
    )
    .await?;
    mark_secret_agent_deployment(
        &state,
        deployed.deployment_id,
        body.deployment_id,
        &body.tier_id,
    )
    .await?;

    let deployment: Deployment = sqlx::query_as("SELECT * FROM deployments WHERE id = $1")
        .bind(deployed.deployment_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| internal_server_error())?;

    Ok((
        StatusCode::CREATED,
        Json(response_from_parts(
            body.deployment_id,
            &app,
            Some(&deployment),
            Some(image.to_string()),
            body.manifest_ref,
            Some("attestation-policy:cap-native".to_string()),
        )),
    ))
}

/// GET /v1/deployments/{deployment_id}/status -- Secret Agent status poll.
pub async fn deployment_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> Result<Json<SecretAgentDeploymentResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "apps:read")?;
    let found = find_secret_agent_deployment(&state, auth.org_id, deployment_id)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "deployment not found"})),
        ))?;

    Ok(Json(response_from_parts(
        deployment_id,
        &found.app,
        Some(&found.deployment),
        latest_image_for_app(&state, found.app.id).await?,
        latest_manifest_ref(Some(&found.deployment)),
        Some("attestation-policy:cap-native".to_string()),
    )))
}

/// POST /v1/deployments/{deployment_id}/config-token -- Secret Agent config bridge.
pub async fn config_token(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(deployment_id): Path<Uuid>,
) -> Result<Json<SecretAgentConfigTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let found = find_secret_agent_deployment(&state, auth.org_id, deployment_id)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "deployment not found"})),
        ))?;
    let Json(token) =
        config::issue_config_token_route(auth, State(state), Path(found.app.name.clone())).await?;
    Ok(Json(SecretAgentConfigTokenResponse {
        deployment_id,
        token: token.token,
        tee_url: token.tee_url,
        expires_at: Utc::now() + Duration::seconds(token.expires_in_seconds as i64),
    }))
}

struct FoundSecretAgentDeployment {
    app: App,
    deployment: Deployment,
}

async fn find_secret_agent_deployment(
    state: &AppState,
    org_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<FoundSecretAgentDeployment>, (StatusCode, Json<serde_json::Value>)> {
    let app_name = secret_agent_app_name(deployment_id);
    let Some(app) = fetch_app(state, org_id, &app_name).await? else {
        return Ok(None);
    };

    let Some(deployment) = sqlx::query_as(
        "SELECT d.*
           FROM deployments d
          WHERE d.app_id = $1
            AND d.spec_snapshot->>'secret_agent_deployment_id' = $2
          ORDER BY d.created_at DESC
          LIMIT 1",
    )
    .bind(app.id)
    .bind(deployment_id.to_string())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| internal_server_error())?
    else {
        return Ok(None);
    };

    Ok(Some(FoundSecretAgentDeployment { app, deployment }))
}

async fn fetch_app(
    state: &AppState,
    org_id: Uuid,
    app_name: &str,
) -> Result<Option<App>, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(org_id)
        .bind(app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_server_error())
}

async fn mark_secret_agent_deployment(
    state: &AppState,
    cap_deployment_id: Uuid,
    secret_agent_deployment_id: Uuid,
    tier_id: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    sqlx::query(
        "UPDATE deployments
            SET spec_snapshot =
                jsonb_set(
                    jsonb_set(
                        COALESCE(spec_snapshot, '{}'::jsonb),
                        '{secret_agent_deployment_id}',
                        to_jsonb($2::text),
                        true
                    ),
                    '{secret_agent_tier_id}',
                    to_jsonb($3::text),
                    true
                )
          WHERE id = $1",
    )
    .bind(cap_deployment_id)
    .bind(secret_agent_deployment_id.to_string())
    .bind(tier_id)
    .execute(&state.db)
    .await
    .map_err(|_| internal_server_error())?;
    Ok(())
}

async fn latest_image_for_app(
    state: &AppState,
    app_id: Uuid,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query_scalar(
        "SELECT image_ref
           FROM app_containers
          WHERE app_id = $1 AND is_primary = true
          ORDER BY id
          LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| internal_server_error())
}

fn response_from_parts(
    secret_agent_deployment_id: Uuid,
    app: &App,
    deployment: Option<&Deployment>,
    image_ref: Option<String>,
    manifest_ref: Option<String>,
    attestation_ref: Option<String>,
) -> SecretAgentDeploymentResponse {
    let (status, bootstrap_state) = deployment
        .map(|deployment| secret_agent_status_pair(&format!("{:?}", deployment.status)))
        .unwrap_or(("provisioning".to_string(), "requested".to_string()));
    let domain = app
        .custom_domain
        .clone()
        .unwrap_or_else(|| app.domain.clone());
    SecretAgentDeploymentResponse {
        deployment_id: secret_agent_deployment_id,
        status,
        bootstrap_state,
        tracking_id: deployment.map(|deployment| deployment.id.to_string()),
        app_ref: Some(app.name.clone()),
        deployment_ref: deployment.map(|deployment| deployment.id.to_string()),
        domain_ref: Some(domain.clone()),
        hermes_workspace_url: Some(format!("https://{domain}")),
        image_ref,
        manifest_ref,
        attestation_ref,
    }
}

fn latest_manifest_ref(deployment: Option<&Deployment>) -> Option<String> {
    deployment
        .and_then(|deployment| deployment.manifest_hash.clone())
        .map(|hash| format!("manifest:{hash}"))
}

fn secret_agent_status_pair(cap_status: &str) -> (String, String) {
    match cap_status.to_ascii_lowercase().as_str() {
        "healthy" => ("ready".to_string(), "complete".to_string()),
        "failed" => ("failed".to_string(), "failed".to_string()),
        "rolledback" | "rolled_back" => ("failed".to_string(), "rolled_back".to_string()),
        "pending" => ("provisioning".to_string(), "requested".to_string()),
        "applying" | "watching" => ("provisioning".to_string(), "applying".to_string()),
        _ => ("provisioning".to_string(), "unknown".to_string()),
    }
}

fn secret_agent_app_name(deployment_id: Uuid) -> String {
    let simple = deployment_id.simple().to_string();
    format!("hermes-{}", &simple[..20])
}

fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_name_is_stable_and_valid_for_cap() {
        let deployment_id = Uuid::parse_str("019e3560-9096-70d2-900b-a9f9aaeca45e").unwrap();
        let app_name = secret_agent_app_name(deployment_id);
        assert_eq!(app_name, "hermes-019e3560909670d2900b");
        assert!(app_name.len() <= 32);
        assert!(
            app_name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        );
    }

    #[test]
    fn cap_statuses_map_to_secret_agent_states() {
        assert_eq!(
            secret_agent_status_pair("Healthy"),
            ("ready".to_string(), "complete".to_string())
        );
        assert_eq!(
            secret_agent_status_pair("Applying"),
            ("provisioning".to_string(), "applying".to_string())
        );
        assert_eq!(
            secret_agent_status_pair("Pending"),
            ("provisioning".to_string(), "requested".to_string())
        );
        assert_eq!(
            secret_agent_status_pair("Failed"),
            ("failed".to_string(), "failed".to_string())
        );
    }
}
