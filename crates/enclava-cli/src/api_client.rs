use crate::api_types::*;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

/// Typed HTTP client for the Enclava Platform API.
pub struct ApiClient {
    base_url: String,
    http: reqwest::Client,
    auth_token: Option<String>,
    org_hint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("not authenticated -- run `enclava login` first")]
    NotAuthenticated,
}

impl ApiClient {
    /// Create a new API client.
    pub fn new(base_url: &str, auth_token: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
            auth_token,
            org_hint: None,
        }
    }

    /// Create a client from CLI config and credentials.
    pub fn from_config(
        config: &crate::config::CliConfig,
        creds: &crate::config::Credentials,
    ) -> Self {
        let mut client = Self::new(&config.api_url, creds.auth_token().map(|s| s.to_string()));
        client.org_hint = config
            .org
            .as_ref()
            .map(|org| org.trim().to_string())
            .filter(|org| !org.is_empty());
        client
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_headers(&self) -> Result<HeaderMap, ApiError> {
        let token = self.auth_token.as_ref().ok_or(ApiError::NotAuthenticated)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| ApiError::Api {
                status: 0,
                message: format!("invalid auth token: {e}"),
            })?,
        );
        if let Some(org) = &self.org_hint {
            headers.insert(
                "X-Enclava-Org",
                HeaderValue::from_str(org).map_err(|e| ApiError::Api {
                    status: 0,
                    message: format!("invalid org header: {e}"),
                })?,
            );
        }
        Ok(headers)
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response, ApiError> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let status_code = status.as_u16();
            let message = match resp.json::<ApiErrorBody>().await {
                Ok(body) => {
                    let mut message = body
                        .message
                        .or(body.detail)
                        .unwrap_or_else(|| body.error.clone());
                    if let Some(reason) = body.reason {
                        message = format!("{message} ({reason})");
                    }
                    if message == body.error {
                        message
                    } else {
                        format!("{}: {message}", body.error)
                    }
                }
                Err(_) => format!("HTTP {status_code}"),
            };
            Err(ApiError::Api {
                status: status_code,
                message,
            })
        }
    }

    // --- Auth ---

    pub async fn signup(&self, req: &SignupRequest) -> Result<AuthResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/auth/signup"))
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<AuthResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/auth/login"))
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn start_device_login(
        &self,
        req: &DeviceLoginStartRequest,
    ) -> Result<DeviceLoginStartResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/auth/device/start"))
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn poll_device_login(
        &self,
        req: &DeviceLoginPollRequest,
    ) -> Result<DeviceLoginPollResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/auth/device/poll"))
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_current_user(&self) -> Result<CurrentUserResponse, ApiError> {
        let resp = self
            .http
            .get(self.url("/users/me"))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // --- Apps ---

    pub async fn create_app(&self, req: &CreateAppRequest) -> Result<AppResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/apps"))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn list_apps(&self) -> Result<Vec<AppResponse>, ApiError> {
        let resp = self
            .http
            .get(self.url("/apps"))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_app(&self, name: &str) -> Result<AppResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{name}")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn set_signer(
        &self,
        app_name: &str,
        req: &SetSignerRequest,
    ) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .http
            .patch(self.url(&format!("/apps/{app_name}/signer")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn issue_signer_rotation_token(
        &self,
        app_name: &str,
        req: &SignerRotationTokenRequest,
    ) -> Result<SignerRotationTokenResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/signer/rotation-token")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn delete_app(&self, name: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .delete(self.url(&format!("/apps/{name}")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // --- Deployments ---

    pub async fn deploy(
        &self,
        app_name: &str,
        req: &DeployRequest,
    ) -> Result<DeployResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/deploy")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn list_deployments(&self, app_name: &str) -> Result<Vec<DeploymentEntry>, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/deployments")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn rollback(
        &self,
        app_name: &str,
        req: &RollbackRequest,
    ) -> Result<RollbackResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/rollback")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn generate_agent_policy(
        &self,
        app_name: &str,
        req: &AgentPolicyRequest,
    ) -> Result<AgentPolicyResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/agent-policy")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn deployment_context(&self) -> Result<DeploymentContextResponse, ApiError> {
        let resp = self
            .http
            .get(self.url("/platform/deployment-context"))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // --- Hosted Templates ---

    pub async fn list_templates(&self) -> Result<Vec<HostedTemplate>, ApiError> {
        let resp = self
            .http
            .get(self.url("/templates"))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn create_template_instance(
        &self,
        req: &CreateTemplateInstanceRequest,
    ) -> Result<TemplateInstanceResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/template-instances"))
            .headers(self.auth_headers()?)
            .header(
                "Idempotency-Key",
                format!(
                    "template-instance-{}-{}",
                    req.template_slug, req.instance_name
                ),
            )
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // --- Status ---

    pub async fn get_status(&self, app_name: &str) -> Result<AppStatus, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/status")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_logs(
        &self,
        app_name: &str,
        follow: bool,
    ) -> Result<reqwest::Response, ApiError> {
        let mut url = self.url(&format!("/apps/{app_name}/logs"));
        if follow {
            url.push_str("?follow=true");
        }
        let resp = self
            .http
            .get(&url)
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp)
    }

    // --- Config ---

    pub async fn get_config_token(&self, app_name: &str) -> Result<ConfigTokenResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/config-token")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn list_config_keys(&self, app_name: &str) -> Result<ConfigKeysResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/config")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn sync_config_key(
        &self,
        app_name: &str,
        key: &str,
        deleted: bool,
    ) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/config/sync")))
            .headers(self.auth_headers()?)
            .json(&serde_json::json!({
                "key_name": key,
                "deleted": deleted,
            }))
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    pub async fn delete_config_meta(&self, app_name: &str, key: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .delete(self.url(&format!("/apps/{app_name}/config/{key}/meta")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // --- Domains ---

    pub async fn create_domain_challenge(
        &self,
        app_name: &str,
        req: &CreateChallengeRequest,
    ) -> Result<ChallengeResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/domains")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn verify_domain(
        &self,
        app_name: &str,
        domain: &str,
    ) -> Result<VerifyResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/apps/{app_name}/domains/{domain}/verify")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_domain(&self, app_name: &str) -> Result<DomainResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/domain")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn delete_custom_domain(&self, app_name: &str, domain: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .delete(self.url(&format!("/apps/{app_name}/domains/{domain}")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // --- Unlock ---

    pub async fn get_unlock_endpoint(
        &self,
        app_name: &str,
    ) -> Result<UnlockEndpointResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/unlock/endpoint")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_unlock_status(
        &self,
        app_name: &str,
    ) -> Result<UnlockStatusResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/apps/{app_name}/unlock/status")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn update_unlock_mode(
        &self,
        app_name: &str,
        req: &UpdateUnlockModeRequest,
    ) -> Result<UpdateUnlockModeResponse, ApiError> {
        let resp = self
            .http
            .put(self.url(&format!("/apps/{app_name}/unlock/mode")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    // --- Orgs ---

    pub async fn create_org(&self, req: &CreateOrgRequest) -> Result<OrgResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/orgs"))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn list_orgs(&self) -> Result<Vec<OrgResponse>, ApiError> {
        let resp = self
            .http
            .get(self.url("/orgs"))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn invite_member(&self, org_name: &str, req: &InviteRequest) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url(&format!("/orgs/{org_name}/invite")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    pub async fn list_members(&self, org_name: &str) -> Result<Vec<MemberResponse>, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/orgs/{org_name}/members")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn register_public_key(
        &self,
        req: &RegisterPublicKeyRequest,
    ) -> Result<RegisterPublicKeyResponse, ApiError> {
        let resp = self
            .http
            .post(self.url("/users/me/public-keys"))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn put_org_keyring(
        &self,
        org_name: &str,
        req: &PutOrgKeyringRequest,
    ) -> Result<OrgKeyringResponse, ApiError> {
        let resp = self
            .http
            .put(self.url(&format!("/orgs/{org_name}/keyring")))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn get_org_keyring(&self, org_name: &str) -> Result<OrgKeyringResponse, ApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/orgs/{org_name}/keyring")))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn bootstrap_signing_service_owner(
        &self,
        org_name: &str,
        req: &BootstrapSigningServiceRequest,
    ) -> Result<BootstrapSigningServiceResponse, ApiError> {
        let resp = self
            .http
            .post(self.url(&format!(
                "/orgs/{org_name}/keyring/bootstrap-signing-service"
            )))
            .headers(self.auth_headers()?)
            .json(req)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }
}
