//! Client and persistence adapter for the platform policy signing service.
//!
//! CAP does not author Rego here. It forwards the customer-signed deployment
//! descriptor and owner-signed org keyring to the signing service, then stores
//! the returned signed policy artifact for workload-attested fetches.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use enclava_common::descriptor::{DeploymentDescriptor, descriptor_core_hash};
use enclava_engine::manifest::containers::ENCLAVA_WAIT_EXEC_PATH;
use enclava_engine::types::{GeneratedAgentPolicy, WorkloadArtifactBinding};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::App;

const DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS: u64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum SigningServiceError {
    #[error("customer_descriptor_blob and org_keyring_blob must be provided together")]
    PartialBlobs,
    #[error("signed_policy_artifact requires customer_descriptor_blob and org_keyring_blob")]
    ArtifactWithoutBlobs,
    #[error("invalid signing service URL: {0}")]
    InvalidUrl(String),
    #[error("invalid signing service timeout: {0}")]
    InvalidTimeout(String),
    #[error("blob decode error: {0}")]
    Blob(String),
    #[error("signing artifact does not match deployment: {0}")]
    Mismatch(String),
    #[error("signed policy artifact signature verification failed")]
    InvalidSignature,
    #[error("signing service HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("signing service rejected request with status {status}: {body}")]
    Upstream {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct SigningServiceClient {
    base_url: Url,
    bearer_token: Option<String>,
    http: reqwest::Client,
}

impl SigningServiceClient {
    pub fn new(
        base_url: String,
        bearer_token: Option<String>,
    ) -> Result<Self, SigningServiceError> {
        let timeout = signing_service_timeout_from_env()?;
        Self::new_with_timeout(base_url, bearer_token, timeout)
    }

    pub fn new_with_timeout(
        base_url: String,
        bearer_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self, SigningServiceError> {
        let mut base_url = Url::parse(&base_url)
            .map_err(|err| SigningServiceError::InvalidUrl(err.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(SigningServiceError::InvalidUrl(
                "scheme must be http or https".to_string(),
            ));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        Ok(Self {
            base_url,
            bearer_token,
            http,
        })
    }

    pub async fn sign(
        &self,
        request: &SignRequest,
    ) -> Result<SignedPolicyArtifact, SigningServiceError> {
        let url = self
            .base_url
            .join("sign")
            .map_err(|err| SigningServiceError::InvalidUrl(err.to_string()))?;
        let mut builder = self.http.post(url).json(request);
        if let Some(token) = self.bearer_token.as_deref() {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SigningServiceError::Upstream { status, body });
        }
        Ok(response.json().await?)
    }

    pub async fn agent_policy(
        &self,
        request: &AgentPolicyRequest,
    ) -> Result<AgentPolicyResponse, SigningServiceError> {
        let url = self
            .base_url
            .join("agent-policy")
            .map_err(|err| SigningServiceError::InvalidUrl(err.to_string()))?;
        let mut builder = self.http.post(url).json(request);
        if let Some(token) = self.bearer_token.as_deref() {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SigningServiceError::Upstream { status, body });
        }
        Ok(response.json().await?)
    }

    pub async fn bootstrap_org(
        &self,
        request: &BootstrapOrgRequest,
    ) -> Result<BootstrapOrgResponse, SigningServiceError> {
        let url = self
            .base_url
            .join("bootstrap-org")
            .map_err(|err| SigningServiceError::InvalidUrl(err.to_string()))?;
        let mut builder = self.http.post(url).json(request);
        if let Some(token) = self.bearer_token.as_deref() {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SigningServiceError::Upstream { status, body });
        }
        Ok(response.json().await?)
    }
}

fn signing_service_timeout_from_env() -> Result<Duration, SigningServiceError> {
    parse_signing_service_timeout(std::env::var("PLATFORM_SIGNING_SERVICE_TIMEOUT_SECONDS").ok())
}

fn parse_signing_service_timeout(raw: Option<String>) -> Result<Duration, SigningServiceError> {
    let Some(raw) = raw else {
        return Ok(Duration::from_secs(DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS));
    };
    let seconds = raw.parse::<u64>().map_err(|err| {
        SigningServiceError::InvalidTimeout(format!(
            "PLATFORM_SIGNING_SERVICE_TIMEOUT_SECONDS must be an integer number of seconds: {err}"
        ))
    })?;
    if seconds == 0 {
        return Err(SigningServiceError::InvalidTimeout(
            "PLATFORM_SIGNING_SERVICE_TIMEOUT_SECONDS must be greater than zero".to_string(),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

#[derive(Debug, Serialize)]
pub struct AgentPolicyRequest {
    pub descriptor: DeploymentDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicyResponse {
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
}

#[derive(Debug, Serialize)]
pub struct BootstrapOrgRequest {
    pub org_id: Uuid,
    pub owner_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapOrgResponse {
    pub org_id: Uuid,
    pub state: String,
    pub owner_pubkey_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct SignRequest {
    pub app_id: Uuid,
    pub deploy_id: Uuid,
    pub platform_release_version: String,
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyArtifact {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    pub rego_sha256: String,
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub signature: String,
    pub verify_pubkey_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_keyring: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub app_id: String,
    pub deploy_id: String,
    pub descriptor_core_hash: String,
    pub descriptor_signing_pubkey: String,
    pub platform_release_version: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
    pub signed_at: String,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct DeploymentSigningArtifacts {
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
    pub org_keyring_envelope: serde_json::Value,
    pub descriptor: DeploymentDescriptor,
    pub descriptor_signature: [u8; 64],
    pub descriptor_signing_key_id: String,
    pub descriptor_signing_pubkey: [u8; 32],
    pub descriptor_core_hash: [u8; 32],
    pub org_keyring: OrgKeyring,
    pub org_keyring_signature: [u8; 64],
    pub org_keyring_signing_pubkey: [u8; 32],
    pub org_keyring_fingerprint: [u8; 32],
}

impl DeploymentSigningArtifacts {
    pub fn binding(&self) -> WorkloadArtifactBinding {
        WorkloadArtifactBinding {
            descriptor_core_hash: self.descriptor_core_hash,
            descriptor_signing_pubkey: self.descriptor_signing_pubkey,
            org_keyring_fingerprint: self.org_keyring_fingerprint,
        }
    }

    pub fn sign_request(&self) -> SignRequest {
        SignRequest {
            app_id: self.descriptor.app_id,
            deploy_id: self.descriptor.deploy_id,
            platform_release_version: self.descriptor.platform_release_version.clone(),
            customer_descriptor_blob: self.customer_descriptor_blob.clone(),
            org_keyring_blob: self.org_keyring_blob.clone(),
        }
    }

    pub fn validate_deployment_inputs(
        &self,
        app: &App,
        image_digest: &str,
        api_signing_pubkey: &str,
    ) -> Result<(), SigningServiceError> {
        self.validate_workload_runtime_spec()?;
        if self.descriptor.org_id != app.org_id {
            return Err(SigningServiceError::Mismatch("org_id".into()));
        }
        if self.descriptor.app_id != app.id {
            return Err(SigningServiceError::Mismatch("app_id".into()));
        }
        if self.descriptor.app_name != app.name {
            return Err(SigningServiceError::Mismatch("app_name".into()));
        }
        if self.descriptor.namespace != app.namespace {
            return Err(SigningServiceError::Mismatch("namespace".into()));
        }
        if self.descriptor.service_account != app.service_account {
            return Err(SigningServiceError::Mismatch("service_account".into()));
        }
        if self.descriptor.app_domain != app.domain {
            return Err(SigningServiceError::Mismatch("app_domain".into()));
        }
        if self.descriptor.tee_domain
            != app.tee_domain.clone().unwrap_or_else(|| app.domain.clone())
        {
            return Err(SigningServiceError::Mismatch("tee_domain".into()));
        }
        if self.descriptor.identity_hash
            != decode_hex32(
                "tenant_instance_identity_hash",
                &app.tenant_instance_identity_hash,
            )?
        {
            return Err(SigningServiceError::Mismatch(
                "tenant_instance_identity_hash".into(),
            ));
        }
        if self.descriptor.image_digest != image_digest {
            return Err(SigningServiceError::Mismatch("image_digest".into()));
        }
        if self.descriptor.api_signing_pubkey != api_signing_pubkey {
            return Err(SigningServiceError::Mismatch("api_signing_pubkey".into()));
        }
        if self.descriptor.unlock_mode != app_unlock_mode(app.unlock_mode) {
            return Err(SigningServiceError::Mismatch("unlock_mode".into()));
        }
        if self.descriptor.signer_identity.subject
            != app.signer_identity_subject.clone().unwrap_or_default()
        {
            return Err(SigningServiceError::Mismatch(
                "signer_identity.subject".into(),
            ));
        }
        if self.descriptor.signer_identity.issuer
            != app.signer_identity_issuer.clone().unwrap_or_default()
        {
            return Err(SigningServiceError::Mismatch(
                "signer_identity.issuer".into(),
            ));
        }
        if self.org_keyring.org_id != app.org_id {
            return Err(SigningServiceError::Mismatch("org_keyring.org_id".into()));
        }
        Ok(())
    }

    fn validate_workload_runtime_spec(&self) -> Result<(), SigningServiceError> {
        let command = &self.descriptor.oci_runtime_spec.command;
        if command.len() != 1 || command[0] != ENCLAVA_WAIT_EXEC_PATH {
            return Err(SigningServiceError::Mismatch(
                "oci_runtime_spec.command".into(),
            ));
        }
        if self.descriptor.oci_runtime_spec.args.is_empty() {
            return Err(SigningServiceError::Mismatch(
                "oci_runtime_spec.args".into(),
            ));
        }
        if self
            .descriptor
            .oci_runtime_spec
            .args
            .iter()
            .any(|arg| arg.is_empty())
        {
            return Err(SigningServiceError::Mismatch(
                "oci_runtime_spec.args".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_rendered_cc_init_data_hash(
        &self,
        actual_hash_hex: &str,
    ) -> Result<(), SigningServiceError> {
        let expected = hex::encode(self.descriptor.expected_cc_init_data_hash);
        if expected != actual_hash_hex {
            return Err(SigningServiceError::Mismatch(
                "expected_cc_init_data_hash".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_signed_artifact(
        &self,
        artifact: &SignedPolicyArtifact,
        signing_service_pubkey_hex: &str,
    ) -> Result<(), SigningServiceError> {
        self.validate_signed_artifact_common(artifact)?;
        let rego_hash: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
        verify_signed_policy_artifact(artifact, &rego_hash, signing_service_pubkey_hex)?;
        Ok(())
    }

    pub async fn validate_customer_authority(
        &self,
        pool: &PgPool,
    ) -> Result<(), SigningServiceError> {
        self.verify_keyring_signature()?;
        self.verify_descriptor_signature()?;
        if !self.descriptor_signing_key_is_authorized() {
            return Err(SigningServiceError::Mismatch(
                "descriptor_signing_pubkey not authorized by org_keyring".into(),
            ));
        }
        self.verify_matches_latest_cap_keyring(pool).await?;
        Ok(())
    }

    pub fn validate_canonical_agent_policy(
        &self,
        artifact: &SignedPolicyArtifact,
        generated: &AgentPolicyResponse,
    ) -> Result<(), SigningServiceError> {
        let generated_hash = decode_hex32(
            "generated_agent_policy.agent_policy_sha256",
            &generated.agent_policy_sha256,
        )?;
        let generated_actual: [u8; 32] =
            Sha256::digest(generated.agent_policy_text.as_bytes()).into();
        if generated_hash != generated_actual {
            return Err(SigningServiceError::Mismatch(
                "generated_agent_policy.agent_policy_sha256".into(),
            ));
        }
        if self.descriptor.expected_agent_policy_hash != generated_hash {
            return Err(SigningServiceError::Mismatch(
                "generated_agent_policy.expected_agent_policy_hash".into(),
            ));
        }
        if artifact.agent_policy_sha256 != generated.agent_policy_sha256 {
            return Err(SigningServiceError::Mismatch(
                "canonical_agent_policy_sha256".into(),
            ));
        }
        if artifact.agent_policy_text != generated.agent_policy_text {
            return Err(SigningServiceError::Mismatch(
                "canonical_agent_policy_text".into(),
            ));
        }
        if artifact.metadata.genpolicy_version_pin != generated.genpolicy_version_pin {
            return Err(SigningServiceError::Mismatch(
                "canonical_genpolicy_version_pin".into(),
            ));
        }
        Ok(())
    }

    pub fn attach_customer_authority(
        &self,
        artifact: &mut SignedPolicyArtifact,
    ) -> Result<(), SigningServiceError> {
        if let Some(existing) = artifact.org_keyring.as_ref() {
            let existing: OrgKeyringEnvelope = serde_json::from_value(existing.clone())?;
            if keyring_fingerprint(&existing.keyring) != self.org_keyring_fingerprint {
                return Err(SigningServiceError::Mismatch(
                    "artifact.org_keyring does not match deployment org_keyring".into(),
                ));
            }
            if existing.signature != self.org_keyring_signature {
                return Err(SigningServiceError::Mismatch(
                    "artifact.org_keyring.signature".into(),
                ));
            }
            if existing.signing_pubkey != self.org_keyring_signing_pubkey {
                return Err(SigningServiceError::Mismatch(
                    "artifact.org_keyring.signing_pubkey".into(),
                ));
            }
            return Ok(());
        }

        artifact.org_keyring = Some(self.org_keyring_envelope.clone());
        Ok(())
    }

    fn validate_signed_artifact_common(
        &self,
        artifact: &SignedPolicyArtifact,
    ) -> Result<(), SigningServiceError> {
        let metadata = &artifact.metadata;
        if metadata.app_id != self.descriptor.app_id.to_string() {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.app_id".into(),
            ));
        }
        if metadata.deploy_id != self.descriptor.deploy_id.to_string() {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.deploy_id".into(),
            ));
        }
        if metadata.descriptor_core_hash != hex::encode(self.descriptor_core_hash) {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.descriptor_core_hash".into(),
            ));
        }
        if metadata.descriptor_signing_pubkey != hex::encode(self.descriptor_signing_pubkey) {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.descriptor_signing_pubkey".into(),
            ));
        }
        if metadata.platform_release_version != self.descriptor.platform_release_version {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.platform_release_version".into(),
            ));
        }
        if metadata.policy_template_id != self.descriptor.policy_template_id {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.policy_template_id".into(),
            ));
        }
        if metadata.policy_template_sha256 != hex::encode(self.descriptor.policy_template_sha256) {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.policy_template_sha256".into(),
            ));
        }
        if metadata.agent_policy_sha256 != artifact.agent_policy_sha256 {
            return Err(SigningServiceError::Mismatch(
                "artifact.metadata.agent_policy_sha256".into(),
            ));
        }

        let rego_hash: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
        let artifact_rego_hash = decode_hex32("rego_sha256", &artifact.rego_sha256)?;
        if artifact_rego_hash != rego_hash {
            return Err(SigningServiceError::Mismatch("artifact.rego_sha256".into()));
        }
        if self.descriptor.expected_kbs_policy_hash != rego_hash {
            return Err(SigningServiceError::Mismatch(
                "expected_kbs_policy_hash".into(),
            ));
        }
        let agent_policy_hash: [u8; 32] =
            Sha256::digest(artifact.agent_policy_text.as_bytes()).into();
        let artifact_agent_policy_hash =
            decode_hex32("agent_policy_sha256", &artifact.agent_policy_sha256)?;
        if artifact_agent_policy_hash != agent_policy_hash {
            return Err(SigningServiceError::Mismatch(
                "artifact.agent_policy_sha256".into(),
            ));
        }
        if self.descriptor.expected_agent_policy_hash != agent_policy_hash {
            return Err(SigningServiceError::Mismatch(
                "expected_agent_policy_hash".into(),
            ));
        }
        Ok(())
    }

    fn verify_keyring_signature(&self) -> Result<(), SigningServiceError> {
        if !self.org_keyring.members.iter().any(|member| {
            member.pubkey == self.org_keyring_signing_pubkey
                && matches!(member.role, KeyringRole::Owner)
        }) {
            return Err(SigningServiceError::Mismatch(
                "org_keyring.signing_pubkey owner member".into(),
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&self.org_keyring_signing_pubkey)
            .map_err(|_| SigningServiceError::Mismatch("org_keyring.signing_pubkey".into()))?;
        let signature = Signature::from_bytes(&self.org_keyring_signature);
        verifying_key
            .verify(&canonical_keyring_bytes(&self.org_keyring), &signature)
            .map_err(|_| SigningServiceError::InvalidSignature)
    }

    fn verify_descriptor_signature(&self) -> Result<(), SigningServiceError> {
        let verifying_key = VerifyingKey::from_bytes(&self.descriptor_signing_pubkey)
            .map_err(|_| SigningServiceError::Mismatch("descriptor.signing_pubkey".into()))?;
        let signature = Signature::from_bytes(&self.descriptor_signature);
        verifying_key
            .verify(
                &enclava_common::descriptor::descriptor_canonical_bytes(&self.descriptor),
                &signature,
            )
            .map_err(|_| SigningServiceError::InvalidSignature)
    }

    fn descriptor_signing_key_is_authorized(&self) -> bool {
        self.org_keyring
            .members
            .iter()
            .any(|member| member.pubkey == self.descriptor_signing_pubkey && member.allows_deploy())
    }

    async fn verify_matches_latest_cap_keyring(
        &self,
        pool: &PgPool,
    ) -> Result<(), SigningServiceError> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT ok.keyring_payload, ok.signature, usk.pubkey
             FROM org_keyrings ok
             JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
             WHERE ok.org_id = $1
             ORDER BY ok.version DESC
             LIMIT 1",
        )
        .bind(self.org_keyring.org_id)
        .fetch_optional(pool)
        .await?;

        let Some((payload, signature, signing_pubkey)) = row else {
            return Err(SigningServiceError::Mismatch(
                "org_keyring not registered with CAP".into(),
            ));
        };
        let stored: OrgKeyring = serde_json::from_slice(&payload)?;
        if keyring_fingerprint(&stored) != self.org_keyring_fingerprint {
            return Err(SigningServiceError::Mismatch(
                "org_keyring does not match latest CAP keyring".into(),
            ));
        }
        if signature.as_slice() != self.org_keyring_signature.as_slice() {
            return Err(SigningServiceError::Mismatch(
                "org_keyring.signature does not match latest CAP keyring".into(),
            ));
        }
        if signing_pubkey.as_slice() != self.org_keyring_signing_pubkey.as_slice() {
            return Err(SigningServiceError::Mismatch(
                "org_keyring.signing_pubkey does not match latest CAP keyring".into(),
            ));
        }
        Ok(())
    }

    pub fn generated_agent_policy(
        &self,
        artifact: &SignedPolicyArtifact,
    ) -> Result<GeneratedAgentPolicy, SigningServiceError> {
        let policy_sha256 = decode_hex32("agent_policy_sha256", &artifact.agent_policy_sha256)?;
        let actual: [u8; 32] = Sha256::digest(artifact.agent_policy_text.as_bytes()).into();
        if actual != policy_sha256 {
            return Err(SigningServiceError::Mismatch(
                "artifact.agent_policy_sha256".into(),
            ));
        }
        if self.descriptor.expected_agent_policy_hash != policy_sha256 {
            return Err(SigningServiceError::Mismatch(
                "expected_agent_policy_hash".into(),
            ));
        }
        Ok(GeneratedAgentPolicy {
            policy_text: artifact.agent_policy_text.clone(),
            policy_sha256,
            genpolicy_version_pin: artifact.metadata.genpolicy_version_pin.clone(),
        })
    }
}

fn app_unlock_mode(mode: crate::models::UnlockMode) -> &'static str {
    match mode {
        crate::models::UnlockMode::Auto => "auto",
        crate::models::UnlockMode::Password => "password",
    }
}

fn verify_signed_policy_artifact(
    artifact: &SignedPolicyArtifact,
    rego_hash: &[u8; 32],
    signing_service_pubkey_hex: &str,
) -> Result<(), SigningServiceError> {
    let expected_pubkey = decode_hex32("signing_service_pubkey_hex", signing_service_pubkey_hex)?;
    verify_signed_policy_artifact_with_pubkey(
        artifact,
        rego_hash,
        &expected_pubkey,
        "artifact.verify_pubkey_b64",
    )
}

fn verify_signed_policy_artifact_with_pubkey(
    artifact: &SignedPolicyArtifact,
    rego_hash: &[u8; 32],
    expected_pubkey: &[u8; 32],
    pubkey_field: &'static str,
) -> Result<(), SigningServiceError> {
    let diagnostic_pubkey = decode_pubkey_b64("verify_pubkey_b64", &artifact.verify_pubkey_b64)?;
    if &diagnostic_pubkey != expected_pubkey {
        return Err(SigningServiceError::Mismatch(pubkey_field.into()));
    }

    let verifying_key = VerifyingKey::from_bytes(expected_pubkey)
        .map_err(|_| SigningServiceError::Mismatch(pubkey_field.into()))?;
    let signature = Signature::from_bytes(&decode_signature(&artifact.signature)?);
    let signing_input = policy_artifact_signing_input(&artifact.metadata, rego_hash)?;
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|_| SigningServiceError::InvalidSignature)
}

fn canonical_policy_metadata_hash(
    metadata: &PolicyMetadata,
) -> Result<[u8; 32], SigningServiceError> {
    let app_id = Uuid::parse_str(&metadata.app_id)
        .map_err(|err| SigningServiceError::Blob(format!("parsing metadata.app_id: {err}")))?;
    let deploy_id = Uuid::parse_str(&metadata.deploy_id)
        .map_err(|err| SigningServiceError::Blob(format!("parsing metadata.deploy_id: {err}")))?;
    let descriptor_core_hash = decode_hex32(
        "metadata.descriptor_core_hash",
        &metadata.descriptor_core_hash,
    )?;
    let descriptor_signing_pubkey = decode_hex32(
        "metadata.descriptor_signing_pubkey",
        &metadata.descriptor_signing_pubkey,
    )?;
    let policy_template_sha256 = decode_hex32(
        "metadata.policy_template_sha256",
        &metadata.policy_template_sha256,
    )?;
    let agent_policy_sha256 = decode_hex32(
        "metadata.agent_policy_sha256",
        &metadata.agent_policy_sha256,
    )?;

    Ok(ce_v1_hash(&[
        ("app_id", app_id.as_bytes().as_slice()),
        ("deploy_id", deploy_id.as_bytes().as_slice()),
        ("descriptor_core_hash", &descriptor_core_hash),
        ("descriptor_signing_pubkey", &descriptor_signing_pubkey),
        (
            "platform_release_version",
            metadata.platform_release_version.as_bytes(),
        ),
        ("policy_template_id", metadata.policy_template_id.as_bytes()),
        ("policy_template_sha256", &policy_template_sha256),
        ("agent_policy_sha256", &agent_policy_sha256),
        (
            "genpolicy_version_pin",
            metadata.genpolicy_version_pin.as_bytes(),
        ),
        ("signed_at", metadata.signed_at.as_bytes()),
        ("key_id", metadata.key_id.as_bytes()),
    ]))
}

fn policy_artifact_signing_input(
    metadata: &PolicyMetadata,
    rego_hash: &[u8; 32],
) -> Result<Vec<u8>, SigningServiceError> {
    let metadata_hash = canonical_policy_metadata_hash(metadata)?;
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", &metadata_hash),
        ("rego_sha256", rego_hash),
    ]))
}

pub fn decode_optional_blobs(
    customer_descriptor_blob: Option<String>,
    org_keyring_blob: Option<String>,
) -> Result<Option<DeploymentSigningArtifacts>, SigningServiceError> {
    let (customer_descriptor_blob, org_keyring_blob) =
        match (customer_descriptor_blob, org_keyring_blob) {
            (Some(customer_descriptor_blob), Some(org_keyring_blob)) => {
                (customer_descriptor_blob, org_keyring_blob)
            }
            (None, None) => return Ok(None),
            _ => return Err(SigningServiceError::PartialBlobs),
        };

    let descriptor_envelope: DeploymentDescriptorEnvelope =
        decode_json_blob("customer_descriptor_blob", &customer_descriptor_blob)?;
    let keyring_envelope: OrgKeyringEnvelope =
        decode_json_blob("org_keyring_blob", &org_keyring_blob)?;
    let org_keyring_envelope: serde_json::Value =
        decode_json_blob("org_keyring_blob", &org_keyring_blob)?;
    let descriptor_core_hash = descriptor_core_hash(&descriptor_envelope.descriptor);
    let org_keyring_fingerprint = keyring_fingerprint(&keyring_envelope.keyring);

    Ok(Some(DeploymentSigningArtifacts {
        customer_descriptor_blob,
        org_keyring_blob,
        org_keyring_envelope,
        descriptor: descriptor_envelope.descriptor,
        descriptor_signature: descriptor_envelope.signature,
        descriptor_signing_key_id: descriptor_envelope.signing_key_id,
        descriptor_signing_pubkey: descriptor_envelope.signing_pubkey,
        descriptor_core_hash,
        org_keyring: keyring_envelope.keyring,
        org_keyring_signature: keyring_envelope.signature,
        org_keyring_signing_pubkey: keyring_envelope.signing_pubkey,
        org_keyring_fingerprint,
    }))
}

pub fn decode_optional_policy_artifact(
    signed_policy_artifact: Option<String>,
) -> Result<Option<SignedPolicyArtifact>, SigningServiceError> {
    signed_policy_artifact
        .map(|artifact| decode_json_blob("signed_policy_artifact", &artifact))
        .transpose()
}

pub async fn persist_workload_artifacts(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
    artifacts: &DeploymentSigningArtifacts,
    signed_policy_artifact: &SignedPolicyArtifact,
) -> Result<(), SigningServiceError> {
    let descriptor_payload = serde_json::to_value(&artifacts.descriptor)?;
    let org_keyring_payload = serde_json::to_value(&artifacts.org_keyring)?;
    let signed_policy_artifact = serde_json::to_value(signed_policy_artifact)?;

    sqlx::query(
        "INSERT INTO workload_artifacts (
             descriptor_core_hash, app_id, deploy_id, descriptor_payload,
             descriptor_signature, descriptor_signing_key_id, org_keyring_payload,
             org_keyring_signature, signed_policy_artifact
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (descriptor_core_hash) DO UPDATE SET
             app_id = EXCLUDED.app_id,
             deploy_id = EXCLUDED.deploy_id,
             descriptor_payload = EXCLUDED.descriptor_payload,
             descriptor_signature = EXCLUDED.descriptor_signature,
             descriptor_signing_key_id = EXCLUDED.descriptor_signing_key_id,
             org_keyring_payload = EXCLUDED.org_keyring_payload,
             org_keyring_signature = EXCLUDED.org_keyring_signature,
             signed_policy_artifact = EXCLUDED.signed_policy_artifact",
    )
    .bind(artifacts.descriptor_core_hash.to_vec())
    .bind(app_id)
    .bind(deploy_id)
    .bind(descriptor_payload)
    .bind(artifacts.descriptor_signature.to_vec())
    .bind(&artifacts.descriptor_signing_key_id)
    .bind(org_keyring_payload)
    .bind(artifacts.org_keyring_signature.to_vec())
    .bind(signed_policy_artifact)
    .execute(pool)
    .await?;

    Ok(())
}

pub fn workload_artifacts_json(
    artifacts: &DeploymentSigningArtifacts,
    signed_policy_artifact: &SignedPolicyArtifact,
) -> Result<String, SigningServiceError> {
    let value = serde_json::json!({
        "descriptor_payload": serde_json::to_value(&artifacts.descriptor)?,
        "descriptor_signature": hex::encode(artifacts.descriptor_signature),
        "descriptor_signing_key_id": artifacts.descriptor_signing_key_id,
        "org_keyring_payload": serde_json::to_value(&artifacts.org_keyring)?,
        "org_keyring_signature": hex::encode(artifacts.org_keyring_signature),
        "signed_policy_artifact": serde_json::to_value(signed_policy_artifact)?,
    });
    Ok(serde_json::to_string(&value)?)
}

pub fn trustee_policy_json(
    signed_policy_artifact: &SignedPolicyArtifact,
) -> Result<String, SigningServiceError> {
    Ok(serde_json::to_string(signed_policy_artifact)?)
}

#[derive(Debug, sqlx::FromRow)]
struct StoredWorkloadArtifactsJsonRow {
    descriptor_payload: serde_json::Value,
    descriptor_signature: Vec<u8>,
    descriptor_signing_key_id: String,
    org_keyring_payload: serde_json::Value,
    org_keyring_signature: Vec<u8>,
    signed_policy_artifact: serde_json::Value,
}

pub async fn load_workload_artifacts_json(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
) -> Result<Option<(String, String)>, SigningServiceError> {
    let Some(row) = sqlx::query_as::<_, StoredWorkloadArtifactsJsonRow>(
        "SELECT descriptor_payload, descriptor_signature, descriptor_signing_key_id,
                org_keyring_payload, org_keyring_signature, signed_policy_artifact
         FROM workload_artifacts
         WHERE app_id = $1 AND deploy_id = $2",
    )
    .bind(app_id)
    .bind(deploy_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let artifacts = serde_json::json!({
        "descriptor_payload": row.descriptor_payload,
        "descriptor_signature": hex::encode(row.descriptor_signature),
        "descriptor_signing_key_id": row.descriptor_signing_key_id,
        "org_keyring_payload": row.org_keyring_payload,
        "org_keyring_signature": hex::encode(row.org_keyring_signature),
        "signed_policy_artifact": row.signed_policy_artifact,
    });
    let policy = artifacts
        .get("signed_policy_artifact")
        .cloned()
        .ok_or_else(|| SigningServiceError::Blob("signed_policy_artifact missing".into()))?;
    Ok(Some((
        serde_json::to_string(&artifacts)?,
        serde_json::to_string(&policy)?,
    )))
}

pub async fn load_workload_descriptor(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
) -> Result<Option<DeploymentDescriptor>, SigningServiceError> {
    let Some(descriptor_payload) = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT descriptor_payload
         FROM workload_artifacts
         WHERE app_id = $1 AND deploy_id = $2",
    )
    .bind(app_id)
    .bind(deploy_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    Ok(Some(serde_json::from_value(descriptor_payload)?))
}

#[derive(Debug, sqlx::FromRow)]
struct StoredWorkloadArtifactRow {
    descriptor_core_hash: Vec<u8>,
    org_keyring_payload: serde_json::Value,
    signed_policy_artifact: serde_json::Value,
}

pub async fn load_workload_artifact_binding(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
) -> Result<Option<(WorkloadArtifactBinding, SignedPolicyArtifact)>, SigningServiceError> {
    let Some(row) = sqlx::query_as::<_, StoredWorkloadArtifactRow>(
        "SELECT descriptor_core_hash, org_keyring_payload, signed_policy_artifact
         FROM workload_artifacts
         WHERE app_id = $1 AND deploy_id = $2",
    )
    .bind(app_id)
    .bind(deploy_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let descriptor_core_hash: [u8; 32] =
        row.descriptor_core_hash
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "descriptor_core_hash must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
    let org_keyring: OrgKeyring = serde_json::from_value(row.org_keyring_payload)?;
    let signed_policy_artifact: SignedPolicyArtifact =
        serde_json::from_value(row.signed_policy_artifact)?;
    let descriptor_signing_pubkey = decode_hex32(
        "artifact.metadata.descriptor_signing_pubkey",
        &signed_policy_artifact.metadata.descriptor_signing_pubkey,
    )?;

    Ok(Some((
        WorkloadArtifactBinding {
            descriptor_core_hash,
            descriptor_signing_pubkey,
            org_keyring_fingerprint: keyring_fingerprint(&org_keyring),
        },
        signed_policy_artifact,
    )))
}

#[derive(Debug, Deserialize)]
struct DeploymentDescriptorEnvelope {
    descriptor: DeploymentDescriptor,
    #[serde(deserialize_with = "deserialize_sig")]
    signature: [u8; 64],
    signing_key_id: String,
    #[serde(deserialize_with = "deserialize_pubkey")]
    signing_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrgKeyringEnvelope {
    keyring: OrgKeyring,
    #[serde(with = "hex_signature_array")]
    signature: [u8; 64],
    #[allow(dead_code)]
    #[serde(with = "hex_bytes32")]
    signing_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<KeyringMember>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyringMember {
    user_id: Uuid,
    #[serde(with = "hex_bytes32")]
    pubkey: [u8; 32],
    role: KeyringRole,
    added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum KeyringRole {
    Owner,
    Admin,
    Deployer,
}

impl KeyringRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Deployer => "deployer",
        }
    }
}

impl KeyringMember {
    fn allows_deploy(&self) -> bool {
        matches!(
            self.role,
            KeyringRole::Owner | KeyringRole::Admin | KeyringRole::Deployer
        )
    }
}

fn decode_json_blob<T: for<'de> Deserialize<'de>>(
    name: &str,
    blob: &str,
) -> Result<T, SigningServiceError> {
    let trimmed = blob.trim();
    if trimmed.is_empty() {
        return Err(SigningServiceError::Blob(format!("{name} is required")));
    }
    if let Ok(decoded) = B64.decode(trimmed.as_bytes())
        && let Ok(parsed) = serde_json::from_slice(&decoded)
    {
        return Ok(parsed);
    }
    serde_json::from_str(trimmed)
        .map_err(|err| SigningServiceError::Blob(format!("parsing {name}: {err}")))
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_hex32("pubkey", &value).map_err(serde::de::Error::custom)
}

fn deserialize_sig<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_signature(&value).map_err(serde::de::Error::custom)
}

mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 32"))
    }
}

mod hex_signature_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 64"))
    }
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32], SigningServiceError> {
    hex::decode(value.trim())
        .map_err(|err| SigningServiceError::Blob(format!("decoding {name}: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("{name} must be 32 bytes, got {}", bytes.len()))
        })
}

fn decode_signature(value: &str) -> Result<[u8; 64], SigningServiceError> {
    let trimmed = value.trim();
    if let Ok(bytes) = hex::decode(trimmed) {
        return bytes.try_into().map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("signature must be 64 bytes, got {}", bytes.len()))
        });
    }
    B64.decode(trimmed.as_bytes())
        .map_err(|err| SigningServiceError::Blob(format!("decoding signature: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("signature must be 64 bytes, got {}", bytes.len()))
        })
}

fn decode_pubkey_b64(name: &str, value: &str) -> Result<[u8; 32], SigningServiceError> {
    B64.decode(value.trim().as_bytes())
        .map_err(|err| SigningServiceError::Blob(format!("decoding {name}: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("{name} must be 32 bytes, got {}", bytes.len()))
        })
}

fn keyring_fingerprint(keyring: &OrgKeyring) -> [u8; 32] {
    Sha256::digest(canonical_keyring_bytes(keyring)).into()
}

fn canonical_keyring_bytes(keyring: &OrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&keyring.members);
    let version = keyring.version.to_be_bytes();
    let updated = keyring.updated_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated.as_bytes()),
    ])
}

fn canonical_member_hash(member: &KeyringMember) -> [u8; 32] {
    let added = member.added_at.to_rfc3339();
    ce_v1_hash(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", &member.pubkey),
        ("role", member.role.as_str().as_bytes()),
        ("added_at", added.as_bytes()),
    ])
}

fn canonical_members_hash(members: &[KeyringMember]) -> [u8; 32] {
    let mut sorted: Vec<&KeyringMember> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let records: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| (member.user_id.to_string(), canonical_member_hash(member)))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use enclava_common::descriptor::{
        Capabilities, EnvVar, Mount, OciRuntimeSpec, Port, Resources, SecurityContext, Sidecars,
        SignerIdentity,
    };
    use enclava_common::image::ImageRef;
    use enclava_common::types::{Durability, ResourceLimits, UnlockMode};
    use enclava_engine::types::{
        AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec,
        VolumeSpec,
    };

    #[test]
    fn signing_service_timeout_defaults_to_genpolicy_friendly_value() {
        assert_eq!(
            parse_signing_service_timeout(None).unwrap(),
            Duration::from_secs(DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS)
        );
        assert_eq!(
            parse_signing_service_timeout(Some("180".to_string())).unwrap(),
            Duration::from_secs(180)
        );
    }

    #[test]
    fn signing_service_timeout_rejects_invalid_values() {
        assert!(matches!(
            parse_signing_service_timeout(Some("0".to_string())).unwrap_err(),
            SigningServiceError::InvalidTimeout(_)
        ));
        assert!(matches!(
            parse_signing_service_timeout(Some("abc".to_string())).unwrap_err(),
            SigningServiceError::InvalidTimeout(_)
        ));
    }

    fn descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            nonce: [1; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec![],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [2; 32],
            image_ref:
                "ghcr.io/enclava-ai/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject:
                    "https://github.com/example/repo/.github/workflows/deploy.yml@refs/heads/main"
                        .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec![ENCLAVA_WAIT_EXEC_PATH.to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![EnvVar {
                    name: "RUST_LOG".to_string(),
                    value: "info".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![Mount {
                    source: "/data/app".to_string(),
                    destination: "/app/data".to_string(),
                    mount_type: "bind".to_string(),
                    options: vec!["rw".to_string()],
                }],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                caddy_digest:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-owner".to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "cap-test".to_string(),
            expected_agent_policy_hash: Sha256::digest(
                b"package agent_policy\n\ndefault CreateContainerRequest := true\n",
            )
            .into(),
            expected_cc_init_data_hash: [5; 32],
            expected_kbs_policy_hash: Sha256::digest(b"package policy\n\ndefault allow := false\n")
                .into(),
        }
    }

    fn signing_artifacts(descriptor: DeploymentDescriptor) -> DeploymentSigningArtifacts {
        DeploymentSigningArtifacts {
            customer_descriptor_blob: "{}".to_string(),
            org_keyring_blob: "{}".to_string(),
            org_keyring_envelope: serde_json::json!({
                "keyring": {
                    "org_id": "11111111-1111-1111-1111-111111111111",
                    "version": 1,
                    "members": [],
                    "updated_at": "2026-04-01T00:00:00Z"
                },
                "signature": "cc".repeat(64),
                "signing_pubkey": "dd".repeat(32)
            }),
            descriptor_core_hash: descriptor_core_hash(&descriptor),
            descriptor,
            descriptor_signature: [0xaa; 64],
            descriptor_signing_key_id: "deployer-key-1".to_string(),
            descriptor_signing_pubkey: [0xbb; 32],
            org_keyring: OrgKeyring {
                org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: 1,
                members: vec![],
                updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            },
            org_keyring_signature: [0xcc; 64],
            org_keyring_signing_pubkey: [0xdd; 32],
            org_keyring_fingerprint: [0xdd; 32],
        }
    }

    fn api_app_for_descriptor(
        descriptor: &DeploymentDescriptor,
        unlock_mode: crate::models::UnlockMode,
    ) -> App {
        App {
            id: descriptor.app_id,
            org_id: descriptor.org_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "demo-instance".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            service_account: descriptor.service_account.clone(),
            bootstrap_owner_pubkey_hash: "aa".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            unlock_mode,
            domain: descriptor.app_domain.clone(),
            tee_domain: Some(descriptor.tee_domain.clone()),
            custom_domain: None,
            status: crate::models::AppStatus::Creating,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            signer_identity_set_at: Some("2026-04-01T00:00:00Z".parse().unwrap()),
            created_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
        }
    }

    fn signed_policy_artifact(
        artifacts: &DeploymentSigningArtifacts,
        signing_key: &SigningKey,
    ) -> SignedPolicyArtifact {
        let rego_text = "package policy\n\ndefault allow := false\n".to_string();
        let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
        let agent_policy_text =
            "package agent_policy\n\ndefault CreateContainerRequest := true\n".to_string();
        let agent_policy_hash: [u8; 32] = Sha256::digest(agent_policy_text.as_bytes()).into();
        let metadata = PolicyMetadata {
            app_id: artifacts.descriptor.app_id.to_string(),
            deploy_id: artifacts.descriptor.deploy_id.to_string(),
            descriptor_core_hash: hex::encode(artifacts.descriptor_core_hash),
            descriptor_signing_pubkey: hex::encode(artifacts.descriptor_signing_pubkey),
            platform_release_version: artifacts.descriptor.platform_release_version.clone(),
            policy_template_id: artifacts.descriptor.policy_template_id.clone(),
            policy_template_sha256: hex::encode(artifacts.descriptor.policy_template_sha256),
            agent_policy_sha256: hex::encode(agent_policy_hash),
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            signed_at: "2026-04-01T12:30:00+00:00".to_string(),
            key_id: "policy-test-key-v1".to_string(),
        };
        let signing_input = policy_artifact_signing_input(&metadata, &rego_hash).unwrap();
        let signature = signing_key.sign(&signing_input);
        SignedPolicyArtifact {
            metadata,
            rego_text,
            rego_sha256: hex::encode(rego_hash),
            agent_policy_text,
            agent_policy_sha256: hex::encode(agent_policy_hash),
            signature: hex::encode(signature.to_bytes()),
            verify_pubkey_b64: B64.encode(signing_key.verifying_key().to_bytes()),
            org_keyring: None,
        }
    }

    fn agent_policy_response_for(artifact: &SignedPolicyArtifact) -> AgentPolicyResponse {
        AgentPolicyResponse {
            agent_policy_text: artifact.agent_policy_text.clone(),
            agent_policy_sha256: artifact.agent_policy_sha256.clone(),
            genpolicy_version_pin: artifact.metadata.genpolicy_version_pin.clone(),
        }
    }

    #[test]
    fn decodes_descriptor_and_keyring_blobs() {
        let descriptor = descriptor();
        let descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": "aa".repeat(64),
            "signing_key_id": "deployer-key-1",
            "signing_pubkey": "bb".repeat(32)
        })
        .to_string();
        let keyring_blob = serde_json::json!({
            "keyring": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "version": 1,
                "members": [{
                    "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "pubkey": "bb".repeat(32),
                    "role": "deployer",
                    "added_at": "2026-04-01T00:00:00Z"
                }],
                "updated_at": "2026-04-01T00:00:00Z"
            },
            "signature": "cc".repeat(64),
            "signing_pubkey": "dd".repeat(32)
        })
        .to_string();

        let decoded = decode_optional_blobs(Some(descriptor_blob), Some(keyring_blob))
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded.descriptor_core_hash,
            descriptor_core_hash(&decoded.descriptor)
        );
        assert_eq!(decoded.descriptor_signing_pubkey, [0xbb; 32]);
        assert_eq!(decoded.descriptor_signature, [0xaa; 64]);
        assert_ne!(decoded.org_keyring_fingerprint, [0; 32]);
    }

    #[test]
    fn rejects_descriptor_unlock_mode_that_does_not_match_app() {
        let mut descriptor = descriptor();
        descriptor.unlock_mode = "auto".to_string();
        let artifacts = signing_artifacts(descriptor.clone());
        let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

        let err = artifacts
            .validate_deployment_inputs(
                &app,
                &descriptor.image_digest,
                &descriptor.api_signing_pubkey,
            )
            .unwrap_err();

        assert!(matches!(err, SigningServiceError::Mismatch(field) if field == "unlock_mode"));
    }

    #[test]
    fn rejects_descriptor_for_different_api_signing_key() {
        let descriptor = descriptor();
        let artifacts = signing_artifacts(descriptor.clone());
        let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

        let err = artifacts
            .validate_deployment_inputs(&app, &descriptor.image_digest, "other-api-signing-pubkey")
            .unwrap_err();

        assert!(
            matches!(err, SigningServiceError::Mismatch(field) if field == "api_signing_pubkey")
        );
    }

    #[test]
    fn rejects_descriptor_without_workload_command() {
        let mut descriptor = descriptor();
        descriptor.oci_runtime_spec.args.clear();
        let artifacts = signing_artifacts(descriptor.clone());
        let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

        let err = artifacts
            .validate_deployment_inputs(
                &app,
                &descriptor.image_digest,
                &descriptor.api_signing_pubkey,
            )
            .unwrap_err();

        assert!(
            matches!(err, SigningServiceError::Mismatch(field) if field == "oci_runtime_spec.args")
        );
    }

    #[test]
    fn rejects_partial_blobs() {
        let err = decode_optional_blobs(Some("{}".to_string()), None).unwrap_err();
        assert!(matches!(err, SigningServiceError::PartialBlobs));
    }

    #[test]
    fn policy_artifact_signing_input_matches_rev14_vector() {
        let metadata = PolicyMetadata {
            app_id: "22222222-2222-2222-2222-222222222222".to_string(),
            deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
            descriptor_core_hash:
                "0de9db2fd278a795754120604b68a1fae95d1ba19a66ed9a1df3a76df76f0eea".to_string(),
            descriptor_signing_pubkey:
                "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0".to_string(),
            key_id: "policy-test-key-v1".to_string(),
            platform_release_version: "platform-2026.04".to_string(),
            policy_template_id: "trustee-resource-policy-v1".to_string(),
            policy_template_sha256:
                "e808dd6a40402bad50ea9522cdcd60b6739b78e21006942f4072a08355a24f10".to_string(),
            agent_policy_sha256: "749bf91b70ba77fff6ad79581c0b3319cbff946e8f3783f8a44517fa50d470e9"
                .to_string(),
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            signed_at: "2026-04-01T12:30:00+00:00".to_string(),
        };
        let rego_hash: [u8; 32] =
            hex::decode("244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372")
                .unwrap()
                .try_into()
                .unwrap();

        assert_eq!(
            hex::encode(canonical_policy_metadata_hash(&metadata).unwrap()),
            "364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83"
        );
        assert_eq!(
            hex::encode(policy_artifact_signing_input(&metadata, &rego_hash).unwrap()),
            "0007707572706f73650000001a656e636c6176612d706f6c6963792d61727469666163742d763100086d6574616461746100000020364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83000b7265676f5f73686132353600000020244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372"
        );
    }

    #[test]
    fn validates_signed_policy_artifact_with_configured_key() {
        let artifacts = signing_artifacts(descriptor());
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let artifact = signed_policy_artifact(&artifacts, &signing_key);
        let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        artifacts
            .validate_signed_artifact(&artifact, &configured_pubkey_hex)
            .unwrap();
    }

    #[test]
    fn validates_customer_supplied_policy_artifact_with_platform_key() {
        let artifacts = signing_artifacts(descriptor());
        let platform_key = SigningKey::from_bytes(&[0x33; 32]);
        let artifact = signed_policy_artifact(&artifacts, &platform_key);
        let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

        artifacts
            .validate_signed_artifact(&artifact, &platform_pubkey_hex)
            .unwrap();
    }

    #[test]
    fn rejects_descriptor_key_signed_customer_supplied_policy_artifact() {
        let descriptor_key = SigningKey::from_bytes(&[0x33; 32]);
        let platform_key = SigningKey::from_bytes(&[0x44; 32]);
        let mut artifacts = signing_artifacts(descriptor());
        artifacts.descriptor_signing_pubkey = descriptor_key.verifying_key().to_bytes();
        let artifact = signed_policy_artifact(&artifacts, &descriptor_key);
        let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

        let err = artifacts
            .validate_signed_artifact(&artifact, &platform_pubkey_hex)
            .unwrap_err();
        assert!(
            matches!(err, SigningServiceError::Mismatch(field) if field == "artifact.verify_pubkey_b64")
        );
    }

    #[test]
    fn validates_customer_artifact_against_canonical_agent_policy() {
        let artifacts = signing_artifacts(descriptor());
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let artifact = signed_policy_artifact(&artifacts, &signing_key);
        let generated = agent_policy_response_for(&artifact);

        artifacts
            .validate_canonical_agent_policy(&artifact, &generated)
            .unwrap();
    }

    #[test]
    fn rejects_customer_artifact_when_descriptor_policy_hash_is_stale() {
        let artifacts = signing_artifacts(descriptor());
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let artifact = signed_policy_artifact(&artifacts, &signing_key);
        let agent_policy_text =
            "package agent_policy\n\ndefault CreateContainerRequest := false\n".to_string();
        let generated = AgentPolicyResponse {
            agent_policy_sha256: hex::encode(Sha256::digest(agent_policy_text.as_bytes())),
            agent_policy_text,
            genpolicy_version_pin: artifact.metadata.genpolicy_version_pin.clone(),
        };

        let err = artifacts
            .validate_canonical_agent_policy(&artifact, &generated)
            .unwrap_err();
        assert!(
            matches!(err, SigningServiceError::Mismatch(field) if field == "generated_agent_policy.expected_agent_policy_hash")
        );
    }

    #[test]
    fn rejects_customer_supplied_policy_artifact_from_unconfigured_key() {
        let platform_key = SigningKey::from_bytes(&[0x33; 32]);
        let other_key = SigningKey::from_bytes(&[0x44; 32]);
        let artifacts = signing_artifacts(descriptor());
        let artifact = signed_policy_artifact(&artifacts, &other_key);
        let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

        let err = artifacts
            .validate_signed_artifact(&artifact, &platform_pubkey_hex)
            .unwrap_err();
        assert!(matches!(err, SigningServiceError::Mismatch(_)));
    }

    #[test]
    fn rejects_signed_policy_artifact_with_wrong_expected_kbs_hash() {
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let mut artifacts = signing_artifacts(descriptor());
        artifacts.descriptor.expected_kbs_policy_hash = [0xee; 32];
        artifacts.descriptor_signing_pubkey = signing_key.verifying_key().to_bytes();
        let artifact = signed_policy_artifact(&artifacts, &signing_key);
        let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let err = artifacts
            .validate_signed_artifact(&artifact, &configured_pubkey_hex)
            .unwrap_err();
        assert!(
            matches!(err, SigningServiceError::Mismatch(field) if field == "expected_kbs_policy_hash")
        );
    }

    #[test]
    fn rejects_signed_policy_artifact_random_signature() {
        let artifacts = signing_artifacts(descriptor());
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
        artifact.signature = "11".repeat(64);
        let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let err = artifacts
            .validate_signed_artifact(&artifact, &configured_pubkey_hex)
            .unwrap_err();
        assert!(matches!(err, SigningServiceError::InvalidSignature));
    }

    #[test]
    fn signed_artifact_agent_policy_drives_cc_init_data_hash() {
        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let mut artifacts = signing_artifacts(descriptor());
        let artifact = signed_policy_artifact(&artifacts, &signing_key);
        let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        artifacts
            .validate_signed_artifact(&artifact, &configured_pubkey_hex)
            .unwrap();

        let generated = artifacts.generated_agent_policy(&artifact).unwrap();
        let mut app = confidential_app_for_descriptor(&artifacts.descriptor);
        app.workload_artifact_binding = Some(artifacts.binding());
        app.generated_agent_policy = Some(generated);

        let toml = enclava_engine::manifest::cc_init_data::build_toml(&app);
        assert!(toml.contains(&format!(
            "\"policy.rego\" = '''\n{}'''",
            artifact.agent_policy_text
        )));

        artifacts.descriptor.expected_cc_init_data_hash = Sha256::digest(toml.as_bytes()).into();
        let (_encoded, hash_hex) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app);
        artifacts
            .validate_rendered_cc_init_data_hash(&hash_hex)
            .unwrap();
    }

    fn confidential_app_for_descriptor(descriptor: &DeploymentDescriptor) -> ConfidentialApp {
        let image = format!("ghcr.io/enclava-ai/demo@{}", descriptor.image_digest);
        ConfidentialApp {
            app_id: descriptor.app_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "demo-instance".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "aa".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: descriptor.app_name.clone(),
                image: ImageRef::parse(&image).unwrap(),
                port: Some(3000),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: vec!["/app/data".to_string()],
                is_primary: true,
            }],
            storage: StorageSpec {
                app_data: VolumeSpec {
                    size: "10Gi".to_string(),
                    device_path: "/dev/csi0".to_string(),
                    mount_path: "/data".to_string(),
                    durability: Durability::DurableState,
                    bootstrap_policy: enclava_common::types::BootstrapPolicy::FirstBootOnly,
                    bind_mounts: vec![BindMount {
                        source: "/data/app".to_string(),
                        destination: "/app/data".to_string(),
                    }],
                },
                tls_data: VolumeSpec {
                    size: "1Gi".to_string(),
                    device_path: "/dev/csi1".to_string(),
                    mount_path: "/tls".to_string(),
                    durability: Durability::DisposableState,
                    bootstrap_policy: enclava_common::types::BootstrapPolicy::AllowReinit,
                    bind_mounts: vec![],
                },
            },
            unlock_mode: UnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "512Mi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(&format!(
                    "ghcr.io/enclava-ai/attestation-proxy@{}",
                    descriptor.sidecars.attestation_proxy_digest
                ))
                .unwrap(),
                caddy_image: ImageRef::parse(&format!(
                    "ghcr.io/enclava-ai/caddy-ingress@{}",
                    descriptor.sidecars.caddy_digest
                ))
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: Some("https://api.example.test/artifacts".to_string()),
                tls_certificate_broker_url: None,
                trustee_policy_url: Some("https://kbs.example.test/policy".to_string()),
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: Some("bb".repeat(32)),
                signing_service_pubkey_hex: Some("bb".repeat(32)),
            },
            egress_allowlist: vec![],
            workload_artifact_binding: None,
            generated_agent_policy: None,
        }
    }
}
