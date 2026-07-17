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
use enclava_engine::types::{GeneratedAgentPolicy, LogEncryptionConfig, WorkloadArtifactBinding};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Executor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::models::App;

const DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS: u64 = 120;
const ORG_SIGNING_AUTHORITY_LANE_DOMAIN: i32 = 0x5349_474e;

fn org_signing_advisory_key(id: Uuid) -> i32 {
    let bytes = id.as_bytes();
    let a = u32::from_be_bytes(bytes[0..4].try_into().expect("UUID word"));
    let b = u32::from_be_bytes(bytes[4..8].try_into().expect("UUID word"));
    let c = u32::from_be_bytes(bytes[8..12].try_into().expect("UUID word"));
    let d = u32::from_be_bytes(bytes[12..16].try_into().expect("UUID word"));
    (a ^ b ^ c ^ d) as i32
}

/// Serialize owner keyring rotation with signed deployment acceptance.
///
/// Callers that also depend on hosted entitlements must acquire the
/// entitlement lane first, then this lane, then the app deployment lane.
pub async fn lock_org_signing_authority_lane(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(ORG_SIGNING_AUTHORITY_LANE_DOMAIN)
        .bind(org_signing_advisory_key(org_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_encryption: Option<LogEncryptionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicyResponse {
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_encryption: Option<LogEncryptionConfig>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_encryption: Option<LogEncryptionConfig>,
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

    pub fn sign_request(&self, log_encryption: Option<LogEncryptionConfig>) -> SignRequest {
        SignRequest {
            app_id: self.descriptor.app_id,
            deploy_id: self.descriptor.deploy_id,
            platform_release_version: self.descriptor.platform_release_version.clone(),
            customer_descriptor_blob: self.customer_descriptor_blob.clone(),
            org_keyring_blob: self.org_keyring_blob.clone(),
            log_encryption,
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
        self.validate_customer_authority_signatures()?;
        self.verify_matches_latest_cap_keyring(pool).await?;
        Ok(())
    }

    /// Repeat customer-authority validation inside the serialized acceptance
    /// transaction immediately before committing signed workload artifacts.
    pub async fn validate_customer_authority_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), SigningServiceError> {
        self.validate_customer_authority_signatures()?;
        self.verify_matches_latest_cap_keyring(&mut **tx).await?;
        Ok(())
    }

    fn validate_customer_authority_signatures(&self) -> Result<(), SigningServiceError> {
        self.verify_keyring_signature()?;
        self.verify_descriptor_signature()?;
        if !self.descriptor_signing_key_is_authorized() {
            return Err(SigningServiceError::Mismatch(
                "descriptor_signing_pubkey not authorized by org_keyring".into(),
            ));
        }
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

    async fn verify_matches_latest_cap_keyring<'e, E>(
        &self,
        executor: E,
    ) -> Result<(), SigningServiceError>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT ok.keyring_payload, ok.signature, usk.pubkey
             FROM org_keyrings ok
             JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
             WHERE ok.org_id = $1
             ORDER BY ok.version DESC
             LIMIT 1",
        )
        .bind(self.org_keyring.org_id)
        .fetch_optional(executor)
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

#[derive(Debug, sqlx::FromRow)]
struct StoredCustomerAuthorityRow {
    descriptor_core_hash: Vec<u8>,
    descriptor_payload: serde_json::Value,
    descriptor_signature: Vec<u8>,
    descriptor_signing_key_id: String,
    org_keyring_payload: serde_json::Value,
    org_keyring_signature: Vec<u8>,
    signed_policy_artifact: serde_json::Value,
}

/// Reconstruct the customer authority persisted for one historical deployment.
/// The signing owner pubkey is intentionally taken from the latest CAP keyring;
/// subsequent validation therefore fails closed after a keyring rotation.
pub async fn load_stored_customer_authority_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<DeploymentSigningArtifacts>, SigningServiceError> {
    let row = sqlx::query_as::<_, StoredCustomerAuthorityRow>(
        "SELECT descriptor_core_hash, descriptor_payload, descriptor_signature,
                descriptor_signing_key_id, org_keyring_payload,
                org_keyring_signature, signed_policy_artifact
           FROM workload_artifacts
          WHERE app_id = $1 AND deploy_id = $2",
    )
    .bind(app_id)
    .bind(deployment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let descriptor: DeploymentDescriptor = serde_json::from_value(row.descriptor_payload)?;
    let descriptor_core_hash = descriptor_core_hash(&descriptor);
    if row.descriptor_core_hash.as_slice() != descriptor_core_hash {
        return Err(SigningServiceError::Mismatch(
            "stored descriptor_core_hash".to_string(),
        ));
    }
    let signed_policy_artifact: SignedPolicyArtifact =
        serde_json::from_value(row.signed_policy_artifact)?;
    if signed_policy_artifact.metadata.app_id != app_id.to_string()
        || signed_policy_artifact.metadata.deploy_id != deployment_id.to_string()
        || signed_policy_artifact.metadata.descriptor_core_hash != hex::encode(descriptor_core_hash)
    {
        return Err(SigningServiceError::Mismatch(
            "stored signed policy artifact identity".to_string(),
        ));
    }
    let descriptor_signing_pubkey = decode_hex32(
        "artifact.metadata.descriptor_signing_pubkey",
        &signed_policy_artifact.metadata.descriptor_signing_pubkey,
    )?;
    let org_keyring: OrgKeyring = serde_json::from_value(row.org_keyring_payload.clone())?;
    let latest_signing_pubkey: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT usk.pubkey
           FROM org_keyrings ok
           JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
          WHERE ok.org_id = $1
          ORDER BY ok.version DESC
          LIMIT 1",
    )
    .bind(org_keyring.org_id)
    .fetch_optional(&mut **tx)
    .await?;
    let latest_signing_pubkey: [u8; 32] = latest_signing_pubkey
        .ok_or_else(|| {
            SigningServiceError::Mismatch("org_keyring not registered with CAP".to_string())
        })?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!(
                "latest org keyring signing pubkey must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
    let descriptor_signature: [u8; 64] =
        row.descriptor_signature
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "stored descriptor signature must be 64 bytes, got {}",
                    bytes.len()
                ))
            })?;
    let org_keyring_signature: [u8; 64] =
        row.org_keyring_signature
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "stored org keyring signature must be 64 bytes, got {}",
                    bytes.len()
                ))
            })?;
    let org_keyring_envelope = serde_json::json!({
        "keyring": &row.org_keyring_payload,
        "signature": hex::encode(org_keyring_signature),
        "signing_pubkey": hex::encode(latest_signing_pubkey),
    });

    Ok(Some(DeploymentSigningArtifacts {
        customer_descriptor_blob: String::new(),
        org_keyring_blob: String::new(),
        org_keyring_envelope,
        descriptor,
        descriptor_signature,
        descriptor_signing_key_id: row.descriptor_signing_key_id,
        descriptor_signing_pubkey,
        descriptor_core_hash,
        org_keyring_fingerprint: keyring_fingerprint(&org_keyring),
        org_keyring,
        org_keyring_signature,
        org_keyring_signing_pubkey: latest_signing_pubkey,
    }))
}

pub async fn persist_workload_artifacts<'e, E>(
    executor: E,
    app_id: Uuid,
    deploy_id: Uuid,
    artifacts: &DeploymentSigningArtifacts,
    signed_policy_artifact: &SignedPolicyArtifact,
) -> Result<(), SigningServiceError>
where
    E: Executor<'e, Database = Postgres>,
{
    let descriptor_payload = serde_json::to_value(&artifacts.descriptor)?;
    let org_keyring_payload = serde_json::to_value(&artifacts.org_keyring)?;
    let signed_policy_artifact = serde_json::to_value(signed_policy_artifact)?;

    sqlx::query(
        "INSERT INTO workload_artifacts (
             descriptor_core_hash, app_id, deploy_id, descriptor_payload,
             descriptor_signature, descriptor_signing_key_id, org_keyring_payload,
             org_keyring_signature, signed_policy_artifact
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
    .execute(executor)
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

#[derive(Debug)]
pub struct LoadedWorkloadArtifacts {
    pub descriptor_core_hash: [u8; 32],
    pub descriptor: DeploymentDescriptor,
    pub binding: WorkloadArtifactBinding,
    pub signed_policy_artifact: SignedPolicyArtifact,
    pub workload_artifacts_json: String,
    pub trustee_policy_json: String,
    signing_artifacts: DeploymentSigningArtifacts,
}

impl LoadedWorkloadArtifacts {
    /// Revalidate every stored cryptographic relationship at dispatch time.
    /// Acceptance-time checks are not enough for a durable queue: the org's
    /// latest keyring and the platform signing key may have changed while a
    /// job waited or a stored JSON value may have been corrupted.
    pub async fn validate_stored_authority(
        &self,
        pool: &PgPool,
        app: &App,
        image_digest: &str,
        api_signing_pubkey: &str,
        signing_service_pubkey_hex: &str,
    ) -> Result<(), SigningServiceError> {
        self.signing_artifacts
            .validate_deployment_inputs(app, image_digest, api_signing_pubkey)?;
        self.signing_artifacts
            .validate_customer_authority(pool)
            .await?;
        self.signing_artifacts
            .validate_signed_artifact(&self.signed_policy_artifact, signing_service_pubkey_hex)?;
        // This also ensures the stored policy's attached keyring, signature,
        // and signing key are the authority used for descriptor verification.
        let mut artifact = self.signed_policy_artifact.clone();
        self.signing_artifacts
            .attach_customer_authority(&mut artifact)?;
        Ok(())
    }

    pub fn validate_rendered_cc_init_data_hash(
        &self,
        actual_hash_hex: &str,
    ) -> Result<(), SigningServiceError> {
        self.signing_artifacts
            .validate_rendered_cc_init_data_hash(actual_hash_hex)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct LoadedWorkloadArtifactsRow {
    descriptor_core_hash: Vec<u8>,
    descriptor_payload: serde_json::Value,
    descriptor_signature: Vec<u8>,
    descriptor_signing_key_id: String,
    org_keyring_payload: serde_json::Value,
    org_keyring_signature: Vec<u8>,
    signed_policy_artifact: serde_json::Value,
}

fn decode_loaded_workload_artifacts(
    row: LoadedWorkloadArtifactsRow,
    app_id: Uuid,
    deploy_id: Uuid,
) -> Result<LoadedWorkloadArtifacts, SigningServiceError> {
    let stored_descriptor_core_hash: [u8; 32] =
        row.descriptor_core_hash
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "descriptor_core_hash must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
    let descriptor: DeploymentDescriptor = serde_json::from_value(row.descriptor_payload.clone())?;
    if descriptor.app_id != app_id {
        return Err(SigningServiceError::Mismatch(
            "stored descriptor app_id".into(),
        ));
    }
    if descriptor.deploy_id != deploy_id {
        return Err(SigningServiceError::Mismatch(
            "stored descriptor deploy_id".into(),
        ));
    }
    if descriptor_core_hash(&descriptor) != stored_descriptor_core_hash {
        return Err(SigningServiceError::Mismatch(
            "stored descriptor_core_hash".into(),
        ));
    }

    let org_keyring: OrgKeyring = serde_json::from_value(row.org_keyring_payload.clone())?;
    let signed_policy_artifact: SignedPolicyArtifact =
        serde_json::from_value(row.signed_policy_artifact.clone())?;
    let descriptor_signing_pubkey = decode_hex32(
        "artifact.metadata.descriptor_signing_pubkey",
        &signed_policy_artifact.metadata.descriptor_signing_pubkey,
    )?;
    let attached_keyring: OrgKeyringEnvelope =
        serde_json::from_value(signed_policy_artifact.org_keyring.clone().ok_or_else(|| {
            SigningServiceError::Mismatch("artifact.org_keyring missing".into())
        })?)?;
    let descriptor_signature: [u8; 64] =
        row.descriptor_signature
            .clone()
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "descriptor_signature must be 64 bytes, got {}",
                    bytes.len()
                ))
            })?;
    let org_keyring_signature: [u8; 64] =
        row.org_keyring_signature
            .clone()
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                SigningServiceError::Blob(format!(
                    "org_keyring_signature must be 64 bytes, got {}",
                    bytes.len()
                ))
            })?;
    if keyring_fingerprint(&attached_keyring.keyring) != keyring_fingerprint(&org_keyring)
        || attached_keyring.signature != org_keyring_signature
    {
        return Err(SigningServiceError::Mismatch(
            "artifact.org_keyring does not match stored authority".into(),
        ));
    }
    let org_keyring_fingerprint = keyring_fingerprint(&org_keyring);
    let org_keyring_envelope = serde_json::to_value(&attached_keyring)?;
    let signing_artifacts = DeploymentSigningArtifacts {
        customer_descriptor_blob: String::new(),
        org_keyring_blob: String::new(),
        org_keyring_envelope,
        descriptor: descriptor.clone(),
        descriptor_signature,
        descriptor_signing_key_id: row.descriptor_signing_key_id.clone(),
        descriptor_signing_pubkey,
        descriptor_core_hash: stored_descriptor_core_hash,
        org_keyring: org_keyring.clone(),
        org_keyring_signature,
        org_keyring_signing_pubkey: attached_keyring.signing_pubkey,
        org_keyring_fingerprint,
    };
    let artifacts_json = serde_json::json!({
        "descriptor_payload": row.descriptor_payload,
        "descriptor_signature": hex::encode(row.descriptor_signature),
        "descriptor_signing_key_id": row.descriptor_signing_key_id,
        "org_keyring_payload": row.org_keyring_payload,
        "org_keyring_signature": hex::encode(row.org_keyring_signature),
        "signed_policy_artifact": row.signed_policy_artifact,
    });

    Ok(LoadedWorkloadArtifacts {
        descriptor_core_hash: stored_descriptor_core_hash,
        descriptor,
        binding: WorkloadArtifactBinding {
            descriptor_core_hash: stored_descriptor_core_hash,
            descriptor_signing_pubkey,
            org_keyring_fingerprint,
        },
        trustee_policy_json: serde_json::to_string(&signed_policy_artifact)?,
        workload_artifacts_json: serde_json::to_string(&artifacts_json)?,
        signed_policy_artifact,
        signing_artifacts,
    })
}

/// Load the single authoritative artifact row for a deployment. The unique
/// `(app_id, deploy_id)` constraint makes absence or malformed content
/// unambiguous during rollback preparation.
pub async fn load_workload_artifacts_for_deployment(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
) -> Result<Option<LoadedWorkloadArtifacts>, SigningServiceError> {
    let row = sqlx::query_as::<_, LoadedWorkloadArtifactsRow>(
        "SELECT descriptor_core_hash, descriptor_payload, descriptor_signature,
                descriptor_signing_key_id, org_keyring_payload,
                org_keyring_signature, signed_policy_artifact
           FROM workload_artifacts
          WHERE app_id = $1 AND deploy_id = $2",
    )
    .bind(app_id)
    .bind(deploy_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| decode_loaded_workload_artifacts(row, app_id, deploy_id))
        .transpose()
}

/// Reload an accepted job's exact immutable artifact row. All three identity
/// components are required so neither a colliding core hash nor a repointed
/// app/deployment binding can be mixed into the apply payload.
pub async fn load_workload_artifacts_exact(
    pool: &PgPool,
    app_id: Uuid,
    deploy_id: Uuid,
    expected_descriptor_core_hash: [u8; 32],
) -> Result<Option<LoadedWorkloadArtifacts>, SigningServiceError> {
    let row = sqlx::query_as::<_, LoadedWorkloadArtifactsRow>(
        "SELECT descriptor_core_hash, descriptor_payload, descriptor_signature,
                descriptor_signing_key_id, org_keyring_payload,
                org_keyring_signature, signed_policy_artifact
           FROM workload_artifacts
          WHERE descriptor_core_hash = $1
            AND app_id = $2
            AND deploy_id = $3",
    )
    .bind(expected_descriptor_core_hash.to_vec())
    .bind(app_id)
    .bind(deploy_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| decode_loaded_workload_artifacts(row, app_id, deploy_id))
        .transpose()
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

mod keyring;
use keyring::{
    DeploymentDescriptorEnvelope, KeyringRole, OrgKeyring, OrgKeyringEnvelope,
    canonical_keyring_bytes, decode_hex32, decode_json_blob, decode_pubkey_b64, decode_signature,
    keyring_fingerprint,
};

#[cfg(test)]
#[path = "signing_service/tests/mod.rs"]
mod tests;
