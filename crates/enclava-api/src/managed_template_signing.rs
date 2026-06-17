use chrono::Utc;
use enclava_cli::{
    descriptor::{
        CapAppOciRuntimeSpecInput, DeploymentDescriptorBuildInput, Sidecars, SignerIdentity,
        build_descriptor, cap_app_oci_runtime_spec,
    },
    keyring::{Role, sign_keyring, single_member_keyring},
    keys::UserSigningKey,
};
use enclava_common::{descriptor::descriptor_core_hash, image::ImageRef, types::ResourceLimits};
use enclava_engine::{
    manifest::cc_init_data,
    types::{
        ConfidentialApp, Container, DomainSpec, GeneratedAgentPolicy, HealthCheck, StorageSpec,
        WorkloadArtifactBinding,
    },
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    auth::jwt::public_key_base64, models::App, platform_release::PlatformRelease, state::AppState,
};

#[derive(Debug, thiserror::Error)]
pub enum ManagedTemplateSigningError {
    #[error("{0}")]
    Validation(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("platform release error: {0}")]
    PlatformRelease(#[from] crate::platform_release::PlatformReleaseError),
    #[error("signing service error: {0}")]
    SigningService(#[from] crate::signing_service::SigningServiceError),
    #[error("deploy spec error: {0}")]
    Deploy(#[from] crate::deploy::DeployError),
}

pub struct ManagedTemplateSigningInput {
    pub app: App,
    pub user_id: Uuid,
    pub image: String,
    pub container_name: String,
    pub command: Vec<String>,
    pub port: u16,
    pub storage_paths: Vec<String>,
    pub cpu: String,
    pub memory: String,
}

pub struct ManagedTemplateSigningArtifacts {
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
}

pub async fn build_managed_template_signing_artifacts(
    state: &AppState,
    input: ManagedTemplateSigningInput,
) -> Result<ManagedTemplateSigningArtifacts, ManagedTemplateSigningError> {
    if input.command.is_empty() || input.command.iter().any(|arg| arg.is_empty()) {
        return Err(ManagedTemplateSigningError::Validation(
            "managed template signing requires a non-empty workload command".into(),
        ));
    }

    let attestation = state.attestation.as_ref().ok_or_else(|| {
        ManagedTemplateSigningError::Validation(
            "managed template signing requires attestation runtime configuration".into(),
        )
    })?;
    if attestation.signing_service_pubkey_hex.is_none() {
        return Err(ManagedTemplateSigningError::Validation(
            "managed template signing requires SIGNING_SERVICE_PUBKEY_HEX".into(),
        ));
    }
    let signing_service = state.signing_service.as_ref().ok_or_else(|| {
        ManagedTemplateSigningError::Validation(
            "managed template signing requires PLATFORM_SIGNING_SERVICE_URL".into(),
        )
    })?;

    let image_ref = ImageRef::parse(&input.image)
        .map_err(|err| ManagedTemplateSigningError::Validation(err.to_string()))?;
    image_ref
        .require_digest()
        .map_err(|err| ManagedTemplateSigningError::Validation(err.to_string()))?;

    let release = PlatformRelease::load_verified()?;
    let proxy_image = ImageRef::parse(&release.attestation_proxy_image)
        .map_err(|err| ManagedTemplateSigningError::Validation(err.to_string()))?;
    let caddy_image = ImageRef::parse(&release.caddy_ingress_image)
        .map_err(|err| ManagedTemplateSigningError::Validation(err.to_string()))?;
    let policy_template_sha256 = release.policy_template_sha256_bytes()?;
    let expected_firmware_measurement = release.expected_firmware_measurement_bytes()?;
    let api_signing_pubkey = public_key_base64(&state.signing_key);
    let org_slug = org_slug(&state.db, input.app.org_id).await?;

    let deployer_key = managed_owner_key(&state.signing_key, input.user_id, input.app.org_id);
    let keyring_version = next_keyring_version(&state.db, input.app.org_id).await?;
    let now = Utc::now();
    let keyring = single_member_keyring(
        input.app.org_id,
        keyring_version,
        &deployer_key,
        Role::Owner,
        now,
    );
    let keyring_envelope = sign_keyring(&deployer_key, keyring);
    let org_keyring_fingerprint: [u8; 32] = Sha256::digest(
        enclava_cli::keyring::canonical_keyring_bytes(&keyring_envelope.keyring),
    )
    .into();
    persist_managed_keyring(&state.db, input.user_id, &deployer_key, &keyring_envelope).await?;
    signing_service
        .bootstrap_org(&crate::signing_service::BootstrapOrgRequest {
            org_id: input.app.org_id,
            owner_pubkey_hex: hex::encode(deployer_key.public.to_bytes()),
        })
        .await?;

    let identity_hash = parse_hex32(
        "tenant_instance_identity_hash",
        &input.app.tenant_instance_identity_hash,
    )?;
    let mut descriptor = build_descriptor(DeploymentDescriptorBuildInput {
        org_id: input.app.org_id,
        org_slug,
        app_id: input.app.id,
        app_name: input.app.name.clone(),
        deploy_id: Uuid::new_v4(),
        created_at: now,
        app_domain: input.app.domain.clone(),
        tee_domain: input
            .app
            .tee_domain
            .clone()
            .unwrap_or_else(|| input.app.domain.clone()),
        custom_domains: input.app.custom_domain.clone().into_iter().collect(),
        namespace: input.app.namespace.clone(),
        service_account: input.app.service_account.clone(),
        identity_hash,
        image_ref: image_ref.digest_ref(),
        image_digest: image_ref.digest().to_string(),
        signer_identity: SignerIdentity {
            subject: input
                .app
                .signer_identity_subject
                .clone()
                .unwrap_or_default(),
            issuer: input.app.signer_identity_issuer.clone().unwrap_or_default(),
        },
        oci_runtime_spec: cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
            container_name: input.container_name,
            port: input.port,
            workload_command: input.command,
            storage_paths: input.storage_paths,
            cpu_limit: input.cpu,
            memory_limit: input.memory,
        }),
        sidecars: Sidecars {
            attestation_proxy_digest: proxy_image.digest().to_string(),
            caddy_digest: caddy_image.digest().to_string(),
        },
        api_signing_pubkey,
        expected_firmware_measurement,
        expected_runtime_class: release.expected_runtime_class.clone(),
        kbs_resource_path: format!(
            "default/{}-{}-owner/seed-encrypted",
            input.app.namespace, input.app.name
        ),
        unlock_mode: app_unlock_mode(input.app.unlock_mode).to_string(),
        policy_template_id: release.policy_template_id.clone(),
        policy_template_sha256,
        platform_release_version: release.platform_release_version.clone(),
        expected_agent_policy_hash: [0; 32],
        expected_cc_init_data_hash: [0; 32],
        expected_kbs_policy_hash: [0; 32],
    });

    let generated = signing_service
        .agent_policy(&crate::signing_service::AgentPolicyRequest {
            descriptor: descriptor.clone(),
        })
        .await?;
    if generated.genpolicy_version_pin != release.genpolicy_version {
        return Err(ManagedTemplateSigningError::Validation(format!(
            "policy signing service genpolicy version {} does not match signed platform release {}",
            generated.genpolicy_version_pin, release.genpolicy_version
        )));
    }
    let generated_policy = generated_agent_policy(generated)?;
    descriptor.expected_agent_policy_hash = generated_policy.policy_sha256;

    let descriptor_core_hash = descriptor_core_hash(&descriptor);
    let binding = WorkloadArtifactBinding {
        descriptor_core_hash,
        descriptor_signing_pubkey: deployer_key.public.to_bytes(),
        org_keyring_fingerprint,
    };
    let mut app_spec = confidential_app_for_template_hash(
        &input.app,
        attestation,
        &state.api_url,
        image_ref,
        &descriptor,
    )?;
    crate::routes::deployments::select_local_signed_artifact_delivery(&mut app_spec.attestation);
    app_spec.workload_artifact_binding = Some(binding);
    app_spec.generated_agent_policy = Some(generated_policy);
    let (_, cc_init_data_hash) = cc_init_data::compute_cc_init_data(&app_spec);
    descriptor.expected_cc_init_data_hash =
        parse_hex32("expected_cc_init_data_hash", &cc_init_data_hash)?;
    let rendered_policy = render_trustee_policy(&release.policy_template_text, &descriptor)?;
    descriptor.expected_kbs_policy_hash = Sha256::digest(rendered_policy.as_bytes()).into();

    let descriptor_envelope = enclava_cli::descriptor::sign(
        &deployer_key,
        descriptor,
        format!("paas-managed-template:{}", input.user_id),
    );

    Ok(ManagedTemplateSigningArtifacts {
        customer_descriptor_blob: serde_json::to_string(&descriptor_envelope)?,
        org_keyring_blob: serde_json::to_string(&keyring_envelope)?,
    })
}

fn managed_owner_key(
    api_signing_key: &ed25519_dalek::SigningKey,
    user_id: Uuid,
    org_id: Uuid,
) -> UserSigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"enclava-paas-managed-template-owner-v1");
    hasher.update(api_signing_key.to_bytes());
    hasher.update(org_id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    UserSigningKey::from_seed(user_id, seed)
}

fn confidential_app_for_template_hash(
    app: &App,
    attestation: &enclava_engine::types::AttestationConfig,
    api_url: &str,
    image_ref: ImageRef,
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Result<ConfidentialApp, ManagedTemplateSigningError> {
    let unlock_mode = match app.unlock_mode {
        crate::models::UnlockMode::Auto => enclava_common::types::UnlockMode::Auto,
        crate::models::UnlockMode::Password => enclava_common::types::UnlockMode::Password,
    };
    let egress_allowlist =
        crate::routes::apps::engine_egress_allowlist_from_json(&app.egress_allowlist)
            .map_err(ManagedTemplateSigningError::Validation)?;

    Ok(ConfidentialApp {
        app_id: app.id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers: vec![Container {
            name: descriptor
                .oci_runtime_spec
                .env
                .iter()
                .find(|env| env.name == "ENCLAVA_CONTAINER_NAME")
                .map(|env| env.value.clone())
                .unwrap_or_else(|| "web".to_string()),
            image: image_ref,
            port: crate::deploy::descriptor_primary_port(descriptor)
                .and_then(|port| u16::try_from(port).ok()),
            command: crate::deploy::serialize_workload_command(&descriptor.oci_runtime_spec.args)
                .map_err(|err| ManagedTemplateSigningError::Validation(err.to_string()))?
                .and_then(|raw| serde_json::from_str(&raw).ok()),
            env: HashMap::new(),
            storage_paths: crate::deploy::descriptor_storage_paths(descriptor),
            is_primary: true,
        }],
        storage: StorageSpec::new("5Gi", "2Gi"),
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey: descriptor.api_signing_pubkey.clone(),
        api_url: api_url.to_string(),
        resources: ResourceLimits {
            cpu: descriptor
                .oci_runtime_spec
                .resources
                .limits
                .iter()
                .find(|entry| entry.name == "cpu")
                .map(|entry| entry.value.clone())
                .unwrap_or_default(),
            memory: descriptor
                .oci_runtime_spec
                .resources
                .limits
                .iter()
                .find(|entry| entry.name == "memory")
                .map(|entry| entry.value.clone())
                .unwrap_or_default(),
        },
        health: HealthCheck {
            path: app.health_path.clone(),
            interval_seconds: app.health_interval_seconds.max(1) as u32,
            timeout_seconds: app.health_timeout_seconds.max(1) as u32,
        },
        attestation: attestation.clone(),
        egress_allowlist,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    })
}

fn app_unlock_mode(mode: crate::models::UnlockMode) -> &'static str {
    match mode {
        crate::models::UnlockMode::Auto => "auto",
        crate::models::UnlockMode::Password => "password",
    }
}

fn parse_hex32(field: &'static str, value: &str) -> Result<[u8; 32], ManagedTemplateSigningError> {
    hex::decode(value.trim())
        .map_err(|err| ManagedTemplateSigningError::Validation(format!("{field}: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            ManagedTemplateSigningError::Validation(format!(
                "{field} must be 32 bytes, got {}",
                bytes.len()
            ))
        })
}

fn generated_agent_policy(
    response: crate::signing_service::AgentPolicyResponse,
) -> Result<GeneratedAgentPolicy, ManagedTemplateSigningError> {
    let policy_sha256 = parse_hex32("agent_policy_sha256", &response.agent_policy_sha256)?;
    let actual: [u8; 32] = Sha256::digest(response.agent_policy_text.as_bytes()).into();
    if actual != policy_sha256 {
        return Err(ManagedTemplateSigningError::Validation(
            "policy signing service returned agent_policy_sha256 that does not match agent_policy_text"
                .into(),
        ));
    }
    Ok(GeneratedAgentPolicy {
        policy_text: response.agent_policy_text,
        policy_sha256,
        genpolicy_version_pin: response.genpolicy_version_pin,
    })
}

async fn org_slug(pool: &PgPool, org_id: Uuid) -> Result<String, ManagedTemplateSigningError> {
    Ok(
        sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_one(pool)
            .await?,
    )
}

async fn next_keyring_version(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<u64, ManagedTemplateSigningError> {
    let latest: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    Ok(latest.unwrap_or(0) as u64 + 1)
}

async fn persist_managed_keyring(
    pool: &PgPool,
    user_id: Uuid,
    deployer_key: &UserSigningKey,
    envelope: &enclava_cli::keyring::OrgKeyringEnvelope,
) -> Result<(), ManagedTemplateSigningError> {
    let signing_key_id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_signing_keys (id, user_id, pubkey)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, pubkey) WHERE revoked_at IS NULL
         DO UPDATE SET pubkey = EXCLUDED.pubkey
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(deployer_key.public.to_bytes().to_vec())
    .fetch_one(pool)
    .await?;

    sqlx::query(
        "INSERT INTO org_keyrings
             (org_id, version, keyring_payload, signature, signing_key_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(envelope.keyring.org_id)
    .bind(envelope.keyring.version as i64)
    .bind(serde_json::to_vec(&envelope.keyring)?)
    .bind(envelope.signature.to_bytes().to_vec())
    .bind(signing_key_id)
    .execute(pool)
    .await?;
    Ok(())
}

fn render_trustee_policy(
    template: &str,
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Result<String, ManagedTemplateSigningError> {
    let replacements = [
        (
            "{{init_data_hash}}",
            hex::encode(descriptor.expected_cc_init_data_hash),
        ),
        ("{{image_digest}}", descriptor.image_digest.clone()),
        (
            "{{signer_subject}}",
            descriptor.signer_identity.subject.clone(),
        ),
        (
            "{{signer_issuer}}",
            descriptor.signer_identity.issuer.clone(),
        ),
        ("{{namespace}}", descriptor.namespace.clone()),
        ("{{service_account}}", descriptor.service_account.clone()),
        ("{{identity_hash}}", hex::encode(descriptor.identity_hash)),
        (
            "{{kbs_resource_path}}",
            descriptor.kbs_resource_path.clone(),
        ),
    ];

    let mut rendered = template.to_string();
    for (needle, value) in replacements {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| matches!(byte, b'"' | b'\\' | b'\n' | b'\r'))
        {
            return Err(ManagedTemplateSigningError::Validation(format!(
                "invalid Rego template slot value for {needle}"
            )));
        }
        rendered = rendered.replace(needle, &value);
    }
    if rendered.contains("{{") {
        return Err(ManagedTemplateSigningError::Validation(
            "unrendered Rego template slot remains in platform release".into(),
        ));
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn managed_owner_key_is_stable_per_org() {
        let api_key = SigningKey::from_bytes(&[7; 32]);
        let user_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let org_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let other_org_id = Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();

        let first = managed_owner_key(&api_key, user_id, org_id);
        let second = managed_owner_key(&api_key, user_id, org_id);
        let other = managed_owner_key(&api_key, user_id, other_org_id);

        assert_eq!(first.public.to_bytes(), second.public.to_bytes());
        assert_ne!(first.public.to_bytes(), other.public.to_bytes());
    }
}
