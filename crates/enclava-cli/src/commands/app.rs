use clap::Args;
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use clap::Subcommand;
use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::*;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::descriptor::{
    CapAppOciRuntimeSpecInput, DeploymentDescriptorBuildInput, Sidecars, SignerIdentity,
    build_descriptor, cap_app_oci_runtime_spec,
};
use enclava_cli::keyring::{
    keyring_fingerprint, load_keyring_envelope, load_trusted_owner, member_allows_deploy,
    verify_keyring,
};
use enclava_cli::keys;
use enclava_cli::platform_release::PlatformRelease;
use enclava_cli::tee_client::TeeClient;
use enclava_common::types::{ResourceLimits, UnlockMode};
use enclava_engine::manifest::cc_init_data;
use enclava_engine::types::{
    AttestationConfig, ConfidentialApp, Container, DomainSpec, GeneratedAgentPolicy, StorageSpec,
    WorkloadArtifactBinding,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Resolve app name from --app flag or enclava.toml.
fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

/// Build an authenticated API client from stored config/credentials.
fn build_api_client() -> Result<(ApiClient, CliPaths, config::CliConfig), Box<dyn std::error::Error>>
{
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths, cli_config))
}

/// Parse KEY=VALUE pairs from --set flags.
fn parse_config_vars(vars: &[String]) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    vars.iter()
        .map(|v| {
            let (key, value) = v
                .split_once('=')
                .ok_or_else(|| format!("invalid config format '{v}': expected KEY=VALUE"))?;
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} must be 32 bytes, got {}", bytes.len()).into())
}

fn env_hex32(name: &str) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    std::env::var(name)
        .ok()
        .map(|value| parse_hex32(name, &value))
        .transpose()
}

fn jwt_subject(token: &str) -> Option<Uuid> {
    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let claims: Claims = serde_json::from_slice(&bytes).ok()?;
    Uuid::parse_str(&claims.sub).ok()
}

fn render_trustee_policy(
    template: &str,
    descriptor: &enclava_cli::descriptor::DeploymentDescriptor,
) -> Result<String, Box<dyn std::error::Error>> {
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
            return Err(format!("invalid Rego template slot value for {needle}").into());
        }
        rendered = rendered.replace(needle, &value);
    }
    if rendered.contains("{{") {
        return Err("unrendered Rego template slot remains in platform release".into());
    }
    Ok(rendered)
}

struct ConfidentialAppForCcHash<'a> {
    image: enclava_common::image::ImageRef,
    release: &'a PlatformRelease,
    workload_artifact_binding: WorkloadArtifactBinding,
    generated_agent_policy: GeneratedAgentPolicy,
    unlock_mode: &'a str,
    tenant_id: String,
    tenant_instance_identity_hash: [u8; 32],
    bootstrap_owner_pubkey_hash: String,
}

fn confidential_app_for_cc_hash(
    app: &AppResponse,
    app_config: &AppConfig,
    params: ConfidentialAppForCcHash<'_>,
) -> Result<ConfidentialApp, Box<dyn std::error::Error>> {
    let ConfidentialAppForCcHash {
        image,
        release,
        workload_artifact_binding,
        generated_agent_policy,
        unlock_mode,
        tenant_id,
        tenant_instance_identity_hash,
        bootstrap_owner_pubkey_hash,
    } = params;

    let unlock_mode = match unlock_mode {
        "password" => UnlockMode::Password,
        "auto" | "auto-unlock" => UnlockMode::Auto,
        other => return Err(format!("unsupported unlock mode {other}").into()),
    };

    Ok(ConfidentialApp {
        app_id: Uuid::parse_str(&app.id)?,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id,
        bootstrap_owner_pubkey_hash,
        tenant_instance_identity_hash: hex::encode(tenant_instance_identity_hash),
        service_account: app
            .service_account
            .clone()
            .unwrap_or_else(|| format!("cap-{}-sa", app.name)),
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers: vec![Container {
            name: "web".to_string(),
            image,
            port: Some(app_config.app.port),
            command: None,
            env: HashMap::new(),
            storage_paths: app_config.storage.paths.clone(),
            is_primary: true,
        }],
        storage: StorageSpec::new(&app_config.storage.size, &app_config.storage.tls_size),
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey: String::new(),
        api_url: String::new(),
        resources: ResourceLimits {
            cpu: app_config.resources.cpu.clone(),
            memory: app_config.resources.memory.clone(),
        },
        attestation: AttestationConfig {
            proxy_image: enclava_common::image::ImageRef::parse(&release.attestation_proxy_image)?,
            caddy_image: enclava_common::image::ImageRef::parse(&release.caddy_ingress_image)?,
            acme_ca_url: release.tenant_caddy_acme_ca.clone(),
            caddy_tls_mode: release
                .tenant_caddy_tls_mode
                .parse::<enclava_engine::types::CaddyTlsMode>()
                .map_err(|err| format!("platform release tenant_caddy_tls_mode: {err}"))?,
            trustee_policy_read_available: true,
            workload_artifacts_url: None,
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: Some(release.signing_service_pubkey_hex.clone()),
            signing_service_pubkey_hex: Some(release.signing_service_pubkey_hex.clone()),
        },
        egress_allowlist: Vec::new(),
        workload_artifact_binding: Some(workload_artifact_binding),
        generated_agent_policy: Some(generated_agent_policy),
    })
}

async fn fetch_generated_agent_policy(
    api: &ApiClient,
    release: &PlatformRelease,
    descriptor: &enclava_cli::descriptor::DeploymentDescriptor,
) -> Result<GeneratedAgentPolicy, Box<dyn std::error::Error>> {
    let response = api
        .generate_agent_policy(
            &descriptor.app_name,
            &AgentPolicyRequest {
                descriptor: descriptor.clone(),
            },
        )
        .await?;
    if response.genpolicy_version_pin != release.genpolicy_version {
        return Err(format!(
            "policy signing service genpolicy version {} does not match signed platform release {}",
            response.genpolicy_version_pin, release.genpolicy_version
        )
        .into());
    }
    let policy_sha256: [u8; 32] = hex::decode(&response.agent_policy_sha256)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!("agent_policy_sha256 must be 32 bytes, got {}", bytes.len())
        })?;
    let actual: [u8; 32] = Sha256::digest(response.agent_policy_text.as_bytes()).into();
    if actual != policy_sha256 {
        return Err("policy signing service returned agent_policy_sha256 that does not match agent_policy_text".into());
    }
    Ok(GeneratedAgentPolicy {
        policy_text: response.agent_policy_text,
        policy_sha256,
        genpolicy_version_pin: response.genpolicy_version_pin,
    })
}

fn bootstrap_identity_hash(
    paths: &CliPaths,
    org_name: &str,
    app_name: &str,
    tenant_id: &str,
    instance_id: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let key_path = paths.bootstrap_key_path(org_name, app_name);
    if !key_path.exists() {
        return Ok(None);
    }

    let private_key_hex = std::fs::read_to_string(&key_path)?;
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex.trim())?
        .try_into()
        .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)")?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key_hash = hex::encode(Sha256::digest(signing_key.verifying_key().to_bytes()));
    let identity_hash =
        enclava_common::crypto::compute_identity_hash(tenant_id, instance_id, &public_key_hash);
    Ok(Some(parse_hex32(
        "tenant_instance_identity_hash",
        &identity_hash,
    )?))
}

fn bootstrap_public_key_hash(
    paths: &CliPaths,
    org_name: &str,
    app_name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let key_path = paths.bootstrap_key_path(org_name, app_name);
    if !key_path.exists() {
        return Ok(None);
    }
    let private_key_hex = std::fs::read_to_string(&key_path)?;
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex.trim())?
        .try_into()
        .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)")?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    Ok(Some(hex::encode(Sha256::digest(
        signing_key.verifying_key().to_bytes(),
    ))))
}

pub(crate) struct SignedDeployBlobParams<'a> {
    pub api: &'a ApiClient,
    pub paths: &'a CliPaths,
    pub cli_config: &'a config::CliConfig,
    pub creds: &'a config::Credentials,
    pub app: &'a AppResponse,
    pub app_config: &'a AppConfig,
    pub image: &'a str,
    pub target_unlock_mode: Option<&'a str>,
}

pub(crate) struct SignedDeployBlobs {
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
    pub signed_policy_artifact: String,
}

pub(crate) async fn build_signed_deploy_blobs(
    params: SignedDeployBlobParams<'_>,
) -> Result<SignedDeployBlobs, Box<dyn std::error::Error>> {
    let SignedDeployBlobParams {
        api,
        paths,
        cli_config,
        creds,
        app,
        app_config,
        image,
        target_unlock_mode,
    } = params;
    let image_ref = enclava_common::image::ImageRef::parse(image)?;
    if !image_ref.has_digest() {
        return Err("deployment descriptor signing requires --image to be digest-pinned".into());
    }
    let deploy_unlock_mode = target_unlock_mode.unwrap_or(app.unlock_mode.as_str());
    if app_config.app.command.is_empty() {
        return Err(
            "app.command in enclava.toml must specify the workload argv, for example [\"/usr/local/bin/app\"]"
                .into(),
        );
    }

    let release = PlatformRelease::load_verified()?;
    let policy_template_sha256 = release.policy_template_sha256_bytes()?;
    let _signing_service_pubkey = release.signing_service_pubkey_bytes()?;
    let proxy_image = enclava_common::image::ImageRef::parse(&release.attestation_proxy_image)?;
    let caddy_image = enclava_common::image::ImageRef::parse(&release.caddy_ingress_image)?;
    if !proxy_image.has_digest() || !caddy_image.has_digest() {
        return Err("platform release sidecar anchors must be digest-pinned".into());
    }

    let org_name = match cli_config.org.as_deref() {
        Some(org) => org,
        None => return Err("active org is required to sign deployment descriptor".into()),
    };
    let org_id = if let Ok(value) = std::env::var("ENCLAVA_ORG_ID") {
        Uuid::parse_str(&value)?
    } else {
        api.list_orgs()
            .await?
            .into_iter()
            .find(|org| org.name == org_name)
            .and_then(|org| org.id)
            .ok_or_else(|| format!("active org '{org_name}' was not returned by /orgs"))?
            .parse()?
    };

    let app_id = Uuid::parse_str(&app.id)?;
    let user_id = creds
        .session_token
        .as_deref()
        .and_then(jwt_subject)
        .unwrap_or_else(Uuid::new_v4);
    let deployer_key = keys::create_and_store(user_id)?;
    let trusted_owner = load_trusted_owner(&org_id)?
        .ok_or("org owner pubkey is not trusted; run `enclava org keyring trust` or `enclava org keyring init`")?;
    let keyring_envelope = load_keyring_envelope(&org_id).map_err(|err| {
        format!(
            "org keyring for {org_id} is not available locally: {err}; run `enclava org keyring init` or import the owner-signed keyring"
        )
    })?;
    let verified_keyring = verify_keyring(&keyring_envelope, &trusted_owner)?;
    if !member_allows_deploy(verified_keyring, &deployer_key.public) {
        return Err(
            "current CLI signing key is not an owner/admin/deployer in the org keyring".into(),
        );
    }
    let org_keyring_fingerprint = keyring_fingerprint(verified_keyring);

    let tenant_id = org_name.to_string();
    let identity_hash = if let Some(value) = app.tenant_instance_identity_hash.as_deref() {
        parse_hex32("tenant_instance_identity_hash", value)?
    } else if let Some(value) = env_hex32("ENCLAVA_TENANT_INSTANCE_IDENTITY_HASH")? {
        value
    } else if deploy_unlock_mode == "password" {
        match bootstrap_identity_hash(paths, org_name, &app.name, &tenant_id, &app.instance_id)? {
            Some(hash) => hash,
            None => {
                return Err(
                    "tenant identity hash anchor is required to sign deployment descriptor".into(),
                );
            }
        }
    } else {
        return Err("ENCLAVA_TENANT_INSTANCE_IDENTITY_HASH is required to sign auto-unlock deployment descriptor".into());
    };
    let bootstrap_pubkey_hash = if let Some(value) = app.bootstrap_owner_pubkey_hash.clone() {
        value
    } else if let Some(value) = bootstrap_public_key_hash(paths, org_name, &app.name)? {
        value
    } else {
        std::env::var("ENCLAVA_BOOTSTRAP_OWNER_PUBKEY_HASH")
            .map_err(|_| "bootstrap owner pubkey hash is required to derive cc_init_data hash")?
    };

    let signer_identity = match (
        app.signer_identity_subject.clone(),
        app.signer_identity_issuer.clone(),
    ) {
        (Some(subject), Some(issuer)) if !subject.is_empty() && !issuer.is_empty() => {
            SignerIdentity { subject, issuer }
        }
        _ => {
            return Err(
                "app signer identity must be pinned before signing deployment descriptor".into(),
            );
        }
    };

    let mut descriptor = build_descriptor(DeploymentDescriptorBuildInput {
        org_id,
        org_slug: org_name.to_string(),
        app_id,
        app_name: app.name.clone(),
        deploy_id: Uuid::new_v4(),
        created_at: Utc::now(),
        app_domain: app.domain.clone(),
        tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
        custom_domains: app.custom_domain.clone().into_iter().collect(),
        namespace: app.namespace.clone(),
        service_account: app
            .service_account
            .clone()
            .unwrap_or_else(|| format!("cap-{}-sa", app.name)),
        identity_hash,
        image_ref: image_ref.digest_ref(),
        image_digest: image_ref.digest().to_string(),
        signer_identity,
        oci_runtime_spec: cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
            container_name: "web".to_string(),
            port: app_config.app.port,
            workload_command: app_config.app.command.clone(),
            storage_paths: app_config.storage.paths.clone(),
            cpu_limit: app_config.resources.cpu.clone(),
            memory_limit: app_config.resources.memory.clone(),
        }),
        sidecars: Sidecars {
            attestation_proxy_digest: proxy_image.digest().to_string(),
            caddy_digest: caddy_image.digest().to_string(),
        },
        expected_firmware_measurement: release.expected_firmware_measurement_bytes()?,
        expected_runtime_class: release.expected_runtime_class.clone(),
        kbs_resource_path: format!(
            "default/{}-{}-owner/seed-encrypted",
            app.namespace, app.name
        ),
        unlock_mode: deploy_unlock_mode.to_string(),
        policy_template_id: release.policy_template_id.clone(),
        policy_template_sha256,
        platform_release_version: release.platform_release_version.clone(),
        expected_agent_policy_hash: [0; 32],
        expected_cc_init_data_hash: [0; 32],
        expected_kbs_policy_hash: [0; 32],
    });

    let descriptor_core_hash = enclava_cli::descriptor::descriptor_core_hash(&descriptor);
    let workload_artifact_binding = WorkloadArtifactBinding {
        descriptor_core_hash,
        descriptor_signing_pubkey: deployer_key.public.to_bytes(),
        org_keyring_fingerprint,
    };
    let generated_agent_policy = fetch_generated_agent_policy(api, &release, &descriptor).await?;
    descriptor.expected_agent_policy_hash = generated_agent_policy.policy_sha256;
    let cc_app = confidential_app_for_cc_hash(
        app,
        app_config,
        ConfidentialAppForCcHash {
            image: image_ref.clone(),
            release: &release,
            workload_artifact_binding,
            generated_agent_policy: generated_agent_policy.clone(),
            unlock_mode: deploy_unlock_mode,
            tenant_id,
            tenant_instance_identity_hash: identity_hash,
            bootstrap_owner_pubkey_hash: bootstrap_pubkey_hash,
        },
    )?;
    let cc_init_options = cc_init_data::CcInitDataOptions {
        kbs_url: release.trustee_kbs_url.clone(),
        kbs_ca_cert_pem: (!release.trustee_kbs_ca_cert_pem.trim().is_empty())
            .then(|| release.trustee_kbs_ca_cert_pem.clone()),
    };
    let cc_init_data_hash: [u8; 32] =
        Sha256::digest(cc_init_data::build_toml_with_options(&cc_app, &cc_init_options).as_bytes())
            .into();
    descriptor.expected_cc_init_data_hash = cc_init_data_hash;
    let rendered_policy = render_trustee_policy(&release.policy_template_text, &descriptor)?;
    descriptor.expected_kbs_policy_hash = Sha256::digest(rendered_policy.as_bytes()).into();
    let signing_key_id = format!("cli:{}", deployer_key.user_id);
    let signed_policy_artifact = enclava_cli::policy_artifact::sign_policy_artifact(
        &descriptor,
        &deployer_key,
        signing_key_id.clone(),
        rendered_policy,
        &generated_agent_policy,
        Some(serde_json::to_value(&keyring_envelope)?),
        Utc::now(),
    );

    let descriptor_envelope =
        enclava_cli::descriptor::sign(&deployer_key, descriptor, signing_key_id);

    Ok(SignedDeployBlobs {
        customer_descriptor_blob: serde_json::to_string(&descriptor_envelope)?,
        org_keyring_blob: serde_json::to_string(&keyring_envelope)?,
        signed_policy_artifact: serde_json::to_string(&signed_policy_artifact)?,
    })
}

#[derive(Args)]
pub struct CreateArgs {
    /// Container image to deploy (tag resolved to digest automatically)
    #[arg(long)]
    pub image: Option<String>,
    /// Cosign Fulcio identity subject for image-signature verification.
    /// Examples: GitHub Actions OIDC subject
    /// (`https://github.com/<org>/<repo>/.github/workflows/<wf>.yml@refs/heads/<branch>`),
    /// or a maintainer email tied to the keyless OIDC issuer.
    #[arg(long = "signer-subject")]
    pub signer_subject: Option<String>,
    /// Cosign Fulcio issuer URL for the signer identity. Defaults to
    /// the GitHub Actions OIDC issuer when omitted.
    #[arg(
        long = "signer-issuer",
        default_value = "https://token.actions.githubusercontent.com"
    )]
    pub signer_issuer: String,
}

pub async fn create(args: CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_config = AppConfig::find_and_load()?;
    let (api, paths, cli_config) = build_api_client()?;

    let bootstrap_key = if app_config.unlock.mode == "password" {
        let org = cli_config
            .org
            .as_deref()
            .ok_or("no active org -- run `enclava login` first")?;
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_hash = hex::encode(Sha256::digest(public_key));
        Some((
            org.to_string(),
            hex::encode(signing_key.to_bytes()),
            public_key_hash,
        ))
    } else {
        None
    };

    let services: Vec<ServiceSpec> = app_config
        .services
        .iter()
        .map(|(name, svc)| ServiceSpec {
            name: name.clone(),
            image: svc.image.clone(),
            port: svc.port,
            storage_paths: svc.storage_paths.clone().unwrap_or_default(),
        })
        .collect();

    let signer_identity_subject = args.signer_subject.clone();
    let signer_identity_issuer = signer_identity_subject
        .as_ref()
        .map(|_| args.signer_issuer.clone());

    let req = CreateAppRequest {
        name: app_config.app.name.clone(),
        port: app_config.app.port,
        image: args.image,
        unlock_mode: app_config.unlock.mode.clone(),
        bootstrap_pubkey_hash: bootstrap_key
            .as_ref()
            .map(|(_, _, public_key_hash)| public_key_hash.clone()),
        storage_size: app_config.storage.size.clone(),
        tls_storage_size: app_config.storage.tls_size.clone(),
        storage_paths: app_config.storage.paths.clone(),
        cpu: app_config.resources.cpu.clone(),
        memory: app_config.resources.memory.clone(),
        services,
        health_path: app_config.health.as_ref().map(|h| h.path.clone()),
        health_interval: app_config.health.as_ref().map(|h| h.interval),
        health_timeout: app_config.health.as_ref().map(|h| h.timeout),
        signer_identity_subject,
        signer_identity_issuer,
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message("Creating app...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let resp = api.create_app(&req).await?;

    if let Some((org, private_key_hex, _)) = bootstrap_key {
        let key_path =
            config::save_bootstrap_key(&paths, &org, &app_config.app.name, &private_key_hex)?;
        println!("Bootstrap key saved: {}", key_path.display());
    }

    spinner.finish_with_message(format!("App '{}' created.", resp.name));
    println!();
    println!("  Domain:    {}", resp.domain);
    println!("  Namespace: {}", resp.namespace);
    println!("  Status:    {}", resp.status);
    println!("  Unlock:    {}", resp.unlock_mode);
    println!();
    println!("Next: run `enclava deploy --image <image>@sha256:<digest>` to deploy.");
    if resp.unlock_mode == "password" {
        println!(
            "During deploy, you will be prompted for the initial storage password inside the TEE claim flow."
        );
    }

    Ok(())
}

#[derive(Args)]
pub struct DeployArgs {
    /// Digest-pinned container image to deploy and bind into the customer-signed descriptor.
    #[arg(long)]
    pub image: String,
    /// Set config key=value pairs delivered to TEE after boot
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub config_vars: Vec<String>,
}

pub async fn deploy(args: DeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_config = match AppConfig::find_and_load() {
        Ok(config) => config,
        Err(_) => {
            return Err("no enclava.toml found -- run `enclava init` or specify --app".into());
        }
    };
    let app_name = app_config.app.name.clone();

    let config_pairs = parse_config_vars(&args.config_vars)?;
    let (api, paths, cli_config) = build_api_client()?;
    let creds = config::load_credentials(&paths)?;
    let app = api.get_app(&app_name).await?;
    let is_password_mode = app.unlock_mode == "password";
    let signed_blobs = build_signed_deploy_blobs(SignedDeployBlobParams {
        api: &api,
        paths: &paths,
        cli_config: &cli_config,
        creds: &creds,
        app: &app,
        app_config: &app_config,
        image: &args.image,
        target_unlock_mode: None,
    })
    .await?;

    let req = DeployRequest {
        image: Some(args.image.clone()),
        customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob),
        org_keyring_blob: Some(signed_blobs.org_keyring_blob),
        signed_policy_artifact: Some(signed_blobs.signed_policy_artifact),
    };

    // Phase 1: Deploy
    let pb = ProgressBar::new(5);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_message("Deploying...");

    let resp = api.deploy(&app_name, &req).await?;
    pb.set_position(1);
    pb.set_message("Manifests applied");

    // Phase 2: Wait for TEE boot (poll status)
    pb.set_position(2);
    pb.set_message("Waiting for TEE boot...");

    let max_wait = Duration::from_secs(900);
    let poll_interval = Duration::from_secs(3);

    // Phase 3: First ownership claim for password-mode apps.
    //
    // On first boot the app container is intentionally unhealthy until the
    // owner claims storage, so waiting for app-level readiness deadlocks.
    // Instead, wait for the TEE bootstrap endpoint and claim directly.
    let needs_initial_claim = if is_password_mode {
        api.get_unlock_status(&app_name)
            .await
            .ok()
            .and_then(|status| status.ownership_state)
            .is_none_or(|state| state == "unclaimed")
    } else {
        false
    };

    if needs_initial_claim {
        pb.set_position(3);
        pb.set_message("Waiting for ownership claim endpoint...");
        if wait_for_bootstrap_endpoint(&api, &app_name, max_wait, poll_interval, &pb).await? {
            claim_initial_ownership(&api, &paths, &cli_config, &app_name).await?;
            pb.set_message("Ownership claimed");
        }
    } else {
        wait_for_deploy_runtime(&api, &app_name, max_wait, poll_interval, &pb).await?;
    }

    // Phase 4: Push config if --set was used
    if !config_pairs.is_empty() {
        pb.set_position(4);
        pb.set_message(format!("Setting {} config values...", config_pairs.len()));

        // Get config token from API
        let token_resp = api.get_config_token(&app_name).await?;
        let tee = TeeClient::new(&resp.app_domain);

        for (key, value) in &config_pairs {
            tee.config_set(key, value, &token_resp.token).await?;
        }
    }

    // Phase 4: Health check
    pb.set_position(5);
    pb.set_message("Waiting for health check...");

    let health_start = std::time::Instant::now();
    let health_timeout = Duration::from_secs(60);

    loop {
        if health_start.elapsed() > health_timeout {
            pb.finish_with_message("Deployed (health check timed out)");
            break;
        }

        match api.get_status(&app_name).await {
            Ok(status) if status.status == "running" => {
                pb.finish_with_message("Deployed and healthy");
                break;
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    println!();
    println!("  App:    {app_name}");
    println!("  URL:    https://{}", resp.app_domain);
    println!("  Deploy: {}", resp.deployment_id);
    if !config_pairs.is_empty() {
        println!("  Config: {} key(s) set", config_pairs.len());
    }

    Ok(())
}

async fn wait_for_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_with_timeout(&endpoint.tee_url, Duration::from_secs(10));
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for ownership claim endpoint");
            return Err("deploy timed out waiting for TEE ownership claim endpoint".into());
        }

        match tee.bootstrap_challenge().await {
            Ok(_) => {
                pb.set_message("Ownership claim endpoint ready");
                return Ok(true);
            }
            Err(err) if tee.claim_state_is_successful().await.unwrap_or(false) => {
                pb.set_message("Ownership already claimed");
                let _ = err;
                return Ok(false);
            }
            Err(_) => {
                pb.set_message("Waiting for ownership claim endpoint...");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_deploy_runtime(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for TEE boot");
            return Err("deploy timed out waiting for TEE to boot".into());
        }

        match api.get_status(app_name).await {
            Ok(status) => {
                if matches!(status.status.as_str(), "running" | "locked") {
                    pb.set_position(3);
                    pb.set_message(match status.status.as_str() {
                        "locked" => "TEE running, storage locked",
                        _ => "TEE running, attestation complete",
                    });
                    return Ok(());
                }

                match status.pod_phase.as_deref() {
                    Some("Running") => {
                        pb.set_position(3);
                        pb.set_message("TEE running, attestation complete");
                        return Ok(());
                    }
                    Some(phase) => {
                        pb.set_message(format!("Pod: {phase}"));
                    }
                    None => {}
                }
            }
            Err(_) => {
                // Status endpoint may not be ready yet.
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn claim_initial_ownership(
    api: &ApiClient,
    paths: &CliPaths,
    cli_config: &config::CliConfig,
    app_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new(&endpoint.tee_url);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let challenge = tee.bootstrap_challenge().await?;

    let org = cli_config
        .org
        .as_deref()
        .ok_or("no active org -- run `enclava login` first")?;
    let key_path = paths.bootstrap_key_path(org, app_name);
    let private_key_hex = std::fs::read_to_string(&key_path).map_err(|e| {
        format!(
            "bootstrap key not found at {}: {e}. Was this app created with `enclava create`?",
            key_path.display()
        )
    })?;
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex.trim())
        .map_err(|e| format!("invalid bootstrap key format: {e}"))?
        .try_into()
        .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)")?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge.nonce.as_bytes())
        .map_err(|e| format!("invalid bootstrap challenge encoding: {e}"))?;
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&challenge_bytes).to_bytes());
    let bootstrap_pubkey = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let password = dialoguer::Password::new()
        .with_prompt("Set initial storage password")
        .with_confirmation("Confirm initial storage password", "Passwords don't match")
        .interact()?;

    let result = match tee
        .bootstrap_claim(&challenge.nonce, &bootstrap_pubkey, &signature, &password)
        .await
    {
        Ok(result) => Some(result),
        Err(err) if tee.claim_state_is_successful().await.unwrap_or(false) => {
            eprintln!(
                "Claim response was interrupted after the TEE accepted ownership; continuing."
            );
            let _ = err;
            None
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(mnemonic) = result.and_then(|result| result.mnemonic) {
        println!();
        println!("IMPORTANT: Save your recovery mnemonic. This is shown ONCE.");
        println!("{mnemonic}");
    }

    Ok(())
}

#[derive(Args)]
pub struct StatusArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

pub async fn status(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let status = api.get_status(&app_name).await?;

    let status_colored = match status.status.as_str() {
        "running" => status.status.green().to_string(),
        "creating" | "deploying" => status.status.yellow().to_string(),
        "failed" | "stopped" => status.status.red().to_string(),
        _ => status.status.clone(),
    };

    println!("App:      {}", status.app_name);
    println!("Status:   {}", status_colored);
    println!("Domain:   https://{}", status.domain);
    if let Some(phase) = &status.pod_phase {
        println!("Pod:      {phase}");
    }
    if let Some(tee) = &status.tee_status {
        println!("TEE:      {tee}");
    }
    if let Some(unlock) = &status.unlock_status {
        println!("Unlock:   {unlock}");
    }
    if let Some(deployed) = &status.last_deployed {
        println!("Deployed: {deployed}");
    }

    Ok(())
}

#[derive(Args)]
pub struct LogsArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,
}

pub async fn logs(args: LogsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let resp = api.get_logs(&app_name, args.follow).await?;

    if args.follow {
        // Stream logs line by line
        use tokio::io::AsyncBufReadExt;
        let stream = resp.bytes_stream();
        let reader = tokio_util::io::StreamReader::new(
            stream.map(|result| result.map_err(std::io::Error::other)),
        );
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            println!("{line}");
        }
    } else {
        // Print all logs at once
        let body = resp.text().await?;
        print!("{body}");
    }

    Ok(())
}

#[derive(Args)]
pub struct RollbackArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Deployment ID to rollback to (defaults to previous)
    #[arg(long)]
    pub to: Option<String>,
}

pub async fn rollback(args: RollbackArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let deployment_id = if let Some(id) = args.to.clone() {
        id
    } else {
        // Show recent deployments and let user pick
        let deployments = api.list_deployments(&app_name).await?;
        if deployments.len() < 2 {
            return Err("no previous deployment to roll back to".into());
        }

        println!("Recent deployments for {app_name}:");
        for (i, d) in deployments.iter().enumerate() {
            let marker = if i == 0 { " (current)" } else { "" };
            println!(
                "  {} | {} | {} | {}{}",
                &d.id[..8],
                d.status,
                d.image_digest.as_deref().unwrap_or("n/a"),
                d.created_at,
                marker,
            );
        }

        // Default to the immediately previous deployment
        let previous = &deployments[1];
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Roll back to deployment {}?", &previous.id[..8]))
            .default(true)
            .interact()?;

        if !confirm {
            println!("Rollback cancelled.");
            return Ok(());
        }

        previous.id.clone()
    };

    let req = RollbackRequest {
        deployment_id: Some(deployment_id),
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message(format!("Rolling back {app_name}..."));
    spinner.enable_steady_tick(Duration::from_millis(100));

    let resp = api.rollback(&app_name, &req).await?;

    spinner.finish_with_message(format!("Rolled back to deployment {}", resp.rolled_back_to));
    println!("New deployment: {}", resp.deployment_id);

    Ok(())
}

// ---- Signer identity (set / rotate) ----

#[derive(Subcommand)]
pub enum SignerCommand {
    /// Set the signer identity for an app that has none yet (initial set).
    /// No email confirmation token is required for the first set.
    Set {
        /// Cosign Fulcio identity subject. Examples:
        /// `https://github.com/<org>/<repo>/.github/workflows/deploy.yml@refs/heads/main`
        /// or an email.
        subject: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Cosign Fulcio issuer URL.
        #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
        issuer: String,
    },
    /// Rotate an existing signer identity. Requires an email confirmation
    /// token tied to the requesting user's verified email.
    Rotate {
        /// New cosign Fulcio identity subject.
        subject: String,
        /// Email confirmation token issued by the platform.
        #[arg(long = "confirmation-token")]
        confirmation_token: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Cosign Fulcio issuer URL.
        #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
        issuer: String,
    },
}

pub async fn signer(cmd: SignerCommand) -> Result<(), Box<dyn std::error::Error>> {
    let (api, _paths, _cli_config) = build_api_client()?;
    match cmd {
        SignerCommand::Set {
            subject,
            issuer,
            app,
        } => {
            let app_name = resolve_app_name(&app)?;
            let req = SetSignerRequest {
                subject: subject.clone(),
                issuer: issuer.clone(),
                email_confirmation_token: None,
            };
            let _ = api.set_signer(&app_name, &req).await?;
            println!("Signer identity set for {app_name}.");
            println!("  Subject: {subject}");
            println!("  Issuer:  {issuer}");
        }
        SignerCommand::Rotate {
            subject,
            issuer,
            confirmation_token,
            app,
        } => {
            let app_name = resolve_app_name(&app)?;
            let req = SetSignerRequest {
                subject: subject.clone(),
                issuer: issuer.clone(),
                email_confirmation_token: Some(confirmation_token),
            };
            let _ = api.set_signer(&app_name, &req).await?;
            println!("Signer identity rotated for {app_name}.");
            println!("  Subject: {subject}");
            println!("  Issuer:  {issuer}");
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct DestroyArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Skip confirmation prompt
    #[arg(long)]
    pub force: bool,
}

pub async fn destroy(args: DestroyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    if !args.force {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!(
                "This will permanently destroy '{app_name}' and all its data. Continue?"
            ))
            .default(false)
            .interact()?;

        if !confirm {
            println!("Destroy cancelled.");
            return Ok(());
        }

        // Double confirmation: type the app name
        let typed_name: String = dialoguer::Input::new()
            .with_prompt(format!("Type '{app_name}' to confirm"))
            .interact_text()?;

        if typed_name != app_name {
            println!("Name did not match. Destroy cancelled.");
            return Ok(());
        }
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.red} {msg}")
            .unwrap(),
    );
    spinner.set_message(format!("Destroying {app_name}..."));
    spinner.enable_steady_tick(Duration::from_millis(100));

    api.delete_app(&app_name).await?;

    spinner.finish_with_message(format!("App '{app_name}' destroyed."));

    Ok(())
}
