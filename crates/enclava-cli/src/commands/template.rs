use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use base64::Engine as _;
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use enclava_cli::{
    api_client::{ApiClient, ApiError},
    api_types::{
        AppResponse, CreateAppRequest, CreateTemplateInstanceRequest, DeploymentEntry,
        HostedTemplate, HostedTemplateConfigKey, ServiceSpec, SshCommandResponse,
        TemplateInstanceResponse,
    },
    app_config::{
        AppConfig, AppSection, HealthSection, ResourcesSection, StorageSection, UnlockSection,
    },
    config::{self, CliPaths},
    keys,
    tee_client::{TeeClient, TeeError},
};
use enclava_engine::types::WorkloadSecurityProfile;

use crate::commands::app::{
    SignedDeployBlobParams, StoragePasswordInput, build_signed_deploy_blobs,
    claim_initial_ownership, ensure_manual_deploy_keyring, fetch_verified_platform_release,
    generate_log_key_for_app,
};
use crate::commands::ownership::MnemonicCapture;

const DEBIAN_SSH_NGROK_TEMPLATE: &str = "debian-ssh-ngrok";
const DEBIAN_SSH_FRP_TEMPLATE: &str = "debian-ssh-frp";
const DEFAULT_DEBIAN_SSH_TEMPLATE: &str = DEBIAN_SSH_FRP_TEMPLATE;
const FRP_RELAY_HOST: &str = "relay.enclava.me";
const DEFAULT_SSH_TIMEOUT_SECONDS: u64 = 600;
const TEMPLATE_CONFIG_DELIVERY_ATTEMPTS: usize = 121;
const TEMPLATE_CONFIG_DELIVERY_RETRY_SECONDS: u64 = 2;
const MAX_SSH_COMMAND_BYTES: usize = 256;

#[derive(Subcommand)]
pub enum TemplateCommand {
    /// List hosted templates available to the active organization
    List,
    /// Deploy a hosted template instance
    Deploy(TemplateDeployArgs),
    /// Fetch and validate the PaaS-rendered stable SSH endpoint command for a hosted Debian SSH app
    SshCommand(TemplateSshCommandArgs),
}

#[derive(Args)]
pub struct TemplateDeployArgs {
    /// Template slug to deploy
    #[arg(default_value = DEFAULT_DEBIAN_SSH_TEMPLATE)]
    pub template: String,
    /// Instance/app name to create
    #[arg(long)]
    pub name: String,
    /// SSH public key line to authorize. Can be passed more than once.
    #[arg(long = "ssh-public-key", value_name = "PUBLIC_KEY")]
    pub ssh_public_keys: Vec<String>,
    /// File containing one or more SSH public keys.
    #[arg(long = "ssh-public-key-file", value_name = "PATH")]
    pub ssh_public_key_files: Vec<PathBuf>,
    /// Existing reserved stable SSH endpoint to import instead of letting PaaS reserve one.
    #[arg(
        long = "stable-ssh-endpoint",
        visible_alias = "ngrok-tcp-url",
        value_name = "HOST:PORT"
    )]
    pub ngrok_tcp_url: Option<String>,
    /// Do not wait for stable SSH endpoint command readiness after config delivery.
    #[arg(long)]
    pub no_wait: bool,
    /// Seconds to wait for the stable SSH endpoint command.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// File containing the initial storage password for non-interactive password-mode template deploys.
    #[arg(long = "storage-password-file", value_name = "PATH")]
    pub storage_password_file: Option<PathBuf>,
    /// Select an existing organization log-encryption key before the first deployment.
    #[arg(
        long = "log-key",
        value_name = "KEY_ID",
        conflicts_with = "generate_log_key"
    )]
    pub log_key: Option<String>,
    /// Generate, register, and select a tenant-held log-encryption key before the first deployment.
    #[arg(long = "generate-log-key", value_name = "KEY_ID")]
    pub generate_log_key: Option<String>,
    /// Where to write the generated tenant-held log private key.
    #[arg(
        long = "log-private-key-file",
        value_name = "PATH",
        requires = "generate_log_key"
    )]
    pub log_private_key_file: Option<PathBuf>,
    /// Print machine-readable JSON with deployment, stable SSH endpoint, and stable SSH endpoint command details.
    #[arg(long)]
    pub json: bool,
    /// Persist the recovery mnemonic so `enclava key backup` can back it up (default).
    #[arg(long, conflicts_with = "no_store_mnemonic")]
    pub store_mnemonic: bool,
    /// Do NOT persist the recovery mnemonic (shown once only; opt out of backup coverage).
    #[arg(long, conflicts_with = "store_mnemonic")]
    pub no_store_mnemonic: bool,
}

#[derive(Args)]
pub struct TemplateSshCommandArgs {
    /// Instance/app name to inspect
    #[arg(long)]
    pub name: String,
    /// Reserved stable SSH endpoint expected for this app.
    #[arg(
        long = "stable-ssh-endpoint",
        visible_alias = "ngrok-tcp-url",
        value_name = "HOST:PORT"
    )]
    pub ngrok_tcp_url: Option<String>,
    /// Wait until PaaS reports the stable SSH endpoint command as ready.
    #[arg(long)]
    pub wait: bool,
    /// Seconds to wait for the stable SSH endpoint command when --wait is set.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// Print machine-readable JSON including the stable SSH endpoint command and parsed stable SSH endpoint.
    #[arg(long)]
    pub json: bool,
}

struct TemplateApiContext {
    api: ApiClient,
    paths: CliPaths,
    cli_config: config::CliConfig,
    creds: config::Credentials,
}

fn build_api_context() -> Result<TemplateApiContext, Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok(TemplateApiContext {
        api,
        paths,
        cli_config,
        creds,
    })
}

fn build_api_client() -> Result<ApiClient, Box<dyn std::error::Error>> {
    Ok(build_api_context()?.api)
}

pub async fn run(cmd: TemplateCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        TemplateCommand::List => list().await,
        TemplateCommand::Deploy(args) => deploy(args).await,
        TemplateCommand::SshCommand(args) => ssh_command(args).await,
    }
}

async fn list() -> Result<(), Box<dyn std::error::Error>> {
    let api = build_api_client()?;
    let templates = api.list_templates().await?;
    if templates.is_empty() {
        println!("No hosted templates are available.");
        return Ok(());
    }

    println!("Hosted templates:");
    for template in templates {
        println!("  {} ({})", template.slug, template.version);
        println!("    {}", template.description);
        if !template.features.is_empty() {
            println!("    Features: {}", template.features.join(", "));
        }
        if let Some(summary) = template_required_inputs(&template) {
            println!("    Required inputs: {summary}");
        }
        if let Some(summary) = template_optional_inputs(&template) {
            println!("    Optional inputs: {summary}");
        }
        if let Some(summary) = template_paas_managed_config_summary(&template) {
            println!("    PaaS-managed config: {summary}");
        }
        if let Some(hint) = stable_ssh_endpoint_hint(&template) {
            println!("    Stable SSH endpoint: {hint}");
        }
        if let Some(path) = template.persistence_path {
            println!("    Persistent path: {path}");
        }
    }
    Ok(())
}

async fn deploy(args: TemplateDeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let instance_name = normalize_slug(&args.name)?;
    let explicit_stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_stable_ssh_endpoint)
        .transpose()?;
    if args.template == DEBIAN_SSH_FRP_TEMPLATE && explicit_stable_endpoint.is_some() {
        return Err(
            "--stable-ssh-endpoint is not supported for debian-ssh-frp; PaaS allocates the FRP relay port"
                .into(),
        );
    }

    let ctx = build_api_context()?;
    let api = &ctx.api;
    let templates = api.list_templates().await?;
    let template = templates
        .iter()
        .find(|template| template.slug == args.template)
        .ok_or_else(|| format!("template '{}' is not available", args.template))?;
    if template_key(template, "DEBIAN_SSH_AUTHORIZED_KEYS").is_none() {
        return Err(format!(
            "template '{}' is not a Debian SSH template supported by this CLI",
            args.template
        )
        .into());
    }

    let public_keys = read_ssh_public_keys(&args.ssh_public_keys, &args.ssh_public_key_files)?;
    validate_ssh_public_keys(
        &public_keys,
        template_key(template, "DEBIAN_SSH_AUTHORIZED_KEYS"),
    )?;
    let storage_password =
        StoragePasswordInput::from_file_option(args.storage_password_file.as_ref())?;
    if template.unlock_mode == "password" {
        storage_password.ensure_available_for_password_mode("password-mode template deploy")?;
    }
    // Authenticate platform authority before keyring registration or app creation.
    fetch_verified_platform_release(api).await?;
    let capture = if args.no_store_mnemonic {
        MnemonicCapture::Skip
    } else {
        MnemonicCapture::Store
    };
    let pb = if args.json {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(5)
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")?
            .progress_chars("=> "),
    );
    pb.set_message("Preparing template app...");

    let bootstrap_pubkey_hash =
        template_bootstrap_pubkey_hash(api, &ctx.paths, template, &instance_name).await?;
    let app = ensure_template_app(
        api,
        template,
        &instance_name,
        bootstrap_pubkey_hash.as_deref(),
    )
    .await?;
    let prepared_log_key = prepare_template_log_key(
        api,
        &ctx.paths,
        &instance_name,
        args.log_key.as_deref(),
        args.generate_log_key.as_deref(),
        args.log_private_key_file.clone(),
        &pb,
    )
    .await?;
    pb.set_position(1);
    pb.set_message("Signing deployment descriptor...");

    let app_config = template_app_config(template, &instance_name);
    let workload_security_profile = template_workload_security_profile(template)?;
    let signed_blobs = build_signed_deploy_blobs(SignedDeployBlobParams {
        api,
        paths: &ctx.paths,
        cli_config: &ctx.cli_config,
        creds: &ctx.creds,
        app: &app,
        app_config: &app_config,
        image: &template.image,
        target_unlock_mode: Some(template.unlock_mode.as_str()),
        workload_security_profile,
    })
    .await?;
    verify_signed_template_log_key(
        prepared_log_key.as_ref(),
        signed_blobs.log_encryption.as_ref(),
    )?;
    pb.set_position(2);
    pb.set_message("Creating template instance...");

    let response = match api
        .create_template_instance(&CreateTemplateInstanceRequest {
            template_slug: args.template.clone(),
            instance_name: instance_name.clone(),
            config: template_create_config(explicit_stable_endpoint.as_deref()),
            bootstrap_pubkey_hash: bootstrap_pubkey_hash.clone(),
            customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob),
            org_keyring_blob: Some(signed_blobs.org_keyring_blob),
            signed_policy_artifact: Some(signed_blobs.signed_policy_artifact),
        })
        .await
    {
        Ok(response) => response,
        Err(error) => return Err(template_instance_create_api_error(error)),
    };
    let stable_endpoint = stored_stable_endpoint_from_template_instance_response(
        &response,
        explicit_stable_endpoint.as_deref(),
    )?;
    let deployment_id = response
        .deployment
        .cap_deployment_id
        .as_deref()
        .unwrap_or("pending")
        .to_string();
    pb.set_position(3);
    if template.unlock_mode == "password" {
        pb.set_message("Waiting for ownership claim endpoint...");
        if wait_for_template_bootstrap_endpoint(
            api,
            &instance_name,
            &deployment_id,
            Duration::from_secs(args.ssh_timeout_seconds),
            Duration::from_secs(3),
            &pb,
        )
        .await?
        {
            claim_initial_ownership(
                api,
                &ctx.paths,
                &ctx.cli_config,
                &instance_name,
                &storage_password,
                capture,
            )
            .await?;
        }
    }
    if !template.paas_managed_config_keys.is_empty() {
        pb.set_message("Delivering platform-managed config...");
        let managed = api
            .deliver_managed_template_config(&instance_name)
            .await
            .map_err(managed_template_config_api_error)?;
        if !matches!(managed.status.as_str(), "queued" | "delivered") {
            return Err(format!(
                "PaaS managed config delivery returned unexpected status `{}`",
                managed.status
            )
            .into());
        }
        pb.set_message("Waiting for platform-managed config...");
        wait_for_paas_managed_config_keys(
            api,
            &instance_name,
            &template.paas_managed_config_keys,
            &deployment_id,
            Duration::from_secs(args.ssh_timeout_seconds),
            &pb,
        )
        .await?;
    }
    pb.set_message("Delivering config to TEE...");

    let token = response
        .config_token
        .as_ref()
        .ok_or("PaaS did not return a TEE config token")?;
    let tee_url = token
        .tee_url
        .as_deref()
        .ok_or("PaaS did not return a TEE config URL")?;
    let tee_url = template_config_endpoint_url(tee_url)?;
    let mut tee_resolve_ip = token.tee_resolve_ip;
    let tee = TeeClient::from_config_url_with_resolve_ip(&tee_url, tee_resolve_ip);
    let mut tee = attest_template_config_tee_with_retry(tee).await?;
    let mut tee_url = tee_url;

    let mut config_token = token.token.clone();
    let config_pairs = debian_ssh_config_pairs(public_keys);
    deliver_template_config_with_retry(
        api,
        &mut tee,
        &instance_name,
        &mut config_token,
        &mut tee_url,
        &mut tee_resolve_ip,
        &config_pairs,
    )
    .await?;
    pb.set_position(4);

    let mut app_url = app_url_from_template_response_cap(&response.cap)?;

    let (ssh_command, ssh_endpoint) = if args.no_wait {
        pb.set_position(5);
        (None, None)
    } else {
        pb.set_position(4);
        pb.set_message("Waiting for stable SSH endpoint command...");
        let response = wait_for_paas_ssh_command(
            api,
            &instance_name,
            &deployment_id,
            stable_endpoint.as_str(),
            app_url.as_str(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await?;
        if let Some(url) = response.app_url {
            app_url = normalize_paas_ssh_command_app_url(&url)?;
        }
        pb.set_position(5);
        (response.command, response.endpoint)
    };
    pb.finish_with_message("Template deployed");

    print!(
        "{}",
        deploy_response_output(DeployResponseOutput {
            template_slug: &response.template.slug,
            instance_name: &instance_name,
            app_url: &app_url,
            deployment_id: &deployment_id,
            stable_endpoint: Some(stable_endpoint.as_str()),
            ssh_command: ssh_command.as_deref(),
            ssh_endpoint: ssh_endpoint.as_deref(),
            log_key_id: prepared_log_key
                .as_ref()
                .map(|prepared| prepared.config.key_id.as_str()),
            log_private_key_file: prepared_log_key
                .as_ref()
                .and_then(|prepared| prepared.private_key_file.as_deref()),
            json: args.json,
        })?
    );
    Ok(())
}

struct PreparedTemplateLogKey {
    config: enclava_engine::types::LogEncryptionConfig,
    private_key_file: Option<PathBuf>,
}

impl PreparedTemplateLogKey {
    fn from_api_key(
        key: enclava_cli::api_types::LogEncryptionKey,
        private_key_file: Option<PathBuf>,
    ) -> Self {
        Self {
            config: enclava_engine::types::LogEncryptionConfig {
                algorithm: key.algorithm,
                key_id: key.key_id,
                public_key_base64url: key.public_key_base64url,
                public_key_sha256: key.public_key_sha256,
            },
            private_key_file,
        }
    }
}

async fn prepare_template_log_key(
    api: &ApiClient,
    paths: &CliPaths,
    instance_name: &str,
    existing_key_id: Option<&str>,
    generated_key_id: Option<&str>,
    private_key_file: Option<PathBuf>,
    pb: &ProgressBar,
) -> Result<Option<PreparedTemplateLogKey>, Box<dyn std::error::Error>> {
    match (existing_key_id, generated_key_id) {
        (Some(_), Some(_)) => {
            Err("--log-key and --generate-log-key cannot be used together".into())
        }
        (Some(key_id), None) => {
            pb.set_message("Selecting tenant log-encryption key...");
            let key = api.select_log_key(instance_name, key_id).await?;
            verify_selected_template_log_key(key_id, &key)?;
            Ok(Some(PreparedTemplateLogKey::from_api_key(key, None)))
        }
        (None, Some(key_id)) => {
            pb.set_message("Generating tenant log-encryption key...");
            let generated = generate_log_key_for_app(
                api,
                paths,
                instance_name,
                key_id,
                Some(format!("Hosted template app {instance_name}")),
                private_key_file,
                true,
            )
            .await?;
            Ok(Some(PreparedTemplateLogKey::from_api_key(
                generated.key,
                Some(generated.private_key_file),
            )))
        }
        (None, None) => Ok(None),
    }
}

fn verify_selected_template_log_key(
    requested_key_id: &str,
    selected: &enclava_cli::api_types::LogEncryptionKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if selected.key_id != requested_key_id {
        return Err(format!(
            "log-key selection returned key `{}` instead of requested key `{requested_key_id}`",
            selected.key_id
        )
        .into());
    }
    if selected.status != "active" || !selected.active_for_app {
        return Err(format!(
            "log-key selection did not confirm requested key `{requested_key_id}` as active for the app"
        )
        .into());
    }
    Ok(())
}

fn verify_signed_template_log_key(
    prepared: Option<&PreparedTemplateLogKey>,
    signed: Option<&enclava_engine::types::LogEncryptionConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(prepared) = prepared else {
        return Ok(());
    };
    match signed {
        Some(signed) if signed == &prepared.config => Ok(()),
        Some(signed) => Err(format!(
            "signed deployment log-encryption key `{}` does not match requested key `{}`; retry after the platform key selection is consistent",
            signed.key_id, prepared.config.key_id
        )
        .into()),
        None => Err(format!(
            "signed deployment omitted requested log-encryption key `{}`; retry after the platform supports pre-deploy key selection",
            prepared.config.key_id
        )
        .into()),
    }
}

async fn ssh_command(args: TemplateSshCommandArgs) -> Result<(), Box<dyn std::error::Error>> {
    let instance_name = normalize_slug(&args.name)?;
    let explicit_stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_stable_ssh_endpoint)
        .transpose()?;
    let api = build_api_client()?;
    let app = api.get_app(&instance_name).await?;
    let stored_stable_endpoint = stored_stable_endpoint_from_app(&app)?;
    let stable_endpoint =
        ssh_command_stable_endpoint(explicit_stable_endpoint.as_deref(), &stored_stable_endpoint)?;
    let expected_app_url = app_url_from_app_response(&app)?;
    let latest_deployment_id = if args.wait {
        latest_deployment_id(&api, &instance_name)
            .await?
            .unwrap_or_else(|| "pending".to_string())
    } else {
        "pending".to_string()
    };
    let response = if args.wait {
        let pb = if args.json {
            ProgressBar::hidden()
        } else {
            ProgressBar::new_spinner()
        };
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message("Waiting for stable SSH endpoint command...");
        match wait_for_paas_ssh_command(
            &api,
            &instance_name,
            &latest_deployment_id,
            stable_endpoint,
            expected_app_url.as_str(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await
        {
            Ok(response) => {
                pb.finish_with_message("Stable SSH endpoint command ready");
                response
            }
            Err(error) => {
                pb.abandon_with_message("Stable SSH endpoint command unavailable");
                return Err(error);
            }
        }
    } else {
        let response = match api.get_template_ssh_command(&instance_name).await {
            Ok(response) => response,
            Err(error) => return Err(paas_ssh_command_api_error(error)),
        };
        validate_ssh_command_response(&response, stable_endpoint, expected_app_url.as_str())?;
        response
    };
    print!(
        "{}",
        ssh_command_response_output(
            &instance_name,
            &response,
            stable_endpoint,
            expected_app_url.as_str(),
            args.json,
        )?
    );
    Ok(())
}

async fn ensure_template_app(
    api: &ApiClient,
    template: &HostedTemplate,
    instance_name: &str,
    bootstrap_pubkey_hash: Option<&str>,
) -> Result<AppResponse, Box<dyn std::error::Error>> {
    match api.get_app(instance_name).await {
        Ok(app) => return Ok(app),
        Err(ApiError::Api { status: 404, .. }) => {}
        Err(error) => return Err(error.into()),
    }

    match api
        .create_app(&template_create_app_request(
            template,
            instance_name,
            bootstrap_pubkey_hash,
        )?)
        .await
    {
        Ok(app) => Ok(app),
        Err(ApiError::Api { status: 409, .. }) => Ok(api.get_app(instance_name).await?),
        Err(error) => Err(error.into()),
    }
}

fn template_create_app_request(
    template: &HostedTemplate,
    instance_name: &str,
    bootstrap_pubkey_hash: Option<&str>,
) -> Result<CreateAppRequest, Box<dyn std::error::Error>> {
    let signer_identity_subject =
        required_template_value(template.signer_subject.as_deref(), "signer_subject")?;
    let signer_identity_issuer =
        required_template_value(template.signer_issuer.as_deref(), "signer_issuer")?;
    let storage_defaults = StorageSection::default();
    Ok(CreateAppRequest {
        name: instance_name.to_string(),
        port: template.port,
        image: None,
        unlock_mode: template.unlock_mode.clone(),
        bootstrap_pubkey_hash: bootstrap_pubkey_hash.map(str::to_string),
        storage_size: template.resources.storage.clone(),
        tls_storage_size: storage_defaults.tls_size,
        storage_paths: template.storage_paths.clone(),
        cpu: template.resources.cpu.clone(),
        memory: template.resources.memory.clone(),
        services: Vec::<ServiceSpec>::new(),
        health_path: template.health_path.clone(),
        health_interval: template.health_interval,
        health_timeout: template.health_timeout,
        signer_identity_subject: Some(signer_identity_subject),
        signer_identity_issuer: Some(signer_identity_issuer),
        egress_allowlist: template.egress_allowlist.clone(),
        egress_mode: Some(template.egress_mode.clone()),
    })
}

async fn template_bootstrap_pubkey_hash(
    api: &ApiClient,
    paths: &CliPaths,
    template: &HostedTemplate,
    instance_name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if template.unlock_mode != "password" {
        return Ok(None);
    }
    let (org_id, org_name, _) = ensure_manual_deploy_keyring(api, paths, false).await?;
    let seed = keys::load_or_create_recovery_seed(paths)?;
    let app_seed = keys::derive_app_bootstrap_seed(org_id, instance_name, &seed)?;
    let signing_key = SigningKey::from_bytes(&app_seed);
    let public_key_hash = hex::encode(Sha256::digest(signing_key.verifying_key().to_bytes()));
    config::save_bootstrap_key(paths, &org_name, instance_name, &hex::encode(app_seed))?;
    Ok(Some(public_key_hash))
}

fn template_app_config(template: &HostedTemplate, instance_name: &str) -> AppConfig {
    let storage_defaults = StorageSection::default();
    AppConfig {
        app: AppSection {
            name: instance_name.to_string(),
            port: template.port,
            command: template.command.clone(),
        },
        storage: StorageSection {
            paths: template.storage_paths.clone(),
            size: template.resources.storage.clone(),
            tls_size: storage_defaults.tls_size,
        },
        unlock: UnlockSection {
            mode: template.unlock_mode.clone(),
        },
        services: HashMap::new(),
        resources: ResourcesSection {
            cpu: template.resources.cpu.clone(),
            memory: template.resources.memory.clone(),
        },
        health: template.health_path.as_ref().map(|path| HealthSection {
            path: path.clone(),
            interval: template.health_interval.unwrap_or(30),
            timeout: template.health_timeout.unwrap_or(5),
        }),
    }
}

fn template_workload_security_profile(
    template: &HostedTemplate,
) -> Result<WorkloadSecurityProfile, Box<dyn std::error::Error>> {
    template
        .workload_security_profile
        .as_deref()
        .unwrap_or("restricted")
        .parse()
        .map_err(|error: String| error.into())
}

fn required_template_value(
    value: Option<&str>,
    field: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("template metadata is missing required `{field}`").into())
}

fn template_key<'a>(
    template: &'a HostedTemplate,
    key: &str,
) -> Option<&'a HostedTemplateConfigKey> {
    template_customer_config_keys(template).find(|entry| entry.key == key)
}

fn template_customer_config_keys<'a>(
    template: &'a HostedTemplate,
) -> impl Iterator<Item = &'a HostedTemplateConfigKey> + 'a {
    template.config_keys.iter().filter(|entry| {
        !template
            .paas_managed_config_keys
            .iter()
            .any(|managed| managed == &entry.key)
    })
}

fn template_required_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, true)
}

fn template_optional_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, false)
}

fn template_paas_managed_config_summary(template: &HostedTemplate) -> Option<String> {
    if template.paas_managed_config_keys.is_empty() {
        None
    } else {
        Some(
            template
                .paas_managed_config_keys
                .iter()
                .map(|key| {
                    if key == "NGROK_AUTHTOKEN" {
                        "NGROK_AUTHTOKEN (PaaS-owned; sourced from PaaS deployment env DEBIAN_SSH_NGROK_AUTHTOKEN)"
                            .to_string()
                    } else {
                        key.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

fn template_input_summary(template: &HostedTemplate, required: bool) -> Option<String> {
    let labels = template_customer_config_keys(template)
        .filter(|entry| entry.required == required)
        .map(template_input_label)
        .collect::<Vec<_>>();
    if labels.is_empty() {
        None
    } else {
        Some(labels.join(", "))
    }
}

fn template_input_label(entry: &HostedTemplateConfigKey) -> String {
    if entry
        .validation
        .as_ref()
        .and_then(|validation| validation.example.as_ref())
        .is_some()
        && entry
            .validation
            .as_ref()
            .and_then(|validation| validation.format.as_deref())
            == Some("ngrok_tcp_url")
    {
        return format!(
            "{} (auto-reserved; optional --stable-ssh-endpoint)",
            entry.label
        );
    }
    entry.label.clone()
}

fn stored_stable_endpoint_from_app(
    app: &AppResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    if !app
        .template_slug
        .as_deref()
        .is_some_and(is_supported_stable_ssh_template)
    {
        return Err(
            "Stable SSH endpoint command lookup is only available for Debian SSH apps with stable SSH endpoints".into(),
        );
    }
    let Some(endpoint) = app.template_expected.stable_ssh_endpoint.as_deref() else {
        return Err(
            "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        );
    };
    if endpoint.trim().is_empty() {
        return Err(
            "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        );
    }
    match normalize_stable_ssh_endpoint(endpoint) {
        Ok(normalized) if endpoint == normalized => Ok(normalized),
        _ => Err(
            "Hosted Debian SSH app has invalid stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        ),
    }
}

fn stored_stable_endpoint_from_template_instance_response(
    response: &TemplateInstanceResponse,
    submitted_endpoint: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = response
        .app
        .template_expected
        .stable_ssh_endpoint
        .as_deref()
        .ok_or(
            "PaaS template response did not include its stored stable SSH endpoint expectation",
        )?;
    if endpoint.trim().is_empty() {
        return Err(
            "PaaS template response did not include its stored stable SSH endpoint expectation"
                .into(),
        );
    }
    let normalized = normalize_stable_ssh_endpoint(endpoint)
        .map_err(|_| "PaaS template response included an invalid stored stable SSH endpoint")?;
    if endpoint != normalized {
        return Err(
            "PaaS template response included a non-canonical stored stable SSH endpoint".into(),
        );
    }
    if let Some(submitted_endpoint) = submitted_endpoint {
        let submitted = normalize_stable_ssh_endpoint(submitted_endpoint)
            .map_err(|_| "submitted stable SSH endpoint is invalid")?;
        if normalized != submitted {
            return Err(format!(
                "PaaS stored stable SSH endpoint {normalized} does not match submitted --stable-ssh-endpoint {submitted}"
            )
            .into());
        }
    }
    Ok(normalized)
}

fn stable_ssh_endpoint_hint(template: &HostedTemplate) -> Option<String> {
    let entry = template_customer_config_keys(template).find(|entry| {
        entry.key == "NGROK_TCP_URL"
            || entry
                .validation
                .as_ref()
                .and_then(|validation| validation.format.as_deref())
                == Some("ngrok_tcp_url")
    })?;
    let example = entry
        .validation
        .as_ref()
        .and_then(|validation| validation.example.as_deref())
        .unwrap_or("6.tcp.eu.ngrok.io:17958");
    Some(format!(
        "PaaS reserves one automatically; pass --stable-ssh-endpoint {example} only to import an existing reserved endpoint"
    ))
}

fn ssh_command_stable_endpoint<'a>(
    explicit: Option<&'a str>,
    stored: &'a str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let Some(explicit) = explicit else {
        return Ok(stored);
    };
    if explicit == stored {
        return Ok(stored);
    }
    Err(format!(
        "--stable-ssh-endpoint {explicit} does not match the PaaS-stored stable SSH endpoint {stored}; omit --stable-ssh-endpoint to use the stored expectation or redeploy with the intended endpoint"
    )
    .into())
}

fn normalize_slug(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let slug = value.trim().to_ascii_lowercase();
    if slug.len() < 2
        || slug.len() > 63
        || !slug.bytes().any(|byte| byte.is_ascii_lowercase())
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || slug.starts_with('-')
        || slug.ends_with('-')
    {
        Err("instance name must be 2-63 letters, numbers, or hyphens".into())
    } else {
        Ok(slug)
    }
}

fn is_supported_stable_ssh_template(slug: &str) -> bool {
    matches!(slug, DEBIAN_SSH_NGROK_TEMPLATE | DEBIAN_SSH_FRP_TEMPLATE)
}

fn template_create_config(explicit_stable_endpoint: Option<&str>) -> serde_json::Value {
    match explicit_stable_endpoint {
        Some(endpoint) => serde_json::json!({ "NGROK_TCP_URL": endpoint }),
        None => serde_json::json!({}),
    }
}

fn debian_ssh_config_pairs(public_keys: String) -> Vec<(&'static str, String)> {
    vec![("DEBIAN_SSH_AUTHORIZED_KEYS", public_keys)]
}

async fn wait_for_template_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut tee = None;

    loop {
        fail_if_template_deployment_failed(api, app_name, deployment_id).await?;
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for ownership claim endpoint");
            return Err("deploy timed out waiting for TEE ownership claim endpoint".into());
        }

        if tee.is_none() {
            match api.get_unlock_endpoint(app_name).await {
                Ok(endpoint) => {
                    tee = Some(TeeClient::new_for_ownership_probe_with_resolve_ip(
                        &endpoint.tee_url,
                        endpoint.tee_resolve_ip,
                    ));
                }
                Err(error) if should_retry_template_bootstrap_endpoint_error(&error) => {
                    pb.set_message("Waiting for ownership claim endpoint...");
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }

        let tee = tee
            .as_ref()
            .expect("TEE client must exist after endpoint acquisition");
        match tee.attest_receipt_key().await {
            Ok((_attestation, attested_tee)) => match attested_tee.bootstrap_challenge().await {
                Ok(_) => {
                    pb.set_message("Ownership claim endpoint ready");
                    return Ok(true);
                }
                Err(err)
                    if attested_tee
                        .claim_state_is_successful()
                        .await
                        .unwrap_or(false) =>
                {
                    pb.set_message("Ownership already claimed");
                    let _ = err;
                    return Ok(false);
                }
                Err(_) => {
                    pb.set_message("Waiting for ownership claim endpoint...");
                }
            },
            Err(_) => {
                pb.set_message("Waiting for attested ownership claim endpoint...");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn should_retry_template_bootstrap_endpoint_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(error) => should_retry_api_transport_error(error),
        ApiError::Api { status, code, .. } => match (*status, code.as_deref()) {
            (409, Some("cap_app_sync_pending")) => true,
            (
                _,
                Some("cap_app_sync_pending" | "cap_response_invalid" | "not_implemented_hosted"),
            ) => false,
            (status, _) => matches!(status, 408 | 425 | 429 | 500..=599),
        },
        ApiError::NotAuthenticated => false,
    }
}

fn should_retry_api_transport_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
}

async fn deliver_template_config_with_retry(
    api: &ApiClient,
    tee: &mut TeeClient,
    instance_name: &str,
    config_token: &mut String,
    tee_url: &mut String,
    tee_resolve_ip: &mut Option<std::net::IpAddr>,
    pairs: &[(&'static str, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut delivery = TemplateConfigDeliveryState {
        api,
        tee,
        instance_name,
        config_token,
        tee_url,
        tee_resolve_ip,
    };
    for (key, value) in pairs {
        delivery.set_key(key, value).await?;
        sync_template_config_key_with_retry(api, instance_name, key).await?;
    }
    Ok(())
}

struct TemplateConfigDeliveryState<'a> {
    api: &'a ApiClient,
    tee: &'a mut TeeClient,
    instance_name: &'a str,
    config_token: &'a mut String,
    tee_url: &'a mut String,
    tee_resolve_ip: &'a mut Option<std::net::IpAddr>,
}

impl TemplateConfigDeliveryState<'_> {
    async fn set_key(&mut self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
            match self.tee.config_set(key, value, self.config_token).await {
                Ok(()) => return Ok(()),
                Err(error) if should_refresh_template_config_token(&error) => {
                    if attempt == TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
                        return Err(error.into());
                    }
                    let refreshed =
                        refresh_template_config_token_with_retry(self.api, self.instance_name, key)
                            .await?;
                    let refreshed_tee_url =
                        refreshed_template_config_endpoint_url(&refreshed, self.tee_url)?;
                    let refreshed_tee_resolve_ip =
                        refreshed.tee_resolve_ip.or(*self.tee_resolve_ip);
                    if refreshed_tee_url != *self.tee_url
                        || refreshed_tee_resolve_ip != *self.tee_resolve_ip
                    {
                        let refreshed_tee = TeeClient::from_config_url_with_resolve_ip(
                            &refreshed_tee_url,
                            refreshed_tee_resolve_ip,
                        );
                        *self.tee = attest_template_config_tee_with_retry(refreshed_tee).await?;
                        *self.tee_url = refreshed_tee_url;
                        *self.tee_resolve_ip = refreshed_tee_resolve_ip;
                    }
                    *self.config_token = refreshed.token;
                    tokio::time::sleep(template_config_delivery_retry_delay()).await;
                }
                Err(error)
                    if should_retry_template_config_tee_error(&error)
                        && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
                {
                    tokio::time::sleep(template_config_delivery_retry_delay()).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(format!("TEE config write failed for {key}").into())
    }
}

async fn attest_template_config_tee_with_retry(
    tee: TeeClient,
) -> Result<TeeClient, Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match tee.attest_receipt_key().await {
            Ok((_attestation, attested_tee)) => return Ok(attested_tee),
            Err(error)
                if should_retry_template_config_tee_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err("TEE attestation failed before config delivery".into())
}

async fn sync_template_config_key_with_retry(
    api: &ApiClient,
    instance_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match api.sync_config_key(instance_name, key, false).await {
            Ok(()) => return Ok(()),
            Err(error)
                if should_retry_template_config_sync_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("TEE config metadata sync failed for {key}").into())
}

async fn wait_for_paas_managed_config_keys(
    api: &ApiClient,
    instance_name: &str,
    expected_keys: &[String],
    deployment_id: &str,
    timeout: Duration,
    progress: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = expected_keys
        .iter()
        .map(|key| key.trim())
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if expected.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        fail_if_template_deployment_failed(api, instance_name, deployment_id).await?;
        match api.list_config_keys(instance_name).await {
            Ok(response) => {
                let present = response
                    .keys
                    .into_iter()
                    .map(|entry| entry.key)
                    .collect::<HashSet<_>>();
                let missing = expected
                    .iter()
                    .filter(|key| !present.contains(*key))
                    .cloned()
                    .collect::<Vec<_>>();
                if missing.is_empty() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "PaaS managed config did not become ready before timeout; missing keys: {}",
                        missing.join(", ")
                    )
                    .into());
                }
            }
            Err(error) if should_retry_template_config_sync_error(&error) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "PaaS managed config readiness check did not succeed before timeout: {error}"
                    )
                    .into());
                }
            }
            Err(error) => return Err(error.into()),
        }
        progress.tick();
        tokio::time::sleep(template_config_delivery_retry_delay()).await;
    }
}

async fn refresh_template_config_token_with_retry(
    api: &ApiClient,
    instance_name: &str,
    key: &str,
) -> Result<enclava_cli::api_types::ConfigTokenResponse, Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match api.get_config_token(instance_name).await {
            Ok(response) => return Ok(response),
            Err(error)
                if should_retry_template_config_sync_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => {
                return Err(format!(
                    "TEE config token expired while writing {key}, and PaaS could not issue a replacement token: {error}"
                )
                .into());
            }
        }
    }
    Err(format!("TEE config token refresh failed while writing {key}").into())
}

fn refreshed_template_config_endpoint_url(
    response: &enclava_cli::api_types::ConfigTokenResponse,
    current_tee_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match response.tee_url.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => template_config_endpoint_url(value),
        _ => Ok(current_tee_url.to_string()),
    }
}

fn template_config_delivery_retry_delay() -> Duration {
    Duration::from_secs(TEMPLATE_CONFIG_DELIVERY_RETRY_SECONDS)
}

fn should_refresh_template_config_token(error: &TeeError) -> bool {
    matches!(error, TeeError::Tee { status: 401, .. })
}

fn should_retry_template_config_tee_error(error: &TeeError) -> bool {
    match error {
        TeeError::Http(_) => true,
        TeeError::Tee { status, .. } => {
            matches!(*status, 408 | 409 | 423 | 425 | 429) || *status >= 500
        }
        TeeError::Attestation(message) => is_transient_template_config_attestation_error(message),
        TeeError::InvalidHeader(_) => false,
    }
}

fn is_transient_template_config_attestation_error(message: &str) -> bool {
    message.starts_with("TEE TCP connect failed:")
        || message.starts_with("TEE TLS handshake failed:")
        || message == "TEE did not present a certificate"
        || message == "TEE certificate chain is empty"
}

fn should_retry_template_config_sync_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(_) => true,
        ApiError::Api { status, .. } => matches!(*status, 408 | 409 | 425 | 429) || *status >= 500,
        ApiError::NotAuthenticated => false,
    }
}

fn read_ssh_public_keys(
    direct: &[String],
    files: &[PathBuf],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut lines = Vec::new();
    for value in direct {
        lines.push(value.trim().to_string());
    }
    for path in files {
        let content = fs::read_to_string(path).map_err(|err| {
            format!(
                "failed to read SSH public key file {}: {err}",
                path.display()
            )
        })?;
        lines.push(content.trim().to_string());
    }
    let value = lines
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if value.trim().is_empty() {
        Err("at least one SSH public key is required; pass --ssh-public-key or --ssh-public-key-file".into())
    } else {
        Ok(value)
    }
}

fn validate_ssh_public_keys(
    value: &str,
    metadata: Option<&HostedTemplateConfigKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.contains("-----BEGIN") || value.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err("do not pass a private key; use an SSH public key".into());
    }
    let max_bytes = metadata
        .and_then(|entry| entry.validation.as_ref())
        .and_then(|validation| validation.max_bytes)
        .unwrap_or(32_768) as usize;
    let max_items = metadata
        .and_then(|entry| entry.validation.as_ref())
        .and_then(|validation| validation.max_items)
        .unwrap_or(10) as usize;
    let allowed = metadata
        .and_then(|entry| entry.validation.as_ref())
        .map(|validation| validation.allowed_algorithms.as_slice())
        .filter(|algorithms| !algorithms.is_empty());
    let default_allowed = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ];

    if value.len() > max_bytes {
        return Err(format!("SSH public keys must be {max_bytes} bytes or smaller").into());
    }
    let mut count = 0usize;
    for (index, raw) in value.replace('\r', "").lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        if count > max_items {
            return Err(format!("enter at most {max_items} SSH public keys").into());
        }
        if raw.chars().any(|ch| ch.is_control()) {
            return Err(format!("line {} contains control characters", index + 1).into());
        }
        let mut fields = line.split_whitespace();
        let algorithm = fields.next().unwrap_or_default();
        let body = fields.next().unwrap_or_default();
        let allowed_match = allowed
            .map(|algorithms| algorithms.iter().any(|value| value == algorithm))
            .unwrap_or_else(|| default_allowed.contains(&algorithm));
        if !allowed_match {
            return Err(format!("line {} uses an unsupported SSH key algorithm", index + 1).into());
        }
        if body.is_empty()
            || !body
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=')
        {
            return Err(format!("line {} has a malformed SSH public key", index + 1).into());
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| format!("line {} has a malformed SSH public key", index + 1))?;
        if !ssh_public_key_blob_matches_algorithm(algorithm, &decoded) {
            return Err(format!("line {} has a malformed SSH public key", index + 1).into());
        }
    }
    if count == 0 {
        Err("at least one SSH public key is required".into())
    } else {
        Ok(())
    }
}

fn ssh_public_key_blob_matches_algorithm(algorithm: &str, blob: &[u8]) -> bool {
    let Some((blob_algorithm, offset)) = read_ssh_string(blob, 0) else {
        return false;
    };
    if !ssh_key_algorithm_matches(algorithm, blob_algorithm) {
        return false;
    }
    match algorithm {
        "ssh-ed25519" => {
            let Some((key, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            key.len() == 32 && offset == blob.len()
        }
        "ecdsa-sha2-nistp256" => {
            let Some((curve, offset)) = read_ssh_string(blob, offset) else {
                return false;
            };
            let Some((point, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            curve == "nistp256" && !point.is_empty() && offset == blob.len()
        }
        "rsa-sha2-256" | "rsa-sha2-512" => {
            let Some((exponent, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            let Some((modulus, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            !exponent.is_empty() && !modulus.is_empty() && offset == blob.len()
        }
        _ => false,
    }
}

fn ssh_key_algorithm_matches(algorithm: &str, blob_algorithm: &str) -> bool {
    algorithm == blob_algorithm
        || matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512") && blob_algorithm == "ssh-rsa"
}

fn read_ssh_string(blob: &[u8], offset: usize) -> Option<(&str, usize)> {
    let (value, offset) = read_ssh_bytes(blob, offset)?;
    std::str::from_utf8(value).ok().map(|value| (value, offset))
}

fn read_ssh_bytes(blob: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let length_end = offset.checked_add(4)?;
    let length_bytes: [u8; 4] = blob.get(offset..length_end)?.try_into().ok()?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let start = length_end;
    let end = start.checked_add(length)?;
    let value = blob.get(start..end)?;
    Some((value, end))
}

pub(crate) fn normalize_ngrok_tcp_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_reserved_endpoint(value, is_ngrok_tcp_host)
        .map_err(|_| "reserved stable SSH endpoint must look like 6.tcp.eu.ngrok.io:17958".into())
}

fn normalize_stable_ssh_endpoint(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_reserved_endpoint(value, |host| is_ngrok_tcp_host(host) || is_frp_relay_host(host))
        .map_err(|_| {
            format!(
                "reserved stable SSH endpoint must look like 6.tcp.eu.ngrok.io:17958 or {FRP_RELAY_HOST}:20001"
            )
            .into()
        })
}

fn normalize_reserved_endpoint(
    value: &str,
    valid_host: impl Fn(&str) -> bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    let address = if trimmed
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tcp://"))
    {
        &trimmed[6..]
    } else {
        trimmed
    }
    .to_ascii_lowercase();
    let Some((host, port_text)) = address.rsplit_once(':') else {
        return Err("reserved stable SSH endpoint must include host and port".into());
    };
    let host = host.trim_end_matches('.');
    let port = parse_tcp_port(port_text)
        .ok_or("reserved stable SSH endpoint must include a valid TCP port")?;
    if port == 0 || !valid_host(host) {
        return Err("reserved stable SSH endpoint host is invalid".into());
    }
    Ok(format!("{host}:{port}"))
}

fn template_config_endpoint_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err("TEE config URL is empty".into());
    }
    if raw_template_config_host(value)
        .as_deref()
        .is_some_and(is_ambiguous_numeric_template_config_host)
    {
        return Err("TEE config URL host is invalid".into());
    }
    let mut url = reqwest::Url::parse(value)
        .map_err(|error| format!("TEE config URL is invalid: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(
            "TEE config URL must use http or https and must not include credentials".into(),
        );
    }
    let host = url.host_str().unwrap_or_default();
    let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
    if canonical_host.is_empty() {
        return Err("TEE config URL must include a host".into());
    }
    if !is_valid_template_config_host(&canonical_host) {
        return Err("TEE config URL host is invalid".into());
    }
    let is_local_host = is_local_template_config_host(&canonical_host);
    if url.scheme() == "http" && !is_local_host {
        return Err("TEE config URL must use https for public endpoints".into());
    }
    if url.port().is_some() && !is_local_host {
        return Err("TEE config URL must use the default port for public endpoints".into());
    }
    if canonical_host != host {
        url.set_host(Some(&canonical_host))
            .map_err(|_| "TEE config URL is invalid")?;
    }
    match url.path().trim_end_matches('/') {
        "" | "/" => url.set_path("/.well-known/confidential/config"),
        "/.well-known/confidential" => url.set_path("/.well-known/confidential/config"),
        "/.well-known/confidential/config" => url.set_path("/.well-known/confidential/config"),
        _ => return Err("TEE config URL must point to /.well-known/confidential/config".into()),
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn is_reserved_template_config_host(host: &str) -> bool {
    matches!(host, "example.com" | "example.net" | "example.org")
        || host.ends_with(".example.com")
        || host.ends_with(".example.net")
        || host.ends_with(".example.org")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.ends_with(".invalid")
}

fn raw_template_config_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)?
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_ascii_lowercase());
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(authority);
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_ambiguous_numeric_template_config_host(host: &str) -> bool {
    host.split('.')
        .all(|label| !label.is_empty() && label.chars().all(|ch| ch.is_ascii_digit()))
        && !is_valid_ipv4_host(host)
}

fn is_local_template_config_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

fn is_valid_template_config_host(host: &str) -> bool {
    if is_local_template_config_host(host) {
        return true;
    }
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || !host.chars().any(|ch| ch.is_ascii_alphabetic())
        || is_reserved_template_config_host(host)
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

fn is_ngrok_tcp_host(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    if !matches!(labels.len(), 4 | 5) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) && labels[1] == "tcp"
        && labels[labels.len() - 2] == "ngrok"
        && matches!(labels[labels.len() - 1], "io" | "app")
}

fn is_frp_relay_host(host: &str) -> bool {
    host == FRP_RELAY_HOST
}

fn app_url_from_app_domain(app_domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let app_domain = app_domain.trim();
    if app_domain.is_empty() {
        return Err("template response included an empty app_domain".into());
    }
    normalize_app_url(app_domain).map_err(|error| {
        format!("template response included an invalid app_domain: {error}").into()
    })
}

fn app_url_from_template_response_cap(
    cap: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(app_domain) = cap
        .get("app_domain")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return app_url_from_app_domain(app_domain);
    }

    if let Some(domain) = cap
        .get("domain")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        let domain = domain.trim();
        return normalize_app_url(domain).map_err(|error| {
            format!("template response included an invalid domain: {error}").into()
        });
    }

    Err("template response did not include app_domain or domain".into())
}

fn app_url_from_app_response(app: &AppResponse) -> Result<String, Box<dyn std::error::Error>> {
    let app_domain = app
        .app_domain
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(app.domain.as_str());
    app_url_from_app_domain(app_domain)
}

fn normalize_app_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url_with_policy(value, true)
}

fn normalize_app_url_for_noncanonical_error(
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url_with_policy(value, false)
}

fn normalize_app_url_with_policy(
    value: &str,
    require_root_url: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err("app URL is empty".into());
    }
    let base = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let raw_host = raw_http_app_host(&base).ok_or("app URL is invalid")?;
    if is_ambiguous_numeric_host(&raw_host) {
        return Err("app URL is invalid".into());
    }
    let mut url =
        reqwest::Url::parse(&base).map_err(|error| format!("app URL is invalid: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err("app URL must use http or https and must not include credentials".into());
    }
    if require_root_url && (url.path() != "/" || url.query().is_some() || url.fragment().is_some())
    {
        return Err("app URL must be a canonical root URL".into());
    }
    let host = url.host_str().unwrap_or_default();
    let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_valid_http_app_host(&canonical_host) {
        return Err("app URL is invalid".into());
    }
    if canonical_host != host {
        url.set_host(Some(&canonical_host))
            .map_err(|_| "app URL is invalid")?;
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn raw_http_app_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_ascii_lowercase());
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(authority);
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_ambiguous_numeric_host(host: &str) -> bool {
    host.split('.')
        .all(|label| !label.is_empty() && label.chars().all(|ch| ch.is_ascii_digit()))
        && !is_valid_ipv4_host(host)
}

fn is_valid_ipv4_host(host: &str) -> bool {
    let parts = host.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            matches!(part.len(), 1..=3)
                && part.chars().all(|ch| ch.is_ascii_digit())
                && part
                    .parse::<u8>()
                    .map(|value| value.to_string() == *part || !part.starts_with('0'))
                    .unwrap_or(false)
        })
}

fn is_valid_http_app_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if is_reserved_http_app_host(host) {
        return false;
    }
    if !host.contains('.') {
        return false;
    }
    if !host.chars().any(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

fn is_reserved_http_app_host(host: &str) -> bool {
    matches!(host, "example.com" | "example.net" | "example.org")
        || host.ends_with(".example.com")
        || host.ends_with(".example.net")
        || host.ends_with(".example.org")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.ends_with(".invalid")
}

async fn wait_for_paas_ssh_command(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    stable_endpoint: &str,
    expected_app_url: &str,
    timeout: Duration,
) -> Result<SshCommandResponse, Box<dyn std::error::Error>> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        fail_if_template_deployment_failed(api, app_name, deployment_id).await?;
        let response = match api.get_template_ssh_command(app_name).await {
            Ok(response) => response,
            Err(error) if should_retry_paas_ssh_command_error(&error) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(error) => return Err(paas_ssh_command_api_error(error)),
        };
        validate_ssh_command_response(&response, stable_endpoint, expected_app_url)?;
        if response.status == "ready" {
            return Ok(response);
        }
        if let Some(response) =
            fetch_direct_ssh_command_response(&response, stable_endpoint, expected_app_url).await?
        {
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(format!("timed out waiting for stable SSH endpoint command for app {app_name}").into())
}

async fn latest_deployment_id(api: &ApiClient, app_name: &str) -> Result<Option<String>, ApiError> {
    Ok(api
        .list_deployments(app_name)
        .await?
        .into_iter()
        .next()
        .map(|deployment| deployment.id))
}

async fn fail_if_template_deployment_failed(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if deployment_id == "pending" {
        return Ok(());
    }
    match template_deployment_failure(api, app_name, deployment_id).await {
        Ok(Some(message)) => Err(message.into()),
        Ok(None) => Ok(()),
        Err(error) if should_retry_template_deployment_status_error(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn template_deployment_failure(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
) -> Result<Option<String>, ApiError> {
    let deployment = api
        .list_deployments(app_name)
        .await?
        .into_iter()
        .find(|deployment| deployment.id == deployment_id);
    Ok(deployment
        .as_ref()
        .filter(|deployment| deployment.status == "failed")
        .map(|deployment| template_deployment_failure_message(deployment, deployment_id)))
}

fn template_deployment_failure_message(
    deployment: &DeploymentEntry,
    deployment_id: &str,
) -> String {
    let detail = deployment
        .error_message
        .as_deref()
        .unwrap_or("deployment failed");
    format!("deployment {deployment_id} failed: {detail}")
}

fn should_retry_template_deployment_status_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(error) => should_retry_api_transport_error(error),
        ApiError::Api { status, code, .. } => {
            if matches!(
                code.as_deref(),
                Some("cap_response_invalid" | "not_implemented_hosted")
            ) {
                return false;
            }
            matches!(*status, 404 | 408 | 409 | 425 | 429 | 500..=599)
        }
        ApiError::NotAuthenticated => false,
    }
}

async fn fetch_direct_ssh_command_response(
    response: &SshCommandResponse,
    stable_endpoint: &str,
    expected_app_url: &str,
) -> Result<Option<SshCommandResponse>, Box<dyn std::error::Error>> {
    if response.status != "pending" {
        return Ok(None);
    }
    let Some(app_url) = response.app_url.as_deref() else {
        return Ok(None);
    };
    let app_url =
        normalize_app_url(app_url).map_err(|_| "PaaS /ssh-command response app_url is invalid")?;
    let expected_app_url =
        normalize_app_url(expected_app_url).map_err(|_| "expected app URL is invalid")?;
    if app_url != expected_app_url {
        return Err(format!(
            "PaaS /ssh-command app_url {app_url} does not match expected app URL {expected_app_url}"
        )
        .into());
    }
    let ssh_url = ssh_txt_url_from_app_url(&app_url)?;
    let command = match fetch_direct_ssh_command(&ssh_url).await? {
        Some(command) => command,
        None => return Ok(None),
    };
    ensure_ssh_command_matches_endpoint(&command, stable_endpoint)?;
    let endpoint = ssh_endpoint_string(&command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let ready = SshCommandResponse {
        status: "ready".to_string(),
        stable_ssh_endpoint: normalize_stable_ssh_endpoint(stable_endpoint)?,
        command: Some(command),
        endpoint: Some(endpoint),
        app_url: Some(app_url),
    };
    validate_ssh_command_response(&ready, stable_endpoint, expected_app_url.as_str())?;
    Ok(Some(ready))
}

fn ssh_txt_url_from_app_url(app_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = reqwest::Url::parse(app_url)?;
    url.set_path("/ssh.txt");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

async fn fetch_direct_ssh_command(
    ssh_url: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        // The app command is non-secret and is validated against the PaaS-reserved endpoint.
        // TLS verification is only relaxed under the same debug-gated env vars that govern
        // every other TEE channel (see accepts_invalid_tee_certs); release builds verify
        // normally and simply lose this readiness fallback when the relay presents an
        // untrusted (e.g. Let's Encrypt staging) chain.
        .danger_accept_invalid_certs(enclava_cli::tee_client::accepts_invalid_tee_certs())
        .build()?;
    let response = match client
        .get(ssh_url)
        .header(reqwest::header::ACCEPT, "text/plain")
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SSH_COMMAND_BYTES as u64)
    {
        return Err("stable SSH endpoint command response is too large".into());
    }
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(_) => return Ok(None),
    };
    if body.len() > MAX_SSH_COMMAND_BYTES {
        return Err("stable SSH endpoint command response is too large".into());
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| "stable SSH endpoint command response is not UTF-8")?;
    let command = ssh_command_body_line(body)
        .ok_or("stable SSH endpoint command response must contain exactly one command line")?;
    if !valid_ssh_command(command) {
        return Err(format!("invalid stable SSH endpoint command: {command}").into());
    }
    Ok(Some(command.to_string()))
}

fn ssh_command_body_line(body: &str) -> Option<&str> {
    if let Some(line) = body.strip_suffix('\n') {
        if line.contains('\n') || line.ends_with('\r') {
            return None;
        }
        return Some(line);
    }
    if body.contains('\n') {
        return None;
    }
    Some(body)
}

fn validate_ssh_command_response(
    response: &SshCommandResponse,
    stable_endpoint: &str,
    expected_app_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stable_endpoint = normalize_stable_ssh_endpoint(stable_endpoint)
        .map_err(|_| "expected stable SSH endpoint is invalid")?;
    let api_stable_endpoint = normalize_stable_ssh_endpoint(&response.stable_ssh_endpoint)
        .map_err(|_| "PaaS /ssh-command stable_ssh_endpoint is invalid")?;
    if response.stable_ssh_endpoint != api_stable_endpoint {
        return Err(format!(
            "PaaS /ssh-command stable_ssh_endpoint {api_stable_endpoint} is not canonical"
        )
        .into());
    }
    if api_stable_endpoint != stable_endpoint {
        return Err(format!(
            "PaaS /ssh-command stable_ssh_endpoint {api_stable_endpoint} does not match expected stable SSH endpoint {stable_endpoint}"
        )
        .into());
    }
    validate_ssh_command_app_url(response, expected_app_url)?;
    if response.status != "ready" {
        if response.command.is_some() || response.endpoint.is_some() {
            return Err("PaaS /ssh-command response included ready-only stable SSH endpoint command fields while status was not ready".into());
        }
        if response.status == "pending" {
            return Ok(());
        }
        return Err(format!(
            "PaaS /ssh-command response returned unknown status: {}",
            response.status
        )
        .into());
    }

    let command = response
        .command
        .as_deref()
        .ok_or("PaaS reported stable SSH endpoint command ready without a command")?;
    if !valid_ssh_command(command) {
        return Err(
            format!("PaaS returned an invalid stable SSH endpoint command: {command}").into(),
        );
    }
    let reported_endpoint = response.endpoint.as_deref().ok_or(
        "PaaS /ssh-command response did not include endpoint for ready stable SSH endpoint command",
    )?;
    ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
    ensure_ssh_command_matches_endpoint(command, &stable_endpoint)?;
    Ok(())
}

fn validate_ssh_command_app_url(
    response: &SshCommandResponse,
    expected_app_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected =
        normalize_app_url(expected_app_url).map_err(|_| "expected app URL is invalid")?;
    let Some(raw_app_url) = response.app_url.as_deref() else {
        if response.status == "ready" {
            return Err(
                "PaaS /ssh-command response did not include app_url for ready stable SSH endpoint command".into(),
            );
        }
        return Ok(());
    };
    let app_url = raw_app_url.trim();
    let actual = normalize_app_url_for_noncanonical_error(app_url)
        .map_err(|_| "PaaS /ssh-command response app_url is invalid")?;
    if raw_app_url != app_url || app_url != actual {
        return Err(format!("PaaS /ssh-command response app_url {actual} is not canonical").into());
    }
    if actual != expected {
        return Err(format!(
            "PaaS /ssh-command app_url {actual} does not match expected app URL {expected}"
        )
        .into());
    }
    Ok(())
}

struct DeployResponseOutput<'a> {
    template_slug: &'a str,
    instance_name: &'a str,
    app_url: &'a str,
    deployment_id: &'a str,
    stable_endpoint: Option<&'a str>,
    ssh_command: Option<&'a str>,
    ssh_endpoint: Option<&'a str>,
    log_key_id: Option<&'a str>,
    log_private_key_file: Option<&'a std::path::Path>,
    json: bool,
}

fn deploy_response_output(
    output: DeployResponseOutput<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let DeployResponseOutput {
        template_slug,
        instance_name,
        app_url,
        deployment_id,
        stable_endpoint,
        ssh_command,
        ssh_endpoint,
        log_key_id,
        log_private_key_file,
        json,
    } = output;
    let app_url = normalize_paas_ssh_command_app_url(app_url)?;
    let stable_endpoint = stable_endpoint
        .map(normalize_stable_ssh_endpoint)
        .transpose()
        .map_err(|_| "stable SSH endpoint output is invalid")?;
    let endpoint = display_ssh_endpoint(ssh_command, ssh_endpoint)?;
    if json {
        let output = serde_json::json!({
            "template": template_slug,
            "instance": instance_name,
            "app_url": app_url.as_str(),
            "deployment_id": deployment_id,
            "stable_ssh_endpoint": stable_endpoint.as_deref(),
            "stable_endpoint": stable_endpoint.as_deref(),
            "ssh_command_status": if ssh_command.is_some() { "ready" } else { "pending" },
            "command": ssh_command,
            "endpoint": endpoint,
            "ssh_command_path": format!("/apps/{instance_name}/ssh-command"),
            "log_key_id": log_key_id,
            "log_private_key_file": log_private_key_file.map(|path| path.display().to_string()),
        });
        return Ok(format!("{}\n", serde_json::to_string_pretty(&output)?));
    }

    let mut lines = vec![
        String::new(),
        format!("  Template:   {template_slug}"),
        format!("  Instance:   {instance_name}"),
        format!("  URL:        {}", app_url),
        format!("  Deploy:     {deployment_id}"),
    ];
    if let Some(endpoint) = stable_endpoint.as_deref() {
        lines.push(format!("  Stable SSH endpoint: {endpoint}"));
    }
    if let Some(command) = ssh_command {
        lines.push(format!("  Stable SSH endpoint command: {command}"));
    } else {
        lines.push(format!(
            "  Stable SSH endpoint command: pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    if let Some(key_id) = log_key_id {
        lines.push(format!("  Log key:    {key_id}"));
    }
    if let Some(path) = log_private_key_file {
        lines.push(format!("  Log private key: {}", path.display()));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn ssh_command_response_output(
    instance_name: &str,
    response: &SshCommandResponse,
    stable_endpoint: &str,
    expected_app_url: &str,
    json: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let stable_endpoint = normalize_stable_ssh_endpoint(stable_endpoint)?;
    validate_ssh_command_response(response, &stable_endpoint, expected_app_url)?;
    let endpoint = display_ssh_endpoint(response.command.as_deref(), response.endpoint.as_deref())?;
    let app_url = response_app_url_for_output(response)?;
    if json {
        let output = serde_json::json!({
            "app_name": instance_name,
            "status": response.status.as_str(),
            "app_url": app_url.as_deref(),
            "stable_ssh_endpoint": stable_endpoint.as_str(),
            "stable_endpoint": stable_endpoint.as_str(),
            "command": response.command.as_deref(),
            "endpoint": endpoint,
        });
        return Ok(format!("{}\n", serde_json::to_string_pretty(&output)?));
    }

    let mut lines = vec![format!("  Status:     {}", response.status)];
    if let Some(app_url) = app_url.as_deref() {
        lines.push(format!("  URL:        {app_url}"));
    }
    lines.push(format!("  Stable SSH endpoint: {stable_endpoint}"));
    if let Some(command) = response.command.as_deref() {
        lines.push(format!("  Stable SSH endpoint command: {command}"));
    } else {
        lines.push(format!(
            "  Stable SSH endpoint command: pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn response_app_url_for_output(
    response: &SshCommandResponse,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    response
        .app_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_paas_ssh_command_app_url)
        .transpose()
}

fn normalize_paas_ssh_command_app_url(app_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url(app_url).map_err(|_| "PaaS /ssh-command response app_url is invalid".into())
}

fn should_retry_paas_ssh_command_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(_) => true,
        ApiError::Api { status, code, .. } => {
            if matches!(
                code.as_deref(),
                Some(
                    "unauthenticated"
                        | "org_permission_denied"
                        | "app_not_found"
                        | "ssh_command_not_available"
                        | "stable_ssh_endpoint_missing"
                        | "stable_ssh_endpoint_invalid"
                        | "cap_response_invalid"
                        | "not_implemented_hosted"
                )
            ) {
                return false;
            }
            matches!(*status, 408 | 425 | 429 | 500..=599)
        }
        ApiError::NotAuthenticated => false,
    }
}

fn paas_ssh_command_api_error(error: ApiError) -> Box<dyn std::error::Error> {
    if let Some(message) = paas_ssh_command_api_error_message(&error) {
        message.into()
    } else {
        error.into()
    }
}

fn template_instance_create_api_error(error: ApiError) -> Box<dyn std::error::Error> {
    if let Some(message) = stable_ssh_managed_ngrok_setup_error_message(&error) {
        message.into()
    } else {
        error.into()
    }
}

fn managed_template_config_api_error(error: ApiError) -> Box<dyn std::error::Error> {
    match &error {
        ApiError::Api {
            code: Some(code),
            message,
            ..
        } if code == "managed_config_delivery_failed" => {
            format!(
                "PaaS could not deliver platform-managed template config after ownership claim: {message}"
            )
            .into()
        }
        _ => error.into(),
    }
}

fn stable_ssh_managed_ngrok_setup_error_message(error: &ApiError) -> Option<String> {
    let ApiError::Api { code, message, .. } = error else {
        return None;
    };
    if matches!(
        code.as_deref(),
        Some(
            "ngrok_api_key_required"
                | "ngrok_api_key_invalid"
                | "ngrok_api_key_unavailable"
                | "ngrok_tcp_reservation_failed"
        )
    ) || message.contains("NGROK_API_KEY")
    {
        return Some(
            "Stable SSH endpoint reservation is unavailable because PaaS is missing or cannot use its ngrok management API key. Platform operators must inject NGROK_API_KEY in the PaaS deployment environment, then retry. Do not pass an ngrok API key through the CLI, local text/token file, or release env."
                .to_string(),
        );
    }
    if code.as_deref() == Some("service_unavailable")
        && message.contains("DEBIAN_SSH_NGROK_AUTHTOKEN")
    {
        return Some(
            "Stable SSH setup is unavailable because PaaS is missing its managed ngrok authtoken. Platform operators must inject DEBIAN_SSH_NGROK_AUTHTOKEN through the PaaS deployment environment, then retry. Do not pass an ngrok token through the CLI, local text/token file, or release env."
                .to_string(),
        );
    }
    None
}

fn paas_ssh_command_api_error_message(error: &ApiError) -> Option<String> {
    let ApiError::Api { code, .. } = error else {
        return None;
    };
    let message = match code.as_deref()? {
        "stable_ssh_endpoint_missing" => {
            "Stable SSH endpoint metadata is missing. Redeploy the template so PaaS reserves a stable SSH endpoint."
        }
        "stable_ssh_endpoint_invalid" => {
            "Stable SSH endpoint metadata is invalid. Redeploy the template so PaaS reserves a stable SSH endpoint."
        }
        "cap_response_invalid" => {
            "Stable SSH endpoint API rejected malformed, non-canonical, or mismatched workload output. Redeploy the template if this app was created before stable SSH endpoint metadata was stored. Support must fix non-canonical stable SSH endpoint API or workload output at the template boundary."
        }
        _ => return None,
    };
    Some(message.to_string())
}

fn valid_ssh_command(command: &str) -> bool {
    parse_ssh_endpoint(command).is_some()
}

fn ssh_endpoint_string(command: &str) -> Option<String> {
    let (host, port) = parse_ssh_endpoint(command)?;
    let port = port.parse::<u16>().ok()?;
    Some(format!("{host}:{port}"))
}

fn display_ssh_endpoint(
    command: Option<&str>,
    reported_endpoint: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(command) = command else {
        return Ok(None);
    };
    let command_endpoint = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let reported_endpoint = reported_endpoint.ok_or(
        "PaaS /ssh-command response did not include endpoint for ready stable SSH endpoint command",
    )?;
    ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
    Ok(Some(command_endpoint))
}

fn parse_ssh_endpoint(command: &str) -> Option<(&str, &str)> {
    let parts = command.split(' ').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "ssh" || parts[1] != "-p" {
        return None;
    }
    parse_canonical_tcp_port(parts[2])?;
    let host = parts[3].strip_prefix("user@")?;
    if !is_canonical_stable_ssh_host(host) {
        return None;
    }
    Some((host, parts[2]))
}

fn parse_canonical_tcp_port(port_text: &str) -> Option<u16> {
    if port_text.len() > 1 && port_text.starts_with('0') {
        return None;
    }
    parse_tcp_port(port_text).filter(|port| *port > 0)
}

fn parse_tcp_port(port_text: &str) -> Option<u16> {
    if matches!(port_text.len(), 1..=5) && port_text.chars().all(|ch| ch.is_ascii_digit()) {
        port_text.parse::<u16>().ok()
    } else {
        None
    }
}

fn is_canonical_stable_ssh_host(host: &str) -> bool {
    host == host.trim_end_matches('.')
        && host == host.to_ascii_lowercase()
        && (is_ngrok_tcp_ssh_host(host) || is_frp_relay_host(host))
}

fn is_ngrok_tcp_ssh_host(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    let labels = normalized.split('.').collect::<Vec<_>>();
    if !matches!(labels.len(), 4 | 5) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) && labels[1] == "tcp"
        && labels[labels.len() - 2] == "ngrok"
        && matches!(labels[labels.len() - 1], "io" | "app")
}

fn ensure_reported_ssh_endpoint_matches_command(
    command: &str,
    reported_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let command_endpoint = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let raw_reported_endpoint = reported_endpoint.trim();
    let normalized_reported_endpoint = normalize_stable_ssh_endpoint(raw_reported_endpoint)
        .map_err(|_| "PaaS /ssh-command response endpoint is not a reserved stable SSH endpoint")?;
    if reported_endpoint != raw_reported_endpoint
        || raw_reported_endpoint != normalized_reported_endpoint
    {
        return Err(format!(
            "PaaS /ssh-command response endpoint {normalized_reported_endpoint} is not canonical"
        )
        .into());
    }
    if normalized_reported_endpoint == command_endpoint {
        return Ok(());
    }
    Err(format!(
        "PaaS stable SSH endpoint {normalized_reported_endpoint} does not match endpoint parsed from stable SSH endpoint command {command_endpoint}"
    )
    .into())
}

fn ensure_ssh_command_matches_endpoint(
    command: &str,
    endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let expected = normalize_stable_ssh_endpoint(endpoint)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "Stable SSH endpoint command resolves to {actual}, which does not match reserved endpoint {expected}"
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_cli::api_types::{
        ConfigTokenResponse, HostedTemplateConfigValidation, HostedTemplateEgressRule,
        HostedTemplateResources,
    };
    const VALID_ED25519_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlL21WHthjyXNuxzes5bVqCCqgyWDuMvXcWhOxRGL1P cli-test@example";

    fn hosted_template_with_stable_ssh() -> HostedTemplate {
        HostedTemplate {
            slug: "debian-ssh-ngrok".to_string(),
            name: "Debian Stable SSH Endpoint".to_string(),
            description: "SSH template".to_string(),
            features: vec![
                "SSH over a stable SSH endpoint".to_string(),
                "PaaS-provisioned ngrok TCP address".to_string(),
            ],
            version: "2026-06-18".to_string(),
            image: "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".to_string(),
            source_provider: Some("github".to_string()),
            source_repository: Some("enclava-labs/debian-ssh-ngrok-template".to_string()),
            signer_subject: Some("https://github.com/enclava-labs/enclava-paas/.github/workflows/debian-ssh-ngrok-template-image.yml@refs/heads/main".to_string()),
            signer_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            workload_security_profile: Some("restricted".to_string()),
            container_name: "web".to_string(),
            command: vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "exec /usr/local/bin/debian-ssh-entrypoint".to_string(),
            ],
            port: 8080,
            unlock_mode: "password".to_string(),
            health_path: Some("/healthz".to_string()),
            health_interval: Some(30),
            health_timeout: Some(5),
            resources: HostedTemplateResources {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
                storage: "10Gi".to_string(),
            },
            storage_paths: vec![],
            egress_allowlist: vec![HostedTemplateEgressRule {
                host: "6.tcp.eu.ngrok.io".to_string(),
                ports: vec![17958],
            }],
            egress_mode: "restricted".to_string(),
            paas_managed_config_keys: vec!["NGROK_AUTHTOKEN".to_string()],
            config_keys: vec![
                HostedTemplateConfigKey {
                    key: "NGROK_TCP_URL".to_string(),
                    label: "Stable SSH endpoint".to_string(),
                    description: "Optional existing reserved stable SSH endpoint.".to_string(),
                    input_type: "text".to_string(),
                    required: false,
                    secret: false,
                    default_value: None,
                    validation: Some(HostedTemplateConfigValidation {
                        format: Some("ngrok_tcp_url".to_string()),
                        example: Some("6.tcp.eu.ngrok.io:17958".to_string()),
                        max_bytes: Some(255),
                        max_items: None,
                        allowed_algorithms: vec![],
                    }),
                },
                HostedTemplateConfigKey {
                    key: "DEBIAN_SSH_AUTHORIZED_KEYS".to_string(),
                    label: "SSH public keys".to_string(),
                    description: "One SSH public key per line.".to_string(),
                    input_type: "ssh_public_keys".to_string(),
                    required: true,
                    secret: false,
                    default_value: None,
                    validation: None,
                },
            ],
            persistence_path: Some("/state".to_string()),
            security_notes: vec![],
        }
    }

    #[test]
    fn ngrok_tcp_url_normalizes_tcp_scheme() {
        assert_eq!(
            normalize_ngrok_tcp_url("tcp://6.tcp.eu.ngrok.io:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("TCP://6.TCP.EU.NGROK.IO:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("TCP://6.TCP.EU.NGROK.IO.:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("1.tcp.ngrok.io:22222").unwrap(),
            "1.tcp.ngrok.io:22222"
        );
    }

    #[test]
    fn ngrok_tcp_url_rejects_non_ngrok_hosts() {
        assert!(normalize_ngrok_tcp_url("example.com:22").is_err());
        assert!(normalize_ngrok_tcp_url("relay.enclava.me:20001").is_err());
        assert!(normalize_ngrok_tcp_url("tcp.eu.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.foo.eu.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.extra.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.example:17958").is_err());
        assert!(
            normalize_ngrok_tcp_url(&format!("{}.tcp.eu.ngrok.io:17958", "a".repeat(64))).is_err()
        );
    }

    #[test]
    fn ngrok_tcp_url_rejects_non_decimal_ports() {
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:+123").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:1e2").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:000123").is_err());
    }

    #[test]
    fn stable_ssh_endpoint_accepts_frp_relay_host() {
        assert_eq!(
            normalize_stable_ssh_endpoint("tcp://Relay.Enclava.Me:20001").unwrap(),
            "relay.enclava.me:20001"
        );
    }

    #[test]
    fn tee_config_url_normalizes_confidential_endpoint() {
        assert_eq!(
            template_config_endpoint_url("https://TEE.Enclava.Dev./").unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("https://tee.enclava.dev/.well-known/confidential")
                .unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url(
                "https://tee.enclava.dev/.well-known/confidential/config?ignored=true#frag",
            )
            .unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://localhost:8080/.well-known/confidential").unwrap(),
            "http://localhost:8080/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://127.0.0.1:8080/.well-known/confidential").unwrap(),
            "http://127.0.0.1:8080/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://[::1]:8080/.well-known/confidential").unwrap(),
            "http://[::1]:8080/.well-known/confidential/config"
        );
    }

    #[test]
    fn tee_config_url_rejects_credentials_and_custom_paths() {
        for url in [
            "",
            "file:///tmp/config",
            "http://tee.enclava.dev/.well-known/confidential/config",
            "https://user:pass@tee.enclava.dev/.well-known/confidential/config",
            "https://tee.enclava.dev:8443/.well-known/confidential/config",
            "https://tee.enclava.dev/custom/config",
            "https://-tee.enclava.dev/.well-known/confidential/config",
            "https://tee-.enclava.dev/.well-known/confidential/config",
            "https://123.456/.well-known/confidential/config",
            "https://8.8.8.8/.well-known/confidential/config",
            "http://8.8.8.8:8080/.well-known/confidential/config",
            "https://tee.example.test/.well-known/confidential/config",
            "https://tee.example.com/.well-known/confidential/config",
        ] {
            assert!(
                template_config_endpoint_url(url).is_err(),
                "expected {url:?} to be rejected"
            );
        }
    }

    #[test]
    fn deploy_omits_stable_endpoint_by_default_and_accepts_optional_import() {
        assert_eq!(template_create_config(None), serde_json::json!({}));
        assert_eq!(
            template_create_config(Some("6.tcp.eu.ngrok.io:17958")),
            serde_json::json!({
                "NGROK_TCP_URL": "6.tcp.eu.ngrok.io:17958"
            })
        );
        assert_eq!(
            normalize_ngrok_tcp_url("tcp://6.TCP.EU.NGROK.IO:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
    }

    #[test]
    fn deploy_cli_defers_stable_endpoint_requirement_to_debian_ssh_runtime_and_accepts_legacy_alias()
     {
        use clap::Parser as _;

        let cli = crate::commands::Cli::try_parse_from([
            "enclava", "template", "deploy", "--name", "shell",
        ])
        .expect("template deploy should parse without making every template SSH-specific");

        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(args.template, DEBIAN_SSH_FRP_TEMPLATE);
        assert_eq!(args.ngrok_tcp_url, None);
        assert_eq!(
            template_create_config(args.ngrok_tcp_url.as_deref()),
            serde_json::json!({})
        );

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "deploy",
            "--name",
            "shell",
            "--ngrok-tcp-url",
            "6.tcp.eu.ngrok.io:17958",
        ])
        .expect("legacy ngrok endpoint flag must remain accepted");
        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(
            args.ngrok_tcp_url.as_deref(),
            Some("6.tcp.eu.ngrok.io:17958")
        );

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "deploy",
            "--name",
            "shell",
            "--storage-password-file",
            "/tmp/enclava-password",
        ])
        .expect("template deploy should accept storage password file");
        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(
            args.storage_password_file.as_deref(),
            Some(std::path::Path::new("/tmp/enclava-password"))
        );
    }

    #[test]
    fn deploy_help_names_stable_ssh_endpoint_and_legacy_alias() {
        use clap::Parser as _;

        let help =
            match crate::commands::Cli::try_parse_from(["enclava", "template", "deploy", "--help"])
            {
                Ok(_) => panic!("help should exit through clap"),
                Err(error) => error.to_string(),
            };

        assert!(
            help.contains("Existing reserved stable SSH endpoint"),
            "template deploy help should frame --stable-ssh-endpoint as an optional import path: {help}"
        );
        assert!(
            help.contains("--stable-ssh-endpoint <HOST:PORT>"),
            "template deploy help should lead with --stable-ssh-endpoint: {help}"
        );
        assert!(
            help.contains("--ngrok-tcp-url"),
            "template deploy help should keep the legacy --ngrok-tcp-url alias visible: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command readiness"),
            "template deploy help should frame --no-wait around stable SSH endpoint command readiness: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command details"),
            "template deploy JSON help should name the stable SSH endpoint command: {help}"
        );
        assert!(
            help.contains("--storage-password-file <PATH>"),
            "template deploy help should expose non-interactive password-mode deploy support: {help}"
        );
        assert!(
            help.contains("--log-key <KEY_ID>")
                && help.contains("--generate-log-key <KEY_ID>")
                && help.contains("--log-private-key-file <PATH>"),
            "template deploy help should expose pre-deploy tenant log-encryption setup: {help}"
        );
        let command_centric_hint = ["for a stable SSH", " command"].concat();
        assert!(
            !help.contains(&command_centric_hint),
            "template deploy help should not frame the reserved endpoint as merely command-oriented: {help}"
        );
    }

    #[test]
    fn deploy_cli_accepts_predeploy_log_encryption_options() {
        use clap::Parser as _;

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "deploy",
            "--name",
            "shell",
            "--log-key",
            "team-logs",
        ])
        .expect("template deploy should accept an existing log key");
        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(args.log_key.as_deref(), Some("team-logs"));
        assert_eq!(args.generate_log_key, None);

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "deploy",
            "--name",
            "shell",
            "--generate-log-key",
            "shell-logs",
            "--log-private-key-file",
            "/tmp/shell-logs.x25519",
        ])
        .expect("template deploy should generate and store a new log key");
        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(args.generate_log_key.as_deref(), Some("shell-logs"));
        assert_eq!(args.log_key, None);
        assert_eq!(
            args.log_private_key_file.as_deref(),
            Some(std::path::Path::new("/tmp/shell-logs.x25519"))
        );

        assert!(
            crate::commands::Cli::try_parse_from([
                "enclava",
                "template",
                "deploy",
                "--name",
                "shell",
                "--log-key",
                "team-logs",
                "--generate-log-key",
                "shell-logs",
            ])
            .is_err(),
            "existing and generated log-key choices must conflict"
        );
        assert!(
            crate::commands::Cli::try_parse_from([
                "enclava",
                "template",
                "deploy",
                "--name",
                "shell",
                "--log-private-key-file",
                "/tmp/shell-logs.x25519",
            ])
            .is_err(),
            "a private-key path without key generation must be rejected"
        );
    }

    #[test]
    fn template_deploy_requires_requested_log_key_in_signed_policy() {
        let config = enclava_engine::types::LogEncryptionConfig {
            algorithm: "x25519-hpke-v1".to_string(),
            key_id: "shell-logs".to_string(),
            public_key_base64url: "public-key".to_string(),
            public_key_sha256: "sha256:public-key".to_string(),
        };
        let prepared = PreparedTemplateLogKey {
            config: config.clone(),
            private_key_file: None,
        };

        verify_signed_template_log_key(Some(&prepared), Some(&config)).unwrap();
        verify_signed_template_log_key(None, None).unwrap();

        let mut different = config.clone();
        different.key_id = "other-key".to_string();
        let mismatch = verify_signed_template_log_key(Some(&prepared), Some(&different))
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("does not match requested key `shell-logs`"));

        let missing = verify_signed_template_log_key(Some(&prepared), None)
            .unwrap_err()
            .to_string();
        assert!(missing.contains("omitted requested log-encryption key `shell-logs`"));
    }

    #[test]
    fn template_deploy_validates_log_key_selection_response() {
        let selected = enclava_cli::api_types::LogEncryptionKey {
            key_id: "shell-logs".to_string(),
            algorithm: "x25519-hpke-v1".to_string(),
            public_key_base64url: "public-key".to_string(),
            public_key_sha256: "sha256:public-key".to_string(),
            label: None,
            status: "active".to_string(),
            active_for_app: true,
            selected_at: Some("2026-07-15T00:00:00Z".to_string()),
            created_at: "2026-07-15T00:00:00Z".to_string(),
            revoked_at: None,
        };

        verify_selected_template_log_key("shell-logs", &selected).unwrap();

        let mut stale = selected;
        stale.key_id = "stale-key".to_string();
        let mismatch = verify_selected_template_log_key("shell-logs", &stale)
            .unwrap_err()
            .to_string();
        assert!(
            mismatch.contains("returned key `stale-key` instead of requested key `shell-logs`")
        );

        stale.key_id = "shell-logs".to_string();
        stale.active_for_app = false;
        let inactive = verify_selected_template_log_key("shell-logs", &stale)
            .unwrap_err()
            .to_string();
        assert!(inactive.contains("did not confirm requested key `shell-logs` as active"));

        stale.active_for_app = true;
        stale.status = "revoked".to_string();
        let revoked = verify_selected_template_log_key("shell-logs", &stale)
            .unwrap_err()
            .to_string();
        assert!(revoked.contains("did not confirm requested key `shell-logs` as active"));
    }

    #[test]
    fn ssh_command_help_names_stable_ssh_endpoint_and_legacy_alias() {
        use clap::Parser as _;

        let help = match crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "ssh-command",
            "--help",
        ]) {
            Ok(_) => panic!("help should exit through clap"),
            Err(error) => error.to_string(),
        };

        assert!(
            help.contains("Reserved stable SSH endpoint expected for this app"),
            "template ssh-command help should frame --stable-ssh-endpoint as a stable SSH endpoint assertion: {help}"
        );
        assert!(
            help.contains("--stable-ssh-endpoint <HOST:PORT>"),
            "template ssh-command help should lead with --stable-ssh-endpoint: {help}"
        );
        assert!(
            help.contains("--ngrok-tcp-url"),
            "template ssh-command help should keep the legacy --ngrok-tcp-url alias visible: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command as ready"),
            "template ssh-command help should describe waiting for stable SSH endpoint command readiness: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command and parsed stable SSH endpoint"),
            "template ssh-command JSON help should describe endpoint-first JSON output: {help}"
        );
        let command_centric_hint = ["returned stable SSH", " command"].concat();
        assert!(
            !help.contains(&command_centric_hint),
            "template ssh-command help should not frame the reserved endpoint as merely command-oriented: {help}"
        );
    }

    #[test]
    fn template_help_names_ssh_command_as_stable_ssh_endpoint_recovery() {
        use clap::Parser as _;

        let help = match crate::commands::Cli::try_parse_from(["enclava", "template", "--help"]) {
            Ok(_) => panic!("help should exit through clap"),
            Err(error) => error.to_string(),
        };

        assert!(
            help.contains("Fetch and validate the PaaS-rendered stable SSH endpoint command"),
            "template help should make ssh-command discoverable as stable SSH endpoint recovery: {help}"
        );
    }

    #[tokio::test]
    async fn unknown_templates_are_resolved_by_paas_before_ssh_validation() {
        let err = deploy(TemplateDeployArgs {
            template: "future-template".to_string(),
            name: "shell".to_string(),
            ssh_public_keys: vec![],
            ssh_public_key_files: vec![],
            ngrok_tcp_url: None,
            no_wait: false,
            ssh_timeout_seconds: DEFAULT_SSH_TIMEOUT_SECONDS,
            storage_password_file: None,
            log_key: None,
            generate_log_key: None,
            log_private_key_file: None,
            json: false,
            store_mnemonic: false,
            no_store_mnemonic: false,
        })
        .await
        .expect_err("unknown templates should fail before stable SSH endpoint validation");

        let message = err.to_string();
        assert!(
            !message.contains("stored stable SSH endpoint")
                && !message.contains("PaaS template response")
                && !message.contains("submitted stable SSH endpoint"),
            "unknown template errors must not come from stable SSH endpoint validation: {message}"
        );
    }

    #[test]
    fn template_instance_name_uses_server_slug_rules() {
        assert_eq!(normalize_slug(" Shell-01 ").unwrap(), "shell-01");
        assert!(normalize_slug("1234").is_err());
        assert!(normalize_slug("-shell").is_err());
        assert!(normalize_slug("shell_01").is_err());
    }

    fn stable_ssh_app_response(endpoint: Option<&str>) -> AppResponse {
        AppResponse {
            id: "app-1".to_string(),
            name: "shell".to_string(),
            namespace: "ns-shell".to_string(),
            instance_id: "instance-1".to_string(),
            service_account: None,
            bootstrap_owner_pubkey_hash: None,
            tenant_instance_identity_hash: None,
            domain: "shell.enclava.dev".to_string(),
            app_domain: None,
            tee_domain: None,
            custom_domain: None,
            status: "running".to_string(),
            unlock_mode: "password".to_string(),
            signer_identity_subject: None,
            signer_identity_issuer: None,
            template_slug: Some(DEBIAN_SSH_NGROK_TEMPLATE.to_string()),
            template_version: Some("2026-06-18".to_string()),
            template_expected: enclava_cli::api_types::TemplateExpected {
                stable_ssh_endpoint: endpoint.map(str::to_string),
                ..Default::default()
            },
            created_at: "2026-06-24T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn ssh_command_uses_stored_stable_endpoint_from_app_metadata() {
        let app = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:123"));
        assert_eq!(
            stored_stable_endpoint_from_app(&app).unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );

        let mut non_template = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:17958"));
        non_template.template_slug = Some("mini-enclava-go".to_string());
        assert!(
            stored_stable_endpoint_from_app(&non_template)
                .unwrap_err()
                .to_string()
                .contains("only available for Debian SSH apps")
        );

        let mut frp_app = stable_ssh_app_response(Some("relay.enclava.me:20001"));
        frp_app.template_slug = Some(DEBIAN_SSH_FRP_TEMPLATE.to_string());
        assert_eq!(
            stored_stable_endpoint_from_app(&frp_app).unwrap(),
            "relay.enclava.me:20001"
        );

        for endpoint in [None, Some("   ")] {
            let app = stable_ssh_app_response(endpoint);
            assert!(
                stored_stable_endpoint_from_app(&app)
                    .unwrap_err()
                    .to_string()
                    .contains("missing its stored stable SSH endpoint expectation")
            );
        }

        for endpoint in [
            "tcp://6.tcp.eu.ngrok.io:123",
            "6.TCP.EU.NGROK.IO:123",
            "6.tcp.eu.ngrok.io.:123",
            "6.tcp.eu.ngrok.io:00123",
            " tcp://6.TCP.EU.NGROK.IO.:00123 ",
            "example.com:22",
        ] {
            let app = stable_ssh_app_response(Some(endpoint));
            assert!(
                stored_stable_endpoint_from_app(&app)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid stored stable SSH endpoint expectation"),
                "{endpoint} must be treated as corrupt stored metadata"
            );
        }
    }

    fn template_instance_response_with_stored_endpoint(
        endpoint: Option<&str>,
    ) -> TemplateInstanceResponse {
        TemplateInstanceResponse {
            template: hosted_template_with_stable_ssh(),
            app: enclava_cli::api_types::TemplateInstanceAppResponse {
                name: Some("shell".to_string()),
                template_expected: enclava_cli::api_types::TemplateExpected {
                    stable_ssh_endpoint: endpoint.map(str::to_string),
                    ..Default::default()
                },
                ..Default::default()
            },
            deployment: enclava_cli::api_types::TemplateDeploymentResponse {
                cap_deployment_id: Some("deploy-123".to_string()),
                status: "pending".to_string(),
                template_expected: enclava_cli::api_types::TemplateExpected {
                    stable_ssh_endpoint: endpoint.map(str::to_string),
                    ..Default::default()
                },
            },
            config_token: None,
            cap: serde_json::json!({
                "app_domain": "shell.enclava.dev"
            }),
        }
    }

    #[test]
    fn deploy_uses_server_stored_stable_endpoint_from_template_instance_response() {
        let response =
            template_instance_response_with_stored_endpoint(Some("6.tcp.eu.ngrok.io:17958"));

        assert_eq!(
            stored_stable_endpoint_from_template_instance_response(
                &response,
                Some("tcp://6.TCP.EU.NGROK.IO:17958")
            )
            .unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            stored_stable_endpoint_from_template_instance_response(&response, None).unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );

        let missing = template_instance_response_with_stored_endpoint(None);
        assert!(
            stored_stable_endpoint_from_template_instance_response(
                &missing,
                Some("6.tcp.eu.ngrok.io:17958")
            )
            .unwrap_err()
            .to_string()
            .contains("did not include its stored stable SSH endpoint expectation")
        );

        for endpoint in [
            "6.TCP.EU.NGROK.IO:17958",
            "tcp://6.tcp.eu.ngrok.io:17958",
            "6.tcp.eu.ngrok.io:00123",
            "example.com:22",
        ] {
            let response = template_instance_response_with_stored_endpoint(Some(endpoint));
            assert!(
                stored_stable_endpoint_from_template_instance_response(
                    &response,
                    Some("6.tcp.eu.ngrok.io:17958")
                )
                .unwrap_err()
                .to_string()
                .contains("stored stable SSH endpoint"),
                "{endpoint} must not be accepted as stored endpoint authority"
            );
        }

        let mismatch =
            template_instance_response_with_stored_endpoint(Some("6.tcp.eu.ngrok.io:17959"));
        assert!(
            stored_stable_endpoint_from_template_instance_response(
                &mismatch,
                Some("6.tcp.eu.ngrok.io:17958")
            )
            .unwrap_err()
            .to_string()
            .contains("does not match submitted --stable-ssh-endpoint")
        );
    }

    #[test]
    fn template_deploy_claims_password_template_before_config_delivery() {
        let source = include_str!("template.rs");
        let deploy_start = source.find("async fn deploy").expect("deploy exists");
        let deploy_end = source[deploy_start..]
            .find("async fn ssh_command")
            .expect("ssh_command follows deploy")
            + deploy_start;
        let body = &source[deploy_start..deploy_end];

        let bootstrap_hash = body
            .find("template_bootstrap_pubkey_hash")
            .expect("template deploy derives bootstrap hash");
        let password_preflight = body
            .find("storage_password.ensure_available_for_password_mode")
            .expect("template deploy preflights password input availability");
        let ensure_app = body
            .find("ensure_template_app")
            .expect("template deploy creates app");
        let prepare_log_key = body
            .find("prepare_template_log_key")
            .expect("template deploy prepares tenant log encryption");
        let create_instance = body
            .find("create_template_instance")
            .expect("template deploy creates template instance");
        let wait_claim = body
            .find("wait_for_template_bootstrap_endpoint")
            .expect("template deploy waits for ownership claim endpoint");
        let claim = body
            .find("claim_initial_ownership")
            .expect("template deploy claims ownership");
        let managed_config = body
            .find("deliver_managed_template_config")
            .expect("template deploy asks PaaS to deliver managed config");
        let wait_managed_config = body
            .find("wait_for_paas_managed_config_keys")
            .expect("template deploy waits for PaaS-managed config metadata");
        let config = body
            .find("deliver_template_config_with_retry")
            .expect("template deploy writes customer config");

        assert!(
            password_preflight < bootstrap_hash
                && bootstrap_hash < ensure_app
                && ensure_app < prepare_log_key
                && prepare_log_key < create_instance
                && create_instance < wait_claim
                && wait_claim < claim
                && claim < managed_config
                && managed_config < wait_managed_config
                && wait_managed_config < config,
            "template deploy must prepare tenant log encryption before deployment, then make the config store writable before writing customer config"
        );
    }

    #[test]
    fn template_deploy_verifies_platform_trust_before_remote_mutation() {
        let source = include_str!("template.rs");
        let deploy_start = source.find("async fn deploy").expect("deploy exists");
        let deploy_end = source[deploy_start..]
            .find("async fn ssh_command")
            .expect("ssh_command follows deploy")
            + deploy_start;
        let body = &source[deploy_start..deploy_end];

        let verify_platform = body
            .find("fetch_verified_platform_release(api).await?")
            .expect("template deploy verifies the signed platform release");
        let bootstrap = body
            .find("template_bootstrap_pubkey_hash")
            .expect("template deploy may bootstrap remote keyring state");
        let ensure_app = body
            .find("ensure_template_app")
            .expect("template deploy may create a remote app");

        assert!(
            verify_platform < bootstrap && verify_platform < ensure_app,
            "template deploy must verify platform trust before remote mutation"
        );
    }

    #[test]
    fn template_bootstrap_endpoint_retries_without_redeploying() {
        let body = include_str!("template.rs")
            .split_once("async fn wait_for_template_bootstrap_endpoint")
            .unwrap();
        let body = body
            .1
            .split_once("async fn deliver_template_config_with_retry")
            .unwrap()
            .0;
        let wait_loop = body.find("loop {").unwrap();
        let failure_check = body.find("fail_if_template_deployment_failed").unwrap();
        let endpoint = body.find("get_unlock_endpoint").unwrap();
        let retry = body[endpoint..].find("continue;").unwrap() + endpoint;

        assert!(wait_loop < failure_check && failure_check < endpoint && endpoint < retry);
        assert!(body.contains("should_retry_template_bootstrap_endpoint_error"));
        assert!(body.contains("tokio::time::sleep(poll_interval).await"));
        assert!(!body.contains("create_template_instance"));
        assert!(!body.contains(".deploy("));
    }

    #[test]
    fn template_bootstrap_endpoint_retries_only_transient_api_errors() {
        let api_error = |status, code: Option<&str>| ApiError::Api {
            status,
            code: code.map(str::to_string),
            message: "test error".to_string(),
        };
        let endpoint_retries =
            |status, code| should_retry_template_bootstrap_endpoint_error(&api_error(status, code));
        let status_retries =
            |status| should_retry_template_deployment_status_error(&api_error(status, None));

        assert!(endpoint_retries(409, Some("cap_app_sync_pending")));
        for status in [408, 425, 429, 500, 503] {
            assert!(endpoint_retries(status, None));
        }
        for (status, code) in [
            (401, "cap_app_sync_pending"),
            (403, "cap_app_sync_pending"),
            (500, "cap_app_sync_pending"),
            (401, "unauthenticated"),
            (403, "org_permission_denied"),
            (404, "app_not_found"),
            (409, "hosted_operation_failed_drift"),
            (502, "cap_response_invalid"),
            (501, "not_implemented_hosted"),
        ] {
            assert!(!endpoint_retries(status, Some(code)));
        }
        assert!(!should_retry_template_bootstrap_endpoint_error(
            &ApiError::NotAuthenticated
        ));
        for status in [404, 409, 425] {
            assert!(status_retries(status));
        }
        for status in [400, 401, 403, 422] {
            assert!(!status_retries(status));
        }
    }

    #[tokio::test]
    async fn template_bootstrap_endpoint_rejects_decode_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 8\r\n\r\nnot-json",
                )
                .await
                .unwrap();
        });

        let error = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()))
            .get_unlock_endpoint("shell")
            .await
            .unwrap_err();
        assert!(matches!(&error, ApiError::Http(error) if error.is_decode()));
        assert!(!should_retry_template_bootstrap_endpoint_error(&error));
        assert!(!should_retry_template_deployment_status_error(&error));
    }

    #[test]
    fn ssh_command_endpoint_assertion_must_match_stored_metadata() {
        assert_eq!(
            ssh_command_stable_endpoint(None, "6.tcp.eu.ngrok.io:123").unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );
        assert_eq!(
            ssh_command_stable_endpoint(Some("6.tcp.eu.ngrok.io:123"), "6.tcp.eu.ngrok.io:123")
                .unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );

        let err =
            ssh_command_stable_endpoint(Some("6.tcp.eu.ngrok.io:124"), "6.tcp.eu.ngrok.io:123")
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the PaaS-stored stable SSH endpoint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ssh_command_wait_surfaces_progress_without_polluting_json() {
        let source = include_str!("template.rs");
        let fn_start = source
            .find("async fn ssh_command")
            .expect("ssh_command function exists");
        let fn_end = source[fn_start..]
            .find("fn template_key")
            .expect("template_key follows ssh_command function")
            + fn_start;
        let body = &source[fn_start..fn_end];

        assert!(body.contains("if args.json"));
        assert!(body.contains("ProgressBar::hidden()"));
        assert!(body.contains("ProgressBar::new_spinner()"));
        assert!(body.contains("Waiting for stable SSH endpoint command..."));
        assert!(body.contains("Stable SSH endpoint command ready"));
        assert!(body.contains("Stable SSH endpoint command unavailable"));
    }

    #[test]
    fn ssh_command_endpoint_match_requires_reserved_address() {
        ensure_ssh_command_matches_endpoint(
            "ssh -p 17958 user@6.tcp.eu.ngrok.io",
            "tcp://6.tcp.eu.ngrok.io:17958",
        )
        .unwrap();
        assert!(
            ensure_ssh_command_matches_endpoint(
                "ssh -p 17959 user@6.tcp.eu.ngrok.io",
                "6.tcp.eu.ngrok.io:17958",
            )
            .is_err()
        );
        assert!(
            ensure_ssh_command_matches_endpoint(
                "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "example.com:22",
            )
            .is_err()
        );
    }

    #[test]
    fn app_url_normalizes_domain_and_root_url() {
        assert_eq!(
            app_url_from_app_domain("shell.enclava.dev").unwrap(),
            "https://shell.enclava.dev"
        );
        assert_eq!(
            app_url_from_app_domain("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            app_url_from_app_domain("https://Shell.Enclava.Dev./").unwrap(),
            "https://shell.enclava.dev"
        );
    }

    #[test]
    fn app_url_from_app_response_prefers_cap_app_domain_for_stable_ssh_lookup() {
        let mut app = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:17958"));
        app.domain = "legacy-shell.enclava.dev".to_string();
        app.app_domain = Some("shell.enclava.dev".to_string());

        assert_eq!(
            app_url_from_app_response(&app).unwrap(),
            "https://shell.enclava.dev"
        );

        app.app_domain = None;
        assert_eq!(
            app_url_from_app_response(&app).unwrap(),
            "https://legacy-shell.enclava.dev"
        );
    }

    #[test]
    fn app_url_from_template_response_cap_prefers_app_domain_and_falls_back_to_domain() {
        let both = serde_json::json!({
            "app_domain": "shell.enclava.dev",
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&both).unwrap(),
            "https://shell.enclava.dev"
        );

        let fallback = serde_json::json!({
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&fallback).unwrap(),
            "https://legacy-shell.enclava.dev"
        );

        let blank_app_domain = serde_json::json!({
            "app_domain": " ",
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&blank_app_domain).unwrap(),
            "https://legacy-shell.enclava.dev"
        );

        let missing = serde_json::json!({});
        assert!(
            app_url_from_template_response_cap(&missing)
                .unwrap_err()
                .to_string()
                .contains("app_domain or domain")
        );

        let invalid_domain = serde_json::json!({
            "domain": "https://shell.enclava.dev/path"
        });
        assert!(
            app_url_from_template_response_cap(&invalid_domain)
                .unwrap_err()
                .to_string()
                .contains("invalid domain")
        );
    }

    #[test]
    fn app_url_rejects_invalid_app_domains() {
        for domain in [
            "",
            "ftp://shell.enclava.dev",
            "https://user:pass@shell.enclava.dev",
            "not a host",
            "https://-shell.enclava.dev",
            "https://shell-.example.test",
            "https://shell.example_test.com",
            "https://metadata",
            "https://shell.example.test",
            "https://shell.example",
            "https://shell.invalid",
            "https://shell.example.com",
            "https://999.999.999.999",
            "https://123.456",
            "http://0127.0.0.1:8080/ssh.txt",
            "https://shell.enclava.dev/ssh.txt",
            "https://shell.enclava.dev?ignored=true",
            "https://shell.enclava.dev#frag",
            "http://localhost:8080/path?ignored=true",
        ] {
            assert!(
                app_url_from_app_domain(domain).is_err(),
                "{domain} should be rejected"
            );
        }
        assert_eq!(
            app_url_from_app_domain("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            app_url_from_app_domain("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn ssh_command_parser_requires_nonzero_tcp_port() {
        assert!(valid_ssh_command("ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(valid_ssh_command("ssh -p 20001 user@relay.enclava.me"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.TCP.EU.NGROK.IO."));
        assert!(!valid_ssh_command("ssh -p 20001 user@Relay.Enclava.Me"));
        assert!(!valid_ssh_command("ssh -p 20001 user@relay.enclava.me."));
        assert!(!valid_ssh_command("ssh -p 00123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command(" ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh  -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.tcp.eu.ngrok.io "));
        assert!(!valid_ssh_command("ssh -p nope user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 0 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p +123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 1e2 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 000123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@"));
        assert!(!valid_ssh_command("ssh -p 17958 user@example.com"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.tcp.example.com"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.foo.eu.ngrok.io"));
        assert!(!valid_ssh_command(
            "ssh -p 17958 user@6.tcp.eu.extra.ngrok.io"
        ));
        assert!(!valid_ssh_command(
            "ssh -p 17958 user@6.tcp.eu.ngrok.example"
        ));
    }

    #[test]
    fn paas_ssh_command_poll_retries_only_transient_api_errors() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(should_retry_paas_ssh_command_error(&ApiError::Api {
                status,
                code: None,
                message: "temporary".to_string(),
            }));
        }

        for status in [400, 401, 403, 404, 409, 422] {
            assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
                status,
                code: None,
                message: "permanent".to_string(),
            }));
        }
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("cap_response_invalid".to_string()),
            message: "CAP app response included an invalid app domain".to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_missing".to_string()),
            message: "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation"
                .to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_invalid".to_string()),
            message: "Hosted Debian SSH app has invalid stored stable SSH endpoint expectation"
                .to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn paas_ssh_command_api_errors_are_actionable_for_stable_ssh_contract_failures() {
        let missing = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_missing".to_string()),
            message: "stored endpoint missing".to_string(),
        })
        .unwrap();
        assert!(missing.contains("Stable SSH endpoint metadata is missing"));
        assert!(missing.contains("Redeploy the template"));

        let invalid = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_invalid".to_string()),
            message: "stored endpoint invalid".to_string(),
        })
        .unwrap();
        assert!(invalid.contains("Stable SSH endpoint metadata is invalid"));
        assert!(invalid.contains("Redeploy the template"));

        let cap_invalid = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("cap_response_invalid".to_string()),
            message: "CAP app /ssh.txt returned an invalid stable SSH endpoint command".to_string(),
        })
        .unwrap();
        assert!(cap_invalid.contains(
            "Stable SSH endpoint API rejected malformed, non-canonical, or mismatched workload output"
        ));
        assert!(cap_invalid.contains(
            "Support must fix non-canonical stable SSH endpoint API or workload output at the template boundary"
        ));
        assert!(!cap_invalid.contains(&["Stable SSH", " broker rejected"].join("")));
        assert!(!cap_invalid.contains(&["stable", "endpoint metadata was stored"].join(" ")));

        assert!(
            paas_ssh_command_api_error_message(&ApiError::Api {
                status: 425,
                code: Some("ssh_command_not_available".to_string()),
                message: "pending".to_string(),
            })
            .is_none()
        );
    }

    #[test]
    fn stable_ssh_template_create_errors_are_actionable_for_missing_managed_ngrok_env() {
        let missing = stable_ssh_managed_ngrok_setup_error_message(&ApiError::Api {
            status: 503,
            code: Some("service_unavailable".to_string()),
            message: "service_unavailable: DEBIAN_SSH_NGROK_AUTHTOKEN is not configured"
                .to_string(),
        })
        .unwrap();

        assert!(missing.contains("PaaS is missing its managed ngrok authtoken"));
        assert!(missing.contains("inject DEBIAN_SSH_NGROK_AUTHTOKEN"));
        assert!(missing.contains(
            "Do not pass an ngrok token through the CLI, local text/token file, or release env"
        ));

        assert!(
            stable_ssh_managed_ngrok_setup_error_message(&ApiError::Api {
                status: 502,
                code: Some("cap_write_failed".to_string()),
                message: "CAP write failed".to_string(),
            })
            .is_none()
        );
    }

    #[test]
    fn ssh_command_response_validation_allows_pending_and_validates_ready() {
        let expected_endpoint = "6.tcp.eu.ngrok.io:17958";
        let expected_app_url = "https://shell.enclava.dev";
        let pending = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        validate_ssh_command_response(&pending, expected_endpoint, expected_app_url).unwrap();
        let err = validate_ssh_command_response(&pending, "example.com:22", expected_app_url)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("expected stable SSH endpoint is invalid")
        );
        let err = validate_ssh_command_response(&pending, expected_endpoint, "").unwrap_err();
        assert!(err.to_string().contains("expected app URL is invalid"));

        let noncanonical_api_stable_endpoint = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "tcp://6.TCP.EU.NGROK.IO.:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(
            &noncanonical_api_stable_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("stable_ssh_endpoint"));
        assert!(err.to_string().contains("is not canonical"));

        let mismatched_api_stable_endpoint = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17959".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(
            &mismatched_api_stable_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains(
            "stable_ssh_endpoint 6.tcp.eu.ngrok.io:17959 does not match expected stable SSH endpoint"
        ));

        let pending_with_app_url = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        validate_ssh_command_response(
            &pending_with_app_url,
            expected_endpoint,
            "shell.enclava.dev",
        )
        .unwrap();

        let pending_with_blank_app_url = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some(" ".to_string()),
        };
        let err = validate_ssh_command_response(
            &pending_with_blank_app_url,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url is invalid"));

        let pending_with_command = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &pending_with_command,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains(
            "included ready-only stable SSH endpoint command fields while status was not ready"
        ));

        let unknown = SshCommandResponse {
            status: "degraded".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(&unknown, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("returned unknown status: degraded")
        );

        let ready = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        validate_ssh_command_response(
            &ready,
            "tcp://6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev/",
        )
        .unwrap();

        let noncanonical_command = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.TCP.EU.NGROK.IO.".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_command,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid stable SSH endpoint command")
        );

        let noncanonical_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("tcp://6.TCP.EU.NGROK.IO.:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response endpoint"));
        assert!(err.to_string().contains("is not canonical"));

        let missing_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &missing_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("did not include endpoint for ready stable SSH endpoint command")
        );

        let mismatched_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &mismatched_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );

        let overlong_host_label = "a".repeat(64);
        let overlong_host = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some(format!(
                "ssh -p 17958 user@{overlong_host_label}.tcp.eu.ngrok.io"
            )),
            endpoint: Some(format!("{overlong_host_label}.tcp.eu.ngrok.io:17958")),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&overlong_host, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid stable SSH endpoint command")
        );

        let mismatched = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(&mismatched, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(err.to_string().contains("does not match reserved endpoint"));

        let noncanonical_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://Shell.Enclava.Dev/ssh.txt?ignored=true#frag".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_app_url,
            expected_endpoint,
            "shell.enclava.dev",
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url"));
        assert!(err.to_string().contains("is not canonical"));

        let mismatched_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://wrong.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&mismatched_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("app_url https://wrong.enclava.dev does not match expected app URL")
        );

        let invalid_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("ssh://shell.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&invalid_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(err.to_string().contains("response app_url is invalid"));

        let missing_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: None,
        };
        let err =
            validate_ssh_command_response(&missing_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("did not include app_url for ready stable SSH endpoint command")
        );

        let missing = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(&missing, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(err.to_string().contains("ready without a command"));
    }

    #[tokio::test]
    async fn pending_paas_ssh_command_can_be_confirmed_from_public_app_url() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind direct ssh command fixture");
        let addr = listener.local_addr().expect("direct ssh command addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept direct ssh command request");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = "ssh -p 20051 user@relay.enclava.me\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write direct ssh command response");
        });
        let app_url = format!("http://{addr}");
        let pending = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "relay.enclava.me:20051".to_string(),
            command: None,
            endpoint: None,
            app_url: Some(app_url.clone()),
        };

        let ready = fetch_direct_ssh_command_response(&pending, "relay.enclava.me:20051", &app_url)
            .await
            .expect("direct app URL fallback should not fail")
            .expect("direct app URL should confirm readiness");

        assert_eq!(ready.status, "ready");
        assert_eq!(
            ready.command.as_deref(),
            Some("ssh -p 20051 user@relay.enclava.me")
        );
        assert_eq!(ready.endpoint.as_deref(), Some("relay.enclava.me:20051"));
        assert_eq!(ready.app_url.as_deref(), Some(app_url.as_str()));
    }

    #[test]
    fn deploy_output_surfaces_stable_ssh_details_for_humans() {
        let output = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://shell.enclava.dev",
            deployment_id: "deploy-123",
            stable_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            ssh_command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            ssh_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            log_key_id: Some("shell-logs"),
            log_private_key_file: Some(std::path::Path::new("/tmp/shell-logs.x25519")),
            json: false,
        })
        .unwrap();

        assert!(output.contains("  Template:   debian-ssh-ngrok"));
        assert!(output.contains("  Instance:   shell"));
        assert!(output.contains("  URL:        https://shell.enclava.dev"));
        assert!(output.contains("  Deploy:     deploy-123"));
        assert!(output.contains("  Stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
        assert!(
            output.contains("  Stable SSH endpoint command: ssh -p 17958 user@6.tcp.eu.ngrok.io")
        );
        assert!(output.contains("  Log key:    shell-logs"));
        assert!(output.contains("  Log private key: /tmp/shell-logs.x25519"));
        assert!(!output.contains("Verified stable SSH endpoint"));
    }

    #[test]
    fn deploy_output_json_is_machine_readable() {
        let output = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://shell.enclava.dev",
            deployment_id: "deploy-123",
            stable_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            ssh_command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            ssh_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            log_key_id: Some("shell-logs"),
            log_private_key_file: Some(std::path::Path::new("/tmp/shell-logs.x25519")),
            json: true,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "template": "debian-ssh-ngrok",
                "instance": "shell",
                "app_url": "https://shell.enclava.dev",
                "deployment_id": "deploy-123",
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
                "stable_endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_status": "ready",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_path": "/apps/shell/ssh-command",
                "log_key_id": "shell-logs",
                "log_private_key_file": "/tmp/shell-logs.x25519"
            })
        );
    }

    #[test]
    fn template_deployment_failure_message_includes_api_error_detail() {
        let deployment = DeploymentEntry {
            id: "deploy-123".to_string(),
            status: "failed".to_string(),
            image_digest: None,
            error_message: Some(
                "KBS policy error: signed policy artifact set exceeds byte budget".to_string(),
            ),
            template_slug: Some("debian-ssh-frp".to_string()),
            template_version: Some("2026.07.03".to_string()),
            template_expected: Default::default(),
            created_at: "2026-07-03T15:48:25Z".to_string(),
            completed_at: None,
        };

        assert_eq!(
            template_deployment_failure_message(&deployment, "deploy-123"),
            "deployment deploy-123 failed: KBS policy error: signed policy artifact set exceeds byte budget"
        );
    }

    #[test]
    fn deploy_output_canonicalizes_and_validates_stable_endpoint() {
        let output = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://shell.enclava.dev",
            deployment_id: "deploy-123",
            stable_endpoint: Some("tcp://6.TCP.EU.NGROK.IO.:00123"),
            ssh_command: None,
            ssh_endpoint: None,
            log_key_id: None,
            log_private_key_file: None,
            json: true,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["stable_ssh_endpoint"], "6.tcp.eu.ngrok.io:123");
        assert_eq!(value["stable_endpoint"], "6.tcp.eu.ngrok.io:123");
        assert_eq!(value["ssh_command_status"], "pending");
        assert_eq!(value["endpoint"], serde_json::Value::Null);

        let err = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://shell.enclava.dev",
            deployment_id: "deploy-123",
            stable_endpoint: Some("example.com:22"),
            ssh_command: None,
            ssh_endpoint: None,
            log_key_id: None,
            log_private_key_file: None,
            json: true,
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("stable SSH endpoint output is invalid")
        );
    }

    #[test]
    fn deploy_output_normalizes_app_url_for_stable_ssh_handoff() {
        let human = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://Shell.Enclava.Dev./",
            deployment_id: "deploy-123",
            stable_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            ssh_command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            ssh_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            log_key_id: None,
            log_private_key_file: None,
            json: false,
        })
        .unwrap();
        assert!(human.contains("  URL:        https://shell.enclava.dev"));
        assert!(!human.contains("Shell.Enclava.Dev"));
        assert!(!human.contains("/ssh.txt"));

        let json = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://Shell.Enclava.Dev./",
            deployment_id: "deploy-123",
            stable_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            ssh_command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            ssh_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            log_key_id: None,
            log_private_key_file: None,
            json: true,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["app_url"], "https://shell.enclava.dev");
    }

    #[test]
    fn deploy_output_rejects_mismatched_endpoint_api_endpoint() {
        let err = deploy_response_output(DeployResponseOutput {
            template_slug: "debian-ssh-ngrok",
            instance_name: "shell",
            app_url: "https://shell.enclava.dev",
            deployment_id: "deploy-123",
            stable_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            ssh_command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io"),
            ssh_endpoint: Some("6.tcp.eu.ngrok.io:17958"),
            log_key_id: None,
            log_private_key_file: None,
            json: false,
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );
    }

    #[test]
    fn ssh_command_output_surfaces_endpoint_for_humans() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let output = ssh_command_response_output(
            "shell",
            &response,
            "tcp://6.TCP.EU.NGROK.IO.:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap();

        assert!(output.contains("  Status:     ready"));
        assert!(output.contains("  URL:        https://shell.enclava.dev"));
        assert!(output.contains("  Stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
        assert!(
            output.contains("  Stable SSH endpoint command: ssh -p 17958 user@6.tcp.eu.ngrok.io")
        );
        assert!(!output.contains("Verified stable SSH endpoint"));
    }

    #[test]
    fn cli_stable_ssh_human_copy_is_endpoint_first() {
        let template_source = include_str!("template.rs");
        let app_source = include_str!("app.rs");
        let stale_summary = ["Stable SSH", ":"].join("");

        assert!(
            !template_source.contains(&stale_summary),
            "template CLI output should spell out Stable SSH endpoint"
        );
        assert!(
            !app_source.contains(&stale_summary),
            "app CLI output should spell out Stable SSH endpoint"
        );
        assert!(template_source.contains("Stable SSH endpoint: {hint}"));
        assert!(template_source.contains("Stable SSH endpoint: {endpoint}"));
        assert!(template_source.contains("Stable SSH endpoint command: {command}"));
        let stale_command_label = ["  Com", "mand:    "].concat();
        assert!(!template_source.contains(&stale_command_label));
        assert!(app_source.contains("Stable SSH endpoint: {endpoint}"));
        assert!(
            app_source.contains(
                "Stable SSH endpoint metadata missing; redeploy the template so PaaS reserves a stable SSH endpoint"
            )
        );
        assert!(
            app_source.contains(
                "Stable SSH endpoint metadata invalid; redeploy the template so PaaS reserves a stable SSH endpoint"
            )
        );
    }

    #[test]
    fn ssh_command_output_json_is_machine_readable() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let output = ssh_command_response_output(
            "shell",
            &response,
            "tcp://6.TCP.EU.NGROK.IO.:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "app_name": "shell",
                "status": "ready",
                "app_url": "https://shell.enclava.dev",
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
                "stable_endpoint": "6.tcp.eu.ngrok.io:17958",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958"
            })
        );
    }

    #[test]
    fn ssh_command_output_rejects_noncanonical_app_url() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://Shell.Enclava.Dev./ssh.txt?ignored=true#frag".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url"));
        assert!(err.to_string().contains("is not canonical"));
    }

    #[test]
    fn ssh_command_output_rejects_mismatched_endpoint_api_app_url() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://wrong.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("app_url https://wrong.enclava.dev does not match expected app URL")
        );
    }

    #[test]
    fn ssh_command_output_rejects_mismatched_endpoint_api_endpoint() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );
    }

    #[test]
    fn ssh_command_output_rejects_reserved_endpoint_mismatch() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not match reserved endpoint"));
    }

    #[test]
    fn template_input_summary_surfaces_stable_ssh_endpoint() {
        let mut template = hosted_template_with_stable_ssh();
        template.config_keys.push(HostedTemplateConfigKey {
            key: "NGROK_AUTHTOKEN".to_string(),
            label: "ngrok auth token".to_string(),
            description: "Malformed registry response that exposes a managed key.".to_string(),
            input_type: "password".to_string(),
            required: true,
            secret: true,
            default_value: None,
            validation: Some(HostedTemplateConfigValidation {
                format: Some("single_token".to_string()),
                example: None,
                max_bytes: Some(4096),
                max_items: None,
                allowed_algorithms: vec![],
            }),
        });

        assert_eq!(
            template_required_inputs(&template).as_deref(),
            Some("SSH public keys")
        );
        assert_eq!(
            template_optional_inputs(&template).as_deref(),
            Some("Stable SSH endpoint (auto-reserved; optional --stable-ssh-endpoint)")
        );
        assert_eq!(
            template_paas_managed_config_summary(&template).as_deref(),
            Some(
                "NGROK_AUTHTOKEN (PaaS-owned; sourced from PaaS deployment env DEBIAN_SSH_NGROK_AUTHTOKEN)"
            )
        );
        assert_eq!(
            stable_ssh_endpoint_hint(&template).as_deref(),
            Some(
                "PaaS reserves one automatically; pass --stable-ssh-endpoint 6.tcp.eu.ngrok.io:17958 only to import an existing reserved endpoint"
            )
        );
    }

    #[test]
    fn debian_ssh_config_pairs_only_write_customer_owned_keys() {
        let pairs = debian_ssh_config_pairs("ssh-ed25519 AAAA".to_string());

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "DEBIAN_SSH_AUTHORIZED_KEYS");
    }

    #[test]
    fn stable_ssh_template_config_delivery_retries_only_transient_failures() {
        assert!(should_refresh_template_config_token(&TeeError::Tee {
            status: 401,
            message: "expired token".to_string(),
        }));
        assert!(!should_retry_template_config_tee_error(&TeeError::Tee {
            status: 401,
            message: "expired token".to_string(),
        }));
        for status in [408, 409, 423, 425, 429, 500, 503] {
            assert!(should_retry_template_config_tee_error(&TeeError::Tee {
                status,
                message: "transient".to_string(),
            }));
        }
        for status in [408, 409, 425, 429, 500, 503] {
            assert!(should_retry_template_config_sync_error(&ApiError::Api {
                status,
                code: Some("transient".to_string()),
                message: "transient".to_string(),
            }));
        }
        assert!(
            should_retry_template_config_sync_error(&ApiError::Api {
                status: 503,
                code: None,
                message: "proxy unavailable while refreshing config token".to_string(),
            }),
            "config token refresh uses the same transient PaaS retry classifier"
        );
        for message in [
            "TEE TCP connect failed: failed to lookup address information: Name or service not known",
            "TEE TLS handshake failed: tls handshake eof",
            "TEE did not present a certificate",
            "TEE certificate chain is empty",
        ] {
            assert!(should_retry_template_config_tee_error(
                &TeeError::Attestation(message.to_string())
            ));
        }
        for message in [
            "TEE URL must be https",
            "TEE host is not a valid DNS name",
            "certificate parse failed: bad certificate",
            "SNP report validation failed",
        ] {
            assert!(!should_retry_template_config_tee_error(
                &TeeError::Attestation(message.to_string())
            ));
        }
        for status in [400, 403, 404, 422] {
            assert!(!should_retry_template_config_tee_error(&TeeError::Tee {
                status,
                message: "permanent".to_string(),
            }));
            assert!(!should_retry_template_config_sync_error(&ApiError::Api {
                status,
                code: Some("permanent".to_string()),
                message: "permanent".to_string(),
            }));
        }
        assert!(!should_retry_template_config_sync_error(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn template_config_delivery_retry_budget_covers_live_rollout_delay() {
        let generated_readiness_delay_with_jitter = Duration::from_secs(240);
        let retry_budget = Duration::from_secs(
            TEMPLATE_CONFIG_DELIVERY_ATTEMPTS.saturating_sub(1) as u64
                * TEMPLATE_CONFIG_DELIVERY_RETRY_SECONDS,
        );

        assert!(
            retry_budget >= generated_readiness_delay_with_jitter,
            "template config delivery must cover the 180s generated readiness delay plus rollout jitter"
        );
    }

    #[test]
    fn config_token_refresh_honors_replacement_tee_url() {
        let current = "https://old.enclava.dev/.well-known/confidential/config";
        let refreshed = ConfigTokenResponse {
            token: "next-token".to_string(),
            tee_url: Some("https://NEW.Enclava.Dev./.well-known/confidential".to_string()),
            tee_resolve_ip: Some("95.217.56.248".parse().unwrap()),
            expires_at: None,
            expires_in_seconds: None,
        };

        assert_eq!(
            refreshed_template_config_endpoint_url(&refreshed, current).unwrap(),
            "https://new.enclava.dev/.well-known/confidential/config"
        );

        let without_tee_url = ConfigTokenResponse {
            token: "next-token".to_string(),
            tee_url: None,
            tee_resolve_ip: None,
            expires_at: None,
            expires_in_seconds: None,
        };
        assert_eq!(
            refreshed_template_config_endpoint_url(&without_tee_url, current).unwrap(),
            current
        );
    }

    #[test]
    fn ssh_public_key_validation_requires_public_key_blob() {
        validate_ssh_public_keys(VALID_ED25519_PUBLIC_KEY, None).unwrap();

        let err = validate_ssh_public_keys("ssh-ed25519 cmFuZG9tLWJhc2U2NA==", None).unwrap_err();

        assert!(err.to_string().contains("malformed SSH public key"));
    }
}
