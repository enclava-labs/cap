use clap::Args;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::IsTerminal,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::commands::ownership::MnemonicCapture;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use clap::Subcommand;
use enclava_cli::api_client::{ApiClient, ApiError};
use enclava_cli::api_types::*;
use enclava_cli::app_config::{AppConfig, AppConfigError};
use enclava_cli::config::{self, CliPaths};
use enclava_cli::descriptor::{
    CapAppOciRuntimeSpecInput, DeploymentDescriptorBuildInput, Sidecars, SignerIdentity,
    build_descriptor, cap_app_oci_runtime_spec,
};
use enclava_cli::keyring::{
    OrgKeyringEnvelope, Role, keyring_fingerprint, load_keyring_envelope, load_trusted_owner,
    member_allows_deploy, sign_keyring, single_member_keyring, store_keyring_envelope,
    store_trusted_owner, verify_keyring,
};
use enclava_cli::keys;
use enclava_cli::platform_release::{PlatformRelease, PlatformReleaseEnvelope, verify_envelope};
use enclava_cli::tee_client::TeeClient;
use enclava_common::log_encryption::{
    EncryptedLogFrame, LOG_ENCRYPTION_ALGORITHM, decrypt_log_frame, generate_log_keypair,
    log_keypair_from_private_key,
};
use enclava_common::types::{ResourceLimits, UnlockMode};
use enclava_engine::manifest::cc_init_data;
use enclava_engine::types::{
    AttestationConfig, ConfidentialApp, Container, DomainSpec, GeneratedAgentPolicy,
    LogEncryptionConfig, StorageSpec, WorkloadArtifactBinding, WorkloadSecurityProfile,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::commands::template::normalize_ngrok_tcp_url;

const DEPLOY_HEALTH_TIMEOUT_SECONDS: u64 = 900;

/// Resolve app name from --app flag or enclava.toml.
fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

/// Like `resolve_app_name`, but returns `Ok(None)` when neither `--app` nor an
/// `enclava.toml` is present, so org-level `list`/`revoke` can fall back to the
/// org-scoped endpoints. `select`/`generate` keep using `resolve_app_name`.
fn resolve_optional_app_name(
    explicit: &Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(Some(name.clone()));
    }
    Ok(optional_app_name_from_config_result(
        AppConfig::find_and_load(),
    )?)
}

fn optional_app_name_from_config_result(
    result: Result<AppConfig, AppConfigError>,
) -> Result<Option<String>, AppConfigError> {
    match result {
        Ok(config) => Ok(Some(config.app.name)),
        Err(AppConfigError::ReadFile { path, source })
            if source.kind() == std::io::ErrorKind::NotFound
                && Path::new(&path).file_name().and_then(|name| name.to_str())
                    == Some("enclava.toml") =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
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

fn parse_config_inputs(
    vars: &[String],
    file_vars: &[String],
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut pairs = parse_config_vars(vars)?;
    for entry in file_vars {
        let (key, path) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid config file format '{entry}': expected KEY=PATH"))?;
        let value = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read config file for {key} at {path}: {err}"))?;
        pairs.push((
            key.to_string(),
            value.trim_end_matches(['\r', '\n']).to_string(),
        ));
    }
    Ok(pairs)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoragePasswordInput {
    value: Option<String>,
}

impl StoragePasswordInput {
    pub(crate) fn from_file_option(
        path: Option<&PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match path {
            Some(path) => Ok(Self {
                value: Some(read_storage_password_file(path)?),
            }),
            None => Ok(Self { value: None }),
        }
    }

    pub(crate) fn ensure_available_for_password_mode(
        &self,
        action: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.value.is_some() || storage_password_prompt_available() {
            return Ok(());
        }
        Err(format!(
            "{action} requires an interactive terminal or --storage-password-file <PATH> before changing remote resources"
        )
        .into())
    }

    fn initial_claim_password(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.value {
            Some(value) => Ok(value.clone()),
            None => Ok(dialoguer::Password::new()
                .with_prompt("Set initial storage password")
                .with_confirmation("Confirm initial storage password", "Passwords don't match")
                .interact()?),
        }
    }

    fn unlock_password(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.value {
            Some(value) => Ok(value.clone()),
            None => Ok(dialoguer::Password::new()
                .with_prompt("Unlock password")
                .interact()?),
        }
    }
}

fn read_storage_password_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::fs::read_to_string(path)
        .map_err(|err| {
            format!(
                "failed to read storage password file {}: {err}",
                path.display()
            )
        })?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if value.is_empty() {
        Err(format!("storage password file {} is empty", path.display()).into())
    } else {
        Ok(value)
    }
}

fn storage_password_prompt_available() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn deploy_should_unlock_before_config(
    is_password_mode: bool,
    needs_initial_claim: bool,
    _has_config_pairs: bool,
) -> bool {
    is_password_mode && !needs_initial_claim
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeployRuntimeTarget {
    AnyReady,
    PasswordLocked,
}

impl DeployRuntimeTarget {
    fn accepts_api_status(self, status: &str) -> bool {
        match self {
            Self::AnyReady => matches!(status, "running" | "locked"),
            Self::PasswordLocked => status == "locked",
        }
    }

    fn accepts_running_pod_phase(self) -> bool {
        matches!(self, Self::AnyReady)
    }

    fn accepts_direct_unlocked(self) -> bool {
        matches!(self, Self::AnyReady)
    }
}

fn deploy_needs_initial_claim(
    is_password_mode: bool,
    ownership_state: Option<&str>,
    app_status: &str,
) -> bool {
    if !is_password_mode {
        return false;
    }
    match ownership_state {
        Some("unclaimed") => true,
        Some(_) => false,
        None => app_status == "creating",
    }
}

mod signing;
#[cfg(test)]
pub(crate) use signing::{ConfidentialAppForCcHash, confidential_app_for_cc_hash};
pub(crate) use signing::{
    SignedDeployBlobParams, build_signed_deploy_blobs, ensure_manual_deploy_keyring,
    load_or_derive_bootstrap_private_key, resolve_current_user_org,
};

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
    let (api, paths, _cli_config) = build_api_client()?;

    let bootstrap_key = if app_config.unlock.mode == "password" {
        let (org_id, org, _) = ensure_manual_deploy_keyring(&api, &paths).await?;
        let seed = keys::load_or_create_recovery_seed(&paths)?;
        let app_seed = keys::derive_app_bootstrap_seed(org_id, &app_config.app.name, &seed)?;
        let signing_key = SigningKey::from_bytes(&app_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_hash = hex::encode(Sha256::digest(public_key));
        Some((org, hex::encode(app_seed), public_key_hash))
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
        egress_allowlist: vec![],
        egress_mode: None,
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
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
    /// Set config key from a local file without exposing the value in process arguments.
    #[arg(long = "set-file", value_name = "KEY=PATH")]
    pub config_file_vars: Vec<String>,
    /// File containing the storage password for non-interactive password-mode deploys.
    #[arg(long = "storage-password-file", value_name = "PATH")]
    pub storage_password_file: Option<PathBuf>,
    /// Persist the recovery mnemonic so `enclava key backup` can back it up (default).
    #[arg(long, conflicts_with = "no_store_mnemonic")]
    pub store_mnemonic: bool,
    /// Do NOT persist the recovery mnemonic (shown once only; opt out of backup coverage).
    #[arg(long, conflicts_with = "store_mnemonic")]
    pub no_store_mnemonic: bool,
}

pub async fn deploy(args: DeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_config = match AppConfig::find_and_load() {
        Ok(config) => config,
        Err(_) => {
            return Err("no enclava.toml found -- run `enclava init` or specify --app".into());
        }
    };
    let app_name = app_config.app.name.clone();

    let config_pairs = parse_config_inputs(&args.config_vars, &args.config_file_vars)?;
    let (api, paths, cli_config) = build_api_client()?;
    let creds = config::load_credentials(&paths)?;
    let app = api.get_app(&app_name).await?;
    let is_password_mode = app.unlock_mode == "password";
    let storage_password =
        StoragePasswordInput::from_file_option(args.storage_password_file.as_ref())?;
    if is_password_mode {
        storage_password.ensure_available_for_password_mode("password-mode deploy")?;
    }
    let capture = if args.no_store_mnemonic {
        MnemonicCapture::Skip
    } else {
        MnemonicCapture::Store
    };
    let signed_blobs = build_signed_deploy_blobs(SignedDeployBlobParams {
        api: &api,
        paths: &paths,
        cli_config: &cli_config,
        creds: &creds,
        app: &app,
        app_config: &app_config,
        image: &args.image,
        target_unlock_mode: None,
        workload_security_profile: WorkloadSecurityProfile::Restricted,
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
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")?
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
    wait_for_deployment_apply_start(
        &api,
        &app_name,
        &resp.deployment_id,
        max_wait,
        poll_interval,
        &pb,
    )
    .await?;

    // Phase 3: First ownership claim for password-mode apps.
    //
    // On first boot the app container is intentionally unhealthy until the
    // owner claims storage, so waiting for app-level readiness deadlocks.
    // Instead, wait for the TEE bootstrap endpoint and claim directly.
    let ownership_state = api
        .get_unlock_status(&app_name)
        .await
        .ok()
        .and_then(|status| status.ownership_state);
    let needs_initial_claim =
        deploy_needs_initial_claim(is_password_mode, ownership_state.as_deref(), &app.status);

    if needs_initial_claim {
        pb.set_position(3);
        pb.set_message("Waiting for ownership claim endpoint...");
        if wait_for_bootstrap_endpoint(&api, &app_name, max_wait, poll_interval, &pb).await? {
            claim_initial_ownership(
                &api,
                &paths,
                &cli_config,
                &app_name,
                &storage_password,
                capture,
            )
            .await?;
            pb.set_message("Ownership claimed");
        } else {
            let runtime_target = if deploy_should_unlock_before_config(
                is_password_mode,
                false,
                !config_pairs.is_empty(),
            ) {
                DeployRuntimeTarget::PasswordLocked
            } else {
                DeployRuntimeTarget::AnyReady
            };
            wait_for_deploy_runtime(
                &api,
                &app_name,
                &resp.deployment_id,
                max_wait,
                poll_interval,
                &pb,
                runtime_target,
            )
            .await?;
            if deploy_should_unlock_before_config(is_password_mode, false, !config_pairs.is_empty())
            {
                ensure_password_storage_unlocked_for_config(
                    &api,
                    &app_name,
                    &pb,
                    &storage_password,
                )
                .await?;
            }
        }
    } else {
        let runtime_target = if deploy_should_unlock_before_config(
            is_password_mode,
            false,
            !config_pairs.is_empty(),
        ) {
            DeployRuntimeTarget::PasswordLocked
        } else {
            DeployRuntimeTarget::AnyReady
        };
        wait_for_deploy_runtime(
            &api,
            &app_name,
            &resp.deployment_id,
            max_wait,
            poll_interval,
            &pb,
            runtime_target,
        )
        .await?;
        if deploy_should_unlock_before_config(is_password_mode, false, !config_pairs.is_empty()) {
            ensure_password_storage_unlocked_for_config(&api, &app_name, &pb, &storage_password)
                .await?;
        }
    }

    // Phase 4: Push config if --set was used
    if !config_pairs.is_empty() {
        pb.set_position(4);
        pb.set_message(format!("Setting {} config values...", config_pairs.len()));

        // Get config token from API
        let token_resp = api.get_config_token(&app_name).await?;
        let tee = token_resp
            .tee_url
            .as_deref()
            .map(|tee_url| {
                TeeClient::from_config_url_with_resolve_ip(tee_url, token_resp.tee_resolve_ip)
            })
            .unwrap_or_else(|| {
                TeeClient::new_with_resolve_ip(&resp.app_domain, token_resp.tee_resolve_ip)
            });
        let (_attestation, tee) = tee.attest_receipt_key().await?;

        for (key, value) in &config_pairs {
            tee.config_set(key, value, &token_resp.token).await?;
            api.sync_config_key(&app_name, key, false).await?;
        }
    }

    // Phase 4: Health check
    pb.set_position(5);
    pb.set_message("Waiting for health check...");

    let health_timeout = Duration::from_secs(DEPLOY_HEALTH_TIMEOUT_SECONDS);
    wait_for_deployment_completion(
        &api,
        &app_name,
        &resp.deployment_id,
        health_timeout,
        Duration::from_secs(2),
        &pb,
    )
    .await?;
    pb.finish_with_message("Deployed and healthy");

    println!();
    println!("  App:    {app_name}");
    println!("  URL:    https://{}", resp.app_domain);
    println!("  Deploy: {}", resp.deployment_id);
    if !config_pairs.is_empty() {
        println!("  Config: {} key(s) set", config_pairs.len());
    }

    Ok(())
}

pub(crate) async fn wait_for_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_for_ownership_probe_with_resolve_ip(
        &endpoint.tee_url,
        endpoint.tee_resolve_ip,
    );
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for ownership claim endpoint");
            return Err("deploy timed out waiting for TEE ownership claim endpoint".into());
        }

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

async fn wait_for_deploy_runtime(
    api: &ApiClient,
    app_name: &str,
    expected_deployment_id: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
    target: DeployRuntimeTarget,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let direct_tee = api
        .get_unlock_endpoint(app_name)
        .await
        .ok()
        .map(|endpoint| {
            TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip)
        });

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for TEE boot");
            return Err("deploy timed out waiting for TEE to boot".into());
        }

        let direct_tee_allowed = match api.get_status(app_name).await {
            Ok(status) => {
                let observation_is_fresh = observation_is_fresh_for_deployment(
                    status.observation.as_ref(),
                    expected_deployment_id,
                );
                let direct_tee_allowed = status.status != "failed"
                    && observation_allows_direct_tee_fallback(
                        status.observation.as_ref(),
                        expected_deployment_id,
                    );
                if observation_is_fresh && target.accepts_api_status(status.status.as_str()) {
                    pb.set_position(3);
                    pb.set_message(match status.status.as_str() {
                        "locked" => "TEE running, storage locked",
                        _ => "TEE running, attestation complete",
                    });
                    return Ok(());
                }

                let pod_phase_is_verified = observation_is_fresh && status.status != "failed";
                match status.pod_phase.as_deref() {
                    Some("Running")
                        if pod_phase_is_verified && target.accepts_running_pod_phase() =>
                    {
                        pb.set_position(3);
                        pb.set_message("TEE running, attestation complete");
                        return Ok(());
                    }
                    Some(phase) => {
                        pb.set_message(format!("Pod: {phase}"));
                    }
                    None => {}
                }
                direct_tee_allowed
            }
            Err(_) => {
                // Status endpoint may not be ready yet.
                false
            }
        };

        if direct_tee_allowed
            && let Some(tee) = direct_tee.as_ref()
            && let Ok((_attestation, attested_tee)) = tee.attest_receipt_key().await
            && let Ok(status) = attested_tee.status_json().await
        {
            match tee_unlock_state(&status) {
                "locked" => {
                    pb.set_position(3);
                    pb.set_message("TEE running, storage locked");
                    return Ok(());
                }
                "unlocked" if target.accepts_direct_unlocked() => {
                    pb.set_position(3);
                    pb.set_message("TEE running, attestation complete");
                    return Ok(());
                }
                "unlocked" => {
                    pb.set_message("Waiting for replacement TEE lock...");
                }
                _ => {}
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn observation_is_fresh_for_deployment(
    observation: Option<&AppStatusObservation>,
    expected_deployment_id: &str,
) -> bool {
    observation.is_none_or(|observation| {
        observation.state == "fresh"
            && !observation.drifted
            && observation.deployment_id.as_deref() == Some(expected_deployment_id)
    })
}

fn observation_allows_direct_tee_fallback(
    observation: Option<&AppStatusObservation>,
    expected_deployment_id: &str,
) -> bool {
    observation.is_none_or(|observation| {
        matches!(observation.state.as_str(), "fresh" | "partial")
            && !observation.drifted
            && observation.deployment_id.as_deref() == Some(expected_deployment_id)
    })
}

async fn find_deployment_entry(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
) -> Result<Option<DeploymentEntry>, ApiError> {
    Ok(api
        .list_deployments(app_name)
        .await?
        .into_iter()
        .find(|deployment| deployment.id == deployment_id))
}

async fn wait_for_deployment_apply_start(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for deployment apply");
            return Err(format!("deployment {deployment_id} did not start applying").into());
        }

        match find_deployment_entry(api, app_name, deployment_id).await {
            Ok(Some(deployment)) => match deployment.status.as_str() {
                "pending" => pb.set_message("Waiting for deployment apply..."),
                "failed" => {
                    let detail = deployment
                        .error_message
                        .as_deref()
                        .unwrap_or("deployment failed before apply");
                    return Err(format!("deployment {deployment_id} failed: {detail}").into());
                }
                _ => return Ok(()),
            },
            Ok(None) => pb.set_message("Waiting for deployment record..."),
            Err(_) => pb.set_message("Waiting for deployment status..."),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_deployment_completion(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for deployment health");
            return Err(format!("deployment {deployment_id} timed out waiting for health").into());
        }

        match find_deployment_entry(api, app_name, deployment_id).await {
            Ok(Some(deployment)) => match deployment.status.as_str() {
                "healthy" => return Ok(()),
                "failed" => {
                    let detail = deployment
                        .error_message
                        .as_deref()
                        .unwrap_or("deployment failed");
                    return Err(format!("deployment {deployment_id} failed: {detail}").into());
                }
                "pending" | "applying" | "watching" => {
                    pb.set_message(format!("Deployment: {}", deployment.status));
                }
                other => {
                    pb.set_message(format!("Deployment: {other}"));
                }
            },
            Ok(None) => pb.set_message("Waiting for deployment record..."),
            Err(_) => pb.set_message("Waiting for deployment status..."),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn ensure_password_storage_unlocked_for_config(
    api: &ApiClient,
    app_name: &str,
    pb: &ProgressBar,
    storage_password: &StoragePasswordInput,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;
    let status = tee.status_json().await?;
    let state = tee_unlock_state(&status);

    match state {
        "unlocked" => Ok(()),
        "locked" => {
            pb.set_message("Unlocking storage before config delivery...");
            let password = storage_password.unlock_password()?;
            tee.unlock(&password).await?;
            wait_for_deploy_unlock_completion(&tee).await?;
            Ok(())
        }
        "unclaimed" => {
            Err("storage ownership is unclaimed; claim ownership before setting config".into())
        }
        "error" => {
            let detail = status
                .get("error")
                .and_then(|value| value.as_str())
                .unwrap_or("storage unlock failed");
            Err(detail.to_string().into())
        }
        _ => Ok(()),
    }
}

fn tee_unlock_state(status: &serde_json::Value) -> &str {
    status
        .get("state")
        .or_else(|| status.get("unlock_state"))
        .or_else(|| status.get("ownership_state"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
}

async fn wait_for_deploy_unlock_completion(
    tee: &TeeClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let status = tee.status_json().await?;
        match tee_unlock_state(&status) {
            "unlocked" => return Ok(()),
            "error" => {
                let detail = status
                    .get("error")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unlock failed");
                return Err(detail.to_string().into());
            }
            "locked" => {
                let detail = status
                    .get("error")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unlock did not complete");
                return Err(detail.to_string().into());
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for unlock completion".into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub(crate) async fn claim_initial_ownership(
    api: &ApiClient,
    paths: &CliPaths,
    _cli_config: &config::CliConfig,
    app_name: &str,
    storage_password: &StoragePasswordInput,
    capture: MnemonicCapture,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let challenge = tee.bootstrap_challenge().await?;

    let active = resolve_current_user_org(api).await?;
    let private_key_bytes =
        load_or_derive_bootstrap_private_key(paths, &active.org_name, active.org_id, app_name)?
            .ok_or("bootstrap key is missing and no recovery seed is available; run `enclava key restore <backup>`")?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge.nonce.as_bytes())
        .map_err(|e| format!("invalid bootstrap challenge encoding: {e}"))?;
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&challenge_bytes).to_bytes());
    let bootstrap_pubkey = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let password = storage_password.initial_claim_password()?;

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
        crate::commands::ownership::present_and_capture_recovery_mnemonic_or_warn(
            paths,
            &active.org_name,
            app_name,
            &mnemonic,
            capture,
            crate::commands::ownership::RecoveryMnemonicOutput::Stderr,
        );
    }

    Ok(())
}

#[derive(Args)]
pub struct StatusArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

fn status_with_attested_tee_state(api_status: &str, tee_state: &str) -> String {
    match tee_state {
        "locked" if api_status == "running" => "locked".to_string(),
        "unlocked" if api_status == "running" => api_status.to_string(),
        "unclaimed" if api_status == "failed" => "creating".to_string(),
        _ => api_status.to_string(),
    }
}

pub async fn status(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let mut status = api.get_status(&app_name).await?;
    let app_metadata = api.get_app(&app_name).await.ok();
    let stable_ssh_endpoint = app_metadata
        .as_ref()
        .map(stable_ssh_endpoint_state_from_app)
        .unwrap_or(StableSshEndpointState::NotStableTemplate);
    if let Ok(endpoint) = api.get_unlock_endpoint(&app_name).await {
        let tee = TeeClient::new_for_ownership_with_resolve_ip(
            &endpoint.tee_url,
            endpoint.tee_resolve_ip,
        );
        if let Ok((_attestation, attested_tee)) = tee.attest_receipt_key().await
            && let Ok(tee_status_json) = attested_tee.status_json().await
        {
            let state = tee_unlock_state(&tee_status_json);
            status.status = status_with_attested_tee_state(&status.status, state);
            if status.tee_status.is_none() {
                status.tee_status = Some(state.to_string());
            }
            if status.unlock_status.is_none() {
                status.unlock_status = Some(state.to_string());
            }
            if status.pod_phase.is_none() {
                status.pod_phase = tee_status_json
                    .get("pod_status")
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
            }
        }
    }

    let status_colored = match status.status.as_str() {
        "running" | "ready" | "healthy" => status.status.green().to_string(),
        "creating" | "deploying" | "applying" | "pending" => status.status.yellow().to_string(),
        "failed" | "stopped" => status.status.red().to_string(),
        _ => status.status.clone(),
    };

    println!("App:      {}", status.app_name);
    println!("Status:   {status_colored}");
    println!("Domain:   https://{}", status.domain);
    match stable_ssh_endpoint {
        StableSshEndpointState::Ready(endpoint) => {
            println!("Stable SSH endpoint: {endpoint}");
            println!("Validate:  enclava template ssh-command --name {app_name} --wait");
        }
        StableSshEndpointState::Missing => {
            println!(
                "Stable SSH endpoint metadata missing; redeploy the template so PaaS reserves a stable SSH endpoint"
            );
        }
        StableSshEndpointState::Invalid => {
            println!(
                "Stable SSH endpoint metadata invalid; redeploy the template so PaaS reserves a stable SSH endpoint"
            );
        }
        StableSshEndpointState::NotStableTemplate => {}
    }
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
    if let Some(observation) = &status.observation {
        println!("Freshness: {}", observation.state);
        if observation.drifted {
            println!("Drift:    deployment identity mismatch");
        }
        if let Some(observed_at) = &observation.observed_at {
            println!("Observed: {observed_at}");
        }
        if let Some(reason) = &observation.reason {
            println!("Evidence: {reason}");
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum StableSshEndpointState {
    NotStableTemplate,
    Ready(String),
    Missing,
    Invalid,
}

fn stable_ssh_endpoint_state_from_app(app: &AppResponse) -> StableSshEndpointState {
    if app.template_slug.as_deref() != Some("debian-ssh-ngrok") {
        return StableSshEndpointState::NotStableTemplate;
    }
    let Some(endpoint) = app.template_expected.stable_ssh_endpoint.as_deref() else {
        return StableSshEndpointState::Missing;
    };
    if endpoint.trim().is_empty() {
        return StableSshEndpointState::Missing;
    }
    match normalize_ngrok_tcp_url(endpoint) {
        Ok(normalized) if endpoint == normalized => StableSshEndpointState::Ready(normalized),
        _ => StableSshEndpointState::Invalid,
    }
}

#[derive(Args)]
pub struct LogsArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,
    /// Tenant-held X25519 private log key file created by `enclava log-key generate`
    #[arg(long = "log-private-key-file")]
    pub log_private_key_file: Option<PathBuf>,
}

pub async fn logs(args: LogsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let resp = match api.get_logs(&app_name, args.follow).await {
        Ok(resp) => resp,
        Err(ApiError::Api {
            status: 501,
            message,
            ..
        }) => {
            println!("{message}");
            return Ok(());
        }
        Err(ApiError::Api {
            status: 403,
            code: Some(code),
            message,
        }) if code == "missing_scope" && message.contains("apps:logs") => {
            return Err(format!(
                "{message}\nRun `enclava login --approve-logs` and approve the new session to read workload logs."
            )
            .into());
        }
        Err(err) => return Err(err.into()),
    };

    if !response_is_encrypted_logs(&resp) {
        return Err(
            "log response was not encrypted; refusing to print plaintext workload logs".into(),
        );
    }
    let private_key = load_log_private_key(args.log_private_key_file.as_ref())?;

    if args.follow {
        // Stream logs line by line
        use tokio::io::AsyncBufReadExt;
        let stream = resp.bytes_stream();
        let reader = tokio_util::io::StreamReader::new(
            stream.map(|result| result.map_err(std::io::Error::other)),
        );
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            print_decrypted_log_frame(&private_key, &line)?;
        }
    } else {
        let body = resp.text().await?;
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            print_decrypted_log_frame(&private_key, line)?;
        }
    }

    Ok(())
}

fn response_is_encrypted_logs(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get("x-enclava-log-format")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("encrypted-jsonl"))
}

fn load_log_private_key(path: Option<&PathBuf>) -> Result<String, Box<dyn std::error::Error>> {
    let value = match path {
        Some(path) => std::fs::read_to_string(path).map_err(|err| {
            format!(
                "failed to read log private key file {}: {err}",
                path.display()
            )
        })?,
        None => std::env::var("ENCLAVA_LOG_PRIVATE_KEY_BASE64URL")
            .map_err(|_| "set ENCLAVA_LOG_PRIVATE_KEY_BASE64URL or pass --log-private-key-file")?,
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        Err("log private key is empty".into())
    } else {
        Ok(value)
    }
}

fn print_decrypted_log_frame(
    private_key: &str,
    line: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", decrypted_log_frame_output(private_key, line)?);
    Ok(())
}

fn decrypted_log_frame_output(
    private_key: &str,
    line: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let frame: EncryptedLogFrame =
        serde_json::from_str(line).map_err(|err| format!("invalid encrypted log frame: {err}"))?;
    let plaintext = decrypt_log_frame(private_key, &frame).map_err(|err| {
        format!(
            "failed to decrypt log frame for key {}: {err}",
            frame.key_id
        )
    })?;
    let message = String::from_utf8_lossy(&plaintext);
    Ok(format!(
        "{} {} {} {}",
        frame.timestamp,
        frame.container,
        frame.stream,
        sanitize_log_output(message.trim_end())
    ))
}

#[derive(Subcommand)]
pub enum LogKeyCommand {
    /// Generate a tenant-held private key and register only its public key
    Generate(LogKeyGenerateArgs),
    /// List public log keys registered for an app
    List(LogKeyAppArgs),
    /// Select an existing public log key for future deploys
    Select(LogKeySelectArgs),
    /// Revoke a public log key
    Revoke(LogKeySelectArgs),
}

#[derive(Args)]
pub struct LogKeyGenerateArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Stable tenant key id, for example logs-laptop-2026q3
    #[arg(long = "key-id")]
    pub key_id: String,
    /// Optional label stored server-side with the public key
    #[arg(long)]
    pub label: Option<String>,
    /// Where to write the tenant-held private key
    #[arg(long = "private-key-file")]
    pub private_key_file: Option<PathBuf>,
    /// Register the key without selecting it for the app
    #[arg(long = "no-activate")]
    pub no_activate: bool,
}

#[derive(Args)]
pub struct LogKeyAppArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Args)]
pub struct LogKeySelectArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Registered log key id
    #[arg(long = "key-id")]
    pub key_id: String,
}

pub async fn log_key(cmd: LogKeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        LogKeyCommand::Generate(args) => generate_log_key(args).await,
        LogKeyCommand::List(args) => list_log_keys(args).await,
        LogKeyCommand::Select(args) => select_log_key(args).await,
        LogKeyCommand::Revoke(args) => revoke_log_key(args).await,
    }
}

async fn generate_log_key(args: LogKeyGenerateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, paths, _cli_config) = build_api_client()?;
    let generated = generate_log_key_for_app(
        &api,
        &paths,
        &app_name,
        &args.key_id,
        args.label,
        args.private_key_file,
        !args.no_activate,
    )
    .await?;
    println!("Registered log key: {}", generated.key.key_id);
    println!("Public key hash: {}", generated.key.public_key_sha256);
    println!("Private key file: {}", generated.private_key_file.display());
    Ok(())
}

pub(crate) struct GeneratedLogKey {
    pub key: LogEncryptionKey,
    pub private_key_file: PathBuf,
}

pub(crate) async fn generate_log_key_for_app(
    api: &ApiClient,
    paths: &CliPaths,
    app_name: &str,
    key_id: &str,
    label: Option<String>,
    private_key_file: Option<PathBuf>,
    activate_for_app: bool,
) -> Result<GeneratedLogKey, Box<dyn std::error::Error>> {
    paths.ensure_dirs()?;
    let private_key_file =
        private_key_file.unwrap_or_else(|| default_log_private_key_path(paths, app_name, key_id));
    if private_key_file.exists() {
        verify_private_log_key_permissions(&private_key_file)?;
        let private_key = std::fs::read_to_string(&private_key_file).map_err(|err| {
            format!(
                "failed to read existing log private key {}: {err}",
                private_key_file.display()
            )
        })?;
        let keypair = log_keypair_from_private_key(private_key.trim()).map_err(|err| {
            format!(
                "existing log private key {} is invalid: {err}",
                private_key_file.display()
            )
        })?;
        let registered = api
            .list_log_keys(app_name)
            .await?
            .keys
            .into_iter()
            .find(|key| key.key_id == key_id);
        let key = match registered {
            Some(key) => {
                verify_registered_log_key_matches_private(
                    &key,
                    key_id,
                    &keypair,
                    &private_key_file,
                    false,
                )?;
                if activate_for_app && !key.active_for_app {
                    let selected = api.select_log_key(app_name, key_id).await?;
                    verify_registered_log_key_matches_private(
                        &selected,
                        key_id,
                        &keypair,
                        &private_key_file,
                        true,
                    )?;
                    selected
                } else {
                    key
                }
            }
            None => {
                let registered =
                    register_log_keypair(api, app_name, key_id, label, activate_for_app, &keypair)
                        .await?;
                verify_registered_log_key_matches_private(
                    &registered,
                    key_id,
                    &keypair,
                    &private_key_file,
                    activate_for_app,
                )?;
                registered
            }
        };
        return Ok(GeneratedLogKey {
            key,
            private_key_file,
        });
    }

    let keypair = generate_log_keypair();
    write_private_log_key(&private_key_file, &keypair.private_key_base64url)?;
    let key =
        register_log_keypair(api, app_name, key_id, label, activate_for_app, &keypair).await?;
    verify_registered_log_key_matches_private(
        &key,
        key_id,
        &keypair,
        &private_key_file,
        activate_for_app,
    )?;
    Ok(GeneratedLogKey {
        key,
        private_key_file,
    })
}

async fn register_log_keypair(
    api: &ApiClient,
    app_name: &str,
    key_id: &str,
    label: Option<String>,
    activate_for_app: bool,
    keypair: &enclava_common::log_encryption::LogEncryptionKeyPair,
) -> Result<LogEncryptionKey, ApiError> {
    api.register_log_key(
        app_name,
        &RegisterLogEncryptionKeyRequest {
            key_id: key_id.to_string(),
            algorithm: LOG_ENCRYPTION_ALGORITHM.to_string(),
            public_key_base64url: keypair.public_key_base64url.clone(),
            label,
            activate_for_app,
        },
    )
    .await
}

fn verify_registered_log_key_matches_private(
    key: &LogEncryptionKey,
    expected_key_id: &str,
    keypair: &enclava_common::log_encryption::LogEncryptionKeyPair,
    private_key_file: &Path,
    require_active_for_app: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if key.key_id != expected_key_id {
        return Err(format!(
            "log-key API returned key `{}` instead of requested key `{expected_key_id}`",
            key.key_id
        )
        .into());
    }
    if key.status != "active" {
        return Err(format!(
            "log key `{expected_key_id}` is not active; choose a new --generate-log-key id"
        )
        .into());
    }
    if key.algorithm != LOG_ENCRYPTION_ALGORITHM
        || key.public_key_base64url != keypair.public_key_base64url
        || key.public_key_sha256 != keypair.public_key_sha256
    {
        return Err(format!(
            "log private key {} does not match API log key `{expected_key_id}`; choose a new key id or restore the matching private key",
            private_key_file.display(),
        )
        .into());
    }
    if require_active_for_app && !key.active_for_app {
        return Err(format!(
            "log-key API did not confirm requested key `{expected_key_id}` as active for the app"
        )
        .into());
    }
    Ok(())
}

fn verify_private_log_key_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect existing log private key {}: {err}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "existing log private key {} is not a regular file",
            path.display()
        )
        .into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "existing log private key {} has insecure permissions {mode:04o}; restrict it to owner-only access (for example, chmod 600)",
            path.display()
        )
        .into());
    }
    Ok(())
}

async fn list_log_keys(args: LogKeyAppArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (api, _paths, _cli_config) = build_api_client()?;
    match resolve_optional_app_name(&args.app)? {
        Some(app_name) => {
            let list = api.list_log_keys(&app_name).await?;
            println!("App: {}", list.app_name);
            println!(
                "Active key: {}",
                list.active_key_id.as_deref().unwrap_or("-")
            );
            for key in list.keys {
                let active = if key.active_for_app { "active" } else { "-" };
                println!(
                    "{} {} {} {}",
                    key.key_id, key.status, active, key.public_key_sha256
                );
            }
        }
        None => {
            let list = api.list_org_log_keys().await?;
            for key in list.keys {
                println!(
                    "{} {} selected-by={} {}",
                    key.key_id, key.status, key.selected_by_count, key.public_key_sha256
                );
            }
        }
    }
    Ok(())
}

async fn select_log_key(args: LogKeySelectArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;
    let key = api.select_log_key(&app_name, &args.key_id).await?;
    println!("Selected log key: {}", key.key_id);
    Ok(())
}

async fn revoke_log_key(args: LogKeySelectArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (api, _paths, _cli_config) = build_api_client()?;
    if let Some(app_name) = resolve_optional_app_name(&args.app)? {
        let key = api.revoke_log_key(&app_name, &args.key_id).await?;
        println!("Revoked log key: {}", key.key_id);
    } else {
        let key = api.revoke_org_log_key(&args.key_id).await?;
        println!("Revoked log key (org): {}", key.key_id);
    }
    Ok(())
}

fn default_log_private_key_path(paths: &CliPaths, app_name: &str, key_id: &str) -> PathBuf {
    let app_component = log_private_key_path_component(app_name);
    let key_component = log_private_key_path_component(key_id);
    paths
        .keys_dir
        .join("logs")
        .join(format!("{app_component}-{key_component}.x25519"))
}

fn log_private_key_path_component(input: &str) -> String {
    let component: String = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if component.is_empty() {
        "key".to_string()
    } else {
        component
    }
}

fn write_private_log_key(path: &Path, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to create log private key {}: {err}", path.display()))?;
    use std::io::Write as _;
    writeln!(file, "{key}")?;
    Ok(())
}

fn sanitize_log_output(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    let mut saw_escape = false;
                    for next in chars.by_ref() {
                        if next == '\u{7}' {
                            break;
                        }
                        if saw_escape && next == '\\' {
                            break;
                        }
                        saw_escape = next == '\u{1b}';
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        match ch {
            '\n' | '\t' => output.push(ch),
            ch if ch.is_control() => output.push('?'),
            ch => output.push(ch),
        }
    }
    output
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
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
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
    /// Rotate an existing signer identity. If omitted, the confirmation token
    /// is issued by the platform for this exact rotation request.
    Rotate {
        /// New cosign Fulcio identity subject.
        subject: String,
        /// Short-lived confirmation token issued by the platform.
        #[arg(long = "confirmation-token")]
        confirmation_token: Option<String>,
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
            let confirmation_token = match confirmation_token {
                Some(token) => token,
                None => {
                    let issued = api
                        .issue_signer_rotation_token(
                            &app_name,
                            &SignerRotationTokenRequest {
                                subject: subject.clone(),
                                issuer: issuer.clone(),
                            },
                        )
                        .await?;
                    println!(
                        "Signer rotation confirmation token issued; expires in {} seconds.",
                        issued.expires_in_seconds
                    );
                    issued.token
                }
            };
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
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.red} {msg}")?);
    spinner.set_message(format!("Destroying {app_name}..."));
    spinner.enable_steady_tick(Duration::from_millis(100));

    api.delete_app(&app_name).await?;

    spinner.finish_with_message(format!("App '{app_name}' destroyed."));

    Ok(())
}

#[cfg(test)]
#[path = "app/tests/mod.rs"]
mod tests;
