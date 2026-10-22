use clap::Args;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::commands::ownership::{MnemonicCapture, mnemonic_capture_from_flags};
use crate::commands::{counted_progress, format_duration, timed_progress};
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
    OrgKeyringEnvelope, keyring_fingerprint, load_keyring_envelope, load_trusted_owner,
    member_allows_deploy, store_keyring_envelope, store_trusted_owner, verify_keyring,
};
use enclava_cli::keys;
use enclava_cli::platform_release::{PlatformRelease, PlatformReleaseEnvelope, verify_envelope};
use enclava_cli::tee_client::{
    TeeBootstrapStatus, TeeClient, TeeError, TerminalBootstrapError, parse_terminal_bootstrap_error,
};
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
use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

use crate::commands::template::{normalize_ngrok_tcp_url, should_retry_api_transport_error};

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

    pub(crate) fn is_from_file(&self) -> bool {
        self.value.is_some()
    }

    fn initial_claim_password(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.value {
            Some(value) => Ok(value.clone()),
            None => {
                // A pty with no stdin feeder blocks here forever (nohup
                // script-class runs), so name the non-interactive path in
                // whatever log the operator will eventually read.
                eprintln!(
                    "Reading the initial storage password from the terminal; \
                     unattended runs must pass --storage-password-file <PATH>."
                );
                Ok(dialoguer::Password::new()
                    .with_prompt("Set initial storage password")
                    .with_confirmation("Confirm initial storage password", "Passwords don't match")
                    .interact()?)
            }
        }
    }

    fn unlock_password(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.value {
            Some(value) => Ok(value.clone()),
            None => {
                eprintln!(
                    "Reading the unlock password from the terminal; \
                     unattended runs must pass --storage-password-file <PATH>."
                );
                Ok(dialoguer::Password::new()
                    .with_prompt("Unlock password")
                    .interact()?)
            }
        }
    }
}

fn read_storage_password_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(enclava_cli::keys::read_secret_file(
        path,
        "storage password",
    )?)
}

fn storage_password_prompt_available() -> bool {
    // Both terminals, mirroring secret_from_file_or_prompt's prompted path:
    // dialoguer renders password prompts on stderr, so a piped stderr cannot
    // host the prompt. Recorded-output runs (`2>&1 | tee`) use the file flags.
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

pub(crate) fn deploy_needs_initial_claim(
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

/// Unresolved ownership requires claim-ready password input before submission,
/// so a first deployment cannot be stranded by a missing password prompt.
pub(crate) fn deploy_preflight_needs_claim(
    is_password_mode: bool,
    ownership_state: Option<&str>,
    app_status: &str,
) -> bool {
    match ownership_state {
        None => is_password_mode,
        Some(state) => deploy_needs_initial_claim(is_password_mode, Some(state), app_status),
    }
}

mod signing;
pub(crate) use enclava_cli::descriptor::TrustedDeploymentExpectation;
#[cfg(test)]
pub(crate) use signing::{ConfidentialAppForCcHash, confidential_app_for_cc_hash};
pub(crate) use signing::{
    SignedDeployBlobParams, build_signed_deploy_blobs, ensure_manual_deploy_keyring,
    fetch_verified_platform_release, load_or_derive_bootstrap_private_key,
    resolve_current_user_org,
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

/// Auto-unlock is only reachable via `enclava auto-unlock enable` after a password-mode
/// claim has established the owner seed inside the TEE (the CLI then wraps that seed
/// for attestation-gated KBS release). At `create` time no claim has happened, so there
/// is no seed to wrap — `unlock.mode = "auto"` is always a category error. Fail fast
/// with the workaround rather than letting enclava-init time out (~60s) fetching a KBS
/// wrap-key that nothing provisions.
fn validate_create_unlock_mode(mode: &str) -> Result<(), &'static str> {
    match mode {
        "auto" => Err(
            "auto-unlock cannot be set at first deploy: the owner seed is \
             established by a password-mode claim. Set `unlock.mode = \"password\"` for \
             the first deploy, then run `enclava auto-unlock enable` to wrap the seed \
             for attestation-gated release on restarts.",
        ),
        _ => Ok(()),
    }
}

pub async fn create(args: CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_config = AppConfig::find_and_load()?;
    validate_create_unlock_mode(&app_config.unlock.mode)?;
    let (api, paths, _cli_config) = build_api_client()?;

    let bootstrap_key = if app_config.unlock.mode == "password" {
        let (org_id, org, _) = ensure_manual_deploy_keyring(&api, &paths, false).await?;
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
    /// Container image to deploy and bind into the customer-signed descriptor.
    /// A tag is resolved to its content digest first.
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
    /// Persist the recovery mnemonic to the protected local keystore so `enclava key backup` can back it up (default).
    #[arg(long, conflicts_with = "no_store_mnemonic")]
    pub store_mnemonic: bool,
    /// Unsupported for password-mode first deploys (which auto-claim): rejected before the deployment is submitted.
    #[arg(long, conflicts_with = "store_mnemonic")]
    pub no_store_mnemonic: bool,
}

pub async fn deploy(args: DeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let deploy_started = Instant::now();
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
    // Pre-mutation claim-session gate: a fresh password-mode deploy auto-claims
    // on first boot; refusing a session that cannot claim BEFORE submitting
    // keeps the abort side-effect-free (the post-mutation refusal strands a
    // server-side deployment nothing terminalizes client-side). Live ownership
    // is read first and fed to the same decision the post-submit claim uses
    // (a failed first deploy leaves the app unclaimed outside `creating`);
    // unresolved ownership fails closed -- see `deploy_preflight_needs_claim`.
    let preflight_ownership = api
        .get_unlock_status(&app_name)
        .await
        .ok()
        .and_then(|status| status.ownership_state);
    let preflight_needs_claim = deploy_preflight_needs_claim(
        is_password_mode,
        preflight_ownership.as_deref(),
        &app.status,
    );
    if preflight_needs_claim {
        crate::commands::ownership::ensure_claim_session_now(storage_password.is_from_file())?;
    }
    let capture = mnemonic_capture_from_flags(args.no_store_mnemonic);
    // A fresh password-mode deploy auto-claims ownership on first boot; refuse the
    // no-store sink mode before submitting anything, while the run can still stop
    // without side effects. (The authoritative pre-claim gate also re-checks this
    // inside `claim_initial_ownership`.)
    if capture == MnemonicCapture::Skip && preflight_needs_claim {
        crate::commands::ownership::validate_recovery_mnemonic_sink_mode(capture)?;
    }
    let pb = ProgressBar::new(5);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")?
            .progress_chars("=> "),
    );
    // Polls redraw this bar with real state. A steady ticker would race the
    // password, unlock, and one-time recovery-mnemonic terminal prompts.
    pb.set_message("Preparing signed deployment...");
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
    // Locally trusted deployment identity, captured before the signed blobs
    // are moved into the deploy request.
    let trusted_deployment = signed_blobs.deployment;

    let req = DeployRequest {
        image: Some(args.image.clone()),
        resources: DeployResourcesSpec {
            cpu: app_config.resources.cpu.clone(),
            memory: app_config.resources.memory.clone(),
            storage: app_config.storage.size.clone(),
            tls_storage: app_config.storage.tls_size.clone(),
        },
        customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob),
        org_keyring_blob: Some(signed_blobs.org_keyring_blob),
        signed_policy_artifact: Some(signed_blobs.signed_policy_artifact),
    };

    // Phase 1: Deploy
    pb.set_message("Submitting deployment...");
    let resp = api.deploy(&app_name, &req).await?;
    pb.set_position(1);
    pb.set_message("Manifests applied");

    // Phase 2: Wait for TEE boot (poll status)
    pb.set_position(2);
    pb.set_message("Waiting for TEE boot...");

    let max_wait = Duration::from_secs(DEPLOY_HEALTH_TIMEOUT_SECONDS);
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
        if wait_for_bootstrap_endpoint(
            &api,
            &app_name,
            DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
            max_wait,
            poll_interval,
            &pb,
        )
        .await?
        {
            claim_initial_ownership(
                &api,
                &paths,
                &app_name,
                DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
                &storage_password,
                capture,
                None,
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
                DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
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
                    DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
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
            DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
            max_wait,
            poll_interval,
            &pb,
            runtime_target,
        )
        .await?;
        if deploy_should_unlock_before_config(is_password_mode, false, !config_pairs.is_empty()) {
            ensure_password_storage_unlocked_for_config(
                &api,
                &app_name,
                DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
                &pb,
                &storage_password,
            )
            .await?;
        }
    }

    // Phase 4: Push config if --set was used
    if !config_pairs.is_empty() {
        pb.set_position(4);
        pb.set_message(counted_progress("Customer config", 0, config_pairs.len()));

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

        for (index, (key, value)) in config_pairs.iter().enumerate() {
            set_deploy_config(
                &api,
                &tee,
                &app_name,
                DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
                key,
                value,
                &token_resp.token,
            )
            .await?;
            api.sync_config_key(&app_name, key, false).await?;
            pb.set_message(counted_progress(
                "Customer config",
                index + 1,
                config_pairs.len(),
            ));
        }
    }

    // Phase 4: Health check
    pb.set_position(5);
    pb.set_message("Waiting for health check...");

    let health_timeout = Duration::from_secs(DEPLOY_HEALTH_TIMEOUT_SECONDS);
    wait_for_deployment_completion(
        &api,
        &app_name,
        DeploymentWait::trusted(&resp.deployment_id, Some(&trusted_deployment)),
        health_timeout,
        Duration::from_secs(2),
        &pb,
    )
    .await?;
    pb.finish_with_message(format!(
        "Deployed and healthy in {}",
        format_duration(deploy_started.elapsed())
    ));

    println!();
    println!("  App:    {app_name}");
    println!("  URL:    https://{}", resp.app_domain);
    println!("  Deploy: {}", resp.deployment_id);
    println!("  Duration: {}", format_duration(deploy_started.elapsed()));
    if !config_pairs.is_empty() {
        println!("  Config: {} key(s) set", config_pairs.len());
    }

    Ok(())
}

async fn set_deploy_config(
    api: &ApiClient,
    tee: &TeeClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    key: &str,
    value: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // First-boot encrypted storage can still be initializing after the ownership claim.
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        match tee.config_set(key, value, token).await {
            Err(error) if should_retry_deploy_config(&error) && Instant::now() < deadline => {
                // The attested channel that just refused the write also
                // carries any terminal bootstrap diagnostic: stop promptly
                // instead of retrying into the deadline, but only when CAP's
                // evidence connects the endpoint to the expected deployment,
                // and under a probe budget capped to the remaining deadline.
                if let Some(diagnostic) = deployment_bound_terminal_bootstrap_error_on_channel(
                    api, app_name, deployment, tee, deadline,
                )
                .await
                {
                    return Err(terminal_bootstrap_failure_message(app_name, &diagnostic).into());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            result => return result.map_err(|error| error.into()),
        }
    }
}

fn should_retry_deploy_config(error: &TeeError) -> bool {
    matches!(error, TeeError::Tee { status: 423, .. })
}

/// Stable, provider-detail-free message for an authenticated terminal
/// bootstrap failure: the recognized error code plus the optional validated
/// retry deadline, in a form a PaaS verifier can safely match later.
pub(crate) fn terminal_bootstrap_failure_message(
    app_name: &str,
    diagnostic: &TerminalBootstrapError,
) -> String {
    format!(
        "terminal bootstrap failure for app {app_name}: {}; run `enclava status --app {app_name}` for the latest state",
        diagnostic.stable_summary()
    )
}

/// Minimum spacing between terminal-diagnostic TEE probes inside long
/// API-only wait loops: bounds attestation cost while keeping the stop
/// prompt after a terminal failure.
const TEE_TERMINAL_DIAGNOSTIC_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// Whether a terminal-diagnostic TEE probe is due in a long wait loop.
pub(crate) fn tee_terminal_diagnostic_probe_due(last: &mut Option<Instant>) -> bool {
    if last
        .as_ref()
        .is_some_and(|probed_at| probed_at.elapsed() < TEE_TERMINAL_DIAGNOSTIC_PROBE_INTERVAL)
    {
        return false;
    }
    *last = Some(Instant::now());
    true
}

/// Deployment identity for a wait: the CAP record id the wait is bound to
/// (deployment-failure checks, messages, deadlines) plus the locally trusted
/// expectation captured at signing time. The expectation is present only for
/// fresh signed deploys whose returned deployment id equals the signed
/// descriptor's `deploy_id`; resumed or rollback paths carry `None` and keep
/// existing timeout behavior -- they must never attribute exact execution
/// terminal.
#[derive(Clone, Copy)]
pub(crate) struct DeploymentWait<'a> {
    pub deployment_id: &'a str,
    pub expectation: Option<&'a TrustedDeploymentExpectation>,
}

impl<'a> DeploymentWait<'a> {
    pub(crate) fn new(deployment_id: &'a str) -> Self {
        Self {
            deployment_id,
            expectation: None,
        }
    }

    /// Bind a wait to a signed deployment, but only when CAP (or the PaaS
    /// forwarding to CAP) returned exactly the deployment id the signed
    /// descriptor carries. A mismatched returned id invalidates the trusted
    /// expectation: the wait falls back to untrusted timeout behavior.
    pub(crate) fn trusted(
        deployment_id: &'a str,
        expectation: Option<&'a TrustedDeploymentExpectation>,
    ) -> Self {
        Self {
            deployment_id,
            expectation: expectation.filter(|expectation| {
                !deployment_id.is_empty()
                    && deployment_id != "pending"
                    && expectation.deploy_id == deployment_id
            }),
        }
    }

    pub(crate) fn matches_launch_identity(
        self,
        identity: Option<&enclava_cli::tee_client::VerifiedSnpLaunchIdentity>,
    ) -> bool {
        self.expectation.is_some_and(|expectation| {
            enclava_cli::tee_client::launch_identity_binds_deployment(
                identity,
                &expectation.expected_cc_init_data_hash,
                &expectation.expected_firmware_measurement,
            )
        })
    }
}

/// Hard cap on one complete terminal-diagnostic probe (CAP endpoint lookup,
/// attested read), so stalled CAP lookups, slow attestation, or KDS retry
/// storms can never exceed the enclosing wait.
const TERMINAL_DIAGNOSTIC_PROBE_BUDGET: Duration = Duration::from_secs(15);

/// Budget for one terminal-diagnostic probe: the hard cap, never more than
/// the enclosing wait's remaining time.
pub(crate) fn terminal_diagnostic_budget(wait_deadline: Option<Instant>) -> Duration {
    TERMINAL_DIAGNOSTIC_PROBE_BUDGET.min(match wait_deadline {
        Some(deadline) => deadline.saturating_duration_since(Instant::now()),
        None => TERMINAL_DIAGNOSTIC_PROBE_BUDGET,
    })
}

/// One complete terminal-diagnostic probe under a hard budget.
///
/// Authorization requires the locally trusted deployment expectation and a
/// verified endpoint-to-deployment binding: the SNP HOST_DATA (launch
/// measurement) verified over the SAME SPKI-pinned client used for the
/// `/status` read must equal the expectation's cc-init-data hash. The proxy
/// `/attestation` binds nonce + TLS leaf SPKI pre-ACME, the AMD chain
/// authenticates the report, and CAP validates the signed descriptor's hash
/// when rendering the deployment (revalidated at apply), so matching
/// HOST_DATA proves the responding TEE executes this deployment's launch
/// configuration and the SPKI pin keeps the status read on that TEE.
///
/// Fresh-observation and deployment-history checks are deliberately NOT used
/// as authorization: they cannot prove which TEE serves the endpoint. Any
/// failure -- missing expectation, unattested client, HOST_DATA mismatch
/// (e.g. an old deployment's TEE still serving), stalled lookup or read --
/// yields no diagnostic, and the caller's existing deadline governs.
pub(crate) async fn terminal_diagnostic_probe_with_budget(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    attested: Option<&TeeClient>,
    budget: Duration,
) -> Option<TerminalBootstrapError> {
    bound_tee_status_probe_with_budget(api, app_name, deployment, attested, budget)
        .await
        .and_then(|body| parse_terminal_bootstrap_error(&body))
}

/// Attested, deployment-bound `/status` read shared by the wait-loop probes:
/// the terminal-diagnostic probe's launch-identity binding discipline, but
/// returning the bounded status body so callers can also act on runtime
/// state (e.g. a password-mode relock) from the same read.
async fn bound_tee_status_probe_with_budget(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    attested: Option<&TeeClient>,
    budget: Duration,
) -> Option<serde_json::Value> {
    if budget.is_zero() {
        return None;
    }
    tokio::time::timeout(budget, async {
        let expectation = deployment.expectation?;
        match attested {
            Some(attested) => bound_tee_status_on_attested(attested, expectation).await,
            None => {
                let endpoint = api.get_unlock_endpoint(app_name).await.ok()?;
                let tee = TeeClient::new_for_ownership_probe_with_resolve_ip(
                    &endpoint.tee_url,
                    endpoint.tee_resolve_ip,
                );
                let (_attestation, attested_tee) = tee.attest_receipt_key().await.ok()?;
                bound_tee_status_on_attested(&attested_tee, expectation).await
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Read the bounded `/status` body over an attested (SPKI-pinned) client, but
/// only when the client's verified SNP HOST_DATA binds it to the expected
/// deployment's launch hash.
async fn bound_tee_status_on_attested(
    attested: &TeeClient,
    expectation: &TrustedDeploymentExpectation,
) -> Option<serde_json::Value> {
    // HOST_DATA alone is hypervisor-supplied launch input: the authenticated
    // firmware measurement must match the existing expectation as well, or
    // the endpoint is not proven to execute this deployment's expected
    // firmware.
    if !enclava_cli::tee_client::launch_identity_binds_deployment(
        attested.verified_launch_identity().as_ref(),
        &expectation.expected_cc_init_data_hash,
        &expectation.expected_firmware_measurement,
    ) {
        return None;
    }
    attested.bounded_status_json().await.ok()
}

/// Deployment-bound attested `/status` read for waits that must act on
/// runtime state beyond terminal diagnostics (e.g. a password-mode relock in
/// the template SSH wait). An unbound, unreadable, or timed-out endpoint
/// yields `None` and the caller keeps waiting — never a guessed state.
pub(crate) async fn deployment_bound_tee_status(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    wait_deadline: Instant,
) -> Option<serde_json::Value> {
    bound_tee_status_probe_with_budget(
        api,
        app_name,
        deployment,
        None,
        terminal_diagnostic_budget(Some(wait_deadline)),
    )
    .await
}

/// Deployment-bound terminal-diagnostic probe for waits that do not hold an
/// attested client: the probe attests the app endpoint itself, entirely under
/// the budget derived from the enclosing wait's deadline.
pub(crate) async fn deployment_bound_terminal_bootstrap_error(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    wait_deadline: Instant,
) -> Option<TerminalBootstrapError> {
    terminal_diagnostic_probe_with_budget(
        api,
        app_name,
        deployment,
        None,
        terminal_diagnostic_budget(Some(wait_deadline)),
    )
    .await
}

/// Deployment-bound terminal-diagnostic probe over an attested channel a
/// caller already holds, entirely under the budget derived from the enclosing
/// wait's deadline.
pub(crate) async fn deployment_bound_terminal_bootstrap_error_on_channel(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    attested: &TeeClient,
    wait_deadline: Instant,
) -> Option<TerminalBootstrapError> {
    terminal_diagnostic_probe_with_budget(
        api,
        app_name,
        deployment,
        Some(attested),
        terminal_diagnostic_budget(Some(wait_deadline)),
    )
    .await
}

/// Classification of one attested direct-TEE `/status` body in the runtime
/// wait. A recognized terminal diagnostic outranks the direct-fallback
/// success states: a TEE whose storage is locked or unlocked but whose
/// bootstrap failed terminally is never reported as ready.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectTeeRuntimeOutcome {
    Terminal(TerminalBootstrapError),
    Locked,
    Unlocked,
    Waiting,
}

pub(crate) fn direct_tee_runtime_outcome(status: &serde_json::Value) -> DirectTeeRuntimeOutcome {
    if let Some(diagnostic) = parse_terminal_bootstrap_error(status) {
        return DirectTeeRuntimeOutcome::Terminal(diagnostic);
    }
    match tee_unlock_state(status) {
        "locked" => DirectTeeRuntimeOutcome::Locked,
        "unlocked" => DirectTeeRuntimeOutcome::Unlocked,
        _ => DirectTeeRuntimeOutcome::Waiting,
    }
}

impl DirectTeeRuntimeOutcome {
    /// The recognized terminal diagnostic, when this outcome is terminal.
    pub(crate) fn terminal_diagnostic(&self) -> Option<TerminalBootstrapError> {
        match self {
            DirectTeeRuntimeOutcome::Terminal(diagnostic) => Some(diagnostic.clone()),
            _ => None,
        }
    }
}

/// Decision from one safe [`TeeBootstrapStatus`] read in the bootstrap
/// endpoint waits. A terminal diagnostic outranks an already-claimed state so
/// a claimed-but-not-ready failure is never reported as success.
pub(crate) enum BootstrapEndpointStatusDecision {
    /// A recognized terminal failure is present: the caller must confirm the
    /// endpoint-to-deployment binding before stopping with the stable code.
    Terminal,
    /// Ownership already claimed; the initial-claim flow may be skipped.
    AlreadyClaimed,
    /// No terminal failure and not claimed: keep waiting.
    Waiting,
}

pub(crate) fn bootstrap_endpoint_status_decision(
    status: &TeeBootstrapStatus,
) -> BootstrapEndpointStatusDecision {
    if status.terminal_bootstrap_error.is_some() {
        BootstrapEndpointStatusDecision::Terminal
    } else if status.claimed {
        BootstrapEndpointStatusDecision::AlreadyClaimed
    } else {
        BootstrapEndpointStatusDecision::Waiting
    }
}

pub(crate) async fn wait_for_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let deployment_id = deployment.deployment_id;
    let mut tee = None;
    let start = std::time::Instant::now();
    let mut history = DeploymentHistoryProbe::new();

    loop {
        // Check the wait deadline before polling deployment history: once
        // the budget is gone the wait must return instead of issuing one
        // more request that could outlive it (cap#220 review).
        if start.elapsed() > max_wait {
            pb.abandon_with_message("TEE ownership timed out");
            return Err(format!(
                "TEE ownership for app {app_name} did not become ready within {}; run `enclava status --app {app_name}` for the latest state",
                format_duration(max_wait)
            )
            .into());
        }
        // Poll the terminal-failure check before any endpoint fetch: a
        // rejected deployment must fail fast rather than block on a
        // request whose response would never satisfy it (#18). Every
        // synchronous request in this loop is cut at the finite per-attempt
        // budget, so a stalled response can never consume the wait
        // (cap#220 review); the history lookups themselves run detached on
        // the probe and never block the poll.
        fail_if_template_deployment_failed(
            api,
            app_name,
            deployment_id,
            start + max_wait,
            &mut history,
        )
        .await?;

        pb.set_message(timed_progress(
            "TEE ownership: waiting for attested endpoint",
            start.elapsed(),
            max_wait,
        ));
        if tee.is_none() {
            match bounded_wait_attempt(start + max_wait, api.get_unlock_endpoint(app_name)).await {
                Some(Ok(endpoint)) => {
                    tee = Some(TeeClient::new_for_ownership_probe_with_resolve_ip(
                        &endpoint.tee_url,
                        endpoint.tee_resolve_ip,
                    ));
                }
                Some(Err(error)) => {
                    // Same retry predicate as the template wait: transient
                    // transport/5xx/rate-limit conditions retry; auth,
                    // decode, and 404-class failures surface immediately
                    // instead of burning the whole wait budget.
                    let error: ApiError = error;
                    if !crate::commands::template::should_retry_template_bootstrap_endpoint_error(
                        &error,
                    ) {
                        return Err(error.into());
                    }
                    pb.set_message(timed_progress(
                        "TEE ownership: waiting for endpoint",
                        start.elapsed(),
                        max_wait,
                    ));
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                // The attempt outlived its per-attempt budget (cap#220
                // review): a stalled endpoint must not consume the wait, so
                // retry on the next tick.
                None => {
                    pb.set_message(timed_progress(
                        "TEE ownership: waiting for endpoint",
                        start.elapsed(),
                        max_wait,
                    ));
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            }
        }
        let tee = tee.as_ref().expect("tee client was just acquired");
        // Attestation and the bootstrap challenge run under the same finite
        // per-attempt budget as every other request in this loop (cap#220
        // review follow-up #3): the ownership-probe client's own 15s request
        // timeout bounds them, but the per-attempt guarantee must hold
        // structurally -- clamped to the wait's remaining time -- instead of
        // relying on client configuration.
        match bounded_wait_attempt(start + max_wait, tee.attest_receipt_key()).await {
            Some(Ok((_attestation, attested_tee))) => {
                match bounded_wait_attempt(start + max_wait, attested_tee.bootstrap_challenge())
                    .await
                {
                    Some(Ok(_)) => {
                        // A terminal diagnostic read over this attested,
                        // SPKI-pinned channel outranks a reachable challenge
                        // endpoint: stop before attempting any claim, but only
                        // when CAP's evidence connects this endpoint to the
                        // expected deployment.
                        if let Some(diagnostic) =
                            deployment_bound_terminal_bootstrap_error_on_channel(
                                api,
                                app_name,
                                deployment,
                                &attested_tee,
                                start + max_wait,
                            )
                            .await
                        {
                            pb.abandon_with_message("TEE bootstrap failed");
                            return Err(
                                terminal_bootstrap_failure_message(app_name, &diagnostic).into()
                            );
                        }
                        // Readiness alone must not end the wait (cap#220
                        // review follow-up): the success must be authorized
                        // by a current deployment-state observation, and an
                        // inconclusive one keeps the wait running (the
                        // enclosing deadline governs).
                        if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                            api,
                            app_name,
                            deployment_id,
                            start + max_wait,
                            &mut history,
                        )
                        .await?
                        {
                            pb.set_message("Ownership claim endpoint ready");
                            return Ok(true);
                        }
                        pb.set_message(timed_progress(
                            "TEE ownership: confirming deployment state",
                            start.elapsed(),
                            max_wait,
                        ));
                    }
                    Some(Err(_)) | None => {
                        // One safe status read decides the challenge-failure
                        // fallback: a terminal diagnostic is never masked by a
                        // claimed ownership state. The read runs under a
                        // budget capped to the wait's remaining time.
                        match attested_tee
                            .bootstrap_status_within(terminal_diagnostic_budget(Some(
                                start + max_wait,
                            )))
                            .await
                        {
                            Ok(status) => match bootstrap_endpoint_status_decision(&status) {
                                BootstrapEndpointStatusDecision::Terminal => {
                                    if let Some(diagnostic) =
                                        deployment_bound_terminal_bootstrap_error_on_channel(
                                            api,
                                            app_name,
                                            deployment,
                                            &attested_tee,
                                            start + max_wait,
                                        )
                                        .await
                                    {
                                        pb.abandon_with_message("TEE bootstrap failed");
                                        return Err(terminal_bootstrap_failure_message(
                                            app_name,
                                            &diagnostic,
                                        )
                                        .into());
                                    }
                                    // Binding unproven: never authorize the
                                    // stop; the wait deadline governs.
                                    pb.set_message(timed_progress(
                                        "TEE ownership: waiting for claim endpoint",
                                        start.elapsed(),
                                        max_wait,
                                    ));
                                }
                                BootstrapEndpointStatusDecision::AlreadyClaimed => {
                                    if let SuccessGate::Confirmed =
                                        reconcile_success_with_deployment_history(
                                            api,
                                            app_name,
                                            deployment_id,
                                            start + max_wait,
                                            &mut history,
                                        )
                                        .await?
                                    {
                                        pb.set_message("Ownership already claimed");
                                        return Ok(false);
                                    }
                                    pb.set_message(timed_progress(
                                        "TEE ownership: confirming deployment state",
                                        start.elapsed(),
                                        max_wait,
                                    ));
                                }
                                BootstrapEndpointStatusDecision::Waiting => {
                                    pb.set_message(timed_progress(
                                        "TEE ownership: waiting for claim endpoint",
                                        start.elapsed(),
                                        max_wait,
                                    ));
                                }
                            },
                            Err(_) => {
                                pb.set_message(timed_progress(
                                    "TEE ownership: waiting for claim endpoint",
                                    start.elapsed(),
                                    max_wait,
                                ));
                            }
                        }
                    }
                }
            }
            Some(Err(_)) | None => {
                pb.set_message(timed_progress(
                    "TEE ownership: waiting for attested endpoint",
                    start.elapsed(),
                    max_wait,
                ));
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_deploy_runtime(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
    target: DeployRuntimeTarget,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_deployment_id = deployment.deployment_id;
    let start = std::time::Instant::now();
    let mut terminal_probe_at: Option<Instant> = None;
    let mut history = DeploymentHistoryProbe::new();

    loop {
        // Check the wait deadline before polling deployment history: once
        // the budget is gone the wait must return instead of issuing one
        // more request that could outlive it (cap#220 review).
        if start.elapsed() > max_wait {
            pb.abandon_with_message("TEE boot timed out");
            return Err(format!(
                "deployment {expected_deployment_id} for app {app_name} did not reach a ready TEE within {}; run `enclava status --app {app_name}` for the latest state",
                format_duration(max_wait)
            )
            .into());
        }
        // Fail fast on a terminalized deployment before any readiness poll
        // (#18). Every synchronous request in this loop is cut at the finite
        // per-attempt budget, so a stalled response can never consume the
        // wait and make a healthy deployment report a boot timeout
        // (cap#220 review); the history lookups themselves run detached on
        // the probe and never block the poll.
        fail_if_template_deployment_failed(
            api,
            app_name,
            expected_deployment_id,
            start + max_wait,
            &mut history,
        )
        .await?;

        pb.set_message(timed_progress(
            "TEE boot: waiting for runtime",
            start.elapsed(),
            max_wait,
        ));
        let observation_is_fresh;
        let direct_tee_allowed =
            match bounded_wait_attempt(start + max_wait, api.get_status(app_name)).await {
                Some(Ok(status)) => {
                    observation_is_fresh = observation_is_fresh_for_deployment(
                        status.observation.as_ref(),
                        expected_deployment_id,
                    );
                    let direct_tee_allowed = status.status != "failed"
                        && observation_allows_direct_tee_fallback(
                            status.observation.as_ref(),
                            expected_deployment_id,
                        );
                    if observation_is_fresh && target.accepts_api_status(status.status.as_str()) {
                        // Readiness alone must not end the wait (cap#220
                        // review follow-up): the success must be authorized
                        // by a current deployment-state observation, and an
                        // inconclusive one keeps the wait running (the
                        // enclosing deadline governs).
                        if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                            api,
                            app_name,
                            expected_deployment_id,
                            start + max_wait,
                            &mut history,
                        )
                        .await?
                        {
                            pb.set_position(3);
                            pb.set_message(match status.status.as_str() {
                                "locked" => "TEE running, storage locked",
                                _ => "TEE running, attestation complete",
                            });
                            return Ok(());
                        }
                    }

                    let pod_phase_is_verified = observation_is_fresh && status.status != "failed";
                    match status.pod_phase.as_deref() {
                        Some("Running")
                            if pod_phase_is_verified && target.accepts_running_pod_phase() =>
                        {
                            if let SuccessGate::Confirmed =
                                reconcile_success_with_deployment_history(
                                    api,
                                    app_name,
                                    expected_deployment_id,
                                    start + max_wait,
                                    &mut history,
                                )
                                .await?
                            {
                                pb.set_position(3);
                                pb.set_message("TEE running, attestation complete");
                                return Ok(());
                            }
                            pb.set_message(timed_progress(
                                "TEE boot: confirming deployment state",
                                start.elapsed(),
                                max_wait,
                            ));
                        }
                        Some(phase) => {
                            pb.set_message(timed_progress(
                                &format!("TEE boot: Pod {phase}"),
                                start.elapsed(),
                                max_wait,
                            ));
                        }
                        None => {}
                    }
                    direct_tee_allowed
                }
                // Ok(Err): the API call failed. None: the attempt outlived
                // its per-attempt budget (cap#220 review) -- a stalled status
                // call must not consume the wait. Either way: the direct
                // endpoint is app-bound rather than deployment-bound. Without
                // a current CAP observation there is no pod/deployment
                // evidence proving it belongs to this deploy, so retry CAP and
                // do not let an old TEE satisfy a replacement rollout.
                Some(Err(_)) | None => false,
            };

        // A terminal bootstrap diagnostic from the attested app TEE stops the
        // wait, but only when CAP's live observation proves the endpoint
        // belongs to the expected deployment before and after the probe, so
        // a stale diagnostic from a replaced TEE cannot abort a replacement
        // rollout. No automatic certificate or bootstrap retry happens here.
        if tee_terminal_diagnostic_probe_due(&mut terminal_probe_at)
            && let Some(diagnostic) = deployment_bound_terminal_bootstrap_error(
                api,
                app_name,
                deployment,
                start + max_wait,
            )
            .await
        {
            pb.abandon_with_message("TEE bootstrap failed");
            return Err(terminal_bootstrap_failure_message(app_name, &diagnostic).into());
        }

        if direct_tee_allowed
            && let Some(Ok(endpoint)) =
                bounded_wait_attempt(start + max_wait, api.get_unlock_endpoint(app_name)).await
            && let tee = TeeClient::new_for_ownership_with_resolve_ip(
                &endpoint.tee_url,
                endpoint.tee_resolve_ip,
            )
            && let Some(Ok((_attestation, attested_tee))) =
                bounded_wait_attempt(start + max_wait, tee.attest_receipt_key()).await
            && let Ok(status) = attested_tee
                .bounded_status_json_within(terminal_diagnostic_budget(Some(start + max_wait)))
                .await
        {
            // A terminal diagnostic in this attested status body outranks both
            // direct-fallback success states -- but it may only stop the wait
            // once CAP's evidence connects this endpoint to the expected
            // deployment, rechecked after the read.
            let outcome = direct_tee_runtime_outcome(&status);
            let terminal_diagnostic = outcome.terminal_diagnostic();
            if terminal_diagnostic.is_some()
                && let Some(diagnostic) = deployment_bound_terminal_bootstrap_error_on_channel(
                    api,
                    app_name,
                    deployment,
                    &attested_tee,
                    start + max_wait,
                )
                .await
            {
                pb.abandon_with_message("TEE bootstrap failed");
                return Err(terminal_bootstrap_failure_message(app_name, &diagnostic).into());
            }
            if tee_supplemental_fields_are_consistent(&status) {
                match outcome {
                    DirectTeeRuntimeOutcome::Locked => {
                        if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                            api,
                            app_name,
                            expected_deployment_id,
                            start + max_wait,
                            &mut history,
                        )
                        .await?
                        {
                            pb.set_position(3);
                            pb.set_message("TEE running, storage locked");
                            return Ok(());
                        }
                        pb.set_message(timed_progress(
                            "TEE boot: confirming deployment state",
                            start.elapsed(),
                            max_wait,
                        ));
                    }
                    DirectTeeRuntimeOutcome::Unlocked if target.accepts_direct_unlocked() => {
                        if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                            api,
                            app_name,
                            expected_deployment_id,
                            start + max_wait,
                            &mut history,
                        )
                        .await?
                        {
                            pb.set_position(3);
                            pb.set_message("TEE running, attestation complete");
                            return Ok(());
                        }
                        pb.set_message(timed_progress(
                            "TEE boot: confirming deployment state",
                            start.elapsed(),
                            max_wait,
                        ));
                    }
                    DirectTeeRuntimeOutcome::Unlocked => {
                        pb.set_message(timed_progress(
                            "TEE boot: waiting for replacement storage lock",
                            start.elapsed(),
                            max_wait,
                        ));
                    }
                    DirectTeeRuntimeOutcome::Waiting | DirectTeeRuntimeOutcome::Terminal(_) => {}
                }
            } else {
                pb.set_message(timed_progress(
                    "TEE boot: waiting for consistent status",
                    start.elapsed(),
                    max_wait,
                ));
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
        let pod_evidence_allows_fallback = match observation.state.as_str() {
            "fresh" => observation.reason.is_none(),
            "partial" => matches!(
                observation.reason.as_deref(),
                Some("tee_unavailable" | "tee_malformed" | "tee_evidence_incomplete")
            ),
            _ => false,
        };

        pod_evidence_allows_fallback
            && !observation.drifted
            && observation.deployment_id.as_deref() == Some(expected_deployment_id)
    })
}

/// Per-attempt budget for the synchronous requests a wait loop makes (the
/// readiness polls: unlock endpoint, runtime status, config keys, SSH
/// command). The shared HTTP client's per-request timeout is generous (it
/// also covers slow deploy/setup calls), so without a cap a single stalled
/// request can hold the loop for up to that timeout and consume the
/// enclosing wait's entire budget (cap#220 review). 60s is the tradeoff the
/// reviews converged on: finite and shorter than any wait (a stalled attempt
/// is cut and the loop retries once the endpoint recovers), and never more
/// than the wait's remaining time (a passed deadline yields zero budget and
/// issues no request at all, so no request can outlive its wait).
///
/// Deployment-history lookups deliberately do NOT cut at this budget: their
/// answers are the wait loops' source of truth, and cutting a request at a
/// fixed budget discards valid responses slower than it (cap#220 review
/// follow-up: a history endpoint consistently answering after 70s must
/// still be observed, not cancelled at 60s). They run as detached requests
/// through [`DeploymentHistoryProbe`], for which this budget is only the
/// refresh cadence.
const WAIT_ATTEMPT_BUDGET: Duration = Duration::from_secs(60);

fn wait_attempt_budget(wait_deadline: Instant) -> Duration {
    WAIT_ATTEMPT_BUDGET.min(wait_deadline.saturating_duration_since(Instant::now()))
}

/// One bounded request attempt inside a wait loop (cap#220 review). `None`
/// means the attempt could not land within `wait_attempt_budget` -- either
/// the wait's deadline has passed (no request is issued at all) or the
/// request stalled and was cut -- so the caller retries on the next tick
/// instead of letting the request consume the wait.
pub(crate) async fn bounded_wait_attempt<T>(
    wait_deadline: Instant,
    request: impl std::future::Future<Output = T>,
) -> Option<T> {
    let budget = wait_attempt_budget(wait_deadline);
    if budget.is_zero() {
        // The wait's deadline has already passed: a response arriving now
        // could only land after the budget is gone, so skip the request.
        return None;
    }
    tokio::time::timeout(budget, request).await.ok()
}

/// A [`tokio::task::JoinHandle`] that aborts its task when dropped
/// (cap#220 review follow-up): a dropped `JoinHandle` detaches its task, so
/// a plain handle would let a stalled history lookup hold its connection
/// until the API client's 900-second request timeout after the enclosing
/// wait has already returned. Every exit from a request -- supersession,
/// a dropped `take_landed` join, or the probe dropping with its wait --
/// therefore cancels the lookup instead of orphaning it.
struct AbortOnDropHandle<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> AbortOnDropHandle<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    fn is_finished(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
    }

    fn abort(&self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }

    /// Await the task's outcome. The handle stays inside the wrapper while
    /// joining, so a dropped or cancelled join still aborts the task through
    /// [`Drop`] instead of detaching it.
    async fn join(&mut self) -> Option<Result<T, tokio::task::JoinError>> {
        Some(self.0.as_mut()?.await)
    }
}

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// One detached deployment-history request ([`DeploymentHistoryProbe`]): the
/// handle stays in flight across wait-loop iterations, so a slow answer is
/// still observed when it lands instead of being cancelled at a budget.
struct HistoryRequest {
    issued_at: Instant,
    handle: AbortOnDropHandle<Result<Vec<DeploymentEntry>, ApiError>>,
}

/// Supersession depth for detached history requests: a request stays in
/// flight across at most this many [`WAIT_ATTEMPT_BUDGET`] refresh windows
/// before a newer one may replace it. That bounds sockets on a stalled
/// endpoint while still observing any response slower than the attempt
/// budget (see [`DeploymentHistoryProbe`]).
const HISTORY_MAX_IN_FLIGHT: usize = 3;

/// Polling granularity for the successful-exit pickup
/// ([`DeploymentHistoryProbe::take_landed_within`]): how often a pending
/// handle is checked while the exit waits, bounded by the pickup budget.
const LANDED_PICKUP_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Detached deployment-history observation for the wait loops (cap#220
/// review follow-ups).
///
/// Deployment history is the source of truth for the apply-start, health,
/// and terminal-failure checks, so its answers must be observed however slow
/// they are -- but no single request may consume the enclosing wait, and the
/// wait must keep retrying after the endpoint recovers. One synchronous
/// request cannot satisfy all three (the reviews alternated between "cut at
/// a small budget", which discards valid slower answers, and "wait up to the
/// deadline", which lets one stalled request block every retry), so history
/// requests are detached from the wait loop instead:
///
/// - a pump issues at most one new request per [`WAIT_ATTEMPT_BUDGET`] window
///   while older ones keep running, so an answer slower than the attempt
///   budget (e.g. 70s) is observed whenever it lands instead of being
///   cancelled at 60s -- any response arriving within
///   [`HISTORY_MAX_IN_FLIGHT`] refresh windows (~3 minutes) of its request
///   start is observed, and older pending requests are superseded;
/// - landed answers are returned to exactly one caller, whenever they land,
///   and a pump never blocks waiting for one, so a stalled history endpoint
///   cannot spend the wait's budget before the readiness polls behind the
///   check run (cap#220 review follow-up #2: a 30s template wait must still
///   poll its ready TEE endpoint);
/// - requests are only issued while the wait still has budget (a passed
///   deadline issues nothing), a landed answer is never dropped (a request
///   is only ever superseded while still pending), and the probe -- with
///   every request it holds -- is dropped when the wait returns.
pub(crate) struct DeploymentHistoryProbe {
    in_flight: VecDeque<HistoryRequest>,
    refresh_age: Duration,
}

impl DeploymentHistoryProbe {
    pub(crate) fn new() -> Self {
        Self::with_refresh_age(WAIT_ATTEMPT_BUDGET)
    }

    /// A probe with a non-default refresh window (tests exercise the
    /// supersession behavior without waiting out the real budget).
    fn with_refresh_age(refresh_age: Duration) -> Self {
        Self {
            in_flight: VecDeque::new(),
            refresh_age,
        }
    }

    /// Keep the observation current: issue a detached request when none is
    /// in flight or the newest one is a refresh window old, applying the
    /// overflow supersession policy. A passed wait deadline issues nothing.
    ///
    /// The supersession check runs on *every* pump, not only when a refresh
    /// is due (cap#220 review follow-up): the successful-exit gate issues
    /// and consumes a fresh request per iteration, which keeps the newest
    /// request younger than the refresh window -- so a pump that only
    /// retired stale requests when issuing new ones would never retire a
    /// request that stalled before the gate.
    fn ensure_request(&mut self, api: &ApiClient, app_name: &str, wait_deadline: Instant) {
        if wait_attempt_budget(wait_deadline).is_zero() {
            return;
        }
        self.supersede_overflow();
        let refresh_due = self
            .in_flight
            .back()
            .is_none_or(|request| request.issued_at.elapsed() >= self.refresh_age);
        if !refresh_due {
            return;
        }
        self.push_request(api, app_name);
        self.supersede_overflow();
    }

    /// Issue a detached request now, ignoring the refresh cadence
    /// (cap#220 review follow-up): a successful exit needs a *current*
    /// observation, and the newest answer the probe already holds may
    /// predate the deployment's failure -- a pre-gate non-failure is not
    /// authority. This never supersedes older pending lookups (cap#220
    /// review): at a successful exit any of them may be the request about to
    /// report the failure, so they get their full chance to land inside the
    /// gate's settle budget; only the wait loop's next pump applies the
    /// overflow policy, after that budget has passed. A passed wait deadline
    /// issues nothing.
    fn force_request(&mut self, api: &ApiClient, app_name: &str, wait_deadline: Instant) {
        if wait_attempt_budget(wait_deadline).is_zero() {
            return;
        }
        self.push_request(api, app_name);
    }

    /// One detached lookup.
    fn push_request(&mut self, api: &ApiClient, app_name: &str) {
        let api = api.clone();
        let app_name = app_name.to_owned();
        self.in_flight.push_back(HistoryRequest {
            issued_at: Instant::now(),
            handle: AbortOnDropHandle::new(tokio::spawn(async move {
                api.list_deployments(&app_name).await
            })),
        });
    }

    /// The pump's overflow policy: bound sockets on a stalled endpoint while
    /// still observing any response slower than the refresh cadence.
    ///
    /// Requests are superseded by *age*, not just by count (cap#220 review
    /// follow-up): a stalled request only ever hits the depth limit when the
    /// endpoint stays silent, but the successful-exit gate consumes every
    /// fresh answer it issues, so a healthy endpoint keeps the queue below
    /// the depth limit indefinitely -- and a request that stalled *before*
    /// the gate would then survive forever, blocking every later gate with
    /// `Inconclusive` until the wait's deadline (the exact bug the review
    /// reported). Aging out at [`HISTORY_MAX_IN_FLIGHT`] refresh windows
    /// gives every request the same bounded lifetime (~3 minutes) the depth
    /// policy intended, independently of how often answers land, while the
    /// landed-answer guard still applies: a finished request is never
    /// superseded (its answer is picked up unobserved-dropping-free by the
    /// next `take_landed`), and aborting a task that already finished is a
    /// no-op anyway.
    fn supersede_overflow(&mut self) {
        let max_age = self.refresh_age * (HISTORY_MAX_IN_FLIGHT as u32);
        while let Some(front) = self.in_flight.front() {
            // Never supersede a landed answer: its result would be dropped
            // unobserved. A finished request is picked up on the next
            // `take_landed`, one per call, before any further supersession.
            if front.handle.is_finished() {
                break;
            }
            // Age bound (cap#220 review follow-up): a request older than
            // `HISTORY_MAX_IN_FLIGHT` refresh windows is retired even below
            // the depth limit. The depth check alone never fires while the
            // successful-exit gate keeps consuming the fresh answers it
            // issues, so a request that stalled before the gate would
            // otherwise stay pending forever and hold every later gate at
            // `Inconclusive` until the wait's deadline.
            let over_depth = self.in_flight.len() > HISTORY_MAX_IN_FLIGHT;
            let expired = front.issued_at.elapsed() >= max_age;
            if !over_depth && !expired {
                break;
            }
            if let Some(superseded) = self.in_flight.pop_front() {
                superseded.handle.abort();
            }
        }
    }

    /// Consume one landed observation, without blocking: `None` means no
    /// answer has landed since the previous call (still in flight, or the
    /// request was cancelled/panicked -- indistinguishable from "no
    /// observation", so the caller keeps waiting and the wait's own deadline
    /// governs).
    async fn take_landed(&mut self) -> Option<(Instant, Result<Vec<DeploymentEntry>, ApiError>)> {
        let index = self
            .in_flight
            .iter()
            .position(|request| request.handle.is_finished())?;
        let mut request = self.in_flight.remove(index)?;
        // A cancelled or panicked task surfaces as `Err` and reads as "no
        // observation", exactly like `take_landed`'s `None`.
        match request.handle.join().await {
            Some(Ok(result)) => Some((request.issued_at, result)),
            Some(Err(_)) | None => None,
        }
    }

    /// Consume observations for a successful wait exit (cap#220 review
    /// follow-up): every answer that lands within `budget`, waiting while
    /// requests are still in flight. Two properties the exit gate needs:
    ///
    /// - a landed answer is never dropped unobserved -- `on_landed` sees it
    ///   the moment it lands (with the request's issue time, so the gate can
    ///   tell a current answer from a stale one), so a failure answer is
    ///   reported right away instead of after the rest settles;
    /// - a pending request keeps the exit waiting, so a stale non-failure
    ///   answer can never authorize success while the request that would
    ///   show the current state is still in flight.
    ///
    /// `on_landed` returns `false` to stop the settle immediately (a
    /// terminal failure needs no further observation). `budget` expires
    /// with requests still pending (a stalled history endpoint): the
    /// returned `bool` says whether everything settled (`true`) or the
    /// budget ran out with answers still pending (`false`) -- the caller
    /// must treat the latter as an inconclusive observation, never as
    /// authority for success.
    async fn take_settled_within(
        &mut self,
        budget: Duration,
        mut on_landed: impl FnMut(Instant, Result<Vec<DeploymentEntry>, ApiError>) -> bool,
    ) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            while let Some((issued_at, result)) = self.take_landed().await {
                if !on_landed(issued_at, result) {
                    return false;
                }
            }
            if self.in_flight.is_empty() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            tokio::time::sleep(remaining.min(LANDED_PICKUP_POLL_INTERVAL)).await;
        }
    }
}

impl Default for DeploymentHistoryProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Fail fast when CAP has already terminalized the deployment we are waiting
/// on (#18): a manifest-apply rejection (e.g. the KBS signed-policy byte
/// budget) otherwise surfaces only as an opaque wait timeout ~10 minutes
/// later. Shared by the standalone `app deploy` waits and the hosted
/// template deploy flow. The history lookup is a non-blocking pickup from
/// the detached probe (cap#220 review follow-ups): the check issues a
/// request and consumes an answer only if one has landed, so it can never
/// spend the enclosing wait's budget on a stalled history endpoint before
/// the readiness polls behind it run -- while a slow-but-valid answer (the
/// one that carries the #18 rejection) is still observed when it lands.
pub(crate) async fn fail_if_template_deployment_failed(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    wait_deadline: Instant,
    history: &mut DeploymentHistoryProbe,
) -> Result<(), Box<dyn std::error::Error>> {
    if deployment_id == "pending" {
        return Ok(());
    }
    match template_deployment_failure(api, app_name, deployment_id, wait_deadline, history).await {
        Ok(Some(message)) => Err(message.into()),
        Ok(None) => Ok(()),
        Err(error) if should_retry_template_deployment_status_error(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Classify one deployment-history answer for `deployment_id`: `Ok(Some)` is
/// the terminal-failure message when the answer records the deployment as
/// `failed`. Shared by the per-iteration failure check and the
/// successful-exit reconciliation (cap#220 review follow-up) so both report
/// exactly the same terminal error.
fn deployment_history_failure(
    result: Result<Vec<DeploymentEntry>, ApiError>,
    deployment_id: &str,
) -> Result<Option<String>, ApiError> {
    let deployment = result?
        .into_iter()
        .find(|deployment| deployment.id == deployment_id);
    Ok(deployment
        .as_ref()
        .filter(|deployment| deployment.status == "failed")
        .map(|deployment| template_deployment_failure_message(deployment, deployment_id)))
}

async fn template_deployment_failure(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    wait_deadline: Instant,
    history: &mut DeploymentHistoryProbe,
) -> Result<Option<String>, ApiError> {
    // Non-blocking pickup from the detached history probe (cap#220 review
    // follow-ups): the request runs past any per-attempt budget, so a
    // slow-but-valid answer -- including the issue #18 rejection -- is
    // observed when it lands, while a stalled endpoint costs this check
    // nothing and the readiness polls still run every iteration.
    history.ensure_request(api, app_name, wait_deadline);
    let Some((_issued_at, result)) = history.take_landed().await else {
        return Ok(None);
    };
    deployment_history_failure(result, deployment_id)
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

pub(crate) fn should_retry_template_deployment_status_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(error) => should_retry_api_transport_error(error),
        // A malformed or oversized body will not improve on retry.
        ApiError::Decode(_) | ApiError::ResponseTooLarge(_) => false,
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

/// Outcome of the successful-exit gate
/// ([`reconcile_success_with_deployment_history`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SuccessGate {
    /// A *current* observation (a request issued at the gate) landed and
    /// shows this deployment present and not failed, with every pending
    /// lookup settled: the success is authorized.
    Confirmed,
    /// No conclusive current observation: the fresh request never landed
    /// within the settle budget, or landed without this deployment's row, or
    /// its lookup failed transiently. The caller keeps the wait running and
    /// the enclosing deadline governs (cap#220 review follow-up): a stalled
    /// or flaky history endpoint may delay a ready deploy to its deadline --
    /// the safe side of the bug this gate exists for -- but success is never
    /// claimed without the observation that rules out a failed deployment.
    Inconclusive,
}

/// Gate a wait's successful exit on deployment history (cap#220 review
/// follow-up). Readiness alone must not end a wait: a failed deployment can
/// otherwise proceed to ownership handling before its history answer lands
/// and the terminal error is never reported. Success is authorized only on a
/// conclusive current observation; the gate settles the probe's requests
/// before returning its three-way verdict:
///
/// - it always asks for a *current* observation first: the newest answer
///   the probe already holds may predate the deployment's failure (a
///   pre-gate non-failure is not authority), so a fresh request goes out at
///   the exit regardless of the refresh cadence;
/// - every landed answer is consumed and reported the moment it lands -- a
///   landed failure is never dropped unobserved and never waits on the rest;
/// - a pending request keeps the exit waiting, so a stale non-failure
///   answer can never authorize success while the request that would show
///   the current state is still in flight;
/// - [`SuccessGate::Confirmed`] requires the fresh answer to land showing
///   the deployment present and not failed, with nothing else pending.
///   Pending, a missing row, a transient lookup error, or budget expiry is
///   [`SuccessGate::Inconclusive`]: the caller keeps the wait and its probe
///   running (nothing is aborted) and the enclosing deadline produces the
///   timeout. The settle is bounded by one per-attempt budget
///   ([`wait_attempt_budget`], 60 seconds, min'd with the wait's remaining
///   time), so an inconclusive exit never consumes more than one attempt.
pub(crate) async fn reconcile_success_with_deployment_history(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    wait_deadline: Instant,
    history: &mut DeploymentHistoryProbe,
) -> Result<SuccessGate, Box<dyn std::error::Error>> {
    if deployment_id == "pending" {
        return Ok(SuccessGate::Confirmed);
    }
    let entry_at = Instant::now();
    history.force_request(api, app_name, wait_deadline);
    let mut failure: Option<Box<dyn std::error::Error>> = None;
    let mut fresh_confirmed = false;
    let settled = history
        .take_settled_within(wait_attempt_budget(wait_deadline), |issued_at, result| {
            let current = issued_at >= entry_at;
            match result {
                Ok(entries) => match entries.into_iter().find(|d| d.id == deployment_id) {
                    Some(deployment) if deployment.status == "failed" => {
                        failure = Some(
                            template_deployment_failure_message(&deployment, deployment_id).into(),
                        );
                        false
                    }
                    Some(_) => {
                        // Only the fresh request's non-failure is authority;
                        // a stale one may predate the failure.
                        fresh_confirmed |= current;
                        true
                    }
                    // A missing row is never authority (cap#220 review
                    // follow-up): without the entry we cannot rule out that
                    // this deployment is the failed one.
                    None => true,
                },
                // A transient lookup error reads as "no observation", the
                // same retry predicate as the per-iteration check -- but it
                // can never authorize success either (cap#220 review
                // follow-up): a conclusive exit needs a landed non-failure
                // for this deployment id.
                Err(error) if should_retry_template_deployment_status_error(&error) => true,
                Err(error) => {
                    failure = Some(error.into());
                    false
                }
            }
        })
        .await;
    match failure {
        Some(error) => Err(error),
        None => Ok(if fresh_confirmed && settled {
            SuccessGate::Confirmed
        } else {
            SuccessGate::Inconclusive
        }),
    }
}

async fn find_deployment_entry(
    api: &ApiClient,
    app_name: &str,
    deployment_id: &str,
    wait_deadline: Instant,
    history: &mut DeploymentHistoryProbe,
) -> Result<Option<DeploymentEntry>, ApiError> {
    // Non-blocking pickup from the detached history probe (cap#220 review
    // follow-ups): the apply-start and health waits learn deployment state
    // only through this lookup, so its request must survive past any
    // per-attempt budget -- a slow-but-valid `healthy` answer is observed
    // when it lands instead of being cancelled and turning the wait into a
    // false timeout.
    history.ensure_request(api, app_name, wait_deadline);
    let Some((_issued_at, result)) = history.take_landed().await else {
        return Ok(None);
    };
    Ok(result?
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
    let mut history = DeploymentHistoryProbe::new();
    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Deployment apply timed out");
            return Err(format!(
                "deployment {deployment_id} for app {app_name} did not start applying within {}; run `enclava status --app {app_name}` for the latest state",
                format_duration(max_wait)
            )
            .into());
        }

        match find_deployment_entry(api, app_name, deployment_id, start + max_wait, &mut history)
            .await
        {
            Ok(Some(deployment)) => match deployment.status.as_str() {
                "pending" => pb.set_message(timed_progress(
                    "Applying deployment: pending",
                    start.elapsed(),
                    max_wait,
                )),
                "failed" => {
                    let detail = deployment
                        .error_message
                        .as_deref()
                        .unwrap_or("deployment failed before apply");
                    return Err(format!("deployment {deployment_id} failed: {detail}").into());
                }
                _ => {
                    // A success exit must be authorized by a current
                    // deployment-state observation (cap#220 review
                    // follow-up): acting on the oldest landed answer and
                    // returning would drop a newer failure already landed or
                    // in flight, and an inconclusive observation keeps the
                    // wait running (the enclosing deadline governs).
                    if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                        api,
                        app_name,
                        deployment_id,
                        start + max_wait,
                        &mut history,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    pb.set_message(timed_progress(
                        "Applying deployment: confirming state",
                        start.elapsed(),
                        max_wait,
                    ));
                }
            },
            Ok(None) => pb.set_message(timed_progress(
                "Applying deployment: waiting for record",
                start.elapsed(),
                max_wait,
            )),
            Err(_) => pb.set_message(timed_progress(
                "Applying deployment: status check retrying",
                start.elapsed(),
                max_wait,
            )),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_deployment_completion(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let deployment_id = deployment.deployment_id;
    let start = Instant::now();
    let mut terminal_probe_at: Option<Instant> = None;
    let mut history = DeploymentHistoryProbe::new();
    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Workload health timed out");
            return Err(format!(
                "deployment {deployment_id} for app {app_name} did not become healthy within {}; run `enclava status --app {app_name}` for the latest state",
                format_duration(max_wait)
            )
            .into());
        }

        // Post-claim health wait: a terminal bootstrap diagnostic, bound to
        // this deployment via CAP before and after the attested probe, stops
        // the wait instead of polling to the deadline.
        if tee_terminal_diagnostic_probe_due(&mut terminal_probe_at)
            && let Some(diagnostic) = deployment_bound_terminal_bootstrap_error(
                api,
                app_name,
                deployment,
                start + max_wait,
            )
            .await
        {
            pb.abandon_with_message("TEE bootstrap failed");
            return Err(terminal_bootstrap_failure_message(app_name, &diagnostic).into());
        }

        match find_deployment_entry(api, app_name, deployment_id, start + max_wait, &mut history)
            .await
        {
            Ok(Some(deployment)) => match deployment.status.as_str() {
                "healthy" => {
                    // The final "Deployed and healthy" exit must be
                    // authorized by a current deployment-state observation
                    // (cap#220 review follow-up): acting on the oldest
                    // landed answer and returning would drop a newer failure
                    // already landed or in flight -- a false success, not
                    // just a delayed one -- and an inconclusive observation
                    // keeps the wait running (the enclosing deadline
                    // governs).
                    if let SuccessGate::Confirmed = reconcile_success_with_deployment_history(
                        api,
                        app_name,
                        deployment_id,
                        start + max_wait,
                        &mut history,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    pb.set_message(timed_progress(
                        "Workload health: confirming state",
                        start.elapsed(),
                        max_wait,
                    ));
                }
                "failed" => {
                    let detail = deployment
                        .error_message
                        .as_deref()
                        .unwrap_or("deployment failed");
                    return Err(format!("deployment {deployment_id} failed: {detail}").into());
                }
                "pending" | "applying" | "watching" => {
                    pb.set_message(timed_progress(
                        &format!("Workload health: {}", deployment.status),
                        start.elapsed(),
                        max_wait,
                    ));
                }
                other => {
                    pb.set_message(timed_progress(
                        &format!("Workload health: {other}"),
                        start.elapsed(),
                        max_wait,
                    ));
                }
            },
            Ok(None) => pb.set_message(timed_progress(
                "Workload health: waiting for deployment record",
                start.elapsed(),
                max_wait,
            )),
            Err(_) => pb.set_message(timed_progress(
                "Workload health: status check retrying",
                start.elapsed(),
                max_wait,
            )),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn ensure_password_storage_unlocked_for_config(
    api: &ApiClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
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
            wait_for_deploy_unlock_completion(api, &tee, app_name, deployment).await?;
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

pub(crate) fn tee_unlock_state(status: &serde_json::Value) -> &str {
    status
        .get("unlock_state")
        .or_else(|| status.get("state"))
        .or_else(|| status.get("ownership_state"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
}

pub(crate) fn tee_supplemental_fields_are_consistent(status: &serde_json::Value) -> bool {
    let live_state = tee_unlock_state(status);
    let optional_field_matches = |name: &str, expected: &str| match status.get(name) {
        None | Some(serde_json::Value::Null) => true,
        Some(value) => value
            .as_str()
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected)),
    };

    optional_field_matches("pod_status", "running")
        && optional_field_matches("tee_status", "ready")
        && optional_field_matches("storage_status", live_state)
}

async fn wait_for_deploy_unlock_completion(
    api: &ApiClient,
    tee: &TeeClient,
    app_name: &str,
    deployment: DeploymentWait<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        // The read runs under a budget capped to the remaining deadline: the
        // ownership client's own request timeout (900 s) must not be able to
        // hold this 300 s wait open.
        let status = match tee
            .bounded_status_json_within(terminal_diagnostic_budget(Some(deadline)))
            .await
        {
            Ok(status) => status,
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for unlock completion".into());
                }
                return Err(error.into());
            }
        };
        // An already-satisfied unlock wins over a stale terminal diagnostic;
        // otherwise a recognized terminal diagnostic parsed from this same
        // bounded status read over the attested channel stops the wait with
        // the stable code instead of spinning to the deadline -- but only
        // when CAP's evidence connects the endpoint to the expected
        // deployment.
        if tee_unlock_state(&status) != "unlocked"
            && let Some(diagnostic) = deployment_bound_terminal_bootstrap_error_on_channel(
                api, app_name, deployment, tee, deadline,
            )
            .await
        {
            return Err(terminal_bootstrap_failure_message(app_name, &diagnostic).into());
        }
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

pub(crate) async fn bounded_request<T>(
    deadline: Option<Instant>,
    request: impl Future<Output = T>,
) -> Option<T> {
    match deadline {
        None => Some(request.await),
        // A zero-duration timeout can still poll a ready request.
        Some(deadline) if deadline <= Instant::now() => None,
        Some(deadline) => {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), request)
                .await
                .ok()
        }
    }
}

pub(crate) async fn claim_initial_ownership(
    api: &ApiClient,
    paths: &CliPaths,
    app_name: &str,
    deployment: DeploymentWait<'_>,
    storage_password: &StoragePasswordInput,
    capture: MnemonicCapture,
    deadline: Option<Instant>,
) -> Result<(), Box<dyn std::error::Error>> {
    let active = match bounded_request(deadline, resolve_current_user_org(api)).await {
        Some(active) => active?,
        None => {
            return Err(
                "customer-config roll hold deadline reached with the org lookup still in \
                 flight; no ownership was claimed and the running workload was left unchanged"
                    .into(),
            );
        }
    };

    // Sink gate, before anything touches the TEE: the TEE returns the one-time
    // recovery mnemonic exactly once and rejects a second claim, so an unsafe
    // sink mode, an unattended session, or an unwritable keystore must abort
    // here, while the claim can still be cancelled without side effects. This
    // gates both `enclava deploy` and `enclava template deploy` auto-claims.
    crate::commands::ownership::prepare_recovery_mnemonic_sink(
        paths,
        &active.org_name,
        app_name,
        capture,
        storage_password.is_from_file(),
    )?;

    let endpoint = match bounded_request(deadline, api.get_unlock_endpoint(app_name)).await {
        Some(endpoint) => endpoint?,
        None => {
            return Err(
                "customer-config roll hold deadline reached with the ownership endpoint read \
                 still in flight; no ownership was claimed and the running workload was left \
                 unchanged"
                    .into(),
            );
        }
    };
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = match bounded_request(deadline, tee.attest_receipt_key()).await {
        Some(attestation) => attestation?,
        None => {
            return Err(
                "customer-config roll hold deadline reached with the TEE attestation still in \
                 flight; no ownership was claimed and the running workload was left unchanged"
                    .into(),
            );
        }
    };
    if !deployment.matches_launch_identity(tee.verified_launch_identity().as_ref()) {
        return Err(
            "TEE launch identity does not match the signed deployment; no ownership was claimed; retry the deployment"
                .into(),
        );
    }

    let challenge = match bounded_request(deadline, tee.bootstrap_challenge()).await {
        Some(challenge) => challenge?,
        None => {
            return Err(
                "customer-config roll hold deadline reached with the bootstrap challenge still \
                 in flight; no ownership was claimed and the running workload was left unchanged"
                    .into(),
            );
        }
    };

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

    // Never cancel an in-flight claim: its one-time mnemonic must be received
    // and persisted even if the hold expires. Check expiry again after saving.
    if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
        return Err(
            "customer-config roll hold expired before the ownership claim was sent; no \
             ownership was claimed and the running workload was left unchanged"
                .into(),
        );
    }

    let result = match tee
        .bootstrap_claim(&challenge.nonce, &bootstrap_pubkey, &signature, &password)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            // One safe status read decides the indeterminate-claim fallback:
            // an already-committed claim keeps the recovery-mnemonic halt (it
            // outranks everything, including a terminal diagnostic), while a
            // recognized terminal diagnostic replaces the raw transport
            // error. Never retry the claim and never regenerate identity.
            match tee
                .bootstrap_status_within(terminal_diagnostic_budget(deadline))
                .await
            {
                Ok(status) if status.claimed => {
                    return Err(
                        crate::commands::ownership::ownership_committed_recovery_backup_incomplete(
                            "the claim response was lost after the TEE committed ownership, so the \
                             one-time recovery mnemonic was never received"
                                .to_string(),
                        ),
                    );
                }
                Ok(status) => {
                    if status.terminal_bootstrap_error.is_some()
                        && let Some(diagnostic) =
                            deployment_bound_terminal_bootstrap_error_on_channel(
                                api,
                                app_name,
                                deployment,
                                &tee,
                                deadline.unwrap_or_else(|| {
                                    Instant::now() + TERMINAL_DIAGNOSTIC_PROBE_BUDGET
                                }),
                            )
                            .await
                    {
                        return Err(
                            terminal_bootstrap_failure_message(app_name, &diagnostic).into()
                        );
                    }
                    // Binding unproven: surface the original claim error
                    // rather than an unauthorized terminal decision.
                    return Err(error.into());
                }
                Err(_) => return Err(error.into()),
            }
        }
    };

    // Persist the one-time mnemonic to the prepared protected sink. The mnemonic
    // is never written to stdout/stderr; on failure this returns the
    // ownership-committed/incomplete-backup error and the deploy/template flow
    // halts rather than proceeding past a claim whose backup is incomplete.
    let mnemonic = result.mnemonic.ok_or_else(|| {
        crate::commands::ownership::ownership_committed_recovery_backup_incomplete(
            "the TEE's claim response contained no recovery mnemonic".to_string(),
        )
    })?;
    crate::commands::ownership::store_recovery_mnemonic_after_claim(
        paths,
        &active.org_name,
        app_name,
        &mnemonic,
    )?;

    if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
        return Err(
            "customer-config roll hold expired after the ownership claim committed and the \
             recovery mnemonic was stored; the customer-config roll was not released"
                .into(),
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
    let mut tee_acme_retry_after: Option<String> = None;
    if let Ok(endpoint) = api.get_unlock_endpoint(&app_name).await {
        let tee = TeeClient::new_for_ownership_with_resolve_ip(
            &endpoint.tee_url,
            endpoint.tee_resolve_ip,
        );
        if let Ok((_attestation, attested_tee)) = tee.attest_receipt_key().await
            && let Ok(tee_status_json) = attested_tee.status_json().await
        {
            tee_acme_retry_after = tee_status_json
                .get("acme_retry_after")
                .and_then(|value| value.as_str())
                .map(str::to_string);
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
            if status.tee_error.is_none() {
                status.tee_error = tee_status_json
                    .get("error")
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
    if let Some(tee_error) = &status.tee_error {
        println!("TEE error: {}", tee_error.red());
    }
    if let Some(retry_after) = &tee_acme_retry_after {
        println!("TEE wait:  acme_rate_limited, retrying after {retry_after}");
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
    if let Some(deployment) = &status.deployment {
        print_deployment_diagnostics(deployment);
    }

    Ok(())
}

/// One owner-facing sentence for the common lifecycle states (#90). The
/// strings are fixed tokens from the API contract; only timing context is
/// appended, never provider or workload text.
fn deployment_condition_action(
    condition: &str,
    phase: Option<&str>,
    reason: Option<&str>,
) -> &'static str {
    if phase == Some("destroying") {
        // Deletion has no durable background job: the API distinguishes
        // finite lease quarantine (app_deleting) from poisoned fences
        // (app_deletion_blocked_by_poisoned_fence). Use the reason to
        // select the correct action.
        return match (condition, reason) {
            ("blocked_by_operation", _) => {
                "deletion stalled after the delete request ended; run the delete again to resume teardown"
            }
            ("waiting_external", Some("app_deletion_blocked_by_poisoned_fence")) => {
                "deletion blocked by a poisoned resource fence; contact support to clear namespace finalizers"
            }
            ("waiting_external", Some("app_deletion_abandoned_waiting_on_foreign_fence")) => {
                "deletion request expired while a foreign operation still holds the namespace; wait for the Blocked: deadline to pass, then re-run delete to resume"
            }
            ("waiting_external", _) => {
                "deletion in progress; wait for teardown to complete before creating it again"
            }
            _ => "the app is being deleted; wait for teardown to complete before creating it again",
        };
    }
    match condition {
        "progressing" => "wait; the deployment is making progress",
        "waiting_external" => {
            "wait; the platform will pick this deployment up automatically at the scheduled time"
        }
        "blocked_by_operation" => {
            "another operation owns this app's mutation lane; wait for it to finish or retry after it completes"
        }
        "stalled" => "no worker or retry schedule is recorded; contact support if this persists",
        "terminal" => match phase {
            Some("healthy") => "the deployment completed successfully",
            Some("cancelled") => "the deployment was superseded by a newer deployment",
            Some("rolled_back") => "the deployment was rolled back to a previous version",
            Some("failed") => {
                "the deployment failed; wait for any rollback to finish, then redeploy to try again"
            }
            _ => "the deployment failed; redeploy to try again",
        },
        _ => "lifecycle details are unavailable from this API instance",
    }
}

/// "3m ago" / "in 25s" style relative age for owner-facing timestamps.
/// Falls back to the raw timestamp when it cannot be parsed.
fn relative_time(timestamp: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|parsed| parsed.with_timezone(&chrono::Utc));
    match parsed {
        Ok(parsed) => {
            let delta = chrono::Utc::now().signed_duration_since(parsed);
            let seconds = delta.num_seconds();
            if seconds >= 0 {
                if seconds < 60 {
                    format!("{timestamp} ({seconds}s ago)")
                } else if seconds < 3600 {
                    format!("{timestamp} ({}m ago)", seconds / 60)
                } else {
                    format!("{timestamp} ({}h ago)", seconds / 3600)
                }
            } else {
                let seconds = -seconds;
                if seconds < 60 {
                    format!("{timestamp} (in {seconds}s)")
                } else if seconds < 3600 {
                    format!("{timestamp} (in {}m)", seconds / 60)
                } else {
                    format!("{timestamp} (in {}h)", seconds / 3600)
                }
            }
        }
        Err(_) => timestamp.to_string(),
    }
}

fn print_deployment_diagnostics(deployment: &DeploymentDiagnostics) {
    use colored::Colorize;
    let phase_colored = match deployment.condition.as_str() {
        "terminal" if deployment.phase == "failed" => deployment.phase.red().to_string(),
        "terminal" if deployment.phase == "healthy" => deployment.phase.green().to_string(),
        "progressing" | "waiting_external" => deployment.phase.yellow().to_string(),
        "stalled" | "blocked_by_operation" => deployment.phase.red().to_string(),
        _ => deployment.phase.yellow().to_string(),
    };
    println!("Deploy:   {phase_colored} ({})", deployment.condition);
    if let Some(reason) = &deployment.reason {
        println!("Reason:   {reason}");
    }
    if let Some(last_progress_at) = &deployment.last_progress_at {
        println!("Progress: {}", relative_time(last_progress_at));
    }
    if let Some(attempts) = deployment.attempts {
        println!("Attempts: {attempts}");
    }
    if let Some(next_retry_at) = &deployment.next_retry_at {
        println!("Retry:    {}", relative_time(next_retry_at));
    }
    if let Some(blocked_until) = &deployment.blocked_until {
        println!(
            "Blocked:  mutation lane admits retries after {}",
            relative_time(blocked_until)
        );
    }
    if let Some(blocking_operation) = &deployment.blocking_operation {
        println!("Holder:   {blocking_operation}");
    }
    if let Some(observing_since) = &deployment.observing_since {
        println!(
            "Watching: observing since {}",
            relative_time(observing_since)
        );
    }
    println!(
        "Action:   {}",
        deployment_condition_action(
            &deployment.condition,
            Some(&deployment.phase),
            deployment.reason.as_deref()
        )
    );
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
        let stream = resp.bytes_stream();
        let reader = tokio_util::io::StreamReader::new(
            stream.map(|result| result.map_err(std::io::Error::other)),
        );
        let mut reader = tokio::io::BufReader::new(reader);
        let mut line = String::new();
        while read_bounded_log_line(&mut reader, &mut line).await? != 0 {
            print_decrypted_log_frame(&private_key, &line)?;
        }
    } else {
        // A hostile API must not turn a buffered log read into unbounded memory use.
        let bytes = enclava_cli::api_client::read_bounded_body(
            resp,
            enclava_cli::api_client::MAX_API_RESPONSE_BODY_BYTES,
        )
        .await?;
        let body = String::from_utf8_lossy(&bytes);
        for line in body.lines() {
            print_decrypted_log_frame(&private_key, line)?;
        }
    }

    Ok(())
}

async fn read_bounded_log_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
) -> Result<usize, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};

    let limit = enclava_cli::api_client::MAX_API_RESPONSE_BODY_BYTES;
    line.clear();
    let read = reader.take((limit + 1) as u64).read_line(line).await?;
    if read > limit {
        return Err(enclava_cli::api_client::ApiError::ResponseTooLarge(limit).into());
    }
    Ok(read)
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
    if let Some(output) = decrypted_log_frame_output(private_key, line)? {
        println!("{output}");
    }
    Ok(())
}

fn decrypted_log_frame_output(
    private_key: &str,
    line: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    let frame: EncryptedLogFrame =
        serde_json::from_str(line).map_err(|err| format!("invalid encrypted log frame: {err}"))?;
    let plaintext = decrypt_log_frame(private_key, &frame).map_err(|err| {
        format!(
            "failed to decrypt log frame for key {}: {err}",
            frame.key_id
        )
    })?;
    let message = String::from_utf8_lossy(&plaintext);
    Ok(Some(format!(
        "{} {} {} {}",
        frame.timestamp,
        frame.container,
        frame.stream,
        sanitize_log_output(message.trim_end())
    )))
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "existing log private key {} has insecure permissions {mode:04o}; restrict it to owner-only access (for example, chmod 600)",
                path.display()
            )
            .into());
        }
    }
    #[cfg(windows)]
    enclava_cli::keys::verify_owner_only_acl(path).map_err(|err| {
        format!(
            "existing log private key {} is readable by other users ({err}); restrict it to owner-only access (icacls <path> /inheritance:r /grant:r <user>:F)",
            path.display()
        )
    })?;
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.open(path)
    }
    .map_err(|err| format!("failed to create log private key {}: {err}", path.display()))?;
    // Owner-only from the very first instant (DACL applied in the CreateFile
    // call), verified before the key material is written.
    #[cfg(windows)]
    let mut file = enclava_cli::keys::create_secret_file(path)
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
    /// Finish the destroy even if the confidential workload teardown cannot
    /// complete. The previous owner seed may remain in KBS; recreating this
    /// app name will be refused until it is erased.
    #[arg(long)]
    pub abandon_teardown: bool,
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

    let result = api
        .delete_app_with_options(&app_name, args.abandon_teardown)
        .await;
    if let Err(ApiError::Api { code, message, .. }) = &result
        && let Some(hint) = destroy_failure_hint(code.as_deref(), message, &app_name)
    {
        spinner.finish_with_message(format!("Destroy of '{app_name}' did not complete."));
        eprintln!("Hint: {hint}");
    }
    result?;

    spinner.finish_with_message(format!("App '{app_name}' destroyed."));

    if args.abandon_teardown {
        println!(
            "Note: destroy completed with --abandon-teardown, which proceeds past a failed workload teardown. If the teardown could not complete, the previous owner seed may remain in KBS and recreating '{app_name}' will be refused until an operator erases it and clears the recorded waiver; if the workload was already gone (or its teardown had completed), no waiver is recorded and recreation is unaffected."
        );
    }

    Ok(())
}

#[cfg(test)]
#[path = "app/tests/mod.rs"]
mod tests;

/// Operator guidance for a failed destroy, keyed on the stable API code (or
/// the in-band cause text hosted deferrals carry). Pure so the prose mapping
/// stays pinned by unit tests before other surfaces match on it.
fn destroy_failure_hint(code: Option<&str>, message: &str, app_name: &str) -> Option<String> {
    // Teardown failures either restore the app to its pre-delete state (the
    // delete is atomic) or leave it marked deleting when restoring would
    // misrepresent an app whose live operation was superseded; the error
    // body's `reason` tells the two apart (older servers without it get the
    // neutral wording). Without this hint the raw API code is the only
    // signal an operator gets. A hosted delete surfaces the locked teardown
    // only as the deferral cause on a generic in-progress error, so the
    // message carries it too.
    let teardown_cause = code == Some("app_delete_teardown_locked")
        || message.contains("app_delete_teardown_locked");
    if teardown_cause {
        return Some(format!(
            "the confidential workload is locked and the app remains intact; unlock it with its storage password (`enclava unlock --app {app_name}`), then retry destroy. If the unlock cannot reach the workload at all (the TEE endpoint never came up, e.g. every attempt fails the TEE TLS handshake -- not a transient network error), retrying will not help: contact the operator, or as a last resort `destroy --abandon-teardown` (it leaves the previous owner seed in KBS, which blocks recreating this app name until an operator cleans it up)"
        ));
    }
    match code {
        Some("app_delete_teardown_unavailable") => Some(if message.contains("(app_restored)") {
            "the confidential workload teardown did not complete and the app was restored to its previous state -- retry destroy when the workload becomes reachable, or contact the operator if it keeps failing".to_string()
        } else if message.contains("(app_kept_deleting)") {
            "the confidential workload teardown did not complete and the app remains in the deleting state -- it stays wired and the destroy is retryable once the workload becomes reachable, or use `destroy --abandon-teardown` once recovery is ruled out".to_string()
        } else {
            "the confidential workload teardown did not complete -- retry destroy when the workload becomes reachable, or contact the operator if it keeps failing".to_string()
        }),
        // Lane etiquette (#83/#194): the 409 answers either carry the
        // server's lease hints in `message` (held by / retry after) or
        // come from an older server without them -- the prose stays
        // neutral so both read correctly.
        Some("app mutation already in progress") => Some(
            "another operation holds this app's mutation lane (a deploy or an earlier delete); it retries automatically once free -- retry destroy shortly".to_string(),
        ),
        Some("idempotency_request_in_progress") => Some(
            "a previous destroy attempt is still settling its idempotency lease; retry destroy with the same command shortly".to_string(),
        ),
        _ => None,
    }
}
