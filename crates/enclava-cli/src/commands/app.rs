use clap::Args;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use clap::Subcommand;
use enclava_cli::api_client::{ApiClient, ApiError};
use enclava_cli::api_types::*;
use enclava_cli::app_config::AppConfig;
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

const DEPLOY_HEALTH_TIMEOUT_SECONDS: u64 = 900;

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
        egress_allowlist: app_config.egress.allow.clone(),
        signer_identity_subject,
        signer_identity_issuer,
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
    /// Return after the API accepts the deployment instead of waiting for runtime health.
    #[arg(long)]
    pub no_wait: bool,
    /// Set config key=value pairs delivered to TEE after boot
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub config_vars: Vec<String>,
    /// Set config key from a local file without exposing the value in process arguments.
    #[arg(long = "set-file", value_name = "KEY=PATH")]
    pub config_file_vars: Vec<String>,
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
    if let Ok(path) = std::env::var("ENCLAVA_DEBUG_DEPLOY_REQUEST_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&req)?)?;
    }

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

    if args.no_wait {
        pb.finish_with_message("Deployment accepted");
        println!();
        println!("  App:    {app_name}");
        println!("  URL:    https://{}", resp.app_domain);
        println!("  Deploy: {}", resp.deployment_id);
        println!("  Status: {}", resp.status);
        return Ok(());
    }

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
            claim_initial_ownership(&api, &paths, &cli_config, &app_name).await?;
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
                max_wait,
                poll_interval,
                &pb,
                runtime_target,
            )
            .await?;
            if deploy_should_unlock_before_config(is_password_mode, false, !config_pairs.is_empty())
            {
                ensure_password_storage_unlocked_for_config(&api, &app_name, &pb).await?;
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
            max_wait,
            poll_interval,
            &pb,
            runtime_target,
        )
        .await?;
        if deploy_should_unlock_before_config(is_password_mode, false, !config_pairs.is_empty()) {
            ensure_password_storage_unlocked_for_config(&api, &app_name, &pb).await?;
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
            .map(TeeClient::from_config_url)
            .unwrap_or_else(|| TeeClient::new(&resp.app_domain));
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

async fn wait_for_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_for_ownership(&endpoint.tee_url);
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
        .map(|endpoint| TeeClient::new_for_ownership(&endpoint.tee_url));

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for TEE boot");
            return Err("deploy timed out waiting for TEE to boot".into());
        }

        match api.get_status(app_name).await {
            Ok(status) => {
                if target.accepts_api_status(status.status.as_str()) {
                    pb.set_position(3);
                    pb.set_message(match status.status.as_str() {
                        "locked" => "TEE running, storage locked",
                        _ => "TEE running, attestation complete",
                    });
                    return Ok(());
                }

                match status.pod_phase.as_deref() {
                    Some("Running") if target.accepts_running_pod_phase() => {
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

        if let Some(tee) = direct_tee.as_ref()
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
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_for_ownership(&endpoint.tee_url);
    let (_attestation, tee) = tee.attest_receipt_key().await?;
    let status = tee.status_json().await?;
    let state = tee_unlock_state(&status);

    match state {
        "unlocked" => Ok(()),
        "locked" => {
            pb.set_message("Unlocking storage before config delivery...");
            let password = dialoguer::Password::new()
                .with_prompt("Unlock password")
                .interact()?;
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

async fn claim_initial_ownership(
    api: &ApiClient,
    paths: &CliPaths,
    _cli_config: &config::CliConfig,
    app_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_for_ownership(&endpoint.tee_url);
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

    let mut status = api.get_status(&app_name).await?;
    if let Ok(endpoint) = api.get_unlock_endpoint(&app_name).await {
        let tee = TeeClient::new_for_ownership(&endpoint.tee_url);
        if let Ok((_attestation, attested_tee)) = tee.attest_receipt_key().await
            && let Ok(tee_status_json) = attested_tee.status_json().await
        {
            let state = tee_unlock_state(&tee_status_json);
            match state {
                "locked" => status.status = "locked".to_string(),
                "unlocked" if status.status == "running" => {}
                "unclaimed" if status.status == "failed" => status.status = "creating".to_string(),
                _ => {}
            }
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

    let resp = match api.get_logs(&app_name, args.follow).await {
        Ok(resp) => resp,
        Err(ApiError::Api {
            status: 501,
            message,
        }) => {
            println!("{message}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

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
        match serde_json::from_str::<Vec<LogLine>>(&body) {
            Ok(lines) => {
                for line in lines {
                    println!(
                        "{} {} {}",
                        line.timestamp,
                        line.container,
                        line.message.trim_end()
                    );
                }
            }
            Err(_) => print!("{body}"),
        }
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
