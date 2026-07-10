use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Password};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{UnlockEndpointResponse, UpdateUnlockModeRequest};
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::keys;
use enclava_cli::tee_client::{TeeClient, TeeError};
use enclava_engine::types::WorkloadSecurityProfile;
use uuid::Uuid;

#[derive(Args)]
pub struct ClaimArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Persist the recovery mnemonic so `enclava key backup` can back it up (default).
    #[arg(long, conflicts_with = "no_store_mnemonic")]
    pub store_mnemonic: bool,
    /// Do NOT persist the recovery mnemonic (shown once only; opt out of backup coverage).
    #[arg(long, conflicts_with = "store_mnemonic")]
    pub no_store_mnemonic: bool,
}

#[derive(Args)]
pub struct UnlockArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Args)]
pub struct RecoverArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Read the recovery mnemonic from a file (non-interactive; BIP39, whitespace-trimmed).
    #[arg(long)]
    pub mnemonic_file: Option<PathBuf>,
    /// Read the new unlock password from a file (non-interactive; trailing newline trimmed).
    #[arg(long)]
    pub new_password_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct ChangePasswordArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Subcommand)]
pub enum AutoUnlockCommand {
    /// Seal owner seed with VMPCK for automatic restart
    Enable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Digest-pinned container image to bind into the signed redeploy descriptor.
        #[arg(long)]
        image: String,
    },
    /// Remove sealed seed, require password on restart
    Disable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Digest-pinned container image to bind into the signed redeploy descriptor.
        #[arg(long)]
        image: String,
    },
}

/// Resolve app name from --app flag or enclava.toml.
fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

/// Get the TEE endpoint for an app by querying the API.
async fn resolve_tee_endpoint(
    api: &ApiClient,
    app_name: &str,
) -> Result<UnlockEndpointResponse, Box<dyn std::error::Error>> {
    Ok(api.get_unlock_endpoint(app_name).await?)
}

/// Build an authenticated API client from stored config/credentials.
fn build_api_client() -> Result<(ApiClient, CliPaths), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths))
}

fn load_or_derive_bootstrap_private_key(
    paths: &CliPaths,
    org_name: &str,
    org_id: Uuid,
    app_name: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let key_path = paths.bootstrap_key_path(org_name, app_name);
    if key_path.exists() {
        let private_key_hex = std::fs::read_to_string(&key_path)?;
        return hex::decode(private_key_hex.trim())
            .map_err(|e| format!("invalid bootstrap key format: {e}"))?
            .try_into()
            .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)".into());
    }

    let seed = keys::load_recovery_seed(paths)?.ok_or(
        "bootstrap key is missing and no recovery seed is available; run `enclava key restore <backup>`",
    )?;
    let app_seed = keys::derive_app_bootstrap_seed(org_id, app_name, &seed)?;
    config::save_bootstrap_key(paths, org_name, app_name, &hex::encode(app_seed))?;
    Ok(app_seed)
}

pub async fn claim(args: ClaimArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, paths) = build_api_client()?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    println!("Claiming ownership of {app_name}...");

    // Step 1: Get challenge from TEE
    let challenge = tee.bootstrap_challenge().await?;
    println!("Challenge received (expires in {}s)", challenge.ttl_seconds);

    // Step 2: Load or re-derive the deterministic bootstrap keypair.
    let me = api.get_current_user().await?;
    let org_id = Uuid::parse_str(&me.active_org.id)?;
    let private_key_bytes =
        load_or_derive_bootstrap_private_key(&paths, &me.active_org.name, org_id, &app_name)?;

    // Step 3: Sign challenge with Ed25519 bootstrap keypair
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();

    // The TEE challenge is base64url-encoded bytes. Sign the decoded challenge
    // bytes, matching the attestation-proxy verifier.
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge.nonce.as_bytes())
        .map_err(|e| format!("invalid bootstrap challenge encoding: {e}"))?;
    let signature_bytes = signing_key.sign(&challenge_bytes);

    let bootstrap_pubkey = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature_bytes.to_bytes());

    // Step 4: Get password
    let password = Password::new()
        .with_prompt("Set unlock password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    // Step 5: Claim
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

    println!("Ownership claimed.");

    let capture = if args.no_store_mnemonic {
        MnemonicCapture::Skip
    } else {
        MnemonicCapture::Store
    };
    if let Some(mnemonic) = result.as_ref().and_then(|result| result.mnemonic.as_ref()) {
        present_and_capture_recovery_mnemonic_or_warn(
            &paths,
            &me.active_org.name,
            &app_name,
            mnemonic,
            capture,
            RecoveryMnemonicOutput::Stdout,
        );
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryMnemonicOutput {
    Stdout,
    Stderr,
}

/// Operator's choice on whether to persist a freshly-observed recovery mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MnemonicCapture {
    /// Persist to local state so `key backup` can include it (default).
    Store,
    /// Do not persist; the mnemonic is shown once only.
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryMnemonicCaptureAction {
    PromptToStore,
    Store,
    Skip,
}

fn store_mnemonic_local(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    keys::store_app_mnemonic(paths, org, app, mnemonic)
        .map_err(|e| format!("failed to store recovery mnemonic: {e}").into())
}

/// Present the one-time LUKS recovery mnemonic and, by default, persist it to local
/// state so `enclava key backup` can bundle it with the deploy keys.
///
/// The `capture` flag is authoritative: `--no-store-mnemonic` never prompts to store,
/// even on an interactive terminal. Otherwise, interactive terminals ask whether to store
/// (default yes); declining runs the standard "I have recorded it" confirmation gate.
/// Off-TTY the `capture` flag decides (`Store` by default), because no prompt is possible.
///
/// Returns an error only on write/prompt failure (e.g. EOF at the prompt); callers past
/// an irreversible server-side action should use
/// [`present_and_capture_recovery_mnemonic_or_warn`].
pub(crate) fn present_and_capture_recovery_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
    capture: MnemonicCapture,
    output: RecoveryMnemonicOutput,
) -> Result<(), Box<dyn std::error::Error>> {
    match output {
        RecoveryMnemonicOutput::Stdout => {
            let mut stdout = io::stdout().lock();
            write_recovery_mnemonic(&mut stdout, mnemonic)?;
            stdout.flush()?;
        }
        RecoveryMnemonicOutput::Stderr => {
            let mut stderr = io::stderr().lock();
            write_recovery_mnemonic(&mut stderr, mnemonic)?;
            stderr.flush()?;
        }
    }

    if capture == MnemonicCapture::Skip {
        debug_assert_eq!(
            recovery_mnemonic_capture_action(capture, recovery_mnemonic_confirmation_available()),
            RecoveryMnemonicCaptureAction::Skip
        );
    }

    match recovery_mnemonic_capture_action(capture, recovery_mnemonic_confirmation_available()) {
        RecoveryMnemonicCaptureAction::PromptToStore => {
            let want_store = Confirm::new()
                .with_prompt("Store this recovery mnemonic so `enclava key backup` can back it up?")
                .default(true)
                .interact()?;
            if want_store {
                store_mnemonic_local(paths, org, app, mnemonic)?;
                eprintln!(
                    "Recovery mnemonic stored locally. Run `enclava key backup` and keep that file OFF this machine — the local copy is lost if this machine is lost."
                );
                return Ok(());
            }
            // Declined: the operator keeps it offline, so require the standard acknowledgement.
            confirm_recovery_mnemonic_recorded()?;
            eprintln!("Recovery mnemonic not stored. It will not be shown again.");
        }
        RecoveryMnemonicCaptureAction::Store => {
            store_mnemonic_local(paths, org, app, mnemonic)?;
            eprintln!(
                "Recovery mnemonic stored locally (non-interactive default). Run `enclava key backup` and keep that file OFF this machine — the local copy is lost if this machine is lost."
            );
        }
        RecoveryMnemonicCaptureAction::Skip => {
            confirm_recovery_mnemonic_recorded()?;
            eprintln!(
                "Recovery mnemonic not stored (--no-store-mnemonic). Record it now; it will not be shown again."
            );
        }
    }
    Ok(())
}

/// Like [`present_and_capture_recovery_mnemonic`] but downgrades any presentation failure
/// to a loud stderr warning instead of an error. Use this — not the fallible form — from
/// flows that run *after* the TEE has accepted ownership (`claim`, `claim_initial_ownership`
/// via `deploy`/template deploy): ownership is already recorded server-side, so mnemonic
/// handling must never turn a successful claim into a reported failure. On failure the
/// mnemonic is re-printed as a fallback.
pub(crate) fn present_and_capture_recovery_mnemonic_or_warn(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
    capture: MnemonicCapture,
    output: RecoveryMnemonicOutput,
) {
    if let Err(err) =
        present_and_capture_recovery_mnemonic(paths, org, app, mnemonic, capture, output)
    {
        let mut stderr = io::stderr().lock();
        emit_recovery_mnemonic_interrupted_warning(&mut stderr, mnemonic, &*err);
    }
}

/// Best-effort warning for when recovery-mnemonic presentation is interrupted. This is
/// a last-resort fallback (the claim already succeeded), so further IO errors are ignored.
fn emit_recovery_mnemonic_interrupted_warning(
    output: &mut impl Write,
    mnemonic: &str,
    err: &dyn std::error::Error,
) {
    let _ = writeln!(
        output,
        "WARNING: ownership was claimed, but the one-time recovery mnemonic could not be fully presented ({err})."
    );
    let _ = writeln!(
        output,
        "It is NOT stored anywhere by the CLI; re-printing it here as a fallback - record it now:"
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "    {mnemonic}");
    let _ = writeln!(output);
}

fn write_recovery_mnemonic(
    output: &mut impl Write,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(output)?;
    writeln!(
        output,
        "==================== RECOVERY MNEMONIC (shown ONCE) ===================="
    )?;
    writeln!(
        output,
        "This is the ONLY recovery for your encrypted storage."
    )?;
    writeln!(
        output,
        "Store it now (the default) and `enclava key backup` can bundle it with your deploy keys; if you skip, it is stored nowhere."
    )?;
    writeln!(
        output,
        "If you lose this AND your storage password, your data cannot be recovered."
    )?;
    writeln!(output)?;
    writeln!(output, "    {mnemonic}")?;
    writeln!(output)?;
    Ok(())
}

fn confirm_recovery_mnemonic_recorded() -> Result<(), Box<dyn std::error::Error>> {
    if !recovery_mnemonic_confirmation_available() {
        return Ok(());
    }

    loop {
        let confirmed = Confirm::new()
            .with_prompt("I have recorded my recovery mnemonic")
            .default(false)
            .interact()?;
        if confirmed {
            return Ok(());
        }
        eprintln!("Please record it now; it will not be shown again after this command exits.");
    }
}

fn recovery_mnemonic_confirmation_available() -> bool {
    recovery_mnemonic_confirmation_required(io::stdin().is_terminal(), io::stderr().is_terminal())
}

fn recovery_mnemonic_confirmation_required(
    stdin_is_terminal: bool,
    prompt_is_terminal: bool,
) -> bool {
    stdin_is_terminal && prompt_is_terminal
}

fn recovery_mnemonic_storage_prompt_required(
    capture: MnemonicCapture,
    confirmation_available: bool,
) -> bool {
    capture == MnemonicCapture::Store && confirmation_available
}

fn recovery_mnemonic_capture_action(
    capture: MnemonicCapture,
    confirmation_available: bool,
) -> RecoveryMnemonicCaptureAction {
    if capture == MnemonicCapture::Skip {
        RecoveryMnemonicCaptureAction::Skip
    } else if recovery_mnemonic_storage_prompt_required(capture, confirmation_available) {
        RecoveryMnemonicCaptureAction::PromptToStore
    } else {
        RecoveryMnemonicCaptureAction::Store
    }
}

pub async fn unlock(args: UnlockArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let password = Password::new().with_prompt("Unlock password").interact()?;

    println!("Unlocking {app_name}...");
    tee.unlock(&password).await?;
    wait_for_unlock_completion(&tee).await?;
    println!("Storage unlocked. App is starting.");
    Ok(())
}

async fn wait_for_unlock_completion(tee: &TeeClient) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let status = tee.status_json().await?;
        let state = status
            .get("state")
            .or_else(|| status.get("unlock_state"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        match state {
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

pub async fn recover(args: RecoverArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, paths) = build_api_client()?;
    let me = api.get_current_user().await?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let is_tty = io::stdin().is_terminal();

    // Resolve the initial mnemonic. Priority: --mnemonic-file, then the local
    // store (TTY confirms; headless uses it silently), then an interactive prompt.
    let from_file = match args.mnemonic_file.as_ref() {
        Some(path) => Some(read_mnemonic_file(path)?),
        None => None,
    };
    let mut mnemonic = match (
        from_file,
        keys::load_app_mnemonic(&paths, &me.active_org.name, &app_name)?,
    ) {
        (Some(from_file), _) => from_file,
        (None, Some(stored)) if is_tty => {
            let use_stored = Confirm::new()
                .with_prompt(format!("Use the stored recovery mnemonic for {app_name}?"))
                .default(true)
                .interact()?;
            if use_stored {
                stored
            } else {
                prompt_recovery_mnemonic()?
            }
        }
        (None, Some(stored)) => stored,
        (None, None) if is_tty => prompt_recovery_mnemonic()?,
        (None, None) => {
            return Err(format!(
                "no stored recovery mnemonic for {app_name}; pass --mnemonic-file, run `enclava key restore <backup>` first, or run this command in an interactive shell"
            )
            .into());
        }
    };

    let new_password = match args.new_password_file.as_ref() {
        Some(path) => read_new_password_file(path)?,
        None => Password::new()
            .with_prompt("New unlock password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?,
    };

    println!("Recovering {app_name}...");
    // A stored/provided mnemonic may be stale (e.g. the app was destroyed and
    // redeployed, minting a fresh one). On mnemonic_invalid, retry from a fresh
    // prompt on a TTY; headless gets a clear, actionable error.
    loop {
        match tee.recover(&mnemonic, &new_password).await {
            Ok(()) => break,
            Err(err) if is_mnemonic_invalid(&err) && is_tty => {
                eprintln!(
                    "The recovery mnemonic was rejected by the TEE (mnemonic_invalid). \
                     It may be stale, e.g. if the app was destroyed and redeployed. \
                     Enter the correct mnemonic, or Ctrl-C to abort."
                );
                mnemonic = prompt_recovery_mnemonic()?;
            }
            Err(err) if is_mnemonic_invalid(&err) => {
                return Err(
                    "recovery mnemonic rejected by the TEE (mnemonic_invalid); it may be stale \
                     (e.g. after a destroy + redeploy). Provide the correct mnemonic via --mnemonic-file."
                        .into(),
                );
            }
            Err(err) => return Err(err.into()),
        }
    }
    println!("Recovery complete. Use the new password to unlock.");
    Ok(())
}

/// Read a BIP39 mnemonic from a file, trimming surrounding whitespace.
fn read_mnemonic_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("mnemonic file {} is empty", path.display()).into());
    }
    Ok(trimmed)
}

/// Read the new unlock password from a file, trimming a single trailing newline. Mirrors
/// `--storage-password-file`: no confirmation prompt when read from a file, and interior
/// whitespace is preserved (only `\r`/`\n` are stripped from the end).
fn read_new_password_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::fs::read_to_string(path)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if value.is_empty() {
        return Err(format!("new password file {} is empty", path.display()).into());
    }
    Ok(value)
}

/// True when a TEE recover error indicates the mnemonic was wrong/stale.
fn is_mnemonic_invalid(err: &TeeError) -> bool {
    match err {
        TeeError::Tee { message, .. } => message.contains("mnemonic_invalid"),
        _ => false,
    }
}

fn prompt_recovery_mnemonic() -> Result<String, Box<dyn std::error::Error>> {
    Ok(Input::new()
        .with_prompt("Recovery mnemonic (BIP39)")
        .interact_text()?)
}

pub async fn change_password(args: ChangePasswordArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee = TeeClient::new_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let current = Password::new().with_prompt("Current password").interact()?;

    let new_password = Password::new()
        .with_prompt("New password")
        .with_confirmation("Confirm new password", "Passwords don't match")
        .interact()?;

    println!("Changing password for {app_name}...");
    tee.change_password(&current, &new_password).await?;
    println!("Password changed.");
    Ok(())
}

pub async fn auto_unlock(cmd: AutoUnlockCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AutoUnlockCommand::Enable { app, image } => {
            let app_name = resolve_app_name(&app)?;
            let (api, paths) = build_api_client()?;
            let cli_config = config::load_config(&paths)?;
            let creds = config::load_credentials(&paths)?;
            let app_config = AppConfig::find_and_load()?;
            let app_meta = api.get_app(&app_name).await?;
            println!("Signing auto-unlock redeploy descriptor for {app_name}...");
            let signed_blobs =
                super::app::build_signed_deploy_blobs(super::app::SignedDeployBlobParams {
                    api: &api,
                    paths: &paths,
                    cli_config: &cli_config,
                    creds: &creds,
                    app: &app_meta,
                    app_config: &app_config,
                    image: &image,
                    target_unlock_mode: Some("auto"),
                    workload_security_profile: WorkloadSecurityProfile::Restricted,
                })
                .await?;
            let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
            let tee = TeeClient::new_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
            let (transition_attestation, tee) = tee.attest_receipt_key().await?;

            let password = Password::new()
                .with_prompt("Unlock password (to authorize sealing)")
                .interact()?;

            println!("Enabling auto-unlock for {app_name}...");
            tee.enable_auto_unlock(&password).await?;
            println!("Sealed seed written inside the TEE.");

            let transition_receipt = tee
                .sign_unlock_mode_transition(
                    &app_meta.id,
                    &app_meta.unlock_mode,
                    "auto",
                    &transition_attestation,
                )
                .await?;
            let transition = api
                .update_unlock_mode(
                    &app_name,
                    &UpdateUnlockModeRequest {
                        mode: "auto-unlock".to_string(),
                        transition_receipt: Some(transition_receipt),
                        transition_attestation: Some(transition_attestation),
                        customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob),
                        org_keyring_blob: Some(signed_blobs.org_keyring_blob),
                        signed_policy_artifact: Some(signed_blobs.signed_policy_artifact),
                    },
                )
                .await?;
            match transition.deployment_id {
                Some(id) => println!(
                    "CAP unlock mode updated to {}. Redeploy started: {id}",
                    transition.unlock_mode
                ),
                None => println!("CAP unlock mode already set to {}.", transition.unlock_mode),
            }
            println!("Auto-unlock enabled. Restarts no longer require a password.");
            Ok(())
        }
        AutoUnlockCommand::Disable { app, image } => {
            let app_name = resolve_app_name(&app)?;
            let (api, paths) = build_api_client()?;
            let cli_config = config::load_config(&paths)?;
            let creds = config::load_credentials(&paths)?;
            let app_config = AppConfig::find_and_load()?;
            let app_meta = api.get_app(&app_name).await?;
            println!("Signing password-mode redeploy descriptor for {app_name}...");
            let signed_blobs =
                super::app::build_signed_deploy_blobs(super::app::SignedDeployBlobParams {
                    api: &api,
                    paths: &paths,
                    cli_config: &cli_config,
                    creds: &creds,
                    app: &app_meta,
                    app_config: &app_config,
                    image: &image,
                    target_unlock_mode: Some("password"),
                    workload_security_profile: WorkloadSecurityProfile::Restricted,
                })
                .await?;
            let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
            let tee = TeeClient::new_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
            let (transition_attestation, tee) = tee.attest_receipt_key().await?;

            let password = Password::new()
                .with_prompt("Unlock password (to authorize unsealing)")
                .interact()?;

            println!("Disabling auto-unlock for {app_name}...");
            tee.disable_auto_unlock(&password).await?;
            println!("Sealed seed removed inside the TEE.");

            let transition_receipt = tee
                .sign_unlock_mode_transition(
                    &app_meta.id,
                    &app_meta.unlock_mode,
                    "password",
                    &transition_attestation,
                )
                .await?;
            let transition = api
                .update_unlock_mode(
                    &app_name,
                    &UpdateUnlockModeRequest {
                        mode: "password".to_string(),
                        transition_receipt: Some(transition_receipt),
                        transition_attestation: Some(transition_attestation),
                        customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob),
                        org_keyring_blob: Some(signed_blobs.org_keyring_blob),
                        signed_policy_artifact: Some(signed_blobs.signed_policy_artifact),
                    },
                )
                .await?;
            match transition.deployment_id {
                Some(id) => println!(
                    "CAP unlock mode updated to {}. Redeploy started: {id}",
                    transition.unlock_mode
                ),
                None => println!("CAP unlock mode already set to {}.", transition.unlock_mode),
            }
            println!("Auto-unlock disabled. Restarts require the password.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn recovery_mnemonic_writer_includes_scope_warning_and_secret() {
        let mut output = Vec::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        write_recovery_mnemonic(&mut output, mnemonic).expect("writer should succeed");
        let output = String::from_utf8(output).expect("output should be utf-8");

        assert!(output.contains("RECOVERY MNEMONIC (shown ONCE)"));
        assert!(output.contains("enclava key backup"));
        assert!(output.contains("stored nowhere"));
        assert!(output.contains(mnemonic));
    }

    #[test]
    fn confirmation_gate_requires_visible_prompt_terminal() {
        assert!(recovery_mnemonic_confirmation_required(true, true));
        assert!(!recovery_mnemonic_confirmation_required(true, false));
        assert!(!recovery_mnemonic_confirmation_required(false, true));
        assert!(!recovery_mnemonic_confirmation_required(false, false));
    }

    #[test]
    fn capture_action_honors_no_store_mnemonic() {
        assert_eq!(
            recovery_mnemonic_capture_action(MnemonicCapture::Store, true),
            RecoveryMnemonicCaptureAction::PromptToStore
        );
        assert_eq!(
            recovery_mnemonic_capture_action(MnemonicCapture::Store, false),
            RecoveryMnemonicCaptureAction::Store
        );
        assert_eq!(
            recovery_mnemonic_capture_action(MnemonicCapture::Skip, true),
            RecoveryMnemonicCaptureAction::Skip
        );
        assert_eq!(
            recovery_mnemonic_capture_action(MnemonicCapture::Skip, false),
            RecoveryMnemonicCaptureAction::Skip
        );
    }

    #[test]
    fn interrupted_presentation_warning_reprints_mnemonic() {
        let mut output = Vec::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err: Box<dyn std::error::Error> = "stdin closed".into();

        emit_recovery_mnemonic_interrupted_warning(&mut output, mnemonic, &*err);

        let output = String::from_utf8(output).expect("warning should be utf-8");
        assert!(output.contains("WARNING"));
        assert!(output.contains("ownership was claimed"));
        assert!(output.contains("NOT stored"));
        assert!(output.contains("record it now"));
        assert!(output.contains(mnemonic));
        assert!(output.contains("stdin closed"));
    }

    #[cfg(unix)]
    #[test]
    fn capture_storage_helper_persists_default() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        store_mnemonic_local(&paths, "org-a", "shell1", mnemonic)
            .expect("default capture storage helper must persist");
        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some(mnemonic.to_string())
        );
    }

    #[test]
    fn read_mnemonic_file_trims_and_rejects_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("m.txt");
        std::fs::write(&path, "  abandon abandon abandon  \n").unwrap();
        assert_eq!(
            read_mnemonic_file(&path).unwrap(),
            "abandon abandon abandon"
        );

        let empty = tmp.path().join("empty.txt");
        std::fs::write(&empty, "   \n").unwrap();
        assert!(read_mnemonic_file(&empty).is_err());
    }

    #[test]
    fn is_mnemonic_invalid_detects_tee_rejection() {
        let yes = TeeError::Tee {
            status: 400,
            message: "{\"error\":\"mnemonic_invalid\"}".into(),
        };
        let no = TeeError::Tee {
            status: 400,
            message: "{\"error\":\"other\"}".into(),
        };
        let nottee = TeeError::Attestation("x".into());
        assert!(is_mnemonic_invalid(&yes));
        assert!(!is_mnemonic_invalid(&no));
        assert!(!is_mnemonic_invalid(&nottee));
    }

    #[test]
    fn read_new_password_file_trims_trailing_newline_and_rejects_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pw.txt");
        std::fs::write(&path, "s3cret-pw\n").unwrap();
        assert_eq!(read_new_password_file(&path).unwrap(), "s3cret-pw");

        // interior/leading whitespace preserved; only trailing newline trimmed
        std::fs::write(&path, "  lead keep \r\n").unwrap();
        assert_eq!(read_new_password_file(&path).unwrap(), "  lead keep ");

        let empty = tmp.path().join("empty.txt");
        std::fs::write(&empty, "\n").unwrap();
        assert!(read_new_password_file(&empty).is_err());
    }
}
