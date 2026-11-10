use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Password};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use enclava_cli::api_client::{ApiClient, ApiError};
use enclava_cli::api_types::{
    UnlockEndpointResponse, UnlockLockedGeneration, UnlockStatusResponse, UpdateUnlockModeRequest,
};
use enclava_cli::app_config::{
    AppConfig, AppConfigError, AppSection, ResourcesSection, StorageSection, UnlockSection,
};
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
    /// Read the initial unlock password from a file (non-interactive; trailing newline trimmed). Replaces the password prompt and its confirmation; you are responsible for observing the claim result — the one-time recovery mnemonic is stored to the protected local keystore, never printed.
    #[arg(long)]
    pub password_file: Option<PathBuf>,
    /// Persist the recovery mnemonic to the protected local keystore so `enclava key backup` can back it up (default).
    #[arg(long, conflicts_with = "no_store_mnemonic")]
    pub store_mnemonic: bool,
    /// Unsupported for claims: rejected before the claim is sent (the mnemonic is never printed; use `enclava key backup` for deliberate export).
    #[arg(long, conflicts_with = "store_mnemonic")]
    pub no_store_mnemonic: bool,
}

#[derive(Args)]
pub struct UnlockArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Read the unlock password from a file (non-interactive; trailing newline trimmed).
    #[arg(long)]
    pub password_file: Option<PathBuf>,
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
    /// Read the current password from a file (non-interactive; trailing newline trimmed).
    #[arg(long)]
    pub current_password_file: Option<PathBuf>,
    /// Read the new password from a file (non-interactive; trailing newline trimmed).
    #[arg(long)]
    pub new_password_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum AutoUnlockCommand {
    /// Removed: auto-unlock cannot be enabled anymore (refuses immediately)
    Enable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Digest-pinned container image to bind into the signed redeploy descriptor.
        #[arg(long)]
        image: String,
        /// Read the unlock password from a file (non-interactive; trailing newline trimmed).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Remove the KBS-gated seed wrap and require a password on restart.
    /// Signs the stored primary from unlock status `locked_generation`
    /// (`source = apply_job_generation`), which hosted platforms proxy.
    /// A local enclava.toml is not required and is not signed. A deployment
    /// list is not that generation. Enable stays refused.
    Disable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Digest-pinned container image to bind into the signed redeploy descriptor.
        #[arg(long)]
        image: String,
        /// Read the unlock password from a file (non-interactive; trailing newline trimmed).
        #[arg(long)]
        password_file: Option<PathBuf>,
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

/// True only for the hosted placeholder answer (`501 not_implemented_hosted`).
/// Every other outcome (implemented surface, auth error, unknown app, invalid
/// transition) belongs to the real flow and must not abort here.
fn is_unimplemented_hosted(err: &ApiError) -> bool {
    matches!(
        err,
        ApiError::Api {
            status: 501,
            code: Some(code),
            ..
        } if code == "not_implemented_hosted"
    )
}

/// Capability preflight before any TEE mutation (the seal at
/// `tee.disable_auto_unlock` must never run before this passes —
/// enclava-paas#189's half-enabled residue is exactly what this guards).
///
/// The probe carries an intentionally invalid mode, so it can never be a
/// valid mutation: every handler lineage parses the mode string before
/// touching the app (the receipt-gated `update_unlock_mode` and the
/// pre-receipt legacy one alike), answering `400` with zero side effects.
/// Only that exact shape passes. The hosted placeholder ignores the body and
/// answers `501 not_implemented_hosted`, which becomes the honest "not
/// implemented" error; every other answer (auth, management-write freeze
/// gates, transport) propagates instead of being swallowed — a preflight that
/// cannot prove the surface is safe must not let the TEE seal proceed.
async fn ensure_unlock_mode_change_supported(
    api: &ApiClient,
    app_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let probe = UpdateUnlockModeRequest {
        mode: "__capability_probe__".to_string(),
        transition_receipt: None,
        transition_attestation: None,
        customer_descriptor_blob: None,
        org_keyring_blob: None,
        signed_policy_artifact: None,
        validate_only: false,
    };
    println!("Checking unlock-mode support for {app_name}...");
    match api.update_unlock_mode(app_name, &probe).await {
        Err(ApiError::Api { status: 400, .. }) => Ok(()),
        Err(err) if is_unimplemented_hosted(&err) => {
            Err("unlock-mode switching is not implemented on this platform \
             (the apps route answers not_implemented_hosted); no TEE changes were made"
                .into())
        }
        Err(err) => Err(err.into()),
        Ok(_) => Err(
            "unlock-mode capability probe got an unexpected success; refusing to touch the TEE"
                .into(),
        ),
    }
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
    let capture = mnemonic_capture_from_flags(args.no_store_mnemonic);
    let (api, paths) = build_api_client()?;
    let me = api.get_current_user().await?;

    // Validate the recovery destination before the TEE can commit ownership.
    prepare_recovery_mnemonic_sink(
        &paths,
        &me.active_org.name,
        &app_name,
        capture,
        args.password_file.is_some(),
    )?;

    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    println!("Claiming ownership of {app_name}...");

    let challenge = tee.bootstrap_challenge().await?;
    println!("Challenge received (expires in {}s)", challenge.ttl_seconds);

    let org_id = Uuid::parse_str(&me.active_org.id)?;
    let private_key_bytes =
        load_or_derive_bootstrap_private_key(&paths, &me.active_org.name, org_id, &app_name)?;

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

    let password = secret_from_file_or_prompt(
        args.password_file.as_deref(),
        "password",
        "Set unlock password",
        Some(("Confirm password", "Passwords don't match")),
        "--password-file",
    )?;

    let result = match tee
        .bootstrap_claim(&challenge.nonce, &bootstrap_pubkey, &signature, &password)
        .await
    {
        Ok(result) => result,
        Err(_) if tee.claim_state_is_successful().await.unwrap_or(false) => {
            // Ownership committed server-side but the response (which carries the
            // one-time mnemonic) was lost. Halt with the incomplete-backup error:
            // never retry the claim, never imply rollback, never print secrets.
            return Err(ownership_committed_recovery_backup_incomplete(
                "the claim response was lost after the TEE committed ownership, so the \
                 one-time recovery mnemonic was never received"
                    .to_string(),
            ));
        }
        Err(err) => return Err(err.into()),
    };

    println!("Ownership claimed.");

    // Persist the one-time mnemonic to the prepared protected sink. The
    // mnemonic is never written to stdout/stderr; on failure this returns the
    // ownership-committed/incomplete-backup error and halts.
    let mnemonic = result.mnemonic.ok_or_else(|| {
        ownership_committed_recovery_backup_incomplete(
            "the TEE's claim response contained no recovery mnemonic".to_string(),
        )
    })?;
    store_recovery_mnemonic_after_claim(&paths, &me.active_org.name, &app_name, &mnemonic)?;
    Ok(())
}

/// Operator's choice on whether to persist a freshly-observed recovery mnemonic.
/// `Skip` (`--no-store-mnemonic`) is rejected by
/// [`validate_recovery_mnemonic_sink_mode`] before any claim is sent: the
/// mnemonic is never printed to stdout/stderr, so an unpersisted mnemonic is
/// permanently lost, and no tenant-authenticated re-export exists yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MnemonicCapture {
    /// Persist to the protected local keystore so `key backup` can back it up.
    Store,
    /// Do not persist. Rejected pre-claim; kept so the flag still parses and
    /// fails with actionable guidance instead of a clap unknown-argument error.
    Skip,
}

/// Map the `--no-store-mnemonic` flag to the capture mode shared by every claim
/// caller (explicit `enclava claim`, `enclava deploy`, `enclava template deploy`).
pub(crate) fn mnemonic_capture_from_flags(no_store_mnemonic: bool) -> MnemonicCapture {
    if no_store_mnemonic {
        MnemonicCapture::Skip
    } else {
        MnemonicCapture::Store
    }
}

/// Stable, greppable error code for: the TEE already committed ownership, but
/// the one-time recovery mnemonic is not safely persisted in the local keystore.
pub(crate) const OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE: &str =
    "ownership_committed_recovery_backup_incomplete";

/// Bounded retry budget for persisting the same in-memory mnemonic to the
/// prepared private sink after the claim committed ownership.
const MNEMONIC_PERSIST_ATTEMPTS: u32 = 3;

/// Reject unsafe sink modes before any claim is sent. `--no-store-mnemonic` used
/// to display the mnemonic once on stdout/stderr; that display path is gone
/// (transcripts and CI artifacts captured it, evidence E11), and until a
/// tenant-authenticated export exists an unpersisted mnemonic is unrecoverable,
/// so the mode is refused before the TEE mints anything.
pub(crate) fn validate_recovery_mnemonic_sink_mode(
    capture: MnemonicCapture,
) -> Result<(), Box<dyn std::error::Error>> {
    if capture == MnemonicCapture::Skip {
        return Err(
            "--no-store-mnemonic is not allowed for ownership claims: the recovery mnemonic is \
             never printed to stdout/stderr, so an unpersisted mnemonic would be permanently \
             lost. Omit the flag - the mnemonic is stored in the protected local keystore, and \
             `enclava key backup` performs the deliberate encrypted export."
                .into(),
        );
    }
    Ok(())
}

/// Reject missing password input before creating server-side deployment state.
pub(crate) fn ensure_claim_session_now(
    password_from_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_claim_session_for(
        super::interactive::stdin_interactive(),
        super::interactive::stderr_interactive(),
        password_from_file,
    )
}

fn ensure_claim_session_for(
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    password_from_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if password_from_file || (stdin_is_terminal && stderr_is_terminal) {
        return Ok(());
    }
    Err(
        "ownership claim password input requires terminal stdin and stderr; \
         for noninteractive runs pass --password-file <PATH> to `enclava claim`, \
         or --storage-password-file <PATH> to `enclava deploy` / `enclava template deploy`."
            .into(),
    )
}

/// Prove the protected recovery destination is writable before requesting a claim.
pub(crate) fn prepare_recovery_mnemonic_sink(
    paths: &CliPaths,
    org: &str,
    app: &str,
    capture: MnemonicCapture,
    password_from_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    prepare_recovery_mnemonic_sink_for_session(
        paths,
        org,
        app,
        capture,
        super::interactive::stdin_interactive(),
        super::interactive::stderr_interactive(),
        password_from_file,
    )
}

/// Testable core of [`prepare_recovery_mnemonic_sink`] with the session
/// terminals and password source supplied by the caller.
pub(crate) fn prepare_recovery_mnemonic_sink_for_session(
    paths: &CliPaths,
    org: &str,
    app: &str,
    capture: MnemonicCapture,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    password_from_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_recovery_mnemonic_sink_mode(capture)?;
    ensure_claim_session_for(stdin_is_terminal, stderr_is_terminal, password_from_file)?;
    keys::prepare_app_mnemonic_sink(paths, org, app)
        .map_err(|e| format!("recovery mnemonic sink is not ready for the claim: {e}").into())
}

/// Persist the one-time recovery mnemonic to the prepared protected sink after
/// the TEE has committed ownership. The same in-memory result is retried a
/// bounded number of times; on failure the error carries
/// [`OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE`], never the mnemonic
/// itself, and callers must propagate it so dependent actions halt (ownership
/// is committed and is NOT rolled back).
pub(crate) fn store_recovery_mnemonic_after_claim(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_error = String::new();
    for attempt in 1..=MNEMONIC_PERSIST_ATTEMPTS {
        match keys::store_app_mnemonic(paths, org, app, mnemonic) {
            Ok(()) => {
                eprintln!(
                    "Recovery mnemonic stored in the protected local keystore ({}). Run `enclava key backup` and keep that file off this machine - the local copy is lost if this machine is lost.",
                    keys::app_mnemonic_path(paths, org, app).display()
                );
                return Ok(());
            }
            Err(err) => {
                last_error = err.to_string();
                if attempt < MNEMONIC_PERSIST_ATTEMPTS {
                    eprintln!(
                        "Storing the recovery mnemonic failed (attempt {attempt}/{MNEMONIC_PERSIST_ATTEMPTS}); retrying."
                    );
                    std::thread::sleep(Duration::from_millis(200 * u64::from(attempt)));
                }
            }
        }
    }
    Err(ownership_committed_recovery_backup_incomplete(format!(
        "persisting the one-time recovery mnemonic to the protected keystore failed \
         after {MNEMONIC_PERSIST_ATTEMPTS} attempts: {last_error}"
    )))
}

/// Build the post-commit incomplete-backup error. `detail` must describe the
/// failure without embedding the mnemonic or any other secret.
pub(crate) fn ownership_committed_recovery_backup_incomplete(
    detail: String,
) -> Box<dyn std::error::Error> {
    format!(
        "{OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE}: the TEE accepted ownership and it is \
         NOT rolled back, but {detail}. The mnemonic is never printed and cannot be requested \
         again; keep the unlock password safe - without the mnemonic, lost-password recovery \
         for this app's encrypted storage is impossible. Dependent actions were halted."
    )
    .into()
}

pub async fn unlock(args: UnlockArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let password = secret_from_file_or_prompt(
        args.password_file.as_deref(),
        "password",
        "Unlock password",
        None,
        "--password-file",
    )?;

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

    let is_tty = super::interactive::stdin_interactive();

    // An explicit file must take priority even when local state is unreadable.
    let mnemonic = match load_recovery_mnemonic(
        &paths,
        &me.active_org.name,
        &app_name,
        args.mnemonic_file.as_deref(),
    )? {
        Some(stored_or_file) if is_tty && args.mnemonic_file.is_none() => {
            let use_stored = Confirm::new()
                .with_prompt(format!("Use the stored recovery mnemonic for {app_name}?"))
                .default(true)
                .interact()?;
            if use_stored {
                stored_or_file
            } else {
                prompt_recovery_mnemonic()?
            }
        }
        Some(stored_or_file) => stored_or_file,
        None if is_tty => prompt_recovery_mnemonic()?,
        None => {
            return Err(format!(
                "no stored recovery mnemonic for {app_name}; pass --mnemonic-file, run `enclava key restore <backup>` first, or run this command in an interactive shell"
            )
            .into());
        }
    };

    let new_password = secret_from_file_or_prompt(
        args.new_password_file.as_deref(),
        "new password",
        "New unlock password",
        Some(("Confirm password", "Passwords don't match")),
        "--new-password-file",
    )?;

    println!("Recovering {app_name}...");
    if let Err(err) = tee.recover(&mnemonic, &new_password).await {
        if let Some(guidance) = recovery_restart_guidance(&err) {
            return Err(format!("{guidance} ({err})").into());
        }
        return Err(err.into());
    }

    if let Err(err) =
        persist_verified_recovery_mnemonic(&paths, &me.active_org.name, &app_name, &mnemonic)
    {
        eprintln!(
            "WARNING: recovery succeeded, but the verified mnemonic could not be stored locally: {err}"
        );
    } else {
        eprintln!(
            "Verified recovery mnemonic stored locally. Run `enclava key backup` and keep that file off this machine."
        );
    }
    println!("Recovery complete. Use the new password to unlock.");
    Ok(())
}

fn load_recovery_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic_file: Option<&Path>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(path) = mnemonic_file {
        return Ok(Some(read_mnemonic_file(path)?));
    }
    Ok(keys::load_app_mnemonic(paths, org, app)?)
}

fn persist_verified_recovery_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    keys::store_app_mnemonic(paths, org, app, mnemonic)
        .map_err(|err| format!("failed to store recovery mnemonic: {err}").into())
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
fn recovery_restart_guidance(err: &TeeError) -> Option<&'static str> {
    if matches!(
        err,
        TeeError::Tee {
            status: 409,
            message,
        } if message.contains("recover_verification_unavailable")
            || message.contains("recovery_requires_locked_init_verifier")
    ) {
        return Some(
            "recovery requires the app to be locked so its storage can verify the mnemonic; restart the app, wait for the locked state, then run `enclava recover` again",
        );
    }
    if matches!(err, TeeError::Tee { message, .. } if message.contains("restart_required")) {
        return Some(
            "the mnemonic was verified, but the new password could not be saved; restart the app, wait for the locked state, then run `enclava recover` again",
        );
    }
    None
}

/// Resolve a secret from a file, or from a terminal prompt: a provided file
/// replaces the prompt and any confirmation prompt with it (the caller
/// confirms by providing the file). Prompting requires a terminal on BOTH
/// stdin and stderr — dialoguer renders password prompts on stderr and
/// errors on a non-terminal stderr — so having neither a file nor both
/// terminals is a hard error that names the flag, mirroring how
/// `deploy --storage-password-file` behaves for non-interactive sessions.
pub(crate) fn secret_from_file_or_prompt(
    file: Option<&Path>,
    kind: &str,
    prompt: &str,
    confirmation: Option<(&str, &str)>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    secret_from_file_or_prompt_for_session(
        file,
        kind,
        prompt,
        confirmation,
        flag,
        super::interactive::stdin_interactive(),
        super::interactive::stderr_interactive(),
    )
}

/// Testable core of [`secret_from_file_or_prompt`] with the session
/// terminals supplied by the caller.
pub(crate) fn secret_from_file_or_prompt_for_session(
    file: Option<&Path>,
    kind: &str,
    prompt: &str,
    confirmation: Option<(&str, &str)>,
    flag: &str,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = file {
        return Ok(keys::read_secret_file(path, kind)?);
    }
    if !(stdin_is_terminal && stderr_is_terminal) {
        return Err(format!(
            "an interactive terminal or {flag} <PATH> is required to provide the {kind} non-interactively"
        )
        .into());
    }
    let mut password = Password::new().with_prompt(prompt);
    if let Some((confirmation_prompt, mismatch)) = confirmation {
        password = password.with_confirmation(confirmation_prompt, mismatch);
    }
    Ok(password.interact()?)
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

    let current = secret_from_file_or_prompt(
        args.current_password_file.as_deref(),
        "current password",
        "Current password",
        None,
        "--current-password-file",
    )?;

    let new_password = secret_from_file_or_prompt(
        args.new_password_file.as_deref(),
        "new password",
        "New password",
        Some(("Confirm new password", "Passwords don't match")),
        "--new-password-file",
    )?;

    println!("Changing password for {app_name}...");
    tee.change_password(&current, &new_password).await?;
    println!("Password changed.");
    Ok(())
}

const LOCKED_GENERATION_SOURCE: &str = "apply_job_generation";

#[derive(Debug)]
struct SignedDisableShape {
    app_config: AppConfig,
    workload_security_profile: WorkloadSecurityProfile,
    container_name: String,
    image_ref: String,
    generation: UnlockLockedGeneration,
    log_encryption: Option<enclava_engine::types::LogEncryptionConfig>,
}

/// A local project file is not the signed shape. A name mismatch or an
/// unreadable file refuses; a missing file is the hosted path.
fn guard_local_project_file(
    app_name: &str,
    local: Result<AppConfig, AppConfigError>,
) -> Result<(), String> {
    match local {
        Ok(config) if config.app.name != app_name => Err(format!(
            "enclava.toml app name '{}' does not match {app_name}; refusing to sign that \
             project file. Run from a directory without an enclava.toml",
            config.app.name
        )),
        Ok(_) => Ok(()),
        Err(AppConfigError::ReadFile { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(err) => Err(err.to_string()),
    }
}

fn image_ref_pinned_to(image_ref: &str, digest: &str) -> bool {
    let Some(repository) = image_ref.strip_suffix(&format!("@{digest}")) else {
        return false;
    };
    !repository.is_empty()
        && !repository.ends_with('@')
        && enclava_common::validate::validate_image_digest(digest).is_ok()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.trim().is_empty())
}

/// Accept only the generation the unlock handler locks.
///
/// A missing field is the old server, or a proxy that did not forward it.
/// `GET /apps/{name}/deployments` is not consulted: for a hosted app that
/// list is not this generation.
fn require_signable_generation(
    status: &UnlockStatusResponse,
    image: &str,
) -> Result<SignedDisableShape, String> {
    let Some(generation) = status.locked_generation.clone() else {
        return Err(
            "unlock status did not include locked_generation (source apply_job_generation). \
             A hosted deployment list is not the generation the unlock handler locks, so \
             auto-unlock disable will not remove the guest wrap"
                .into(),
        );
    };
    if generation.source != LOCKED_GENERATION_SOURCE {
        return Err(format!(
            "unlock status locked_generation.source is {:?}, not {LOCKED_GENERATION_SOURCE}; \
             refusing to treat another deployment list as the locked generation",
            generation.source
        ));
    }
    if !generation.acceptable {
        let reason = generation
            .refusal
            .as_deref()
            .unwrap_or("generation is not acceptable");
        return Err(format!(
            "the CAP apply generation the unlock handler locks is not signable ({reason}); \
             the guest wrap was not removed"
        ));
    }
    let image_ref = generation.image_ref.clone().ok_or_else(|| {
        "locked generation omitted image_ref; refusing to sign a different reference".to_string()
    })?;
    let digest = generation.image_digest.clone().ok_or_else(|| {
        "locked generation omitted image_digest; refusing to remove the guest wrap".to_string()
    })?;
    let requested = enclava_common::image::ImageRef::parse(image).map_err(|err| {
        format!(
            "auto-unlock disable requires a digest-pinned --image (<registry>/<repo>@sha256:<hex>); {err}"
        )
    })?;
    if !requested.has_digest() {
        return Err(
            "auto-unlock disable requires a digest-pinned --image; a tag is not checked against \
             the locked generation before the guest mutation"
                .into(),
        );
    }
    if requested.digest() != digest {
        return Err(format!(
            "--image digest {} does not match locked generation digest {digest}; refusing to \
             remove the guest wrap for an image the control plane will reject",
            requested.digest()
        ));
    }
    if !image_ref_pinned_to(&image_ref, &digest) {
        return Err(
            "locked generation image_ref is not digest-pinned to image_digest; refusing to sign \
             a substituted reference"
                .into(),
        );
    }
    let port = generation
        .port
        .filter(|port| *port > 0)
        .ok_or_else(|| "locked generation omitted port; refusing to assume 8080".to_string())?;
    let command = generation
        .command
        .clone()
        .filter(|argv| !argv.is_empty() && argv.iter().all(|arg| !arg.is_empty()))
        .ok_or_else(|| "locked generation omitted command".to_string())?;
    let Some(paths) = generation.storage_paths.clone() else {
        return Err("locked generation omitted storage paths".into());
    };
    if paths.iter().any(|path| path.is_empty()) {
        return Err("locked generation storage paths contain an empty path".into());
    }
    // Match the server: /state is the platform mount, and an empty remainder
    // is a valid no-extra-mount workload.
    let storage_paths: Vec<String> = paths.into_iter().filter(|path| path != "/state").collect();
    let resources = generation
        .resources
        .clone()
        .ok_or_else(|| "locked generation omitted resources".to_string())?;
    for (name, value) in [
        ("cpu", &resources.cpu),
        ("memory", &resources.memory),
        ("storage", &resources.storage),
        ("tls_storage", &resources.tls_storage),
    ] {
        if value.is_empty() {
            return Err(format!("locked generation resources.{name} is empty"));
        }
    }
    let profile_raw = generation
        .workload_security_profile
        .clone()
        .ok_or_else(|| "locked generation omitted workload_security_profile".to_string())?;
    let workload_security_profile = profile_raw.parse().map_err(|err: String| {
        format!("locked generation workload_security_profile is unsupported: {err}")
    })?;
    let container_name = non_empty(generation.container_name.clone())
        .ok_or_else(|| "locked generation omitted container_name".to_string())?;
    if generation.deployment_id.as_deref().unwrap_or("").is_empty() {
        return Err("locked generation omitted deployment_id".into());
    }
    let app_identity = generation.app.clone().ok_or_else(|| {
        "locked generation omitted the CAP app identity; refusing to sign a hosted projection"
            .to_string()
    })?;
    if app_identity.id.trim().is_empty()
        || app_identity.name.trim().is_empty()
        || app_identity.namespace.trim().is_empty()
        || app_identity.service_account.trim().is_empty()
        || app_identity.domain.trim().is_empty()
        || app_identity.tee_domain.trim().is_empty()
        || app_identity.tenant_instance_identity_hash.trim().is_empty()
        || app_identity.bootstrap_owner_pubkey_hash.trim().is_empty()
        || app_identity.signer_identity_subject.trim().is_empty()
        || app_identity.signer_identity_issuer.trim().is_empty()
    {
        return Err(
            "locked generation CAP app identity is incomplete; refusing to sign a hosted projection"
                .into(),
        );
    }
    let log_encryption = generation.log_encryption.clone().ok_or_else(|| {
        "locked generation omitted log_encryption; refusing to sign a pre-claim descriptor that \
         would drop a stored log recipient"
            .to_string()
    })?;
    Ok(SignedDisableShape {
        app_config: AppConfig {
            app: AppSection {
                name: String::new(),
                port,
                command,
            },
            storage: StorageSection {
                paths: storage_paths,
                size: resources.storage,
                tls_size: resources.tls_storage,
            },
            unlock: UnlockSection {
                mode: "password".to_string(),
            },
            services: HashMap::new(),
            resources: ResourcesSection {
                cpu: resources.cpu,
                memory: resources.memory,
            },
            health: None,
        },
        workload_security_profile,
        container_name,
        image_ref,
        generation,
        log_encryption,
    })
}

/// Replace a hosted app projection with the CAP identity the unlock handler
/// compares. The projection is not signed.
fn apply_locked_app_identity(
    app: &mut enclava_cli::api_types::AppResponse,
    generation: &UnlockLockedGeneration,
    unlock_mode: &str,
) -> Result<(), String> {
    let identity = generation.app.as_ref().ok_or_else(|| {
        "locked generation omitted the CAP app identity; refusing to sign a hosted projection"
            .to_string()
    })?;
    app.id = identity.id.clone();
    app.name = identity.name.clone();
    app.namespace = identity.namespace.clone();
    app.service_account = Some(identity.service_account.clone());
    app.domain = identity.domain.clone();
    app.tee_domain = Some(identity.tee_domain.clone());
    app.app_domain = Some(identity.domain.clone());
    app.custom_domain = identity.custom_domain.clone();
    app.tenant_instance_identity_hash = Some(identity.tenant_instance_identity_hash.clone());
    app.bootstrap_owner_pubkey_hash = Some(identity.bootstrap_owner_pubkey_hash.clone());
    app.signer_identity_subject = Some(identity.signer_identity_subject.clone());
    app.signer_identity_issuer = Some(identity.signer_identity_issuer.clone());
    app.unlock_mode = unlock_mode.to_string();
    Ok(())
}

/// The password prompt and descriptor signing are not a safe window. The
/// generation read immediately before `tee.disable_auto_unlock` must still
/// be the one that was signed.
fn require_same_locked_generation(
    signed: &UnlockLockedGeneration,
    latest: &UnlockStatusResponse,
) -> Result<(), String> {
    match latest.locked_generation.as_ref() {
        Some(current) if current == signed => Ok(()),
        Some(_) => Err(
            "the locked CAP apply generation changed before the guest wrap could be removed; \
             refusing"
                .into(),
        ),
        None => Err(
            "unlock status dropped locked_generation before the guest wrap could be removed; \
             refusing"
                .into(),
        ),
    }
}

pub async fn auto_unlock(cmd: AutoUnlockCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AutoUnlockCommand::Enable { .. } => Err(
            "auto_unlock_disabled: auto-unlock enable is no longer available; \
             apps use password unlock, and `enclava auto-unlock disable` converts \
             a legacy auto-unlock app"
                .into(),
        ),
        AutoUnlockCommand::Disable {
            app,
            image,
            password_file,
        } => {
            let app_name = resolve_app_name(&app)?;
            let (api, paths) = build_api_client()?;
            ensure_unlock_mode_change_supported(&api, &app_name).await?;
            // Probe first. A missing project file is the hosted path; a
            // mismatched or unreadable one still refuses, and is never signed.
            guard_local_project_file(&app_name, AppConfig::find_and_load())?;
            if let Ok(config) = AppConfig::find_and_load()
                && config.app.name == app_name
            {
                eprintln!(
                    "Found enclava.toml for {app_name}; it is not signed. The stored CAP \
                     generation is the workload that will be signed."
                );
            }
            let cli_config = config::load_config(&paths)?;
            let creds = config::load_credentials(&paths)?;
            let mut app_meta = api.get_app(&app_name).await?;
            let status = api.get_unlock_status(&app_name).await?;
            let signed = require_signable_generation(&status, &image)?;
            let identity_name = signed
                .generation
                .app
                .as_ref()
                .map(|identity| identity.name.clone())
                .unwrap_or_default();
            if identity_name != app_name {
                return Err(format!(
                    "locked generation app name '{identity_name}' does not match {app_name}; \
                     refusing to sign a different app"
                )
                .into());
            }
            apply_locked_app_identity(&mut app_meta, &signed.generation, &status.unlock_mode)?;
            let mut app_config = signed.app_config;
            app_config.app.name = identity_name;
            eprintln!(
                "Signing password-mode redeploy for {app_name}: image={}, container={}, \
                 port={}, command={:?}, storage_paths={:?}, profile={}, cpu={}, memory={}, \
                 storage={}, tls_storage={}",
                signed.image_ref,
                signed.container_name,
                app_config.app.port,
                app_config.app.command,
                app_config.storage.paths,
                signed.workload_security_profile.as_str(),
                app_config.resources.cpu,
                app_config.resources.memory,
                app_config.storage.size,
                app_config.storage.tls_size,
            );
            // Resolve the local password source before any remote mutation:
            // blob signing bootstraps the org keyring/signing authority, and a
            // missing or unreadable --password-file must not leave that
            // half-done for a command that never ran.
            let password = secret_from_file_or_prompt(
                password_file.as_deref(),
                "password",
                "Unlock password (to remove auto-unlock wrapping)",
                None,
                "--password-file",
            )?;
            println!("Signing password-mode redeploy descriptor for {app_name}...");
            let signed_blobs =
                super::app::build_signed_deploy_blobs(super::app::SignedDeployBlobParams {
                    api: &api,
                    paths: &paths,
                    cli_config: &cli_config,
                    creds: &creds,
                    app: &app_meta,
                    app_config: &app_config,
                    image: &signed.image_ref,
                    target_unlock_mode: Some("password"),
                    workload_security_profile: signed.workload_security_profile,
                    container_name: signed.container_name.as_str(),
                    log_encryption: signed.log_encryption.clone(),
                    pin_log_encryption: true,
                })
                .await?;
            let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
            let tee = TeeClient::new_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
            let (mut transition_attestation, tee) = tee.attest_receipt_key().await?;
            // CRL collateral is transition-specific: fetch it here, not in
            // the shared attestation path, so ordinary TEE operations keep
            // working through a KDS outage.
            tee.complete_transition_quote_crl(&mut transition_attestation)
                .await?;
            // Re-read after the password prompt and signing. The CAP preview below
            // is what must pass before the guest wrap is removed.
            let latest = api.get_unlock_status(&app_name).await?;
            require_same_locked_generation(&signed.generation, &latest)?;

            // CAP must accept the signed descriptor before the wrap is removed.
            // A proxy that rewrote both status reads fails here, with the guest
            // wrap still in place.
            api.update_unlock_mode(
                &app_name,
                &UpdateUnlockModeRequest {
                    mode: "password".to_string(),
                    transition_receipt: None,
                    transition_attestation: None,
                    customer_descriptor_blob: Some(signed_blobs.customer_descriptor_blob.clone()),
                    org_keyring_blob: Some(signed_blobs.org_keyring_blob.clone()),
                    signed_policy_artifact: Some(signed_blobs.signed_policy_artifact.clone()),
                    validate_only: true,
                },
            )
            .await?;

            println!("Disabling auto-unlock for {app_name}...");
            tee.disable_auto_unlock(&password).await?;
            println!("KBS-gated seed wrap removed inside the TEE.");

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
                        validate_only: false,
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

    // Synthetic, publicly-documented BIP39 test vector; never a real secret.
    const SYNTHETIC_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn unimplemented_hosted_classification_is_exact() {
        // False positives abort a working transition; false negatives leave
        // the half-applied TEE seal (enclava-paas#189). Pin both directions.
        let err = |status, code: Option<&str>| ApiError::Api {
            status,
            code: code.map(str::to_string),
            message: String::new(),
        };
        assert!(is_unimplemented_hosted(&err(
            501,
            Some("not_implemented_hosted")
        )));
        assert!(!is_unimplemented_hosted(&err(501, Some("other_code"))));
        assert!(!is_unimplemented_hosted(&err(501, None)));
        assert!(!is_unimplemented_hosted(&err(
            400,
            Some("not_implemented_hosted")
        )));
    }

    #[tokio::test]
    async fn enable_subcommand_refuses_before_any_remote_call() {
        // The refusal must not depend on a local enclava.toml, stored
        // credentials, or network reachability: dummy args must fail with the
        // stable code before any resolution step runs.
        let error = auto_unlock(AutoUnlockCommand::Enable {
            app: Some("never-resolved".to_string()),
            image: "ghcr.io/acme/app@sha256:".to_string() + &"a".repeat(64),
            password_file: None,
        })
        .await
        .expect_err("enable must refuse");
        assert!(
            error.to_string().starts_with("auto_unlock_disabled"),
            "refusal must carry the stable code: {error}"
        );
    }

    fn digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn acceptable_status(port: u16) -> UnlockStatusResponse {
        let digest = digest();
        UnlockStatusResponse {
            unlock_mode: "auto".to_string(),
            tee_url: "https://app.example/.well-known/confidential".to_string(),
            ownership_state: Some("unlocked".to_string()),
            locked_generation: Some(UnlockLockedGeneration {
                source: LOCKED_GENERATION_SOURCE.to_string(),
                acceptable: true,
                refusal: None,
                deployment_id: Some("33333333-3333-3333-3333-333333333333".to_string()),
                status: Some("healthy".to_string()),
                image_digest: Some(digest.clone()),
                image_ref: Some(format!("ghcr.io/acme/app@{digest}")),
                container_name: Some("app".to_string()),
                port: Some(port),
                command: Some(vec!["/bin/app".to_string()]),
                storage_paths: Some(vec!["/data".to_string()]),
                workload_security_profile: Some("rootful-sudo".to_string()),
                resources: Some(enclava_cli::api_types::UnlockLockedGenerationResources {
                    cpu: "1".to_string(),
                    memory: "1Gi".to_string(),
                    storage: "5Gi".to_string(),
                    tls_storage: "2Gi".to_string(),
                }),
                app: Some(enclava_cli::api_types::UnlockLockedGenerationApp {
                    id: "11111111-1111-1111-1111-111111111111".to_string(),
                    name: "hosted-app".to_string(),
                    namespace: "cap-hosted-app".to_string(),
                    service_account: "cap-hosted-app-sa".to_string(),
                    domain: "hosted-app.example".to_string(),
                    tee_domain: "hosted-app.tee.example".to_string(),
                    custom_domain: None,
                    tenant_instance_identity_hash: "22".repeat(32),
                    bootstrap_owner_pubkey_hash: "33".repeat(32),
                    signer_identity_subject: "cosign-subject".to_string(),
                    signer_identity_issuer: "https://token.actions.githubusercontent.com"
                        .to_string(),
                }),
                log_encryption: Some(None),
            }),
        }
    }

    #[test]
    fn hosted_deployment_list_does_not_authorize_disable() {
        let digest = digest();
        let old_status = serde_json::json!({
            "unlock_mode": "auto",
            "tee_url": "https://app.example/.well-known/confidential",
            "ownership_state": "unlocked"
        });
        let parsed: UnlockStatusResponse = serde_json::from_value(old_status).unwrap();
        let image = format!("ghcr.io/acme/app@{digest}");
        let missing = require_signable_generation(&parsed, &image).unwrap_err();
        assert!(
            missing.contains("apply_job_generation"),
            "a status without the locked generation must refuse: {missing}"
        );
        assert!(
            missing.contains("hosted deployment list"),
            "the refusal must say the deployment list is not the lock: {missing}"
        );

        let hosted_row = serde_json::json!({
            "id": "hosted-1",
            "status": "healthy",
            "image_digest": digest,
            "created_at": "2026-01-01T00:00:00Z",
            "source": "hosted_deployments"
        });
        let as_generation = serde_json::from_value::<UnlockLockedGeneration>(hosted_row);
        assert!(
            as_generation.is_err(),
            "a hosted deployment row must not deserialize as the locked generation"
        );

        let mut wrong_source = acceptable_status(8080);
        wrong_source.locked_generation.as_mut().unwrap().source = "hosted_deployments".to_string();
        let wrong = require_signable_generation(&wrong_source, &image).unwrap_err();
        assert!(wrong.contains("hosted_deployments"), "{wrong}");
    }

    #[test]
    fn disable_signs_locked_generation_port_and_refuses_a_changed_reread() {
        let digest = digest();
        let image = format!("ghcr.io/other/app@{digest}");
        let status = acceptable_status(9090);
        let signed = require_signable_generation(&status, &image).unwrap();
        assert_eq!(signed.app_config.app.port, 9090);
        assert_eq!(signed.image_ref, format!("ghcr.io/acme/app@{digest}"));
        assert_eq!(
            signed.workload_security_profile,
            WorkloadSecurityProfile::RootfulSudo
        );
        assert_eq!(signed.container_name, "app");
        assert_eq!(signed.app_config.resources.cpu, "1");
        assert_eq!(
            signed
                .generation
                .app
                .as_ref()
                .map(|identity| identity.id.as_str()),
            Some("11111111-1111-1111-1111-111111111111")
        );
        require_same_locked_generation(&signed.generation, &status).unwrap();

        let mut changed = status;
        changed.locked_generation.as_mut().unwrap().status = Some("pending".to_string());
        let drifted = require_same_locked_generation(&signed.generation, &changed).unwrap_err();
        assert!(drifted.contains("changed"), "{drifted}");

        let mut omitted_port = acceptable_status(9090);
        omitted_port.locked_generation.as_mut().unwrap().port = None;
        let omitted = require_signable_generation(&omitted_port, &image).unwrap_err();
        assert!(omitted.contains("8080"), "{omitted}");

        let tag = require_signable_generation(&acceptable_status(9090), "ghcr.io/acme/app:latest")
            .unwrap_err();
        assert!(tag.contains("digest-pinned"), "{tag}");

        let mut no_identity = acceptable_status(9090);
        no_identity.locked_generation.as_mut().unwrap().app = None;
        let missing_identity = require_signable_generation(&no_identity, &image).unwrap_err();
        assert!(
            missing_identity.contains("hosted projection"),
            "{missing_identity}"
        );

        let mut unpinned = acceptable_status(9090);
        unpinned.locked_generation.as_mut().unwrap().image_ref =
            Some("ghcr.io/acme/app:latest".to_string());
        let substituted = require_signable_generation(&unpinned, &image).unwrap_err();
        assert!(substituted.contains("digest-pinned"), "{substituted}");

        let mut omitted_log = acceptable_status(9090);
        omitted_log
            .locked_generation
            .as_mut()
            .unwrap()
            .log_encryption = None;
        let dropped = require_signable_generation(&omitted_log, &image).unwrap_err();
        assert!(dropped.contains("log_encryption"), "{dropped}");

        let mut empty_paths = acceptable_status(9090);
        empty_paths
            .locked_generation
            .as_mut()
            .unwrap()
            .storage_paths = Some(Vec::new());
        let empty = require_signable_generation(&empty_paths, &image).unwrap();
        assert!(empty.app_config.storage.paths.is_empty());
    }

    #[test]
    fn stray_project_file_is_not_signed_over_a_hosted_app() {
        let mismatch = AppConfig {
            app: AppSection {
                name: "other-app".to_string(),
                port: 8080,
                command: Vec::new(),
            },
            storage: StorageSection::default(),
            unlock: UnlockSection::default(),
            services: HashMap::new(),
            resources: ResourcesSection::default(),
            health: None,
        };
        let err = guard_local_project_file("hosted-app", Ok(mismatch)).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        let missing = AppConfigError::ReadFile {
            path: "enclava.toml".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        guard_local_project_file("hosted-app", Err(missing)).unwrap();
    }

    #[test]
    fn claim_session_accepts_password_file_without_a_terminal() {
        for (stdin, stderr, password_file, accepted) in [
            (true, true, false, true),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, false, false),
            (true, true, true, true),
            (true, false, true, true),
            (false, true, true, true),
            (false, false, true, true),
        ] {
            assert_eq!(
                ensure_claim_session_for(stdin, stderr, password_file).is_ok(),
                accepted,
                "stdin={stdin}, stderr={stderr}, password_file={password_file}"
            );
        }
    }

    #[test]
    fn preclaim_gate_rejects_unsafe_mode_before_touching_the_keystore() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        let err = prepare_recovery_mnemonic_sink_for_session(
            &paths,
            "org-a",
            "shell1",
            MnemonicCapture::Skip,
            false,
            false,
            true,
        )
        .expect_err("unsafe sink mode must be rejected pre-claim");

        assert!(err.to_string().contains("--no-store-mnemonic"));
        // Rejected before any sink preparation side effects.
        assert!(!paths.keys_dir.join("org-a").exists());
    }

    #[test]
    fn preclaim_gate_rejects_missing_password_input() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        prepare_recovery_mnemonic_sink_for_session(
            &paths,
            "org-a",
            "shell1",
            MnemonicCapture::Store,
            false,
            false,
            false,
        )
        .expect_err("missing password input must be rejected before preparing the sink");

        assert!(!paths.keys_dir.join("org-a").exists());
    }

    #[test]
    fn preclaim_gate_rejects_unwritable_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        // A directory squatting on the REAL atomic-write temp name makes the
        // post-claim store fail on any uid (root would bypass permission-based
        // setups); the gate must reject it before the claim is sent.
        let org_dir = paths.keys_dir.join("org-a");
        std::fs::create_dir_all(org_dir.join("shell1.tmp")).unwrap();

        let err = prepare_recovery_mnemonic_sink_for_session(
            &paths,
            "org-a",
            "shell1",
            MnemonicCapture::Store,
            false,
            false,
            true,
        )
        .expect_err("unwritable sink must be rejected before the claim");

        let msg = err.to_string();
        assert!(msg.contains("sink is not ready"));
        assert!(!msg.contains(SYNTHETIC_MNEMONIC));
    }

    #[test]
    fn preclaim_gate_rejects_directory_at_either_real_destination_path() {
        // The store persists to `{app}.mnemonic` via an atomic rename from
        // `{app}.tmp`; a directory at either REAL path guarantees the post-claim
        // store fails, so the pre-claim gate must reject both — behavioral
        // preflight failure, no mocks needed.
        for blocked in ["shell1.mnemonic", "shell1.tmp"] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
            std::fs::create_dir_all(paths.keys_dir.join("org-a").join(blocked)).unwrap();

            let err = prepare_recovery_mnemonic_sink_for_session(
                &paths,
                "org-a",
                "shell1",
                MnemonicCapture::Store,
                true,
                true,
                false,
            )
            .expect_err("blocked real destination must be rejected before the claim");

            let msg = err.to_string();
            assert!(
                msg.contains("sink is not ready"),
                "gate must report the sink failure for {blocked}: {msg}"
            );
            assert!(
                !msg.contains(SYNTHETIC_MNEMONIC),
                "preflight failure must not leak the mnemonic for {blocked}"
            );
            // Rejected pre-claim: the blocking directory is untouched.
            assert!(paths.keys_dir.join("org-a").join(blocked).is_dir());
        }
    }

    #[test]
    fn preclaim_gate_rejection_preserves_existing_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        keys::store_app_mnemonic(&paths, "org-a", "shell1", "prior backup mnemonic").unwrap();
        // Force preflight failure via the temp path while a valid backup exists.
        std::fs::create_dir_all(paths.keys_dir.join("org-a").join("shell1.tmp")).unwrap();

        prepare_recovery_mnemonic_sink_for_session(
            &paths,
            "org-a",
            "shell1",
            MnemonicCapture::Store,
            true,
            true,
            false,
        )
        .expect_err("blocked temp path must fail preflight");

        // The prior mnemonic backup survives the rejected preflight untouched.
        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("prior backup mnemonic".to_string())
        );
    }

    #[test]
    fn preclaim_gate_prepares_sink_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        if keys::secret_rename_durability_supported() {
            prepare_recovery_mnemonic_sink_for_session(
                &paths,
                "org-a",
                "shell1",
                MnemonicCapture::Store,
                true,
                true,
                false,
            )
            .expect("interactive store-mode sink must be prepared");

            assert!(paths.keys_dir.join("org-a").is_dir());
            assert!(!paths.keys_dir.join("org-a").join("shell1.tmp").exists());
        } else {
            // Deliberate fail-closed behavior: without proven secret-rename
            // durability the pre-claim gate refuses instead of preparing a
            // sink whose post-claim write cannot be proven durable -- and it
            // refuses before any path work, so the claim is never sent with
            // an unprovable sink (the before-any-network ordering itself is
            // pinned by the claim_recovery_sink_tests source contracts).
            let err = prepare_recovery_mnemonic_sink_for_session(
                &paths,
                "org-a",
                "shell1",
                MnemonicCapture::Store,
                true,
                true,
                false,
            )
            .expect_err("non-Unix must refuse sink preparation before the claim");
            assert!(
                err.to_string()
                    .contains("claim sink preparation is unsupported on this platform"),
                "unexpected error: {err}"
            );
            assert!(
                !paths.keys_dir.join("org-a").exists(),
                "the non-Unix refusal must precede any filesystem mutation"
            );
        }
    }

    #[test]
    fn store_after_claim_success_persists_to_protected_keystore() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        store_recovery_mnemonic_after_claim(&paths, "org-a", "shell1", SYNTHETIC_MNEMONIC)
            .expect("post-claim persistence must succeed on a prepared sink");

        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some(SYNTHETIC_MNEMONIC.to_string())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(keys::app_mnemonic_path(&paths, "org-a", "shell1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "stored mnemonic must be owner-only");
        }
    }

    #[test]
    fn store_after_claim_forced_failure_is_incomplete_and_never_leaks() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        // Block every store attempt on any uid: a directory squatting on the
        // atomic-write temp name for the real mnemonic file.
        let org_dir = paths.keys_dir.join("org-a");
        std::fs::create_dir_all(org_dir.join("shell1.tmp")).unwrap();

        let err =
            store_recovery_mnemonic_after_claim(&paths, "org-a", "shell1", SYNTHETIC_MNEMONIC)
                .expect_err("forced storage failure must surface after the claim committed");

        let msg = err.to_string();
        assert!(
            msg.starts_with(OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE),
            "error must carry the stable incomplete-backup code: {msg}"
        );
        assert!(msg.contains("NOT rolled back"));
        assert!(msg.contains("Dependent actions were halted"));
        assert!(
            !msg.contains(SYNTHETIC_MNEMONIC),
            "incomplete-backup error must never embed the mnemonic"
        );
        // Nothing may have been persisted under the failure.
        assert!(
            keys::load_app_mnemonic(&paths, "org-a", "shell1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn response_loss_and_missing_mnemonic_errors_are_incomplete_and_secret_free() {
        let response_lost = ownership_committed_recovery_backup_incomplete(
            "the claim response was lost after the TEE committed ownership, so the one-time recovery mnemonic was never received".to_string(),
        )
        .to_string();
        assert!(response_lost.starts_with(OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE));
        assert!(response_lost.contains("never received"));
        assert!(response_lost.contains("NOT rolled back"));
        assert!(!response_lost.contains(SYNTHETIC_MNEMONIC));

        let missing = ownership_committed_recovery_backup_incomplete(
            "the TEE's claim response contained no recovery mnemonic".to_string(),
        )
        .to_string();
        assert!(missing.starts_with(OWNERSHIP_COMMITTED_RECOVERY_BACKUP_INCOMPLETE));
        assert!(!missing.contains(SYNTHETIC_MNEMONIC));
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

    #[cfg(unix)]
    #[test]
    fn mnemonic_file_takes_priority_over_unreadable_local_state() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().join("state")).unwrap();
        keys::store_app_mnemonic(&paths, "org-a", "shell1", "stale mnemonic").unwrap();
        let local_path = keys::app_mnemonic_path(&paths, "org-a", "shell1");
        std::fs::set_permissions(&local_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let supplied = tmp.path().join("mnemonic.txt");
        std::fs::write(&supplied, "verified mnemonic\n").unwrap();
        assert_eq!(
            load_recovery_mnemonic(&paths, "org-a", "shell1", Some(&supplied)).unwrap(),
            Some("verified mnemonic".to_string())
        );
        assert!(load_recovery_mnemonic(&paths, "org-a", "shell1", None).is_err());
    }

    #[test]
    fn verified_recovery_mnemonic_replaces_stale_local_value() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        keys::store_app_mnemonic(&paths, "org-a", "shell1", "stale mnemonic").unwrap();

        persist_verified_recovery_mnemonic(&paths, "org-a", "shell1", "verified mnemonic").unwrap();

        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("verified mnemonic".to_string())
        );
    }

    #[test]
    fn recovery_restart_guidance_covers_locked_and_persistence_failures() {
        let locked = TeeError::Tee {
            status: 409,
            message: "{\"error\":\"recover_verification_unavailable\",\"detail\":\"recovery_requires_locked_init_verifier\"}".into(),
        };
        let persistence = TeeError::Tee {
            status: 500,
            message: "{\"error\":\"recover_failed\",\"retry\":\"restart_required\"}".into(),
        };
        let other_conflict = TeeError::Tee {
            status: 409,
            message: "{\"error\":\"other\"}".into(),
        };

        assert!(
            recovery_restart_guidance(&locked)
                .unwrap()
                .contains("locked")
        );
        assert!(
            recovery_restart_guidance(&persistence)
                .unwrap()
                .contains("could not be saved")
        );
        assert!(recovery_restart_guidance(&other_conflict).is_none());
    }

    #[test]
    fn read_secret_file_trims_trailing_newline_and_rejects_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pw.txt");
        std::fs::write(&path, "s3cret-pw\n").unwrap();
        assert_eq!(
            keys::read_secret_file(&path, "new password").unwrap(),
            "s3cret-pw"
        );

        // interior/leading whitespace preserved; only trailing newline trimmed
        std::fs::write(&path, "  lead keep \r\n").unwrap();
        assert_eq!(
            keys::read_secret_file(&path, "new password").unwrap(),
            "  lead keep "
        );

        let empty = tmp.path().join("empty.txt");
        std::fs::write(&empty, "\n").unwrap();
        assert!(keys::read_secret_file(&empty, "new password").is_err());
    }

    #[test]
    fn secret_from_file_or_prompt_reads_file_and_names_flag_without_terminal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pw.txt");
        std::fs::write(&path, "from-file\n").unwrap();
        assert_eq!(
            secret_from_file_or_prompt(
                Some(&path),
                "password",
                "Unlock password",
                None,
                "--password-file",
            )
            .unwrap(),
            "from-file"
        );

        // No file and no terminal on the prompt path: hard error naming the
        // flag. Redirected stderr alone is also refused — dialoguer renders
        // password prompts on stderr and errors on a non-terminal stderr.
        for (stdin_is_terminal, stderr_is_terminal) in [(false, false), (true, false)] {
            let err = secret_from_file_or_prompt_for_session(
                None,
                "password",
                "Unlock password",
                None,
                "--password-file",
                stdin_is_terminal,
                stderr_is_terminal,
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("--password-file"),
                "error should name the flag: {err}"
            );
        }
    }

    // Runtime coverage for the probe contract the removed source-text pins
    // used to assert: the capability preflight carries an intentionally
    // invalid mode (never a valid mutation), runs before the manifest load
    // and before any TEE seal, and propagates every answer but the
    // side-effect-free 400 (enclava-paas#189).

    #[tokio::test]
    async fn unlock_mode_probe_accepts_only_the_side_effect_free_400() {
        use crate::commands::app::tests::{isolated_state_env, spawn_json_api_stub};

        for (status, ok) in [(400u16, true), (501, false), (403, false), (200, false)] {
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let api_address =
                spawn_json_api_stub(events.clone(), move |_| (status, serde_json::json!({}))).await;
            let _env = isolated_state_env(&format!("http://{api_address}"), false);
            let api = ApiClient::new(&format!("http://{api_address}"), Some("t".to_string()));

            let result = ensure_unlock_mode_change_supported(&api, "shell").await;
            assert_eq!(result.is_ok(), ok, "status {status}: {result:?}");

            let recorded = events.lock().unwrap().clone();
            assert_eq!(recorded.len(), 1, "exactly one probe request: {recorded:?}");
            assert!(
                recorded[0].starts_with("PUT /apps/shell/unlock/mode "),
                "the probe must hit the unlock-mode route: {recorded:?}"
            );
            assert!(
                recorded[0].contains("__capability_probe__"),
                "the probe must carry an invalid mode so it can never be a valid mutation: {recorded:?}"
            );
            assert!(
                !recorded[0].contains("\"transition_receipt\":"),
                "the probe must not carry a transition receipt: {recorded:?}"
            );
        }
    }

    #[tokio::test]
    async fn auto_unlock_preflight_runs_before_manifest_load_and_tee_seals() {
        use crate::commands::app::tests::{isolated_state_env, spawn_json_api_stub};

        // Enable refuses up front (see enable_subcommand_refuses_above); for
        // Disable, a hosted placeholder answer (501) aborts the command before
        // the enclava.toml load and before any TEE contact: with no manifest
        // in the isolated CWD and no TEE stub at all, the run must fail with
        // the probe's answer, not a file or connection error.
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let api_address = spawn_json_api_stub(events.clone(), |path| {
            if path == "/apps/shell/unlock/mode" {
                (501, serde_json::json!({ "code": "not_implemented_hosted" }))
            } else {
                (404, serde_json::json!({}))
            }
        })
        .await;
        let _env = isolated_state_env(&format!("http://{api_address}"), true);

        let error = auto_unlock(AutoUnlockCommand::Disable {
            app: Some("shell".to_string()),
            image: "img".to_string(),
            password_file: None,
        })
        .await
        .expect_err("the hosted placeholder must abort the command")
        .to_string();
        assert!(
            error.contains("not implemented on this platform"),
            "unexpected error: {error}"
        );

        let recorded = events.lock().unwrap().clone();
        assert_eq!(
            recorded.len(),
            1,
            "the command probes exactly once: {recorded:?}"
        );
        assert!(
            recorded.iter().all(
                |request| request.starts_with("PUT /apps/shell/unlock/mode ")
                    && request.contains("__capability_probe__")
            ),
            "the command probes once and stops: no app lookup, no manifest, no TEE seal — {recorded:?}"
        );
    }
}
