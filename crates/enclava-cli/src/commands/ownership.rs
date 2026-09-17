use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Password};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{self, IsTerminal};
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
    /// Enable automatic unlock (owner seed wrapped for KBS-attestation-gated release)
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
    /// Remove the KBS-gated seed wrap, require password on restart
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

    // Sink gate, before anything touches the TEE: the TEE returns the one-time
    // recovery mnemonic exactly once and rejects a second claim, so an unsafe
    // sink mode, an unattended session, or an unwritable keystore must abort
    // here, while the claim can still be cancelled without side effects.
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

    // Step 1: Get challenge from TEE
    let challenge = tee.bootstrap_challenge().await?;
    println!("Challenge received (expires in {}s)", challenge.ttl_seconds);

    // Step 2: Load or re-derive the deterministic bootstrap keypair.
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
    let password = secret_from_file_or_prompt(
        args.password_file.as_deref(),
        "password",
        "Set unlock password",
        Some(("Confirm password", "Passwords don't match")),
        "--password-file",
    )?;

    // Step 5: Claim
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

    // Step 6: Persist the one-time mnemonic to the prepared protected sink. The
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

/// Attendance for an ownership claim, in two shapes.
///
/// Prompted claim: dialoguer renders the password prompt on stderr and
/// errors when stderr is not a terminal, so both stdin and stderr must be
/// terminals. A session with a terminal stdin but redirected stderr
/// (`2>&1 | tee`) is refused up front with an error pointing at
/// `--password-file` as the way to run a recorded-output claim, instead of
/// failing later inside the prompt.
///
/// Password from a file: no prompt is rendered, so the explicit flag is the
/// operator's acknowledgment that they are responsible for observing the
/// claim result; a terminal on stdin keeps the claim in front of a present
/// operator (foreground exit status), while CI and scripts (no terminal on
/// stdin) stay refused pending response-loss recovery. The one-time mnemonic
/// is persisted to the protected local keystore and never printed, so nothing
/// depends on captured output; a lost response halts with a stable error
/// wherever the operator directed their output. The TEE hands out recovery
/// material exactly once and rejects a second claim, so a lost response
/// strands the mnemonic irrecoverably — that residual is why unattended
/// claims without a terminal stay disabled.
pub(crate) fn claim_session_is_interactive(
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    password_from_file: bool,
) -> bool {
    if password_from_file {
        stdin_is_terminal
    } else {
        stdin_is_terminal && stderr_is_terminal
    }
}

fn ensure_claim_session_for(
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    password_from_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if claim_session_is_interactive(stdin_is_terminal, stderr_is_terminal, password_from_file) {
        return Ok(());
    }
    if stdin_is_terminal && !stderr_is_terminal && !password_from_file {
        return Err(
            "the claim password prompt cannot be shown while stderr is redirected (e.g. `2>&1 | tee`): \
             pass --password-file <PATH> to claim with recorded output. Unattended (CI/script) \
             claims remain disabled until response-loss recovery is supported."
                .into(),
        );
    }
    Err(
        "ownership claims require an interactive terminal on stdin: unattended (CI/script) claims are \
         disabled until response-loss recovery is supported. The TEE returns the one-time \
         recovery mnemonic only once, so a lost response in an unattended run is unrecoverable. \
         Run `enclava claim` (or a deploy that auto-claims) from an interactive shell; \
         recorded-output runs (`2>&1 | tee`) are supported with --password-file."
            .into(),
    )
}

/// Prepare and validate the private recovery-mnemonic sink before the claim is
/// sent: reject unsafe sink modes, require an interactive session (unattended
/// claims are disabled), and prove the protected keystore destination is
/// writable with the same owner-only atomic-write primitives the post-claim
/// store uses. Called by the explicit `claim` flow and by
/// `claim_initial_ownership` (deploy/template auto-claim) before any challenge
/// or claim request.
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
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
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

    let is_tty = io::stdin().is_terminal();

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

    let new_password = match args.new_password_file.as_ref() {
        Some(path) => keys::read_secret_file(path, "new password")?,
        None => Password::new()
            .with_prompt("New unlock password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?,
    };

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
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
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

pub async fn auto_unlock(cmd: AutoUnlockCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AutoUnlockCommand::Enable {
            app,
            image,
            password_file,
        } => {
            let app_name = resolve_app_name(&app)?;
            let (api, paths) = build_api_client()?;
            let cli_config = config::load_config(&paths)?;
            let creds = config::load_credentials(&paths)?;
            let app_config = AppConfig::find_and_load()?;
            let app_meta = api.get_app(&app_name).await?;
            // Resolve the local password source before any remote mutation:
            // blob signing bootstraps the org keyring/signing authority, and a
            // missing or unreadable --password-file must not leave that
            // half-done for a command that never ran.
            let password = secret_from_file_or_prompt(
                password_file.as_deref(),
                "password",
                "Unlock password (to authorize auto-unlock wrapping)",
                None,
                "--password-file",
            )?;
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

            println!("Enabling auto-unlock for {app_name}...");
            tee.enable_auto_unlock(&password).await?;
            println!("KBS-gated seed wrap created inside the TEE.");

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
        AutoUnlockCommand::Disable {
            app,
            image,
            password_file,
        } => {
            let app_name = resolve_app_name(&app)?;
            let (api, paths) = build_api_client()?;
            let cli_config = config::load_config(&paths)?;
            let creds = config::load_credentials(&paths)?;
            let app_config = AppConfig::find_and_load()?;
            let app_meta = api.get_app(&app_name).await?;
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
                    image: &image,
                    target_unlock_mode: Some("password"),
                    workload_security_profile: WorkloadSecurityProfile::Restricted,
                })
                .await?;
            let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
            let tee = TeeClient::new_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
            let (transition_attestation, tee) = tee.attest_receipt_key().await?;

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
    fn claim_session_interactivity_matrix() {
        // Prompted claims need both terminals: dialoguer renders the password
        // prompt on stderr and errors on a non-terminal stderr.
        assert!(claim_session_is_interactive(true, true, false));
        assert!(!claim_session_is_interactive(true, false, false));
        assert!(!claim_session_is_interactive(false, true, false));
        assert!(!claim_session_is_interactive(false, false, false));
        // File-based claims render no prompt: an operator-present stdin is the
        // attendance signal, so recorded-output runs (`2>&1 | tee`) work.
        assert!(claim_session_is_interactive(true, true, true));
        assert!(claim_session_is_interactive(true, false, true));
        assert!(!claim_session_is_interactive(false, true, true));
        assert!(!claim_session_is_interactive(false, false, true));
    }

    #[test]
    fn prompted_claim_under_redirected_stderr_points_at_password_file() {
        let err = ensure_claim_session_for(true, false, false)
            .expect_err("prompted claim under redirected stderr must be refused early");
        let message = err.to_string();
        assert!(message.contains("--password-file"), "{message}");
        assert!(message.contains("2>&1 | tee"), "{message}");
    }

    #[test]
    fn sink_mode_rejects_no_store_before_claim_with_guidance() {
        let err = validate_recovery_mnemonic_sink_mode(MnemonicCapture::Skip)
            .expect_err("--no-store-mnemonic must be rejected before the claim");
        let msg = err.to_string();
        assert!(msg.contains("--no-store-mnemonic"));
        assert!(msg.contains("never printed"));
        assert!(msg.contains("enclava key backup"));

        validate_recovery_mnemonic_sink_mode(MnemonicCapture::Store)
            .expect("default store mode must be allowed");
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
            true,
            true,
            false,
        )
        .expect_err("unsafe sink mode must be rejected pre-claim");

        assert!(err.to_string().contains("--no-store-mnemonic"));
        // Rejected before any sink preparation side effects.
        assert!(!paths.keys_dir.join("org-a").exists());
    }

    #[test]
    fn preclaim_gate_rejects_unattended_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        let err = prepare_recovery_mnemonic_sink_for_session(
            &paths,
            "org-a",
            "shell1",
            MnemonicCapture::Store,
            false,
            false,
            false,
        )
        .expect_err("unattended claims must be rejected pre-claim");

        let msg = err.to_string();
        assert!(msg.contains("interactive terminal"));
        assert!(msg.contains("unattended"));
        // No mnemonic exists yet at gate time; the message must stay secret-free.
        assert!(!msg.contains(SYNTHETIC_MNEMONIC));
        // Rejected before any sink preparation side effects.
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
            true,
            true,
            false,
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
    fn claim_flow_gates_the_sink_before_any_network_claim() {
        let source = include_str!("ownership.rs");
        let start = source.find("pub async fn claim").expect("claim exists");
        let end = start
            + source[start..]
                .find("fn mnemonic_capture_from_flags")
                .expect("apparatus follows claim");
        let body = &source[start..end];

        let gate = body
            .find("prepare_recovery_mnemonic_sink(")
            .expect("claim runs the pre-claim sink gate");
        let challenge = body
            .find("bootstrap_challenge")
            .expect("claim requests a challenge");
        let claim = body.find("bootstrap_claim").expect("claim sends the claim");
        assert!(
            gate < challenge && challenge < claim,
            "sink gate must reject before any challenge or claim request"
        );

        let store = body
            .find("store_recovery_mnemonic_after_claim")
            .expect("claim persists the mnemonic post-claim");
        assert!(store > claim);
        assert!(
            !body.contains("present_and_capture_recovery_mnemonic"),
            "claim must not use the removed stdout/stderr presentation path"
        );
    }

    #[test]
    fn ownership_module_never_prints_the_mnemonic_variable() {
        let source = include_str!("ownership.rs");
        for line in source.lines() {
            if line.contains("println!")
                || line.contains("eprintln!")
                || line.contains("write!")
                || line.contains("writeln!")
            {
                assert!(
                    !line.contains("{mnemonic"),
                    "stdout/stderr statement must not interpolate the mnemonic: {line}"
                );
            }
        }
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
}
