use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand};
use dialoguer::{Confirm, Input, Password};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{UnlockEndpointResponse, UpdateUnlockModeRequest};
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::keys;
use enclava_cli::tee_client::TeeClient;
use enclava_engine::types::WorkloadSecurityProfile;
use uuid::Uuid;

#[derive(Args)]
pub struct ClaimArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
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

    if let Some(mnemonic) = result.as_ref().and_then(|result| result.mnemonic.as_ref()) {
        present_recovery_mnemonic(mnemonic)?;
    }

    Ok(())
}

/// Present the one-time LUKS recovery mnemonic to the operator.
///
/// The mnemonic is the only recovery for encrypted storage and is NOT covered by
/// `enclava key backup` (deploy keys only); the CLI never persists it. Output goes to
/// stderr so it never corrupts machine-readable (`--json`) stdout. On an interactive
/// terminal the operator must confirm they recorded it before the command proceeds — it
/// cannot be shown again afterwards. The gate is skipped off-TTY so scripted/CI deploys
/// (e.g. `--storage-password-file`) don't block.
pub(crate) fn present_recovery_mnemonic(mnemonic: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("==================== RECOVERY MNEMONIC (shown ONCE) ====================");
    eprintln!(
        "This is the ONLY recovery for your encrypted storage; `enclava key backup` does not back it up (deploy keys only)."
    );
    eprintln!("If you lose this AND your storage password, your data cannot be recovered.");
    eprintln!();
    eprintln!("    {mnemonic}");
    eprintln!();

    if io::stdin().is_terminal() {
        loop {
            let confirmed = Confirm::new()
                .with_prompt("I have recorded my recovery mnemonic")
                .default(false)
                .interact()?;
            if confirmed {
                return Ok(());
            }
            eprintln!(
                "Please record it now — it will not be shown again after this command exits."
            );
        }
    }
    Ok(())
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
    let (api, _paths) = build_api_client()?;
    let endpoint = resolve_tee_endpoint(&api, &app_name).await?;
    let tee =
        TeeClient::new_for_ownership_with_resolve_ip(&endpoint.tee_url, endpoint.tee_resolve_ip);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let mnemonic: String = Input::new()
        .with_prompt("Recovery mnemonic (BIP39)")
        .interact_text()?;

    let new_password = Password::new()
        .with_prompt("New unlock password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    println!("Recovering {app_name}...");
    tee.recover(&mnemonic, &new_password).await?;
    println!("Recovery complete. Use the new password to unlock.");
    Ok(())
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

    #[test]
    fn non_interactive_present_does_not_block_on_confirmation_gate() {
        // In a non-interactive test harness the confirmation gate must be skipped,
        // otherwise scripted/CI deploys would block. dialoguer errors off-TTY, so if the
        // is_terminal() guard were removed this would return Err instead of Ok.
        present_recovery_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        )
        .expect("non-interactive path must skip the confirmation gate and return Ok");
    }
}
