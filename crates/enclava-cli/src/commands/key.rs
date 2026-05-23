use clap::Subcommand;
use std::path::PathBuf;
use uuid::Uuid;

use enclava_cli::api_client::ApiClient;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::keyring::{fingerprint, load_trusted_owner};
use enclava_cli::keys;

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show local recovery and deploy key status
    Status,
    /// Export an encrypted recovery-seed backup
    Backup {
        /// Backup file path
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore an encrypted recovery-seed backup
    Restore {
        /// Backup file path
        #[arg(long)]
        input: PathBuf,
        /// Overwrite an existing local recovery seed
        #[arg(long)]
        force: bool,
    },
}

pub async fn run(cmd: KeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KeyCommand::Status => status().await,
        KeyCommand::Backup { output } => backup(output).await,
        KeyCommand::Restore { input, force } => restore(input, force).await,
    }
}

async fn current_user_and_org(
    paths: &CliPaths,
) -> Result<Option<(Uuid, Uuid, String)>, Box<dyn std::error::Error>> {
    let cli_config = config::load_config(paths)?;
    let creds = config::load_credentials(paths)?;
    if creds.auth_token().is_none() {
        return Ok(None);
    }
    let api = ApiClient::from_config(&cli_config, &creds);
    let me = api.get_current_user().await?;
    Ok(Some((
        Uuid::parse_str(&me.user_id)?,
        Uuid::parse_str(&me.active_org.id)?,
        me.active_org.name,
    )))
}

async fn status() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let seed = keys::load_recovery_seed(&paths)?;
    match seed {
        Some(seed) => {
            println!("Recovery seed: present");
            println!("Seed fingerprint: {}", keys::seed_fingerprint(&seed));
            if let Some((user_id, org_id, org_name)) = current_user_and_org(&paths).await? {
                let owner = keys::derive_org_owner_key(user_id, org_id, &seed)?;
                println!("Active org: {org_name} ({org_id})");
                println!("Owner key fingerprint: {}", fingerprint(&owner.public));
                if let Some(trusted) = load_trusted_owner(&org_id)? {
                    let state = if trusted.to_bytes() == owner.public.to_bytes() {
                        "matches local trusted owner"
                    } else {
                        "does not match local trusted owner"
                    };
                    println!("Keyring trust: {state}");
                }
            }
        }
        None => {
            println!("Recovery seed: missing");
            println!(
                "Run `enclava key backup --output <file>` after login or deploy setup to create one."
            );
        }
    }
    Ok(())
}

fn prompt_backup_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    Ok(dialoguer::Password::new()
        .with_prompt("Backup passphrase")
        .with_confirmation("Confirm backup passphrase", "Passphrases do not match")
        .interact()?)
}

fn prompt_restore_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    Ok(dialoguer::Password::new()
        .with_prompt("Backup passphrase")
        .interact()?)
}

async fn backup(output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let seed = keys::load_or_create_recovery_seed(&paths)?;
    let passphrase = prompt_backup_passphrase()?;
    let backup = keys::encrypt_recovery_backup(&seed, &passphrase)?;
    let raw = serde_json::to_vec_pretty(&backup)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = output.with_extension("tmp");
    std::fs::write(&tmp, raw)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &output)?;
    println!("Encrypted recovery backup written to {}", output.display());
    println!("Seed fingerprint: {}", keys::seed_fingerprint(&seed));
    Ok(())
}

async fn restore(input: PathBuf, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let raw = std::fs::read_to_string(&input)?;
    let backup: keys::RecoveryBackup = serde_json::from_str(&raw)?;
    let passphrase = prompt_restore_passphrase()?;
    let seed = keys::decrypt_recovery_backup(&backup, &passphrase)?;

    if let Some((user_id, org_id, org_name)) = current_user_and_org(&paths).await? {
        let owner = keys::derive_org_owner_key(user_id, org_id, &seed)?;
        if let Some(trusted) = load_trusted_owner(&org_id)?
            && trusted.to_bytes() != owner.public.to_bytes()
        {
            return Err(format!(
                "restored seed derives owner key {}, but local trusted owner for {org_name} ({org_id}) is {}",
                fingerprint(&owner.public),
                fingerprint(&trusted),
            )
            .into());
        }
    }

    keys::store_seed_at(&paths.recovery_seed, &seed, force)?;
    println!(
        "Recovery seed restored to {}",
        paths.recovery_seed.display()
    );
    println!("Seed fingerprint: {}", keys::seed_fingerprint(&seed));
    Ok(())
}
