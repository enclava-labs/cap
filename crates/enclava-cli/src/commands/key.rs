use clap::Subcommand;
use ed25519_dalek::{Signature, VerifyingKey};
use std::path::PathBuf;
use uuid::Uuid;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{
    BootstrapSigningServiceRequest, CurrentUserResponse, OrgKeyringResponse, PutOrgKeyringRequest,
    RegisterPublicKeyRequest,
};
use enclava_cli::config::{self, CliPaths};
use enclava_cli::keyring::{
    OrgKeyringEnvelope, Role, fingerprint, load_trusted_owner, sign_keyring, single_member_keyring,
    store_keyring_envelope, store_trusted_owner, verify_keyring,
};
use enclava_cli::keys;

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show local recovery and deploy key status
    Status,
    /// Export an encrypted recovery-seed backup
    Backup {
        /// Backup file path
        #[arg(long = "out", visible_alias = "output")]
        output: PathBuf,
        /// Organization name to use for backup metadata
        #[arg(long)]
        org: Option<String>,
        /// Overwrite an existing backup file
        #[arg(long)]
        force: bool,
    },
    /// Restore an encrypted recovery-seed backup
    Restore {
        /// Backup file path
        input: Option<PathBuf>,
        /// Backup file path (legacy flag form)
        #[arg(long = "input")]
        input_file: Option<PathBuf>,
        /// Overwrite an existing local recovery seed
        #[arg(long)]
        force: bool,
    },
}

pub async fn run(cmd: KeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KeyCommand::Status => status().await,
        KeyCommand::Backup { output, org, force } => backup(output, org, force).await,
        KeyCommand::Restore {
            input,
            input_file,
            force,
        } => {
            let input = input.or(input_file).ok_or(
                "backup file is required, for example `enclava key restore enclava-recovery.json`",
            )?;
            restore(input, force).await
        }
    }
}

async fn current_user(
    paths: &CliPaths,
) -> Result<Option<(ApiClient, CurrentUserResponse)>, Box<dyn std::error::Error>> {
    let cli_config = config::load_config(paths)?;
    let creds = config::load_credentials(paths)?;
    if creds.auth_token().is_none() {
        return Ok(None);
    }
    let api = ApiClient::from_config(&cli_config, &creds);
    let me = api.get_current_user().await?;
    Ok(Some((api, me)))
}

fn parse_pubkey(hex_in: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_in)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "pubkey must decode to 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

fn keyring_envelope_from_response(
    response: OrgKeyringResponse,
) -> Result<OrgKeyringEnvelope, Box<dyn std::error::Error>> {
    let sig_bytes: [u8; 64] = hex::decode(response.signature)?
        .try_into()
        .map_err(|_| "API returned org keyring signature with invalid length")?;
    Ok(OrgKeyringEnvelope {
        keyring: serde_json::from_value(response.keyring_payload)?,
        signature: Signature::from_bytes(&sig_bytes),
        signing_pubkey: parse_pubkey(&response.signing_pubkey)?,
    })
}

async fn register_public_key(
    api: &ApiClient,
    public: &VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = api
        .register_public_key(&RegisterPublicKeyRequest {
            public_key: hex::encode(public.to_bytes()),
            label: Some("enclava-cli-owner".to_string()),
        })
        .await?;
    Ok(())
}

async fn upload_keyring(
    api: &ApiClient,
    org_name: &str,
    envelope: &OrgKeyringEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = api
        .put_org_keyring(
            org_name,
            &PutOrgKeyringRequest {
                version: envelope.keyring.version,
                keyring_payload: serde_json::to_value(&envelope.keyring)?,
                signature: hex::encode(envelope.signature.to_bytes()),
                signing_pubkey: hex::encode(envelope.signing_pubkey.to_bytes()),
            },
        )
        .await?;
    Ok(())
}

fn keyring_has_owner(envelope: &OrgKeyringEnvelope, public: &VerifyingKey) -> bool {
    let public = public.to_bytes();
    envelope
        .keyring
        .members
        .iter()
        .any(|member| member.pubkey.to_bytes() == public && matches!(member.role, Role::Owner))
}

async fn verify_or_initialize_remote_keyring(
    api: &ApiClient,
    me: &CurrentUserResponse,
    seed: &[u8; 32],
) -> Result<(Uuid, String, String), Box<dyn std::error::Error>> {
    let user_id = Uuid::parse_str(&me.user_id)?;
    let org_id = Uuid::parse_str(&me.active_org.id)?;
    let org_name = me.active_org.name.clone();
    let owner = keys::derive_org_owner_key(user_id, org_id, seed)?;
    register_public_key(api, &owner.public).await?;

    match api.get_org_keyring(&org_name).await {
        Ok(response) => {
            let envelope = keyring_envelope_from_response(response)?;
            verify_keyring(&envelope, &envelope.signing_pubkey)?;
            if !keyring_has_owner(&envelope, &owner.public) {
                return Err(format!(
                    "restored seed derives owner key {}, but that key is not an owner in the remote keyring for {org_name} ({org_id})",
                    fingerprint(&owner.public)
                )
                .into());
            }
            store_trusted_owner(&org_id, &envelope.signing_pubkey)?;
            store_keyring_envelope(&org_id, &envelope)?;
            Ok((org_id, org_name, fingerprint(&owner.public)))
        }
        Err(enclava_cli::api_client::ApiError::Api { status: 404, .. }) => {
            if !me.active_org.is_personal {
                return Err(
                    "org keyring is missing for a non-personal org; team keyring onboarding is not part of the manual MVP"
                        .into(),
                );
            }
            let keyring = single_member_keyring(org_id, 1, &owner, Role::Owner, chrono::Utc::now());
            let envelope = sign_keyring(&owner, keyring);
            store_trusted_owner(&org_id, &owner.public)?;
            store_keyring_envelope(&org_id, &envelope)?;
            upload_keyring(api, &org_name, &envelope).await?;
            match api
                .bootstrap_signing_service_owner(
                    &org_name,
                    &BootstrapSigningServiceRequest {
                        owner_pubkey_hex: hex::encode(owner.public.to_bytes()),
                    },
                )
                .await
            {
                Ok(_) => {}
                Err(enclava_cli::api_client::ApiError::Api { status: 503, .. }) => {}
                Err(err) => return Err(err.into()),
            }
            Ok((org_id, org_name, fingerprint(&owner.public)))
        }
        Err(err) => Err(err.into()),
    }
}

async fn status() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let seed = keys::load_recovery_seed(&paths)?;
    match seed {
        Some(seed) => {
            println!("Recovery seed: present");
            println!("Seed fingerprint: {}", keys::seed_fingerprint(&seed));
            if let Some((_api, me)) = current_user(&paths).await? {
                let user_id = Uuid::parse_str(&me.user_id)?;
                let org_id = Uuid::parse_str(&me.active_org.id)?;
                let org_name = me.active_org.name;
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
                let stored_mnemonics =
                    keys::list_app_mnemonics(&paths, &org_name).unwrap_or_default();
                if stored_mnemonics.is_empty() {
                    println!("Stored recovery mnemonics: none");
                } else {
                    let apps: Vec<&str> =
                        stored_mnemonics.iter().map(|(a, _)| a.as_str()).collect();
                    println!(
                        "Stored recovery mnemonics: {} app(s) — {}",
                        stored_mnemonics.len(),
                        apps.join(", ")
                    );
                }
                let cli_config = config::load_config(&paths)?;
                match cli_config.last_backup_at.as_deref() {
                    None if !stored_mnemonics.is_empty() => println!(
                        "Backup: none recorded. The mnemonic(s) above are LOCAL ONLY — run `enclava key backup` and keep that file off this machine, or they are lost if this machine is lost."
                    ),
                    None => {
                        println!("Backup: none recorded (run `enclava key backup` to create one).");
                    }
                    Some(ts) => {
                        let when = chrono::DateTime::parse_from_rfc3339(ts)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                            .unwrap_or_else(|_| ts.to_string());
                        println!(
                            "Last `key backup`: {when} (re-run it after each new claim to capture new mnemonics)."
                        );
                    }
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

fn logged_out_backup_metadata(
    org: Option<String>,
) -> (keys::RecoveryBackupMetadata, Option<String>) {
    (
        keys::RecoveryBackupMetadata {
            org_name: org.clone(),
            ..keys::RecoveryBackupMetadata::default()
        },
        org,
    )
}

fn ensure_backup_org_matches_active_org(
    backup_org_id: Option<&str>,
    backup_org_name: Option<&str>,
    active_org_id: &str,
    active_org_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(backup_org_id) = backup_org_id
        && backup_org_id != active_org_id
    {
        return Err(format!(
            "backup is for org {backup_org_id}, but active org is {active_org_name} ({active_org_id})"
        )
        .into());
    }
    if let Some(backup_org_name) = backup_org_name
        && backup_org_name != active_org_name
    {
        return Err(format!(
            "backup is for org {backup_org_name}, but active org is {active_org_name} ({active_org_id})"
        )
        .into());
    }
    Ok(())
}

fn ensure_mnemonic_restore_will_not_overwrite(
    paths: &CliPaths,
    org_name: &str,
    mnemonics: &[keys::RecoveryBackupMnemonic],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if force {
        return Ok(());
    }

    for mnemonic in mnemonics {
        if let Some(existing) = keys::load_app_mnemonic(paths, org_name, &mnemonic.app)?
            && existing != mnemonic.mnemonic
        {
            let path = keys::app_mnemonic_path(paths, org_name, &mnemonic.app);
            return Err(format!(
                "{} already contains a different recovery mnemonic for {}; pass --force to overwrite it after verifying this backup is current",
                path.display(),
                mnemonic.app
            )
            .into());
        }
    }
    Ok(())
}

fn restore_app_mnemonics(
    paths: &CliPaths,
    org_name: &str,
    mnemonics: &[keys::RecoveryBackupMnemonic],
) -> Result<(), Box<dyn std::error::Error>> {
    for mnemonic in mnemonics {
        keys::store_app_mnemonic(paths, org_name, &mnemonic.app, &mnemonic.mnemonic)?;
    }
    Ok(())
}

async fn backup(
    output: PathBuf,
    org: Option<String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if output.exists() && !force {
        return Err(format!(
            "backup file {} already exists; pass --force to overwrite it",
            output.display()
        )
        .into());
    }
    let paths = CliPaths::resolve()?;
    let seed = keys::load_or_create_recovery_seed(&paths)?;
    let (metadata, backup_org_name) = if let Some((_api, me)) = current_user(&paths).await? {
        if let Some(requested_org) = org.as_deref()
            && requested_org != me.active_org.name
            && requested_org != me.active_org.id
        {
            return Err(format!(
                "requested backup org {requested_org} does not match active org {} ({})",
                me.active_org.name, me.active_org.id
            )
            .into());
        }
        let user_id = Uuid::parse_str(&me.user_id)?;
        let org_id = Uuid::parse_str(&me.active_org.id)?;
        let owner = keys::derive_org_owner_key(user_id, org_id, &seed)?;
        let active_name = me.active_org.name.clone();
        (
            keys::RecoveryBackupMetadata {
                org_id: Some(me.active_org.id),
                org_name: Some(active_name.clone()),
                owner_fingerprint: Some(fingerprint(&owner.public)),
            },
            Some(active_name),
        )
    } else {
        if org.is_none() {
            let mnemonic_orgs = keys::list_app_mnemonic_orgs(&paths)?;
            if !mnemonic_orgs.is_empty() {
                return Err(format!(
                    "stored recovery mnemonics exist for org(s) {}; run `enclava key backup --org <org>` or login before backing up so they are not omitted",
                    mnemonic_orgs.join(", ")
                )
                .into());
            }
        }
        logged_out_backup_metadata(org)
    };
    let mnemonics: Vec<keys::RecoveryBackupMnemonic> = match backup_org_name.as_deref() {
        Some(org_name) => keys::list_app_mnemonics(&paths, org_name)?
            .into_iter()
            .map(|(app, mnemonic)| keys::RecoveryBackupMnemonic { app, mnemonic })
            .collect(),
        None => Vec::new(),
    };
    let passphrase = prompt_backup_passphrase()?;
    let backup =
        keys::encrypt_recovery_backup_with_metadata(&seed, &passphrase, metadata, &mnemonics)?;
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
    if mnemonics.is_empty() {
        println!(
            "Note: no recovery mnemonics are stored locally; this backup covers deploy keys only. Store a mnemonic at deploy/claim time (default) to back it up too."
        );
    } else {
        let apps: Vec<&str> = mnemonics.iter().map(|m| m.app.as_str()).collect();
        println!(
            "This backup covers deploy keys plus storage recovery for {} app(s): {}",
            mnemonics.len(),
            apps.join(", ")
        );
    }

    // Record that a backup was made so `key status` can warn about mnemonics
    // that exist only locally (lost if this machine is lost).
    let mut cli_config = config::load_config(&paths)?;
    cli_config.last_backup_at = Some(chrono::Utc::now().to_rfc3339());
    config::save_config(&paths, &cli_config)?;
    Ok(())
}

async fn restore(input: PathBuf, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let raw = std::fs::read_to_string(&input)?;
    let backup: keys::RecoveryBackup = serde_json::from_str(&raw)?;
    let passphrase = prompt_restore_passphrase()?;
    let keys::DecryptedBackup { seed, mnemonics } =
        keys::decrypt_recovery_backup(&backup, &passphrase)?;
    let existing_seed = keys::load_recovery_seed(&paths)?;
    if let Some(existing) = existing_seed
        && existing != seed
        && !force
    {
        return Err(format!(
            "{} already contains a different recovery seed; pass --force to overwrite it after verifying this backup is the one you intend to use",
            paths.recovery_seed.display()
        )
        .into());
    }
    let (api, me) = current_user(&paths)
        .await?
        .ok_or("restore requires an active platform session; run `enclava login` first")?;
    ensure_backup_org_matches_active_org(
        backup.org_id.as_deref(),
        backup.org_name.as_deref(),
        &me.active_org.id,
        &me.active_org.name,
    )?;
    let (_org_id, org_name, owner_fingerprint) =
        verify_or_initialize_remote_keyring(&api, &me, &seed).await?;
    ensure_mnemonic_restore_will_not_overwrite(&paths, &org_name, &mnemonics, force)?;

    if existing_seed == Some(seed) {
        println!(
            "Recovery seed already present at {}",
            paths.recovery_seed.display()
        );
    } else {
        keys::store_seed_at(&paths.recovery_seed, &seed, force)?;
        println!(
            "Recovery seed restored to {}",
            paths.recovery_seed.display()
        );
    }
    println!("Seed fingerprint: {}", keys::seed_fingerprint(&seed));
    println!("Verified owner key for {org_name}: {owner_fingerprint}");
    if mnemonics.is_empty() {
        println!("Note: this backup contained no stored recovery mnemonics (deploy keys only).");
    } else {
        restore_app_mnemonics(&paths, &org_name, &mnemonics)?;
        let apps: Vec<&str> = mnemonics.iter().map(|m| m.app.as_str()).collect();
        println!(
            "Restored storage recovery mnemonic(s) for {} app(s): {}",
            mnemonics.len(),
            apps.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn restore_mnemonics_requires_force_before_overwriting_different_existing_value() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        keys::store_app_mnemonic(&paths, "org-a", "shell", "newer mnemonic").unwrap();
        let mnemonics = vec![keys::RecoveryBackupMnemonic {
            app: "shell".to_string(),
            mnemonic: "older mnemonic".to_string(),
        }];

        let err = ensure_mnemonic_restore_will_not_overwrite(&paths, "org-a", &mnemonics, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("different recovery mnemonic"));
        assert!(err.contains("--force"));
        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell").unwrap(),
            Some("newer mnemonic".to_string())
        );

        ensure_mnemonic_restore_will_not_overwrite(&paths, "org-a", &mnemonics, true).unwrap();
        restore_app_mnemonics(&paths, "org-a", &mnemonics).unwrap();
        assert_eq!(
            keys::load_app_mnemonic(&paths, "org-a", "shell").unwrap(),
            Some("older mnemonic".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_mnemonics_allows_matching_existing_value_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        keys::store_app_mnemonic(&paths, "org-a", "shell", "same mnemonic").unwrap();
        let mnemonics = vec![keys::RecoveryBackupMnemonic {
            app: "shell".to_string(),
            mnemonic: "same mnemonic".to_string(),
        }];

        ensure_mnemonic_restore_will_not_overwrite(&paths, "org-a", &mnemonics, false).unwrap();
    }

    #[test]
    fn logged_out_backup_metadata_records_requested_org_name() {
        let (metadata, backup_org_name) = logged_out_backup_metadata(Some("org-a".to_string()));

        assert_eq!(metadata.org_name.as_deref(), Some("org-a"));
        assert_eq!(backup_org_name.as_deref(), Some("org-a"));
        assert!(metadata.org_id.is_none());
        assert!(metadata.owner_fingerprint.is_none());
    }

    #[test]
    fn restore_rejects_backup_org_name_mismatch() {
        let err = ensure_backup_org_matches_active_org(
            None,
            Some("org-a"),
            "22222222-2222-2222-2222-222222222222",
            "org-b",
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("backup is for org org-a"));
        assert!(err.contains("active org is org-b"));
    }

    #[cfg(unix)]
    #[test]
    fn restore_mnemonics_reject_invalid_app_name_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().join("state")).unwrap();
        let mnemonics = vec![keys::RecoveryBackupMnemonic {
            app: "../escape".to_string(),
            mnemonic: "older mnemonic".to_string(),
        }];

        let err = restore_app_mnemonics(&paths, "org-a", &mnemonics)
            .unwrap_err()
            .to_string();

        assert!(err.contains("invalid recovery mnemonic app name"));
        assert!(!tmp.path().join("state/keys/escape.mnemonic").exists());
        assert!(!tmp.path().join("escape.mnemonic").exists());
    }
}
