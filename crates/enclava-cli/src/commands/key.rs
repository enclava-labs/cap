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
    Member, OrgKeyring, OrgKeyringEnvelope, Role, fingerprint, keyring_fingerprint_hex,
    load_trusted_owner, replace_trusted_owner, sign_keyring, single_member_keyring,
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
    /// Rotate active org keyring ownership to the local recovery-derived owner key
    RecoverOwner {
        /// Confirm that this authenticated owner should replace the org keyring owner key
        #[arg(long)]
        yes: bool,
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
        KeyCommand::RecoverOwner { yes } => recover_owner(yes).await,
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

fn recovered_owner_keyring(
    existing: Option<&OrgKeyringEnvelope>,
    org_id: Uuid,
    owner: &keys::UserSigningKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<OrgKeyring, Box<dyn std::error::Error>> {
    let (version, mut members) = if let Some(envelope) = existing {
        if envelope.keyring.org_id != org_id {
            return Err("remote keyring org_id does not match active org".into());
        }
        (
            envelope.keyring.version + 1,
            envelope.keyring.members.clone(),
        )
    } else {
        (1, Vec::new())
    };

    members.retain(|member| member.user_id != owner.user_id);
    members.push(Member {
        user_id: owner.user_id,
        pubkey: owner.public,
        role: Role::Owner,
        added_at: now,
    });

    Ok(OrgKeyring {
        org_id,
        version,
        members,
        updated_at: now,
    })
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
    let metadata = if let Some((_api, me)) = current_user(&paths).await? {
        if let Some(requested_org) = org
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
        keys::RecoveryBackupMetadata {
            org_id: Some(me.active_org.id),
            org_name: Some(me.active_org.name),
            owner_fingerprint: Some(fingerprint(&owner.public)),
        }
    } else {
        keys::RecoveryBackupMetadata::default()
    };
    let passphrase = prompt_backup_passphrase()?;
    let backup = keys::encrypt_recovery_backup_with_metadata(&seed, &passphrase, metadata)?;
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
    if let Some(backup_org_id) = backup.org_id.as_deref()
        && backup_org_id != me.active_org.id
    {
        return Err(format!(
            "backup is for org {backup_org_id}, but active org is {} ({})",
            me.active_org.name, me.active_org.id
        )
        .into());
    }
    let (_org_id, org_name, owner_fingerprint) =
        verify_or_initialize_remote_keyring(&api, &me, &seed).await?;

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
    Ok(())
}

async fn recover_owner(yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !yes {
        return Err(
            "owner recovery replaces the active org keyring owner key; rerun with `--yes` after confirming this is the intended account and org"
                .into(),
        );
    }

    let paths = CliPaths::resolve()?;
    let seed = keys::load_recovery_seed(&paths)?.ok_or(
        "local recovery seed is missing; restore the intended recovery backup before owner recovery",
    )?;
    let (api, me) = current_user(&paths)
        .await?
        .ok_or("owner recovery requires an active platform session; run `enclava login` first")?;
    let user_id = Uuid::parse_str(&me.user_id)?;
    let org_id = Uuid::parse_str(&me.active_org.id)?;
    let org_name = me.active_org.name.clone();
    let owner = keys::derive_org_owner_key(user_id, org_id, &seed)?;
    register_public_key(&api, &owner.public).await?;

    let current = match api.get_org_keyring(&org_name).await {
        Ok(response) => {
            let envelope = keyring_envelope_from_response(response)?;
            verify_keyring(&envelope, &envelope.signing_pubkey)?;
            if !keyring_has_owner(&envelope, &envelope.signing_pubkey) {
                return Err("remote keyring signing_pubkey is not an owner member".into());
            }
            Some(envelope)
        }
        Err(enclava_cli::api_client::ApiError::Api { status: 404, .. }) => {
            if !me.active_org.is_personal {
                return Err(
                    "org keyring is missing for a non-personal org; create the org keyring through onboarding before recovery"
                        .into(),
                );
            }
            None
        }
        Err(err) => return Err(err.into()),
    };

    let keyring = recovered_owner_keyring(current.as_ref(), org_id, &owner, chrono::Utc::now())?;
    let envelope = sign_keyring(&owner, keyring);
    upload_keyring(&api, &org_name, &envelope).await?;
    replace_trusted_owner(&org_id, &owner.public)?;
    store_keyring_envelope(&org_id, &envelope)?;

    match api
        .bootstrap_signing_service_owner(
            &org_name,
            &BootstrapSigningServiceRequest {
                owner_pubkey_hex: hex::encode(owner.public.to_bytes()),
            },
        )
        .await
    {
        Ok(response) => {
            println!("Policy signing service owner state: {}", response.state);
        }
        Err(enclava_cli::api_client::ApiError::Api { status: 503, .. }) => {
            println!("Policy signing service is not configured; keyring recovery is complete.");
        }
        Err(err) => return Err(err.into()),
    }

    println!(
        "Recovered owner keyring v{} for {} ({})",
        envelope.keyring.version, org_name, org_id
    );
    println!("Owner pubkey fingerprint: {}", fingerprint(&owner.public));
    println!(
        "Keyring fingerprint: {}",
        keyring_fingerprint_hex(&envelope.keyring)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn recovered_owner_keyring_replaces_current_user_and_preserves_others() {
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let old_owner = keys::UserSigningKey::generate(user_id);
        let new_owner = keys::UserSigningKey::generate(user_id);
        let other = keys::UserSigningKey::generate(other_id);
        let old_time = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        let existing = sign_keyring(
            &old_owner,
            OrgKeyring {
                org_id,
                version: 5,
                members: vec![
                    Member {
                        user_id,
                        pubkey: old_owner.public,
                        role: Role::Owner,
                        added_at: old_time,
                    },
                    Member {
                        user_id: other_id,
                        pubkey: other.public,
                        role: Role::Deployer,
                        added_at: old_time,
                    },
                ],
                updated_at: old_time,
            },
        );

        let recovered = recovered_owner_keyring(Some(&existing), org_id, &new_owner, now).unwrap();

        assert_eq!(recovered.version, 6);
        assert_eq!(recovered.members.len(), 2);
        assert!(recovered.members.iter().any(|member| {
            member.user_id == user_id
                && member.pubkey.to_bytes() == new_owner.public.to_bytes()
                && matches!(member.role, Role::Owner)
                && member.added_at == now
        }));
        assert!(recovered.members.iter().any(|member| {
            member.user_id == other_id
                && member.pubkey.to_bytes() == other.public.to_bytes()
                && matches!(member.role, Role::Deployer)
                && member.added_at == old_time
        }));
    }
}
