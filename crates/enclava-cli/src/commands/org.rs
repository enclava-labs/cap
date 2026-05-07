use clap::Subcommand;
use ed25519_dalek::VerifyingKey;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{
    BootstrapSigningServiceRequest, CreateOrgRequest, InviteRequest, OrgKeyringResponse,
    PutOrgKeyringRequest, RegisterPublicKeyRequest,
};
use enclava_cli::config::{self, CliPaths};

#[derive(Subcommand)]
pub enum OrgCommand {
    /// Create a new organization
    Create {
        /// Organization name
        name: String,
    },
    /// Switch active organization
    Switch {
        /// Organization name to switch to
        name: String,
    },
    /// Invite a member to the current organization
    Invite {
        /// Email or Nostr npub of the person to invite
        identifier: String,
        /// Role to assign
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// List members of the current organization
    Members,
    /// Manage the org-signed keyring (Phase 7 D10)
    #[command(subcommand)]
    Keyring(KeyringCommand),
}

#[derive(Subcommand)]
pub enum KeyringCommand {
    /// Owner-only: create v1 keyring, sign, cache, and upload it
    Init {
        /// Org name. Defaults to active org.
        #[arg(long)]
        org: Option<String>,
        /// Skip bootstrapping the off-cluster policy signing service owner map.
        #[arg(long)]
        skip_signing_service_bootstrap: bool,
    },
    /// Owner-only: fetch current keyring, add member, sign, cache, and upload it
    AddMember {
        /// Org name. Defaults to active org.
        #[arg(long)]
        org: Option<String>,
        /// User UUID for the new member.
        #[arg(long)]
        user_id: String,
        /// Hex-encoded Ed25519 public key (32 bytes / 64 hex chars)
        #[arg(long)]
        pubkey: String,
        #[arg(long, default_value = "deployer")]
        role: String,
    },
    /// Member's first encounter: TOFU prompt, cache the owner pubkey
    Trust {
        /// Org UUID.
        #[arg(long)]
        org_id: String,
        /// Hex-encoded owner pubkey (32 bytes / 64 hex chars)
        owner_pubkey: String,
    },
    /// Fetch, verify against trusted owner pubkey, and cache the latest keyring.
    Fetch {
        /// Org name. Defaults to active org.
        #[arg(long)]
        org: Option<String>,
    },
}

fn build_api_client_with_paths()
-> Result<(ApiClient, CliPaths, config::CliConfig), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths, cli_config))
}

pub async fn run(cmd: OrgCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OrgCommand::Create { name } => {
            let (api, paths, mut cli_config) = build_api_client_with_paths()?;

            let req = CreateOrgRequest { name: name.clone() };
            let resp = api.create_org(&req).await?;

            println!("Organization '{}' created.", resp.name);
            println!("Tier: {}", resp.tier);

            // Switch to the new org
            cli_config.org = Some(resp.name.clone());
            config::save_config(&paths, &cli_config)?;
            println!("Switched to org '{}'.", resp.name);
        }

        OrgCommand::Switch { name } => {
            let (api, paths, mut cli_config) = build_api_client_with_paths()?;

            // Verify the org exists and user is a member
            let orgs = api.list_orgs().await?;
            let found = orgs.iter().any(|o| o.name == name);
            if !found {
                return Err(format!(
                    "org '{name}' not found. Available orgs: {}",
                    orgs.iter()
                        .map(|o| o.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }

            cli_config.org = Some(name.clone());
            config::save_config(&paths, &cli_config)?;
            println!("Switched to org '{name}'.");
        }

        OrgCommand::Invite { identifier, role } => {
            let (api, _paths, cli_config) = build_api_client_with_paths()?;
            let org = cli_config
                .org
                .as_deref()
                .ok_or("no active org -- run `enclava org switch <name>`")?;

            let req = InviteRequest {
                identifier: identifier.clone(),
                role: role.clone(),
            };
            api.invite_member(org, &req).await?;
            println!("Invited {identifier} to {org} as {role}.");
        }

        OrgCommand::Keyring(sub) => return run_keyring(sub).await,

        OrgCommand::Members => {
            let (api, _paths, cli_config) = build_api_client_with_paths()?;
            let org = cli_config
                .org
                .as_deref()
                .ok_or("no active org -- run `enclava org switch <name>`")?;

            let members = api.list_members(org).await?;

            println!("Members of {org}:");
            for member in &members {
                let name = member.display_name.as_deref().unwrap_or(&member.user_id);
                println!("  {} ({})", name, member.role);
            }
        }
    }
    Ok(())
}

async fn run_keyring(cmd: KeyringCommand) -> Result<(), Box<dyn std::error::Error>> {
    use chrono::Utc;
    use enclava_cli::keyring::{
        Member, OrgKeyring, OrgKeyringEnvelope, Role, fingerprint, keyring_fingerprint_hex,
        load_trusted_owner, sign_keyring, store_keyring_envelope, store_trusted_owner,
        verify_keyring,
    };
    use enclava_cli::keys;
    use uuid::Uuid;

    fn parse_pubkey(hex_in: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_in)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "pubkey must decode to 32 bytes")?;
        Ok(VerifyingKey::from_bytes(&arr)?)
    }

    fn parse_role(s: &str) -> Result<Role, Box<dyn std::error::Error>> {
        match s {
            "owner" => Ok(Role::Owner),
            "admin" => Ok(Role::Admin),
            "deployer" => Ok(Role::Deployer),
            other => Err(format!("unknown role `{other}`").into()),
        }
    }

    fn active_org(
        override_org: Option<String>,
        config: &config::CliConfig,
    ) -> Result<String, Box<dyn std::error::Error>> {
        override_org
            .or_else(|| config.org.clone())
            .ok_or_else(|| "no active org -- run `enclava org switch <name>`".into())
    }

    async fn resolve_org_id(
        api: &ApiClient,
        org_name: &str,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let org = api
            .list_orgs()
            .await?
            .into_iter()
            .find(|org| org.name == org_name)
            .ok_or_else(|| format!("org '{org_name}' not found"))?;
        let id = org
            .id
            .ok_or_else(|| format!("API did not return an id for org '{org_name}'"))?;
        Ok(Uuid::parse_str(&id)?)
    }

    fn current_user_id(paths: &CliPaths) -> Result<Uuid, Box<dyn std::error::Error>> {
        let creds = config::load_credentials(paths)?;
        let token = creds
            .session_token
            .as_deref()
            .ok_or("session login is required for keyring commands")?;
        #[derive(serde::Deserialize)]
        struct Claims {
            sub: String,
        }
        let payload = token
            .split('.')
            .nth(1)
            .ok_or("invalid session token: missing payload")?;
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.as_bytes())?;
        let claims: Claims = serde_json::from_slice(&bytes)?;
        Ok(Uuid::parse_str(&claims.sub)?)
    }

    async fn register_key(
        api: &ApiClient,
        public: &VerifyingKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = RegisterPublicKeyRequest {
            public_key: hex::encode(public.to_bytes()),
            label: Some("enclava-cli".to_string()),
        };
        let _ = api.register_public_key(&req).await?;
        Ok(())
    }

    async fn upload_keyring(
        api: &ApiClient,
        org_name: &str,
        envelope: &OrgKeyringEnvelope,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = PutOrgKeyringRequest {
            version: envelope.keyring.version,
            keyring_payload: serde_json::to_value(&envelope.keyring)?,
            signature: hex::encode(envelope.signature.to_bytes()),
            signing_pubkey: hex::encode(envelope.signing_pubkey.to_bytes()),
        };
        let resp = api.put_org_keyring(org_name, &req).await?;
        println!(
            "Uploaded keyring v{} for {} (fingerprint {})",
            resp.version, org_name, resp.fingerprint
        );
        Ok(())
    }

    async fn bootstrap_signing_service_owner(
        api: &ApiClient,
        org_name: &str,
        org: Uuid,
        owner_pubkey: &VerifyingKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed = api
            .bootstrap_signing_service_owner(
                org_name,
                &BootstrapSigningServiceRequest {
                    owner_pubkey_hex: hex::encode(owner_pubkey.to_bytes()),
                },
            )
            .await?;
        if parsed.org_id != org.to_string() {
            return Err(
                "CAP API returned an unexpected org id from signing-service bootstrap".into(),
            );
        }
        let expected = hex::encode(owner_pubkey.to_bytes());
        if parsed.owner_pubkey_fingerprint != expected {
            return Err("signing-service returned an unexpected owner fingerprint".into());
        }
        println!(
            "Policy signing service owner state: {} ({})",
            parsed.state, parsed.owner_pubkey_fingerprint
        );
        Ok(())
    }

    fn envelope_from_response(
        response: OrgKeyringResponse,
    ) -> Result<OrgKeyringEnvelope, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Wire {
            keyring: OrgKeyring,
            signature: String,
            signing_pubkey: String,
        }
        let wire = Wire {
            keyring: serde_json::from_value(response.keyring_payload)?,
            signature: response.signature,
            signing_pubkey: response.signing_pubkey,
        };
        let sig_bytes: [u8; 64] = hex::decode(wire.signature)?
            .try_into()
            .map_err(|_| "API returned org keyring signature with invalid length")?;
        Ok(OrgKeyringEnvelope {
            keyring: wire.keyring,
            signature: ed25519_dalek::Signature::from_bytes(&sig_bytes),
            signing_pubkey: parse_pubkey(&wire.signing_pubkey)?,
        })
    }

    match cmd {
        KeyringCommand::Init {
            org,
            skip_signing_service_bootstrap,
        } => {
            let (api, paths, cli_config) = build_api_client_with_paths()?;
            let org_name = active_org(org, &cli_config)?;
            let org = resolve_org_id(&api, &org_name).await?;
            let user_id = current_user_id(&paths)?;
            let key = keys::create_and_store(user_id)?;
            register_key(&api, &key.public).await?;

            let keyring = OrgKeyring {
                org_id: org,
                version: 1,
                members: vec![Member {
                    user_id,
                    pubkey: key.public,
                    role: Role::Owner,
                    added_at: Utc::now(),
                }],
                updated_at: Utc::now(),
            };
            let env = sign_keyring(&key, keyring);
            store_trusted_owner(&org, &key.public)?;
            store_keyring_envelope(&org, &env)?;
            upload_keyring(&api, &org_name, &env).await?;
            if !skip_signing_service_bootstrap {
                bootstrap_signing_service_owner(&api, &org_name, org, &key.public).await?;
            }

            println!("Initialized keyring for {org_name} ({org})");
            println!("Owner pubkey fingerprint: {}", fingerprint(&key.public));
            println!(
                "Keyring fingerprint: {}",
                keyring_fingerprint_hex(&env.keyring)
            );
        }
        KeyringCommand::AddMember {
            org,
            user_id,
            pubkey,
            role,
        } => {
            let (api, paths, cli_config) = build_api_client_with_paths()?;
            let org_name = active_org(org, &cli_config)?;
            let org = resolve_org_id(&api, &org_name).await?;
            let user = Uuid::parse_str(&user_id)?;
            let pk = parse_pubkey(&pubkey)?;
            let role = parse_role(&role)?;
            let owner_user_id = current_user_id(&paths)?;
            let owner_key = keys::load(owner_user_id)?;
            let response = api.get_org_keyring(&org_name).await?;
            let existing = envelope_from_response(response)?;
            let trusted_owner = load_trusted_owner(&org)?
                .ok_or("trusted owner pubkey missing; run `enclava org keyring trust`")?;
            let current = verify_keyring(&existing, &trusted_owner)?;
            if existing.signing_pubkey.to_bytes() != owner_key.public.to_bytes() {
                return Err("current CLI key is not the trusted org owner key".into());
            }
            let mut members = current.members.clone();
            if let Some(member) = members.iter_mut().find(|member| member.user_id == user) {
                member.pubkey = pk;
                member.role = role;
            } else {
                members.push(Member {
                    user_id: user,
                    pubkey: pk,
                    role,
                    added_at: Utc::now(),
                });
            }
            let next = OrgKeyring {
                org_id: org,
                version: current.version + 1,
                members,
                updated_at: Utc::now(),
            };
            let env = sign_keyring(&owner_key, next);
            store_keyring_envelope(&org, &env)?;
            upload_keyring(&api, &org_name, &env).await?;
            println!("Added/updated member {user} ({})", fingerprint(&pk));
        }
        KeyringCommand::Trust {
            org_id,
            owner_pubkey,
        } => {
            let org = Uuid::parse_str(&org_id)?;
            let pk = parse_pubkey(&owner_pubkey)?;

            println!(
                "About to TRUST owner pubkey for org {org}.\n  fingerprint: {}\n\
                 Verify this fingerprint with the org owner over an out-of-band channel.",
                fingerprint(&pk)
            );
            let confirm = dialoguer::Confirm::new()
                .with_prompt("Confirm trust on first use?")
                .default(false)
                .interact()?;
            if !confirm {
                return Err("trust declined".into());
            }
            store_trusted_owner(&org, &pk)?;
            println!("Owner pubkey cached at ~/.enclava/state/{org}/owner_pubkey");
        }
        KeyringCommand::Fetch { org } => {
            let (api, _paths, cli_config) = build_api_client_with_paths()?;
            let org_name = active_org(org, &cli_config)?;
            let org = resolve_org_id(&api, &org_name).await?;
            let response = api.get_org_keyring(&org_name).await?;
            let envelope = envelope_from_response(response)?;
            let trusted_owner = load_trusted_owner(&org)?
                .ok_or("trusted owner pubkey missing; run `enclava org keyring trust`")?;
            verify_keyring(&envelope, &trusted_owner)?;
            store_keyring_envelope(&org, &envelope)?;
            println!(
                "Cached keyring v{} for {} ({})",
                envelope.keyring.version, org_name, org
            );
            println!(
                "Keyring fingerprint: {}",
                keyring_fingerprint_hex(&envelope.keyring)
            );
        }
    }
    Ok(())
}
