use super::*;

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} must be 32 bytes, got {}", bytes.len()).into())
}

fn env_hex32(name: &str) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    std::env::var(name)
        .ok()
        .map(|value| parse_hex32(name, &value))
        .transpose()
}

pub(crate) fn platform_release_from_deployment_context(
    deployment_context: &DeploymentContextResponse,
) -> Result<Option<PlatformRelease>, Box<dyn std::error::Error>> {
    platform_release_from_deployment_context_with_verifier(deployment_context, verify_envelope)
}

pub(crate) async fn fetch_verified_platform_release(
    api: &ApiClient,
) -> Result<(DeploymentContextResponse, PlatformRelease), Box<dyn std::error::Error>> {
    let deployment_context = api.deployment_context().await?;
    let release = match platform_release_from_deployment_context(&deployment_context)? {
        Some(release) => release,
        None => PlatformRelease::load_verified()?,
    };
    Ok((deployment_context, release))
}

pub(crate) fn platform_release_from_deployment_context_with_verifier<Verify, Err>(
    deployment_context: &DeploymentContextResponse,
    verify: Verify,
) -> Result<Option<PlatformRelease>, Box<dyn std::error::Error>>
where
    Verify: FnOnce(PlatformReleaseEnvelope) -> Result<PlatformRelease, Err>,
    Err: std::fmt::Display,
{
    let Some(envelope) = deployment_context.platform_release_envelope.clone() else {
        return Ok(None);
    };
    let release = verify(envelope).map_err(|err| {
        format!("platform deployment context included an invalid platform_release_envelope: {err}")
    })?;
    let expected_release_id = deployment_context
        .current_platform_release_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(expected) = expected_release_id
        .filter(|expected| *expected != release.platform_release_version.as_str())
    {
        return Err(format!(
            "platform deployment context release id `{expected}` does not match signed release `{}`",
            release.platform_release_version
        )
        .into());
    }
    Ok(Some(release))
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
        signature: ed25519_dalek::Signature::from_bytes(&sig_bytes),
        signing_pubkey: parse_pubkey(&response.signing_pubkey)?,
    })
}

pub(crate) struct ActiveUserOrg {
    pub(crate) user_id: Uuid,
    pub(crate) org_id: Uuid,
    pub(crate) org_name: String,
    pub(crate) is_personal: bool,
}

pub(crate) async fn resolve_current_user_org(
    api: &ApiClient,
) -> Result<ActiveUserOrg, Box<dyn std::error::Error>> {
    let me = api.get_current_user().await?;
    Ok(ActiveUserOrg {
        user_id: Uuid::parse_str(&me.user_id)?,
        org_id: Uuid::parse_str(&me.active_org.id)?,
        org_name: me.active_org.name,
        is_personal: me.active_org.is_personal,
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

pub(crate) async fn ensure_manual_deploy_keyring(
    api: &ApiClient,
    paths: &CliPaths,
) -> Result<(Uuid, String, keys::UserSigningKey), Box<dyn std::error::Error>> {
    let active = resolve_current_user_org(api).await?;
    let user_id = active.user_id;
    let org_id = active.org_id;
    let org_name = active.org_name.clone();
    let seed = keys::load_or_create_recovery_seed(paths)?;
    let owner_key = keys::derive_org_owner_key(user_id, org_id, &seed)?;
    register_public_key(api, &owner_key.public).await?;

    if let (Some(trusted_owner), Ok(local_envelope)) =
        (load_trusted_owner(&org_id)?, load_keyring_envelope(&org_id))
    {
        let verified = verify_keyring(&local_envelope, &trusted_owner)?;
        if member_allows_deploy(verified, &owner_key.public) {
            return Ok((org_id, org_name, owner_key));
        }
    }

    match api.get_org_keyring(&org_name).await {
        Ok(response) => {
            let envelope = keyring_envelope_from_response(response)?;
            if envelope.signing_pubkey.to_bytes() != owner_key.public.to_bytes() {
                return Err(
                    "remote org keyring is owned by a different key; restore the matching recovery seed or use org keyring commands"
                        .into(),
                );
            }
            verify_keyring(&envelope, &owner_key.public)?;
            store_trusted_owner(&org_id, &owner_key.public)?;
            store_keyring_envelope(&org_id, &envelope)?;
            Ok((org_id, org_name, owner_key))
        }
        Err(enclava_cli::api_client::ApiError::Api { status: 404, .. }) => {
            if !active.is_personal {
                return Err(
                    "org keyring is missing for a non-personal org; team keyring onboarding is not part of the manual MVP"
                        .into(),
                );
            }
            let now = Utc::now();
            let keyring = single_member_keyring(org_id, 1, &owner_key, Role::Owner, now);
            let envelope = sign_keyring(&owner_key, keyring);
            store_trusted_owner(&org_id, &owner_key.public)?;
            store_keyring_envelope(&org_id, &envelope)?;
            upload_keyring(api, &org_name, &envelope).await?;
            match api
                .bootstrap_signing_service_owner(
                    &org_name,
                    &BootstrapSigningServiceRequest {
                        owner_pubkey_hex: hex::encode(owner_key.public.to_bytes()),
                    },
                )
                .await
            {
                Ok(_) => {}
                Err(enclava_cli::api_client::ApiError::Api { status: 503, .. }) => {}
                Err(err) => return Err(err.into()),
            }
            Ok((org_id, org_name, owner_key))
        }
        Err(err) => Err(err.into()),
    }
}

fn render_trustee_policy(
    template: &str,
    descriptor: &enclava_cli::descriptor::DeploymentDescriptor,
) -> Result<String, Box<dyn std::error::Error>> {
    let replacements = [
        (
            "{{init_data_hash}}",
            hex::encode(descriptor.expected_cc_init_data_hash),
        ),
        ("{{image_digest}}", descriptor.image_digest.clone()),
        (
            "{{signer_subject}}",
            descriptor.signer_identity.subject.clone(),
        ),
        (
            "{{signer_issuer}}",
            descriptor.signer_identity.issuer.clone(),
        ),
        ("{{namespace}}", descriptor.namespace.clone()),
        ("{{service_account}}", descriptor.service_account.clone()),
        ("{{identity_hash}}", hex::encode(descriptor.identity_hash)),
        (
            "{{kbs_resource_path}}",
            descriptor.kbs_resource_path.clone(),
        ),
    ];

    let mut rendered = template.to_string();
    for (needle, value) in replacements {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| matches!(byte, b'"' | b'\\' | b'\n' | b'\r'))
        {
            return Err(format!("invalid Rego template slot value for {needle}").into());
        }
        rendered = rendered.replace(needle, &value);
    }
    if rendered.contains("{{") {
        return Err("unrendered Rego template slot remains in platform release".into());
    }
    Ok(rendered)
}

pub(crate) struct ConfidentialAppForCcHash<'a> {
    pub(crate) image: enclava_common::image::ImageRef,
    pub(crate) deployment_id: Uuid,
    pub(crate) release: &'a PlatformRelease,
    pub(crate) workload_artifact_binding: WorkloadArtifactBinding,
    pub(crate) generated_agent_policy: GeneratedAgentPolicy,
    pub(crate) deployment_context: DeploymentContextResponse,
    pub(crate) unlock_mode: &'a str,
    pub(crate) tenant_id: String,
    pub(crate) tenant_instance_identity_hash: [u8; 32],
    pub(crate) bootstrap_owner_pubkey_hash: String,
    pub(crate) workload_security_profile: WorkloadSecurityProfile,
    pub(crate) log_encryption: Option<LogEncryptionConfig>,
}

pub(crate) fn confidential_app_for_cc_hash(
    app: &AppResponse,
    app_config: &AppConfig,
    params: ConfidentialAppForCcHash<'_>,
) -> Result<ConfidentialApp, Box<dyn std::error::Error>> {
    let ConfidentialAppForCcHash {
        image,
        deployment_id,
        release,
        workload_artifact_binding,
        generated_agent_policy,
        deployment_context,
        unlock_mode,
        tenant_id,
        tenant_instance_identity_hash,
        bootstrap_owner_pubkey_hash,
        workload_security_profile,
        log_encryption,
    } = params;
    let api_signing_pubkey = deployment_context.api_signing_pubkey.trim().to_string();
    if api_signing_pubkey.is_empty() {
        return Err("platform deployment context did not include api_signing_pubkey".into());
    }

    let unlock_mode = match unlock_mode {
        "password" => UnlockMode::Password,
        "auto" | "auto-unlock" => UnlockMode::Auto,
        other => return Err(format!("unsupported unlock mode {other}").into()),
    };

    Ok(ConfidentialApp {
        app_id: Uuid::parse_str(&app.id)?,
        deployment_id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id,
        bootstrap_owner_pubkey_hash,
        tenant_instance_identity_hash: hex::encode(tenant_instance_identity_hash),
        service_account: app
            .service_account
            .clone()
            .unwrap_or_else(|| format!("cap-{}-sa", app.name)),
        image_pull_secret_name: None,
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers: vec![Container {
            name: "web".to_string(),
            image,
            port: Some(app_config.app.port),
            command: None,
            env: HashMap::new(),
            storage_paths: app_config.storage.paths.clone(),
            workload_security_profile,
            is_primary: true,
        }],
        storage: StorageSpec::new(&app_config.storage.size, &app_config.storage.tls_size),
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey,
        api_url: String::new(),
        resources: ResourceLimits {
            cpu: app_config.resources.cpu.clone(),
            memory: app_config.resources.memory.clone(),
        },
        attestation: AttestationConfig {
            proxy_image: enclava_common::image::ImageRef::parse(&release.attestation_proxy_image)?,
            caddy_image: enclava_common::image::ImageRef::parse(&release.caddy_ingress_image)?,
            acme_ca_url: release.tenant_caddy_acme_ca.clone(),
            caddy_tls_mode: release
                .tenant_caddy_tls_mode
                .parse::<enclava_engine::types::CaddyTlsMode>()
                .map_err(|err| format!("platform release tenant_caddy_tls_mode: {err}"))?,
            trustee_policy_read_available: true,
            workload_artifacts_url: None,
            tls_certificate_broker_url: tls_certificate_broker_url_for_cc_hash(
                release,
                &deployment_context,
            )?,
            trustee_policy_url: None,
            local_workload_artifacts_json: Some("{}".to_string()),
            local_trustee_policy_json: Some("{}".to_string()),
            platform_trustee_policy_pubkey_hex: Some(release.signing_service_pubkey_hex.clone()),
            signing_service_pubkey_hex: Some(release.signing_service_pubkey_hex.clone()),
            verification_material: None,
        },
        egress_mode: enclava_engine::types::EgressMode::Restricted,
        public_internet_egress_excluded_cidrs: Vec::new(),
        egress_allowlist: Vec::new(),
        log_encryption,
        workload_artifact_binding: Some(workload_artifact_binding),
        generated_agent_policy: Some(generated_agent_policy),
    })
}

fn tls_certificate_broker_url_for_cc_hash(
    release: &PlatformRelease,
    deployment_context: &DeploymentContextResponse,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mode = release
        .tenant_caddy_tls_mode
        .parse::<enclava_engine::types::CaddyTlsMode>()
        .map_err(|err| format!("platform release tenant_caddy_tls_mode: {err}"))?;
    if mode != enclava_engine::types::CaddyTlsMode::Dns01Broker {
        return Ok(None);
    }

    let url = deployment_context
        .tls_certificate_broker_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("platform deployment context did not include tls_certificate_broker_url for dns01-broker release")?;
    Ok(Some(url.to_string()))
}

async fn fetch_generated_agent_policy(
    api: &ApiClient,
    release: &PlatformRelease,
    descriptor: &enclava_cli::descriptor::DeploymentDescriptor,
) -> Result<(GeneratedAgentPolicy, Option<LogEncryptionConfig>), Box<dyn std::error::Error>> {
    let response = api
        .generate_agent_policy(
            &descriptor.app_name,
            &AgentPolicyRequest {
                descriptor: descriptor.clone(),
            },
        )
        .await?;
    if response.genpolicy_version_pin != release.genpolicy_version {
        return Err(format!(
            "policy signing service genpolicy version {} does not match signed platform release {}",
            response.genpolicy_version_pin, release.genpolicy_version
        )
        .into());
    }
    let policy_sha256: [u8; 32] = hex::decode(&response.agent_policy_sha256)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!("agent_policy_sha256 must be 32 bytes, got {}", bytes.len())
        })?;
    let actual: [u8; 32] = Sha256::digest(response.agent_policy_text.as_bytes()).into();
    if actual != policy_sha256 {
        return Err("policy signing service returned agent_policy_sha256 that does not match agent_policy_text".into());
    }
    Ok((
        GeneratedAgentPolicy {
            policy_text: response.agent_policy_text,
            policy_sha256,
            genpolicy_version_pin: response.genpolicy_version_pin,
        },
        response.log_encryption,
    ))
}

fn bootstrap_identity_hash(
    paths: &CliPaths,
    org_name: &str,
    org_id: Uuid,
    app_name: &str,
    tenant_id: &str,
    instance_id: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let Some(private_key_bytes) =
        load_or_derive_bootstrap_private_key(paths, org_name, org_id, app_name)?
    else {
        return Ok(None);
    };
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key_hash = hex::encode(Sha256::digest(signing_key.verifying_key().to_bytes()));
    let identity_hash =
        enclava_common::crypto::compute_identity_hash(tenant_id, instance_id, &public_key_hash);
    Ok(Some(parse_hex32(
        "tenant_instance_identity_hash",
        &identity_hash,
    )?))
}

fn bootstrap_public_key_hash(
    paths: &CliPaths,
    org_name: &str,
    org_id: Uuid,
    app_name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(private_key_bytes) =
        load_or_derive_bootstrap_private_key(paths, org_name, org_id, app_name)?
    else {
        return Ok(None);
    };
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    Ok(Some(hex::encode(Sha256::digest(
        signing_key.verifying_key().to_bytes(),
    ))))
}

pub(crate) fn load_or_derive_bootstrap_private_key(
    paths: &CliPaths,
    org_name: &str,
    org_id: Uuid,
    app_name: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let key_path = paths.bootstrap_key_path(org_name, app_name);
    if key_path.exists() {
        let private_key_hex = std::fs::read_to_string(&key_path)?;
        let private_key_bytes: [u8; 32] = hex::decode(private_key_hex.trim())?
            .try_into()
            .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)")?;
        return Ok(Some(private_key_bytes));
    }

    let Some(seed) = keys::load_recovery_seed(paths)? else {
        return Ok(None);
    };
    let app_seed = keys::derive_app_bootstrap_seed(org_id, app_name, &seed)?;
    config::save_bootstrap_key(paths, org_name, app_name, &hex::encode(app_seed))?;
    Ok(Some(app_seed))
}

pub(crate) struct SignedDeployBlobParams<'a> {
    pub api: &'a ApiClient,
    pub paths: &'a CliPaths,
    pub cli_config: &'a config::CliConfig,
    pub creds: &'a config::Credentials,
    pub app: &'a AppResponse,
    pub app_config: &'a AppConfig,
    pub image: &'a str,
    pub target_unlock_mode: Option<&'a str>,
    pub workload_security_profile: WorkloadSecurityProfile,
}

pub(crate) struct SignedDeployBlobs {
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
    pub signed_policy_artifact: String,
    pub log_encryption: Option<LogEncryptionConfig>,
}

pub(crate) async fn build_signed_deploy_blobs(
    params: SignedDeployBlobParams<'_>,
) -> Result<SignedDeployBlobs, Box<dyn std::error::Error>> {
    let SignedDeployBlobParams {
        api,
        paths,
        cli_config: _cli_config,
        creds: _creds,
        app,
        app_config,
        image,
        target_unlock_mode,
        workload_security_profile,
    } = params;
    let image_ref = enclava_common::image::ImageRef::parse(image)?;
    if !image_ref.has_digest() {
        return Err(
            "deployment descriptor signing requires --image <image>@sha256:<digest>; build/sign the image first and pass the digest-pinned reference"
                .into(),
        );
    }
    let deploy_unlock_mode = target_unlock_mode.unwrap_or(app.unlock_mode.as_str());
    if app_config.app.command.is_empty() {
        return Err(
            "app.command in enclava.toml must specify the workload argv, for example [\"/usr/local/bin/app\"]"
                .into(),
        );
    }

    let (deployment_context, release) = fetch_verified_platform_release(api).await?;
    let policy_template_sha256 = release.policy_template_sha256_bytes()?;
    let _signing_service_pubkey = release.signing_service_pubkey_bytes()?;
    let proxy_image = enclava_common::image::ImageRef::parse(&release.attestation_proxy_image)?;
    let caddy_image = enclava_common::image::ImageRef::parse(&release.caddy_ingress_image)?;
    if !proxy_image.has_digest() || !caddy_image.has_digest() {
        return Err("platform release sidecar anchors must be digest-pinned".into());
    }
    let api_signing_pubkey = deployment_context.api_signing_pubkey.trim().to_string();
    if api_signing_pubkey.is_empty() {
        return Err("platform deployment context did not include api_signing_pubkey".into());
    }

    let (org_id, org_name, deployer_key) = ensure_manual_deploy_keyring(api, paths).await?;

    let app_id = Uuid::parse_str(&app.id)?;
    let trusted_owner = load_trusted_owner(&org_id)?
        .ok_or("org owner pubkey is not trusted; run `enclava org keyring trust` or `enclava org keyring init`")?;
    let keyring_envelope = load_keyring_envelope(&org_id).map_err(|err| {
        format!(
            "org keyring for {org_id} is not available locally: {err}; run `enclava org keyring init` or import the owner-signed keyring"
        )
    })?;
    let verified_keyring = verify_keyring(&keyring_envelope, &trusted_owner)?;
    if !member_allows_deploy(verified_keyring, &deployer_key.public) {
        return Err(
            "current CLI signing key is not an owner/admin/deployer in the org keyring".into(),
        );
    }
    let org_keyring_fingerprint = keyring_fingerprint(verified_keyring);

    let tenant_id = org_name.clone();
    let identity_hash = if let Some(value) = app.tenant_instance_identity_hash.as_deref() {
        parse_hex32("tenant_instance_identity_hash", value)?
    } else if let Some(value) = env_hex32("ENCLAVA_TENANT_INSTANCE_IDENTITY_HASH")? {
        value
    } else if deploy_unlock_mode == "password" {
        match bootstrap_identity_hash(
            paths,
            &org_name,
            org_id,
            &app.name,
            &tenant_id,
            &app.instance_id,
        )? {
            Some(hash) => hash,
            None => {
                return Err(
                    "bootstrap key is missing and no recovery seed is available; run `enclava key restore <backup>`"
                        .into(),
                );
            }
        }
    } else {
        return Err("ENCLAVA_TENANT_INSTANCE_IDENTITY_HASH is required to sign auto-unlock deployment descriptor".into());
    };
    let bootstrap_pubkey_hash = if let Some(value) = app.bootstrap_owner_pubkey_hash.clone() {
        value
    } else if let Some(value) = bootstrap_public_key_hash(paths, &org_name, org_id, &app.name)? {
        value
    } else {
        std::env::var("ENCLAVA_BOOTSTRAP_OWNER_PUBKEY_HASH")
            .map_err(|_| "bootstrap owner pubkey hash is required to derive cc_init_data hash; run `enclava key restore <backup>` or recreate the password-mode app")?
    };

    let signer_identity = match (
        app.signer_identity_subject.clone(),
        app.signer_identity_issuer.clone(),
    ) {
        (Some(subject), Some(issuer)) if !subject.is_empty() && !issuer.is_empty() => {
            SignerIdentity { subject, issuer }
        }
        _ => {
            return Err(
                "app signer identity must be pinned before deploy; run `enclava signer set <subject> --issuer <issuer>` or pass `--signer-subject` when creating the app"
                    .into(),
            );
        }
    };

    let mut descriptor = build_descriptor(DeploymentDescriptorBuildInput {
        org_id,
        org_slug: org_name.clone(),
        app_id,
        app_name: app.name.clone(),
        deploy_id: Uuid::new_v4(),
        created_at: Utc::now(),
        app_domain: app.domain.clone(),
        tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
        custom_domains: app.custom_domain.clone().into_iter().collect(),
        namespace: app.namespace.clone(),
        service_account: app
            .service_account
            .clone()
            .unwrap_or_else(|| format!("cap-{}-sa", app.name)),
        identity_hash,
        image_ref: image_ref.digest_ref(),
        image_digest: image_ref.digest().to_string(),
        signer_identity,
        oci_runtime_spec: cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
            container_name: "web".to_string(),
            port: app_config.app.port,
            workload_command: app_config.app.command.clone(),
            storage_paths: app_config.storage.paths.clone(),
            workload_security_profile,
            cpu_limit: app_config.resources.cpu.clone(),
            memory_limit: app_config.resources.memory.clone(),
        }),
        sidecars: Sidecars {
            attestation_proxy_digest: proxy_image.digest().to_string(),
            caddy_digest: caddy_image.digest().to_string(),
        },
        api_signing_pubkey,
        expected_firmware_measurement: release.expected_firmware_measurement_bytes()?,
        expected_runtime_class: release.expected_runtime_class.clone(),
        kbs_resource_path: format!(
            "default/{}-{}-owner/seed-encrypted",
            app.namespace, app.name
        ),
        unlock_mode: deploy_unlock_mode.to_string(),
        policy_template_id: release.policy_template_id.clone(),
        policy_template_sha256,
        platform_release_version: release.platform_release_version.clone(),
        expected_agent_policy_hash: [0; 32],
        expected_cc_init_data_hash: [0; 32],
        expected_kbs_policy_hash: [0; 32],
    });

    let descriptor_core_hash = enclava_cli::descriptor::descriptor_core_hash(&descriptor);
    let workload_artifact_binding = WorkloadArtifactBinding {
        descriptor_core_hash,
        descriptor_signing_pubkey: deployer_key.public.to_bytes(),
        org_keyring_fingerprint,
    };
    let (generated_agent_policy, log_encryption) =
        fetch_generated_agent_policy(api, &release, &descriptor).await?;
    descriptor.expected_agent_policy_hash = generated_agent_policy.policy_sha256;
    let cc_app = confidential_app_for_cc_hash(
        app,
        app_config,
        ConfidentialAppForCcHash {
            image: image_ref.clone(),
            deployment_id: descriptor.deploy_id,
            release: &release,
            workload_artifact_binding,
            generated_agent_policy: generated_agent_policy.clone(),
            deployment_context,
            unlock_mode: deploy_unlock_mode,
            tenant_id,
            tenant_instance_identity_hash: identity_hash,
            bootstrap_owner_pubkey_hash: bootstrap_pubkey_hash,
            workload_security_profile,
            log_encryption: log_encryption.clone(),
        },
    )?;
    let cc_init_options = cc_init_data::CcInitDataOptions {
        kbs_url: release.trustee_kbs_url.clone(),
        kbs_ca_cert_pem: (!release.trustee_kbs_ca_cert_pem.trim().is_empty())
            .then(|| release.trustee_kbs_ca_cert_pem.clone()),
        runtime_class: cc_init_data::runtime_class(),
    };
    let cc_init_data_hash: [u8; 32] =
        Sha256::digest(cc_init_data::build_toml_with_options(&cc_app, &cc_init_options).as_bytes())
            .into();
    descriptor.expected_cc_init_data_hash = cc_init_data_hash;
    let rendered_policy = render_trustee_policy(&release.policy_template_text, &descriptor)?;
    descriptor.expected_kbs_policy_hash = Sha256::digest(rendered_policy.as_bytes()).into();
    let signing_key_id = format!("cli:{}", deployer_key.user_id);
    let signed_policy_artifact = enclava_cli::policy_artifact::sign_policy_artifact(
        &descriptor,
        &deployer_key,
        signing_key_id.clone(),
        rendered_policy,
        &generated_agent_policy,
        Some(serde_json::to_value(&keyring_envelope)?),
        Utc::now(),
    );

    let descriptor_envelope =
        enclava_cli::descriptor::sign(&deployer_key, descriptor, signing_key_id);

    Ok(SignedDeployBlobs {
        customer_descriptor_blob: serde_json::to_string(&descriptor_envelope)?,
        org_keyring_blob: serde_json::to_string(&keyring_envelope)?,
        signed_policy_artifact: serde_json::to_string(&signed_policy_artifact)?,
        log_encryption,
    })
}
