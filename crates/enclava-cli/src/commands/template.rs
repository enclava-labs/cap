use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use base64::Engine as _;
use clap::{Args, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use enclava_cli::{
    api_client::{ApiClient, ApiError},
    api_types::{
        AppResponse, CreateTemplateInstanceRequest, HostedTemplate, HostedTemplateConfigKey,
        SshCommandResponse, TemplateInstanceResponse,
    },
    config::{self, CliPaths},
    tee_client::{TeeClient, TeeError},
};

const DEBIAN_SSH_NGROK_TEMPLATE: &str = "debian-ssh-ngrok";
const DEFAULT_SSH_TIMEOUT_SECONDS: u64 = 600;
const TEMPLATE_CONFIG_DELIVERY_ATTEMPTS: usize = 30;
const TEMPLATE_CONFIG_DELIVERY_RETRY_SECONDS: u64 = 2;

#[derive(Subcommand)]
pub enum TemplateCommand {
    /// List hosted templates available to the active organization
    List,
    /// Deploy a hosted template instance
    Deploy(TemplateDeployArgs),
    /// Fetch and validate the PaaS-rendered stable SSH endpoint command for a hosted Debian SSH app
    SshCommand(TemplateSshCommandArgs),
}

#[derive(Args)]
pub struct TemplateDeployArgs {
    /// Template slug to deploy
    #[arg(default_value = DEBIAN_SSH_NGROK_TEMPLATE)]
    pub template: String,
    /// Instance/app name to create
    #[arg(long)]
    pub name: String,
    /// SSH public key line to authorize. Can be passed more than once.
    #[arg(long = "ssh-public-key", value_name = "PUBLIC_KEY")]
    pub ssh_public_keys: Vec<String>,
    /// File containing one or more SSH public keys.
    #[arg(long = "ssh-public-key-file", value_name = "PATH")]
    pub ssh_public_key_files: Vec<PathBuf>,
    /// Existing reserved stable SSH endpoint to import instead of letting PaaS reserve one.
    #[arg(
        long = "stable-ssh-endpoint",
        visible_alias = "ngrok-tcp-url",
        value_name = "HOST:PORT"
    )]
    pub ngrok_tcp_url: Option<String>,
    /// Do not wait for stable SSH endpoint command readiness after config delivery.
    #[arg(long)]
    pub no_wait: bool,
    /// Seconds to wait for the stable SSH endpoint command.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// Print machine-readable JSON with deployment, stable SSH endpoint, and stable SSH endpoint command details.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct TemplateSshCommandArgs {
    /// Instance/app name to inspect
    #[arg(long)]
    pub name: String,
    /// Reserved stable SSH endpoint expected for this app.
    #[arg(
        long = "stable-ssh-endpoint",
        visible_alias = "ngrok-tcp-url",
        value_name = "HOST:PORT"
    )]
    pub ngrok_tcp_url: Option<String>,
    /// Wait until PaaS reports the stable SSH endpoint command as ready.
    #[arg(long)]
    pub wait: bool,
    /// Seconds to wait for the stable SSH endpoint command when --wait is set.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// Print machine-readable JSON including the stable SSH endpoint command and parsed stable SSH endpoint.
    #[arg(long)]
    pub json: bool,
}

fn build_api_client() -> Result<ApiClient, Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    Ok(ApiClient::from_config(&cli_config, &creds))
}

pub async fn run(cmd: TemplateCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        TemplateCommand::List => list().await,
        TemplateCommand::Deploy(args) => deploy(args).await,
        TemplateCommand::SshCommand(args) => ssh_command(args).await,
    }
}

async fn list() -> Result<(), Box<dyn std::error::Error>> {
    let api = build_api_client()?;
    let templates = api.list_templates().await?;
    if templates.is_empty() {
        println!("No hosted templates are available.");
        return Ok(());
    }

    println!("Hosted templates:");
    for template in templates {
        println!("  {} ({})", template.slug, template.version);
        println!("    {}", template.description);
        if !template.features.is_empty() {
            println!("    Features: {}", template.features.join(", "));
        }
        if let Some(summary) = template_required_inputs(&template) {
            println!("    Required inputs: {summary}");
        }
        if let Some(summary) = template_optional_inputs(&template) {
            println!("    Optional inputs: {summary}");
        }
        if let Some(summary) = template_paas_managed_config_summary(&template) {
            println!("    PaaS-managed config: {summary}");
        }
        if let Some(hint) = stable_ssh_endpoint_hint(&template) {
            println!("    Stable SSH endpoint: {hint}");
        }
        if let Some(path) = template.persistence_path {
            println!("    Persistent path: {path}");
        }
    }
    Ok(())
}

async fn deploy(args: TemplateDeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.template != DEBIAN_SSH_NGROK_TEMPLATE {
        return Err(format!(
            "template '{}' is not supported by this CLI yet; use `{DEBIAN_SSH_NGROK_TEMPLATE}`",
            args.template
        )
        .into());
    }
    let instance_name = normalize_slug(&args.name)?;
    let explicit_stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_ngrok_tcp_url)
        .transpose()?;

    let api = build_api_client()?;
    let templates = api.list_templates().await?;
    let template = templates
        .iter()
        .find(|template| template.slug == args.template)
        .ok_or_else(|| format!("template '{}' is not available", args.template))?;

    let public_keys = read_ssh_public_keys(&args.ssh_public_keys, &args.ssh_public_key_files)?;
    validate_ssh_public_keys(
        &public_keys,
        template_key(template, "DEBIAN_SSH_AUTHORIZED_KEYS"),
    )?;
    let pb = if args.json {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(4)
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")?
            .progress_chars("=> "),
    );
    pb.set_message("Creating template instance...");

    let response = match api
        .create_template_instance(&CreateTemplateInstanceRequest {
            template_slug: args.template.clone(),
            instance_name: instance_name.clone(),
            config: template_create_config(explicit_stable_endpoint.as_deref()),
        })
        .await
    {
        Ok(response) => response,
        Err(error) => return Err(template_instance_create_api_error(error)),
    };
    let stable_endpoint = stored_stable_endpoint_from_template_instance_response(
        &response,
        explicit_stable_endpoint.as_deref(),
    )?;
    pb.set_position(1);
    pb.set_message("Delivering config to TEE...");

    let token = response
        .config_token
        .as_ref()
        .ok_or("PaaS did not return a TEE config token")?;
    let tee_url = token
        .tee_url
        .as_deref()
        .ok_or("PaaS did not return a TEE config URL")?;
    let tee_url = template_config_endpoint_url(tee_url)?;
    let tee = TeeClient::from_config_url(&tee_url);
    let (_attestation, tee) = tee.attest_receipt_key().await?;
    let mut tee = tee;
    let mut tee_url = tee_url;

    let mut config_token = token.token.clone();
    let config_pairs = debian_ssh_config_pairs(public_keys);
    deliver_template_config_with_retry(
        &api,
        &mut tee,
        &instance_name,
        &mut config_token,
        &mut tee_url,
        &config_pairs,
    )
    .await?;
    pb.set_position(2);

    let mut app_url = app_url_from_template_response_cap(&response.cap)?;
    let deployment_id = response
        .deployment
        .cap_deployment_id
        .as_deref()
        .unwrap_or("pending")
        .to_string();

    let (ssh_command, ssh_endpoint) = if args.no_wait {
        pb.set_position(4);
        (None, None)
    } else {
        pb.set_position(3);
        pb.set_message("Waiting for stable SSH endpoint command...");
        let response = wait_for_paas_ssh_command(
            &api,
            &instance_name,
            stable_endpoint.as_str(),
            app_url.as_str(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await?;
        if let Some(url) = response.app_url {
            app_url = normalize_paas_ssh_command_app_url(&url)?;
        }
        pb.set_position(4);
        (response.command, response.endpoint)
    };
    pb.finish_with_message("Template deployed");

    print!(
        "{}",
        deploy_response_output(
            &response.template.slug,
            &instance_name,
            &app_url,
            &deployment_id,
            Some(stable_endpoint.as_str()),
            ssh_command.as_deref(),
            ssh_endpoint.as_deref(),
            args.json,
        )?
    );
    Ok(())
}

async fn ssh_command(args: TemplateSshCommandArgs) -> Result<(), Box<dyn std::error::Error>> {
    let instance_name = normalize_slug(&args.name)?;
    let explicit_stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_ngrok_tcp_url)
        .transpose()?;
    let api = build_api_client()?;
    let app = api.get_app(&instance_name).await?;
    let stored_stable_endpoint = stored_stable_endpoint_from_app(&app)?;
    let stable_endpoint =
        ssh_command_stable_endpoint(explicit_stable_endpoint.as_deref(), &stored_stable_endpoint)?;
    let expected_app_url = app_url_from_app_response(&app)?;
    let response = if args.wait {
        let pb = if args.json {
            ProgressBar::hidden()
        } else {
            ProgressBar::new_spinner()
        };
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message("Waiting for stable SSH endpoint command...");
        match wait_for_paas_ssh_command(
            &api,
            &instance_name,
            stable_endpoint,
            expected_app_url.as_str(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await
        {
            Ok(response) => {
                pb.finish_with_message("Stable SSH endpoint command ready");
                response
            }
            Err(error) => {
                pb.abandon_with_message("Stable SSH endpoint command unavailable");
                return Err(error);
            }
        }
    } else {
        let response = match api.get_template_ssh_command(&instance_name).await {
            Ok(response) => response,
            Err(error) => return Err(paas_ssh_command_api_error(error)),
        };
        validate_ssh_command_response(&response, stable_endpoint, expected_app_url.as_str())?;
        response
    };
    print!(
        "{}",
        ssh_command_response_output(
            &instance_name,
            &response,
            stable_endpoint,
            expected_app_url.as_str(),
            args.json,
        )?
    );
    Ok(())
}

fn template_key<'a>(
    template: &'a HostedTemplate,
    key: &str,
) -> Option<&'a HostedTemplateConfigKey> {
    template_customer_config_keys(template).find(|entry| entry.key == key)
}

fn template_customer_config_keys<'a>(
    template: &'a HostedTemplate,
) -> impl Iterator<Item = &'a HostedTemplateConfigKey> + 'a {
    template.config_keys.iter().filter(|entry| {
        !template
            .paas_managed_config_keys
            .iter()
            .any(|managed| managed == &entry.key)
    })
}

fn template_required_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, true)
}

fn template_optional_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, false)
}

fn template_paas_managed_config_summary(template: &HostedTemplate) -> Option<String> {
    if template.paas_managed_config_keys.is_empty() {
        None
    } else {
        Some(
            template
                .paas_managed_config_keys
                .iter()
                .map(|key| {
                    if key == "NGROK_AUTHTOKEN" {
                        "NGROK_AUTHTOKEN (PaaS-owned; sourced from PaaS deployment env DEBIAN_SSH_NGROK_AUTHTOKEN)"
                            .to_string()
                    } else {
                        key.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

fn template_input_summary(template: &HostedTemplate, required: bool) -> Option<String> {
    let labels = template_customer_config_keys(template)
        .filter(|entry| entry.required == required)
        .map(template_input_label)
        .collect::<Vec<_>>();
    if labels.is_empty() {
        None
    } else {
        Some(labels.join(", "))
    }
}

fn template_input_label(entry: &HostedTemplateConfigKey) -> String {
    if entry
        .validation
        .as_ref()
        .and_then(|validation| validation.example.as_ref())
        .is_some()
        && entry
            .validation
            .as_ref()
            .and_then(|validation| validation.format.as_deref())
            == Some("ngrok_tcp_url")
    {
        return format!(
            "{} (auto-reserved; optional --stable-ssh-endpoint)",
            entry.label
        );
    }
    entry.label.clone()
}

fn stored_stable_endpoint_from_app(
    app: &AppResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    if app.template_slug.as_deref() != Some(DEBIAN_SSH_NGROK_TEMPLATE) {
        return Err(
            "Stable SSH endpoint command lookup is only available for debian-ssh-ngrok apps with stable SSH endpoints".into(),
        );
    }
    let Some(endpoint) = app.template_expected.stable_ssh_endpoint.as_deref() else {
        return Err(
            "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        );
    };
    if endpoint.trim().is_empty() {
        return Err(
            "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        );
    }
    match normalize_ngrok_tcp_url(endpoint) {
        Ok(normalized) if endpoint == normalized => Ok(normalized),
        _ => Err(
            "Hosted Debian SSH app has invalid stored stable SSH endpoint expectation; redeploy the template so PaaS reserves a stable SSH endpoint"
                .into(),
        ),
    }
}

fn stored_stable_endpoint_from_template_instance_response(
    response: &TemplateInstanceResponse,
    submitted_endpoint: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = response
        .app
        .template_expected
        .stable_ssh_endpoint
        .as_deref()
        .ok_or(
            "PaaS template response did not include its stored stable SSH endpoint expectation",
        )?;
    if endpoint.trim().is_empty() {
        return Err(
            "PaaS template response did not include its stored stable SSH endpoint expectation"
                .into(),
        );
    }
    let normalized = normalize_ngrok_tcp_url(endpoint)
        .map_err(|_| "PaaS template response included an invalid stored stable SSH endpoint")?;
    if endpoint != normalized {
        return Err(
            "PaaS template response included a non-canonical stored stable SSH endpoint".into(),
        );
    }
    if let Some(submitted_endpoint) = submitted_endpoint {
        let submitted = normalize_ngrok_tcp_url(submitted_endpoint)
            .map_err(|_| "submitted stable SSH endpoint is invalid")?;
        if normalized != submitted {
            return Err(format!(
                "PaaS stored stable SSH endpoint {normalized} does not match submitted --stable-ssh-endpoint {submitted}"
            )
            .into());
        }
    }
    Ok(normalized)
}

fn stable_ssh_endpoint_hint(template: &HostedTemplate) -> Option<String> {
    let entry = template_customer_config_keys(template).find(|entry| {
        entry.key == "NGROK_TCP_URL"
            || entry
                .validation
                .as_ref()
                .and_then(|validation| validation.format.as_deref())
                == Some("ngrok_tcp_url")
    })?;
    let example = entry
        .validation
        .as_ref()
        .and_then(|validation| validation.example.as_deref())
        .unwrap_or("6.tcp.eu.ngrok.io:17958");
    Some(format!(
        "PaaS reserves one automatically; pass --stable-ssh-endpoint {example} only to import an existing reserved endpoint"
    ))
}

fn ssh_command_stable_endpoint<'a>(
    explicit: Option<&'a str>,
    stored: &'a str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let Some(explicit) = explicit else {
        return Ok(stored);
    };
    if explicit == stored {
        return Ok(stored);
    }
    Err(format!(
        "--stable-ssh-endpoint {explicit} does not match the PaaS-stored stable SSH endpoint {stored}; omit --stable-ssh-endpoint to use the stored expectation or redeploy with the intended endpoint"
    )
    .into())
}

fn normalize_slug(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let slug = value.trim().to_ascii_lowercase();
    if slug.len() < 2
        || slug.len() > 63
        || !slug.bytes().any(|byte| byte.is_ascii_lowercase())
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || slug.starts_with('-')
        || slug.ends_with('-')
    {
        Err("instance name must be 2-63 letters, numbers, or hyphens".into())
    } else {
        Ok(slug)
    }
}

fn template_create_config(explicit_stable_endpoint: Option<&str>) -> serde_json::Value {
    match explicit_stable_endpoint {
        Some(endpoint) => serde_json::json!({ "NGROK_TCP_URL": endpoint }),
        None => serde_json::json!({}),
    }
}

fn debian_ssh_config_pairs(public_keys: String) -> Vec<(&'static str, String)> {
    vec![("DEBIAN_SSH_AUTHORIZED_KEYS", public_keys)]
}

async fn deliver_template_config_with_retry(
    api: &ApiClient,
    tee: &mut TeeClient,
    instance_name: &str,
    config_token: &mut String,
    tee_url: &mut String,
    pairs: &[(&'static str, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (key, value) in pairs {
        set_template_config_key_with_retry(
            api,
            tee,
            instance_name,
            key,
            value,
            config_token,
            tee_url,
        )
        .await?;
        sync_template_config_key_with_retry(api, instance_name, key).await?;
    }
    Ok(())
}

async fn set_template_config_key_with_retry(
    api: &ApiClient,
    tee: &mut TeeClient,
    instance_name: &str,
    key: &str,
    value: &str,
    config_token: &mut String,
    tee_url: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match tee.config_set(key, value, config_token).await {
            Ok(()) => return Ok(()),
            Err(error) if should_refresh_template_config_token(&error) => {
                if attempt == TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
                    return Err(error.into());
                }
                let refreshed =
                    refresh_template_config_token_with_retry(api, instance_name, key).await?;
                let refreshed_tee_url =
                    refreshed_template_config_endpoint_url(&refreshed, tee_url)?;
                if refreshed_tee_url != *tee_url {
                    let refreshed_tee = TeeClient::from_config_url(&refreshed_tee_url);
                    let (_attestation, refreshed_tee) = refreshed_tee.attest_receipt_key().await?;
                    *tee = refreshed_tee;
                    *tee_url = refreshed_tee_url;
                }
                *config_token = refreshed.token;
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error)
                if should_retry_template_config_tee_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("TEE config write failed for {key}").into())
}

async fn sync_template_config_key_with_retry(
    api: &ApiClient,
    instance_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match api.sync_config_key(instance_name, key, false).await {
            Ok(()) => return Ok(()),
            Err(error)
                if should_retry_template_config_sync_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("TEE config metadata sync failed for {key}").into())
}

async fn refresh_template_config_token_with_retry(
    api: &ApiClient,
    instance_name: &str,
    key: &str,
) -> Result<enclava_cli::api_types::ConfigTokenResponse, Box<dyn std::error::Error>> {
    for attempt in 1..=TEMPLATE_CONFIG_DELIVERY_ATTEMPTS {
        match api.get_config_token(instance_name).await {
            Ok(response) => return Ok(response),
            Err(error)
                if should_retry_template_config_sync_error(&error)
                    && attempt < TEMPLATE_CONFIG_DELIVERY_ATTEMPTS =>
            {
                tokio::time::sleep(template_config_delivery_retry_delay()).await;
            }
            Err(error) => {
                return Err(format!(
                    "TEE config token expired while writing {key}, and PaaS could not issue a replacement token: {error}"
                )
                .into());
            }
        }
    }
    Err(format!("TEE config token refresh failed while writing {key}").into())
}

fn refreshed_template_config_endpoint_url(
    response: &enclava_cli::api_types::ConfigTokenResponse,
    current_tee_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match response.tee_url.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => template_config_endpoint_url(value),
        _ => Ok(current_tee_url.to_string()),
    }
}

fn template_config_delivery_retry_delay() -> Duration {
    Duration::from_secs(TEMPLATE_CONFIG_DELIVERY_RETRY_SECONDS)
}

fn should_refresh_template_config_token(error: &TeeError) -> bool {
    matches!(error, TeeError::Tee { status: 401, .. })
}

fn should_retry_template_config_tee_error(error: &TeeError) -> bool {
    match error {
        TeeError::Http(_) => true,
        TeeError::Tee { status, .. } => matches!(*status, 408 | 409 | 425 | 429) || *status >= 500,
        TeeError::InvalidHeader(_) | TeeError::Attestation(_) => false,
    }
}

fn should_retry_template_config_sync_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(_) => true,
        ApiError::Api { status, .. } => matches!(*status, 408 | 409 | 425 | 429) || *status >= 500,
        ApiError::NotAuthenticated => false,
    }
}

fn read_ssh_public_keys(
    direct: &[String],
    files: &[PathBuf],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut lines = Vec::new();
    for value in direct {
        lines.push(value.trim().to_string());
    }
    for path in files {
        let content = fs::read_to_string(path).map_err(|err| {
            format!(
                "failed to read SSH public key file {}: {err}",
                path.display()
            )
        })?;
        lines.push(content.trim().to_string());
    }
    let value = lines
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if value.trim().is_empty() {
        Err("at least one SSH public key is required; pass --ssh-public-key or --ssh-public-key-file".into())
    } else {
        Ok(value)
    }
}

fn validate_ssh_public_keys(
    value: &str,
    metadata: Option<&HostedTemplateConfigKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.contains("-----BEGIN") || value.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err("do not pass a private key; use an SSH public key".into());
    }
    let max_bytes = metadata
        .and_then(|entry| entry.validation.as_ref())
        .and_then(|validation| validation.max_bytes)
        .unwrap_or(32_768) as usize;
    let max_items = metadata
        .and_then(|entry| entry.validation.as_ref())
        .and_then(|validation| validation.max_items)
        .unwrap_or(10) as usize;
    let allowed = metadata
        .and_then(|entry| entry.validation.as_ref())
        .map(|validation| validation.allowed_algorithms.as_slice())
        .filter(|algorithms| !algorithms.is_empty());
    let default_allowed = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ];

    if value.as_bytes().len() > max_bytes {
        return Err(format!("SSH public keys must be {max_bytes} bytes or smaller").into());
    }
    let mut count = 0usize;
    for (index, raw) in value.replace('\r', "").lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        if count > max_items {
            return Err(format!("enter at most {max_items} SSH public keys").into());
        }
        if raw.chars().any(|ch| ch.is_control()) {
            return Err(format!("line {} contains control characters", index + 1).into());
        }
        let mut fields = line.split_whitespace();
        let algorithm = fields.next().unwrap_or_default();
        let body = fields.next().unwrap_or_default();
        let allowed_match = allowed
            .map(|algorithms| algorithms.iter().any(|value| value == algorithm))
            .unwrap_or_else(|| default_allowed.contains(&algorithm));
        if !allowed_match {
            return Err(format!("line {} uses an unsupported SSH key algorithm", index + 1).into());
        }
        if body.is_empty()
            || !body
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=')
        {
            return Err(format!("line {} has a malformed SSH public key", index + 1).into());
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| format!("line {} has a malformed SSH public key", index + 1))?;
        if !ssh_public_key_blob_matches_algorithm(algorithm, &decoded) {
            return Err(format!("line {} has a malformed SSH public key", index + 1).into());
        }
    }
    if count == 0 {
        Err("at least one SSH public key is required".into())
    } else {
        Ok(())
    }
}

fn ssh_public_key_blob_matches_algorithm(algorithm: &str, blob: &[u8]) -> bool {
    let Some((blob_algorithm, offset)) = read_ssh_string(blob, 0) else {
        return false;
    };
    if !ssh_key_algorithm_matches(algorithm, blob_algorithm) {
        return false;
    }
    match algorithm {
        "ssh-ed25519" => {
            let Some((key, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            key.len() == 32 && offset == blob.len()
        }
        "ecdsa-sha2-nistp256" => {
            let Some((curve, offset)) = read_ssh_string(blob, offset) else {
                return false;
            };
            let Some((point, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            curve == "nistp256" && !point.is_empty() && offset == blob.len()
        }
        "rsa-sha2-256" | "rsa-sha2-512" => {
            let Some((exponent, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            let Some((modulus, offset)) = read_ssh_bytes(blob, offset) else {
                return false;
            };
            !exponent.is_empty() && !modulus.is_empty() && offset == blob.len()
        }
        _ => false,
    }
}

fn ssh_key_algorithm_matches(algorithm: &str, blob_algorithm: &str) -> bool {
    algorithm == blob_algorithm
        || matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512") && blob_algorithm == "ssh-rsa"
}

fn read_ssh_string(blob: &[u8], offset: usize) -> Option<(&str, usize)> {
    let (value, offset) = read_ssh_bytes(blob, offset)?;
    std::str::from_utf8(value).ok().map(|value| (value, offset))
}

fn read_ssh_bytes(blob: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let length_end = offset.checked_add(4)?;
    let length_bytes: [u8; 4] = blob.get(offset..length_end)?.try_into().ok()?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let start = length_end;
    let end = start.checked_add(length)?;
    let value = blob.get(start..end)?;
    Some((value, end))
}

pub(crate) fn normalize_ngrok_tcp_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    let address = if trimmed
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tcp://"))
    {
        &trimmed[6..]
    } else {
        trimmed
    }
    .to_ascii_lowercase();
    let Some((host, port_text)) = address.rsplit_once(':') else {
        return Err("reserved stable SSH endpoint must look like 6.tcp.eu.ngrok.io:17958".into());
    };
    let host = host.trim_end_matches('.');
    let port = parse_tcp_port(port_text)
        .ok_or("reserved stable SSH endpoint must include a valid TCP port")?;
    if port == 0 || !is_ngrok_tcp_host(host) {
        return Err("reserved stable SSH endpoint must look like 6.tcp.eu.ngrok.io:17958".into());
    }
    Ok(format!("{host}:{port}"))
}

fn template_config_endpoint_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err("TEE config URL is empty".into());
    }
    if raw_template_config_host(value)
        .as_deref()
        .is_some_and(is_ambiguous_numeric_template_config_host)
    {
        return Err("TEE config URL host is invalid".into());
    }
    let mut url = reqwest::Url::parse(value)
        .map_err(|error| format!("TEE config URL is invalid: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(
            "TEE config URL must use http or https and must not include credentials".into(),
        );
    }
    let host = url.host_str().unwrap_or_default();
    let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
    if canonical_host.is_empty() {
        return Err("TEE config URL must include a host".into());
    }
    if !is_valid_template_config_host(&canonical_host) {
        return Err("TEE config URL host is invalid".into());
    }
    let is_local_host = is_local_template_config_host(&canonical_host);
    if url.scheme() == "http" && !is_local_host {
        return Err("TEE config URL must use https for public endpoints".into());
    }
    if url.port().is_some() && !is_local_host {
        return Err("TEE config URL must use the default port for public endpoints".into());
    }
    if canonical_host != host {
        url.set_host(Some(&canonical_host))
            .map_err(|_| "TEE config URL is invalid")?;
    }
    match url.path().trim_end_matches('/') {
        "" | "/" => url.set_path("/.well-known/confidential/config"),
        "/.well-known/confidential" => url.set_path("/.well-known/confidential/config"),
        "/.well-known/confidential/config" => url.set_path("/.well-known/confidential/config"),
        _ => return Err("TEE config URL must point to /.well-known/confidential/config".into()),
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn is_reserved_template_config_host(host: &str) -> bool {
    matches!(host, "example.com" | "example.net" | "example.org")
        || host.ends_with(".example.com")
        || host.ends_with(".example.net")
        || host.ends_with(".example.org")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.ends_with(".invalid")
}

fn raw_template_config_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)?
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_ascii_lowercase());
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(authority);
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_ambiguous_numeric_template_config_host(host: &str) -> bool {
    host.split('.')
        .all(|label| !label.is_empty() && label.chars().all(|ch| ch.is_ascii_digit()))
        && !is_valid_ipv4_host(host)
}

fn is_local_template_config_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

fn is_valid_template_config_host(host: &str) -> bool {
    if is_local_template_config_host(host) {
        return true;
    }
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || !host.chars().any(|ch| ch.is_ascii_alphabetic())
        || is_reserved_template_config_host(host)
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

fn is_ngrok_tcp_host(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    if !matches!(labels.len(), 4 | 5) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) && labels[1] == "tcp"
        && labels[labels.len() - 2] == "ngrok"
        && matches!(labels[labels.len() - 1], "io" | "app")
}

fn app_url_from_app_domain(app_domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let app_domain = app_domain.trim();
    if app_domain.is_empty() {
        return Err("template response included an empty app_domain".into());
    }
    normalize_app_url(app_domain).map_err(|error| {
        format!("template response included an invalid app_domain: {error}").into()
    })
}

fn app_url_from_template_response_cap(
    cap: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(app_domain) = cap
        .get("app_domain")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return app_url_from_app_domain(app_domain);
    }

    if let Some(domain) = cap
        .get("domain")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        let domain = domain.trim();
        return normalize_app_url(domain).map_err(|error| {
            format!("template response included an invalid domain: {error}").into()
        });
    }

    Err("template response did not include app_domain or domain".into())
}

fn app_url_from_app_response(app: &AppResponse) -> Result<String, Box<dyn std::error::Error>> {
    let app_domain = app
        .app_domain
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(app.domain.as_str());
    app_url_from_app_domain(app_domain)
}

fn normalize_app_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url_with_policy(value, true)
}

fn normalize_app_url_for_noncanonical_error(
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url_with_policy(value, false)
}

fn normalize_app_url_with_policy(
    value: &str,
    require_root_url: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err("app URL is empty".into());
    }
    let base = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let raw_host = raw_http_app_host(&base).ok_or("app URL is invalid")?;
    if is_ambiguous_numeric_host(&raw_host) {
        return Err("app URL is invalid".into());
    }
    let mut url =
        reqwest::Url::parse(&base).map_err(|error| format!("app URL is invalid: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err("app URL must use http or https and must not include credentials".into());
    }
    if require_root_url && (url.path() != "/" || url.query().is_some() || url.fragment().is_some())
    {
        return Err("app URL must be a canonical root URL".into());
    }
    let host = url.host_str().unwrap_or_default();
    let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_valid_http_app_host(&canonical_host) {
        return Err("app URL is invalid".into());
    }
    if canonical_host != host {
        url.set_host(Some(&canonical_host))
            .map_err(|_| "app URL is invalid")?;
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn raw_http_app_host(value: &str) -> Option<String> {
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_ascii_lowercase());
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(authority);
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_ambiguous_numeric_host(host: &str) -> bool {
    host.split('.')
        .all(|label| !label.is_empty() && label.chars().all(|ch| ch.is_ascii_digit()))
        && !is_valid_ipv4_host(host)
}

fn is_valid_ipv4_host(host: &str) -> bool {
    let parts = host.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            matches!(part.len(), 1..=3)
                && part.chars().all(|ch| ch.is_ascii_digit())
                && part
                    .parse::<u8>()
                    .map(|value| value.to_string() == *part || !part.starts_with('0'))
                    .unwrap_or(false)
        })
}

fn is_valid_http_app_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if is_reserved_http_app_host(host) {
        return false;
    }
    if !host.contains('.') {
        return false;
    }
    if !host.chars().any(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

fn is_reserved_http_app_host(host: &str) -> bool {
    matches!(host, "example.com" | "example.net" | "example.org")
        || host.ends_with(".example.com")
        || host.ends_with(".example.net")
        || host.ends_with(".example.org")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.ends_with(".invalid")
}

async fn wait_for_paas_ssh_command(
    api: &ApiClient,
    app_name: &str,
    stable_endpoint: &str,
    expected_app_url: &str,
    timeout: Duration,
) -> Result<SshCommandResponse, Box<dyn std::error::Error>> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let response = match api.get_template_ssh_command(app_name).await {
            Ok(response) => response,
            Err(error) if should_retry_paas_ssh_command_error(&error) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(error) => return Err(paas_ssh_command_api_error(error)),
        };
        validate_ssh_command_response(&response, stable_endpoint, expected_app_url)?;
        if response.status == "ready" {
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(format!("timed out waiting for stable SSH endpoint command for app {app_name}").into())
}

fn validate_ssh_command_response(
    response: &SshCommandResponse,
    stable_endpoint: &str,
    expected_app_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stable_endpoint = normalize_ngrok_tcp_url(stable_endpoint)
        .map_err(|_| "expected stable SSH endpoint is invalid")?;
    let api_stable_endpoint = normalize_ngrok_tcp_url(&response.stable_ssh_endpoint)
        .map_err(|_| "PaaS /ssh-command stable_ssh_endpoint is invalid")?;
    if response.stable_ssh_endpoint != api_stable_endpoint {
        return Err(format!(
            "PaaS /ssh-command stable_ssh_endpoint {api_stable_endpoint} is not canonical"
        )
        .into());
    }
    if api_stable_endpoint != stable_endpoint {
        return Err(format!(
            "PaaS /ssh-command stable_ssh_endpoint {api_stable_endpoint} does not match expected stable SSH endpoint {stable_endpoint}"
        )
        .into());
    }
    validate_ssh_command_app_url(response, expected_app_url)?;
    if response.status != "ready" {
        if response.command.is_some() || response.endpoint.is_some() {
            return Err("PaaS /ssh-command response included ready-only stable SSH endpoint command fields while status was not ready".into());
        }
        if response.status == "pending" {
            return Ok(());
        }
        return Err(format!(
            "PaaS /ssh-command response returned unknown status: {}",
            response.status
        )
        .into());
    }

    let command = response
        .command
        .as_deref()
        .ok_or("PaaS reported stable SSH endpoint command ready without a command")?;
    if !valid_ssh_command(command) {
        return Err(
            format!("PaaS returned an invalid stable SSH endpoint command: {command}").into(),
        );
    }
    let reported_endpoint = response.endpoint.as_deref().ok_or(
        "PaaS /ssh-command response did not include endpoint for ready stable SSH endpoint command",
    )?;
    ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
    ensure_ssh_command_matches_endpoint(command, &stable_endpoint)?;
    Ok(())
}

fn validate_ssh_command_app_url(
    response: &SshCommandResponse,
    expected_app_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected =
        normalize_app_url(expected_app_url).map_err(|_| "expected app URL is invalid")?;
    let Some(raw_app_url) = response.app_url.as_deref() else {
        if response.status == "ready" {
            return Err(
                "PaaS /ssh-command response did not include app_url for ready stable SSH endpoint command".into(),
            );
        }
        return Ok(());
    };
    let app_url = raw_app_url.trim();
    let actual = normalize_app_url_for_noncanonical_error(app_url)
        .map_err(|_| "PaaS /ssh-command response app_url is invalid")?;
    if raw_app_url != app_url || app_url != actual {
        return Err(format!("PaaS /ssh-command response app_url {actual} is not canonical").into());
    }
    if actual != expected {
        return Err(format!(
            "PaaS /ssh-command app_url {actual} does not match expected app URL {expected}"
        )
        .into());
    }
    Ok(())
}

fn deploy_response_output(
    template_slug: &str,
    instance_name: &str,
    app_url: &str,
    deployment_id: &str,
    stable_endpoint: Option<&str>,
    ssh_command: Option<&str>,
    ssh_endpoint: Option<&str>,
    json: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let app_url = normalize_paas_ssh_command_app_url(app_url)?;
    let stable_endpoint = stable_endpoint
        .map(normalize_ngrok_tcp_url)
        .transpose()
        .map_err(|_| "stable SSH endpoint output is invalid")?;
    let endpoint = display_ssh_endpoint(ssh_command, ssh_endpoint)?;
    if json {
        let output = serde_json::json!({
            "template": template_slug,
            "instance": instance_name,
            "app_url": app_url.as_str(),
            "deployment_id": deployment_id,
            "stable_ssh_endpoint": stable_endpoint.as_deref(),
            "stable_endpoint": stable_endpoint.as_deref(),
            "ssh_command_status": if ssh_command.is_some() { "ready" } else { "pending" },
            "command": ssh_command,
            "endpoint": endpoint,
            "ssh_command_path": format!("/apps/{instance_name}/ssh-command"),
        });
        return Ok(format!("{}\n", serde_json::to_string_pretty(&output)?));
    }

    let mut lines = vec![
        String::new(),
        format!("  Template:   {template_slug}"),
        format!("  Instance:   {instance_name}"),
        format!("  URL:        {}", app_url),
        format!("  Deploy:     {deployment_id}"),
    ];
    if let Some(endpoint) = stable_endpoint.as_deref() {
        lines.push(format!("  Stable SSH endpoint: {endpoint}"));
    }
    if let Some(command) = ssh_command {
        lines.push(format!("  Stable SSH endpoint command: {command}"));
        if let Some(endpoint) = endpoint {
            lines.push(format!("  Verified stable SSH endpoint: {endpoint}"));
        }
    } else {
        lines.push(format!(
            "  Stable SSH endpoint command: pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn ssh_command_response_output(
    instance_name: &str,
    response: &SshCommandResponse,
    stable_endpoint: &str,
    expected_app_url: &str,
    json: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let stable_endpoint = normalize_ngrok_tcp_url(stable_endpoint)?;
    validate_ssh_command_response(response, &stable_endpoint, expected_app_url)?;
    let endpoint = display_ssh_endpoint(response.command.as_deref(), response.endpoint.as_deref())?;
    let app_url = response_app_url_for_output(response)?;
    if json {
        let output = serde_json::json!({
            "app_name": instance_name,
            "status": response.status.as_str(),
            "app_url": app_url.as_deref(),
            "stable_ssh_endpoint": stable_endpoint.as_str(),
            "stable_endpoint": stable_endpoint.as_str(),
            "command": response.command.as_deref(),
            "endpoint": endpoint,
        });
        return Ok(format!("{}\n", serde_json::to_string_pretty(&output)?));
    }

    let mut lines = vec![format!("  Status:     {}", response.status)];
    if let Some(app_url) = app_url.as_deref() {
        lines.push(format!("  URL:        {app_url}"));
    }
    lines.push(format!("  Stable SSH endpoint: {stable_endpoint}"));
    if let Some(command) = response.command.as_deref() {
        lines.push(format!("  Stable SSH endpoint command: {command}"));
        if let Some(endpoint) = endpoint {
            lines.push(format!("  Verified stable SSH endpoint: {endpoint}"));
        }
    } else {
        lines.push(format!(
            "  Stable SSH endpoint command: pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn response_app_url_for_output(
    response: &SshCommandResponse,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    response
        .app_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_paas_ssh_command_app_url)
        .transpose()
}

fn normalize_paas_ssh_command_app_url(app_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    normalize_app_url(app_url).map_err(|_| "PaaS /ssh-command response app_url is invalid".into())
}

fn should_retry_paas_ssh_command_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(_) => true,
        ApiError::Api { status, code, .. } => {
            if matches!(
                code.as_deref(),
                Some(
                    "unauthenticated"
                        | "org_permission_denied"
                        | "app_not_found"
                        | "ssh_command_not_available"
                        | "stable_ssh_endpoint_missing"
                        | "stable_ssh_endpoint_invalid"
                        | "cap_response_invalid"
                        | "not_implemented_hosted"
                )
            ) {
                return false;
            }
            matches!(*status, 408 | 425 | 429 | 500..=599)
        }
        ApiError::NotAuthenticated => false,
    }
}

fn paas_ssh_command_api_error(error: ApiError) -> Box<dyn std::error::Error> {
    if let Some(message) = paas_ssh_command_api_error_message(&error) {
        message.into()
    } else {
        error.into()
    }
}

fn template_instance_create_api_error(error: ApiError) -> Box<dyn std::error::Error> {
    if let Some(message) = stable_ssh_managed_ngrok_setup_error_message(&error) {
        message.into()
    } else {
        error.into()
    }
}

fn stable_ssh_managed_ngrok_setup_error_message(error: &ApiError) -> Option<String> {
    let ApiError::Api { code, message, .. } = error else {
        return None;
    };
    if matches!(
        code.as_deref(),
        Some(
            "ngrok_api_key_required"
                | "ngrok_api_key_invalid"
                | "ngrok_api_key_unavailable"
                | "ngrok_tcp_reservation_failed"
        )
    ) || message.contains("NGROK_API_KEY")
    {
        return Some(
            "Stable SSH endpoint reservation is unavailable because PaaS is missing or cannot use its ngrok management API key. Platform operators must inject NGROK_API_KEY in the PaaS deployment environment, then retry. Do not pass an ngrok API key through the CLI, local text/token file, or release env."
                .to_string(),
        );
    }
    if code.as_deref() == Some("service_unavailable")
        && message.contains("DEBIAN_SSH_NGROK_AUTHTOKEN")
    {
        return Some(
            "Stable SSH setup is unavailable because PaaS is missing its managed ngrok authtoken. Platform operators must inject DEBIAN_SSH_NGROK_AUTHTOKEN through the PaaS deployment environment, then retry. Do not pass an ngrok token through the CLI, local text/token file, or release env."
                .to_string(),
        );
    }
    None
}

fn paas_ssh_command_api_error_message(error: &ApiError) -> Option<String> {
    let ApiError::Api { code, .. } = error else {
        return None;
    };
    let message = match code.as_deref()? {
        "stable_ssh_endpoint_missing" => {
            "Stable SSH endpoint metadata is missing. Redeploy the template so PaaS reserves a stable SSH endpoint."
        }
        "stable_ssh_endpoint_invalid" => {
            "Stable SSH endpoint metadata is invalid. Redeploy the template so PaaS reserves a stable SSH endpoint."
        }
        "cap_response_invalid" => {
            "Stable SSH endpoint API rejected malformed, non-canonical, or mismatched workload output. Redeploy the template if this app was created before stable SSH endpoint metadata was stored. Support must fix non-canonical stable SSH endpoint API or workload output at the template boundary."
        }
        _ => return None,
    };
    Some(message.to_string())
}

fn valid_ssh_command(command: &str) -> bool {
    parse_ssh_endpoint(command).is_some()
}

fn ssh_endpoint_string(command: &str) -> Option<String> {
    let (host, port) = parse_ssh_endpoint(command)?;
    let port = port.parse::<u16>().ok()?;
    Some(format!("{host}:{port}"))
}

fn display_ssh_endpoint(
    command: Option<&str>,
    reported_endpoint: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(command) = command else {
        return Ok(None);
    };
    let command_endpoint = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let reported_endpoint = reported_endpoint.ok_or(
        "PaaS /ssh-command response did not include endpoint for ready stable SSH endpoint command",
    )?;
    ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
    Ok(Some(command_endpoint))
}

fn parse_ssh_endpoint(command: &str) -> Option<(&str, &str)> {
    let parts = command.split(' ').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "ssh" || parts[1] != "-p" {
        return None;
    }
    if parse_canonical_tcp_port(parts[2]).is_none() {
        return None;
    }
    let host = parts[3].strip_prefix("user@")?;
    if !is_canonical_ngrok_tcp_ssh_host(host) {
        return None;
    }
    Some((host, parts[2]))
}

fn parse_canonical_tcp_port(port_text: &str) -> Option<u16> {
    if port_text.len() > 1 && port_text.starts_with('0') {
        return None;
    }
    parse_tcp_port(port_text).filter(|port| *port > 0)
}

fn parse_tcp_port(port_text: &str) -> Option<u16> {
    if matches!(port_text.len(), 1..=5) && port_text.chars().all(|ch| ch.is_ascii_digit()) {
        port_text.parse::<u16>().ok()
    } else {
        None
    }
}

fn is_canonical_ngrok_tcp_ssh_host(host: &str) -> bool {
    host == host.trim_end_matches('.')
        && host == host.to_ascii_lowercase()
        && is_ngrok_tcp_ssh_host(host)
}

fn is_ngrok_tcp_ssh_host(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    let labels = normalized.split('.').collect::<Vec<_>>();
    if !matches!(labels.len(), 4 | 5) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) && labels[1] == "tcp"
        && labels[labels.len() - 2] == "ngrok"
        && matches!(labels[labels.len() - 1], "io" | "app")
}

fn ensure_reported_ssh_endpoint_matches_command(
    command: &str,
    reported_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let command_endpoint = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let raw_reported_endpoint = reported_endpoint.trim();
    let normalized_reported_endpoint = normalize_ngrok_tcp_url(raw_reported_endpoint)
        .map_err(|_| "PaaS /ssh-command response endpoint is not a reserved stable SSH endpoint")?;
    if reported_endpoint != raw_reported_endpoint
        || raw_reported_endpoint != normalized_reported_endpoint
    {
        return Err(format!(
            "PaaS /ssh-command response endpoint {normalized_reported_endpoint} is not canonical"
        )
        .into());
    }
    if normalized_reported_endpoint == command_endpoint {
        return Ok(());
    }
    Err(format!(
        "PaaS stable SSH endpoint {normalized_reported_endpoint} does not match endpoint parsed from stable SSH endpoint command {command_endpoint}"
    )
    .into())
}

fn ensure_ssh_command_matches_endpoint(
    command: &str,
    endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse stable SSH endpoint command: {command}"))?;
    let expected = normalize_ngrok_tcp_url(endpoint)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "Stable SSH endpoint command resolves to {actual}, which does not match reserved endpoint {expected}"
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_cli::api_types::{ConfigTokenResponse, HostedTemplateConfigValidation};
    const VALID_ED25519_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlL21WHthjyXNuxzes5bVqCCqgyWDuMvXcWhOxRGL1P cli-test@example";

    fn hosted_template_with_stable_ssh() -> HostedTemplate {
        HostedTemplate {
            slug: "debian-ssh-ngrok".to_string(),
            name: "Debian Stable SSH Endpoint".to_string(),
            description: "SSH template".to_string(),
            features: vec![
                "SSH over a stable SSH endpoint".to_string(),
                "PaaS-provisioned ngrok TCP address".to_string(),
            ],
            version: "2026-06-18".to_string(),
            image: "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".to_string(),
            paas_managed_config_keys: vec!["NGROK_AUTHTOKEN".to_string()],
            config_keys: vec![
                HostedTemplateConfigKey {
                    key: "NGROK_TCP_URL".to_string(),
                    label: "Stable SSH endpoint".to_string(),
                    description: "Optional existing reserved stable SSH endpoint.".to_string(),
                    input_type: "text".to_string(),
                    required: false,
                    secret: false,
                    default_value: None,
                    validation: Some(HostedTemplateConfigValidation {
                        format: Some("ngrok_tcp_url".to_string()),
                        example: Some("6.tcp.eu.ngrok.io:17958".to_string()),
                        max_bytes: Some(255),
                        max_items: None,
                        allowed_algorithms: vec![],
                    }),
                },
                HostedTemplateConfigKey {
                    key: "DEBIAN_SSH_AUTHORIZED_KEYS".to_string(),
                    label: "SSH public keys".to_string(),
                    description: "One SSH public key per line.".to_string(),
                    input_type: "ssh_public_keys".to_string(),
                    required: true,
                    secret: false,
                    default_value: None,
                    validation: None,
                },
            ],
            persistence_path: Some("/state".to_string()),
            security_notes: vec![],
        }
    }

    #[test]
    fn ngrok_tcp_url_normalizes_tcp_scheme() {
        assert_eq!(
            normalize_ngrok_tcp_url("tcp://6.tcp.eu.ngrok.io:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("TCP://6.TCP.EU.NGROK.IO:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("TCP://6.TCP.EU.NGROK.IO.:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            normalize_ngrok_tcp_url("1.tcp.ngrok.io:22222").unwrap(),
            "1.tcp.ngrok.io:22222"
        );
    }

    #[test]
    fn ngrok_tcp_url_rejects_non_ngrok_hosts() {
        assert!(normalize_ngrok_tcp_url("example.com:22").is_err());
        assert!(normalize_ngrok_tcp_url("tcp.eu.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.foo.eu.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.extra.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.example:17958").is_err());
        assert!(
            normalize_ngrok_tcp_url(&format!("{}.tcp.eu.ngrok.io:17958", "a".repeat(64))).is_err()
        );
    }

    #[test]
    fn ngrok_tcp_url_rejects_non_decimal_ports() {
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:+123").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:1e2").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.ngrok.io:000123").is_err());
    }

    #[test]
    fn tee_config_url_normalizes_confidential_endpoint() {
        assert_eq!(
            template_config_endpoint_url("https://TEE.Enclava.Dev./").unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("https://tee.enclava.dev/.well-known/confidential")
                .unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url(
                "https://tee.enclava.dev/.well-known/confidential/config?ignored=true#frag",
            )
            .unwrap(),
            "https://tee.enclava.dev/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://localhost:8080/.well-known/confidential").unwrap(),
            "http://localhost:8080/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://127.0.0.1:8080/.well-known/confidential").unwrap(),
            "http://127.0.0.1:8080/.well-known/confidential/config"
        );
        assert_eq!(
            template_config_endpoint_url("http://[::1]:8080/.well-known/confidential").unwrap(),
            "http://[::1]:8080/.well-known/confidential/config"
        );
    }

    #[test]
    fn tee_config_url_rejects_credentials_and_custom_paths() {
        for url in [
            "",
            "file:///tmp/config",
            "http://tee.enclava.dev/.well-known/confidential/config",
            "https://user:pass@tee.enclava.dev/.well-known/confidential/config",
            "https://tee.enclava.dev:8443/.well-known/confidential/config",
            "https://tee.enclava.dev/custom/config",
            "https://-tee.enclava.dev/.well-known/confidential/config",
            "https://tee-.enclava.dev/.well-known/confidential/config",
            "https://123.456/.well-known/confidential/config",
            "https://8.8.8.8/.well-known/confidential/config",
            "http://8.8.8.8:8080/.well-known/confidential/config",
            "https://tee.example.test/.well-known/confidential/config",
            "https://tee.example.com/.well-known/confidential/config",
        ] {
            assert!(
                template_config_endpoint_url(url).is_err(),
                "expected {url:?} to be rejected"
            );
        }
    }

    #[test]
    fn deploy_omits_stable_endpoint_by_default_and_accepts_optional_import() {
        assert_eq!(template_create_config(None), serde_json::json!({}));
        assert_eq!(
            template_create_config(Some("6.tcp.eu.ngrok.io:17958")),
            serde_json::json!({
                "NGROK_TCP_URL": "6.tcp.eu.ngrok.io:17958"
            })
        );
        assert_eq!(
            normalize_ngrok_tcp_url("tcp://6.TCP.EU.NGROK.IO:17958").unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
    }

    #[test]
    fn deploy_cli_defers_stable_endpoint_requirement_to_debian_ssh_runtime_and_accepts_legacy_alias()
     {
        use clap::Parser as _;

        let cli = crate::commands::Cli::try_parse_from([
            "enclava", "template", "deploy", "--name", "shell",
        ])
        .expect("template deploy should parse without making every template SSH-specific");

        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(args.template, DEBIAN_SSH_NGROK_TEMPLATE);
        assert_eq!(args.ngrok_tcp_url, None);
        assert_eq!(
            template_create_config(args.ngrok_tcp_url.as_deref()),
            serde_json::json!({})
        );

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "deploy",
            "--name",
            "shell",
            "--ngrok-tcp-url",
            "6.tcp.eu.ngrok.io:17958",
        ])
        .expect("legacy ngrok endpoint flag must remain accepted");
        let crate::commands::Command::Template(TemplateCommand::Deploy(args)) = cli.command else {
            panic!("expected template deploy command");
        };
        assert_eq!(
            args.ngrok_tcp_url.as_deref(),
            Some("6.tcp.eu.ngrok.io:17958")
        );
    }

    #[test]
    fn deploy_help_names_stable_ssh_endpoint_and_legacy_alias() {
        use clap::Parser as _;

        let help =
            match crate::commands::Cli::try_parse_from(["enclava", "template", "deploy", "--help"])
            {
                Ok(_) => panic!("help should exit through clap"),
                Err(error) => error.to_string(),
            };

        assert!(
            help.contains("Existing reserved stable SSH endpoint"),
            "template deploy help should frame --stable-ssh-endpoint as an optional import path: {help}"
        );
        assert!(
            help.contains("--stable-ssh-endpoint <HOST:PORT>"),
            "template deploy help should lead with --stable-ssh-endpoint: {help}"
        );
        assert!(
            help.contains("--ngrok-tcp-url"),
            "template deploy help should keep the legacy --ngrok-tcp-url alias visible: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command readiness"),
            "template deploy help should frame --no-wait around stable SSH endpoint command readiness: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command details"),
            "template deploy JSON help should name the stable SSH endpoint command: {help}"
        );
        let command_centric_hint = ["for a stable SSH", " command"].concat();
        assert!(
            !help.contains(&command_centric_hint),
            "template deploy help should not frame the reserved endpoint as merely command-oriented: {help}"
        );
    }

    #[test]
    fn ssh_command_help_names_stable_ssh_endpoint_and_legacy_alias() {
        use clap::Parser as _;

        let help = match crate::commands::Cli::try_parse_from([
            "enclava",
            "template",
            "ssh-command",
            "--help",
        ]) {
            Ok(_) => panic!("help should exit through clap"),
            Err(error) => error.to_string(),
        };

        assert!(
            help.contains("Reserved stable SSH endpoint expected for this app"),
            "template ssh-command help should frame --stable-ssh-endpoint as a stable SSH endpoint assertion: {help}"
        );
        assert!(
            help.contains("--stable-ssh-endpoint <HOST:PORT>"),
            "template ssh-command help should lead with --stable-ssh-endpoint: {help}"
        );
        assert!(
            help.contains("--ngrok-tcp-url"),
            "template ssh-command help should keep the legacy --ngrok-tcp-url alias visible: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command as ready"),
            "template ssh-command help should describe waiting for stable SSH endpoint command readiness: {help}"
        );
        assert!(
            help.contains("stable SSH endpoint command and parsed stable SSH endpoint"),
            "template ssh-command JSON help should describe endpoint-first JSON output: {help}"
        );
        let command_centric_hint = ["returned stable SSH", " command"].concat();
        assert!(
            !help.contains(&command_centric_hint),
            "template ssh-command help should not frame the reserved endpoint as merely command-oriented: {help}"
        );
    }

    #[test]
    fn template_help_names_ssh_command_as_stable_ssh_endpoint_recovery() {
        use clap::Parser as _;

        let help = match crate::commands::Cli::try_parse_from(["enclava", "template", "--help"]) {
            Ok(_) => panic!("help should exit through clap"),
            Err(error) => error.to_string(),
        };

        assert!(
            help.contains("Fetch and validate the PaaS-rendered stable SSH endpoint command"),
            "template help should make ssh-command discoverable as stable SSH endpoint recovery: {help}"
        );
    }

    #[tokio::test]
    async fn unsupported_templates_do_not_require_stable_ssh_endpoint() {
        let err = deploy(TemplateDeployArgs {
            template: "future-template".to_string(),
            name: "shell".to_string(),
            ssh_public_keys: vec![],
            ssh_public_key_files: vec![],
            ngrok_tcp_url: None,
            no_wait: false,
            ssh_timeout_seconds: DEFAULT_SSH_TIMEOUT_SECONDS,
            json: false,
        })
        .await
        .expect_err("unsupported templates should fail before stable SSH endpoint validation");

        assert!(
            err.to_string()
                .contains("template 'future-template' is not supported")
        );
    }

    #[test]
    fn template_instance_name_uses_server_slug_rules() {
        assert_eq!(normalize_slug(" Shell-01 ").unwrap(), "shell-01");
        assert!(normalize_slug("1234").is_err());
        assert!(normalize_slug("-shell").is_err());
        assert!(normalize_slug("shell_01").is_err());
    }

    fn stable_ssh_app_response(endpoint: Option<&str>) -> AppResponse {
        AppResponse {
            id: "app-1".to_string(),
            name: "shell".to_string(),
            namespace: "ns-shell".to_string(),
            instance_id: "instance-1".to_string(),
            service_account: None,
            bootstrap_owner_pubkey_hash: None,
            tenant_instance_identity_hash: None,
            domain: "shell.enclava.dev".to_string(),
            app_domain: None,
            tee_domain: None,
            custom_domain: None,
            status: "running".to_string(),
            unlock_mode: "auto".to_string(),
            signer_identity_subject: None,
            signer_identity_issuer: None,
            template_slug: Some(DEBIAN_SSH_NGROK_TEMPLATE.to_string()),
            template_version: Some("2026-06-18".to_string()),
            template_expected: enclava_cli::api_types::TemplateExpected {
                stable_ssh_endpoint: endpoint.map(str::to_string),
                ..Default::default()
            },
            created_at: "2026-06-24T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn ssh_command_uses_stored_stable_endpoint_from_app_metadata() {
        let app = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:123"));
        assert_eq!(
            stored_stable_endpoint_from_app(&app).unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );

        let mut non_template = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:17958"));
        non_template.template_slug = Some("mini-enclava-go".to_string());
        assert!(
            stored_stable_endpoint_from_app(&non_template)
                .unwrap_err()
                .to_string()
                .contains("only available for debian-ssh-ngrok apps")
        );

        for endpoint in [None, Some("   ")] {
            let app = stable_ssh_app_response(endpoint);
            assert!(
                stored_stable_endpoint_from_app(&app)
                    .unwrap_err()
                    .to_string()
                    .contains("missing its stored stable SSH endpoint expectation")
            );
        }

        for endpoint in [
            "tcp://6.tcp.eu.ngrok.io:123",
            "6.TCP.EU.NGROK.IO:123",
            "6.tcp.eu.ngrok.io.:123",
            "6.tcp.eu.ngrok.io:00123",
            " tcp://6.TCP.EU.NGROK.IO.:00123 ",
            "example.com:22",
        ] {
            let app = stable_ssh_app_response(Some(endpoint));
            assert!(
                stored_stable_endpoint_from_app(&app)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid stored stable SSH endpoint expectation"),
                "{endpoint} must be treated as corrupt stored metadata"
            );
        }
    }

    fn template_instance_response_with_stored_endpoint(
        endpoint: Option<&str>,
    ) -> TemplateInstanceResponse {
        TemplateInstanceResponse {
            template: hosted_template_with_stable_ssh(),
            app: enclava_cli::api_types::TemplateInstanceAppResponse {
                name: Some("shell".to_string()),
                template_expected: enclava_cli::api_types::TemplateExpected {
                    stable_ssh_endpoint: endpoint.map(str::to_string),
                    ..Default::default()
                },
                ..Default::default()
            },
            deployment: enclava_cli::api_types::TemplateDeploymentResponse {
                cap_deployment_id: Some("deploy-123".to_string()),
                status: "pending".to_string(),
                template_expected: enclava_cli::api_types::TemplateExpected {
                    stable_ssh_endpoint: endpoint.map(str::to_string),
                    ..Default::default()
                },
            },
            config_token: None,
            cap: serde_json::json!({
                "app_domain": "shell.enclava.dev"
            }),
        }
    }

    #[test]
    fn deploy_uses_server_stored_stable_endpoint_from_template_instance_response() {
        let response =
            template_instance_response_with_stored_endpoint(Some("6.tcp.eu.ngrok.io:17958"));

        assert_eq!(
            stored_stable_endpoint_from_template_instance_response(
                &response,
                Some("tcp://6.TCP.EU.NGROK.IO:17958")
            )
            .unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );
        assert_eq!(
            stored_stable_endpoint_from_template_instance_response(&response, None).unwrap(),
            "6.tcp.eu.ngrok.io:17958"
        );

        let missing = template_instance_response_with_stored_endpoint(None);
        assert!(
            stored_stable_endpoint_from_template_instance_response(
                &missing,
                Some("6.tcp.eu.ngrok.io:17958")
            )
            .unwrap_err()
            .to_string()
            .contains("did not include its stored stable SSH endpoint expectation")
        );

        for endpoint in [
            "6.TCP.EU.NGROK.IO:17958",
            "tcp://6.tcp.eu.ngrok.io:17958",
            "6.tcp.eu.ngrok.io:00123",
            "example.com:22",
        ] {
            let response = template_instance_response_with_stored_endpoint(Some(endpoint));
            assert!(
                stored_stable_endpoint_from_template_instance_response(
                    &response,
                    Some("6.tcp.eu.ngrok.io:17958")
                )
                .unwrap_err()
                .to_string()
                .contains("stored stable SSH endpoint"),
                "{endpoint} must not be accepted as stored endpoint authority"
            );
        }

        let mismatch =
            template_instance_response_with_stored_endpoint(Some("6.tcp.eu.ngrok.io:17959"));
        assert!(
            stored_stable_endpoint_from_template_instance_response(
                &mismatch,
                Some("6.tcp.eu.ngrok.io:17958")
            )
            .unwrap_err()
            .to_string()
            .contains("does not match submitted --stable-ssh-endpoint")
        );
    }

    #[test]
    fn ssh_command_endpoint_assertion_must_match_stored_metadata() {
        assert_eq!(
            ssh_command_stable_endpoint(None, "6.tcp.eu.ngrok.io:123").unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );
        assert_eq!(
            ssh_command_stable_endpoint(Some("6.tcp.eu.ngrok.io:123"), "6.tcp.eu.ngrok.io:123")
                .unwrap(),
            "6.tcp.eu.ngrok.io:123"
        );

        let err =
            ssh_command_stable_endpoint(Some("6.tcp.eu.ngrok.io:124"), "6.tcp.eu.ngrok.io:123")
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the PaaS-stored stable SSH endpoint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ssh_command_wait_surfaces_progress_without_polluting_json() {
        let source = include_str!("template.rs");
        let fn_start = source
            .find("async fn ssh_command")
            .expect("ssh_command function exists");
        let fn_end = source[fn_start..]
            .find("fn template_key")
            .expect("template_key follows ssh_command function")
            + fn_start;
        let body = &source[fn_start..fn_end];

        assert!(body.contains("if args.json"));
        assert!(body.contains("ProgressBar::hidden()"));
        assert!(body.contains("ProgressBar::new_spinner()"));
        assert!(body.contains("Waiting for stable SSH endpoint command..."));
        assert!(body.contains("Stable SSH endpoint command ready"));
        assert!(body.contains("Stable SSH endpoint command unavailable"));
    }

    #[test]
    fn ssh_command_endpoint_match_requires_reserved_address() {
        ensure_ssh_command_matches_endpoint(
            "ssh -p 17958 user@6.tcp.eu.ngrok.io",
            "tcp://6.tcp.eu.ngrok.io:17958",
        )
        .unwrap();
        assert!(
            ensure_ssh_command_matches_endpoint(
                "ssh -p 17959 user@6.tcp.eu.ngrok.io",
                "6.tcp.eu.ngrok.io:17958",
            )
            .is_err()
        );
        assert!(
            ensure_ssh_command_matches_endpoint(
                "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "example.com:22",
            )
            .is_err()
        );
    }

    #[test]
    fn app_url_normalizes_domain_and_root_url() {
        assert_eq!(
            app_url_from_app_domain("shell.enclava.dev").unwrap(),
            "https://shell.enclava.dev"
        );
        assert_eq!(
            app_url_from_app_domain("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            app_url_from_app_domain("https://Shell.Enclava.Dev./").unwrap(),
            "https://shell.enclava.dev"
        );
    }

    #[test]
    fn app_url_from_app_response_prefers_cap_app_domain_for_stable_ssh_lookup() {
        let mut app = stable_ssh_app_response(Some("6.tcp.eu.ngrok.io:17958"));
        app.domain = "legacy-shell.enclava.dev".to_string();
        app.app_domain = Some("shell.enclava.dev".to_string());

        assert_eq!(
            app_url_from_app_response(&app).unwrap(),
            "https://shell.enclava.dev"
        );

        app.app_domain = None;
        assert_eq!(
            app_url_from_app_response(&app).unwrap(),
            "https://legacy-shell.enclava.dev"
        );
    }

    #[test]
    fn app_url_from_template_response_cap_prefers_app_domain_and_falls_back_to_domain() {
        let both = serde_json::json!({
            "app_domain": "shell.enclava.dev",
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&both).unwrap(),
            "https://shell.enclava.dev"
        );

        let fallback = serde_json::json!({
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&fallback).unwrap(),
            "https://legacy-shell.enclava.dev"
        );

        let blank_app_domain = serde_json::json!({
            "app_domain": " ",
            "domain": "legacy-shell.enclava.dev"
        });
        assert_eq!(
            app_url_from_template_response_cap(&blank_app_domain).unwrap(),
            "https://legacy-shell.enclava.dev"
        );

        let missing = serde_json::json!({});
        assert!(
            app_url_from_template_response_cap(&missing)
                .unwrap_err()
                .to_string()
                .contains("app_domain or domain")
        );

        let invalid_domain = serde_json::json!({
            "domain": "https://shell.enclava.dev/path"
        });
        assert!(
            app_url_from_template_response_cap(&invalid_domain)
                .unwrap_err()
                .to_string()
                .contains("invalid domain")
        );
    }

    #[test]
    fn app_url_rejects_invalid_app_domains() {
        for domain in [
            "",
            "ftp://shell.enclava.dev",
            "https://user:pass@shell.enclava.dev",
            "not a host",
            "https://-shell.enclava.dev",
            "https://shell-.example.test",
            "https://shell.example_test.com",
            "https://metadata",
            "https://shell.example.test",
            "https://shell.example",
            "https://shell.invalid",
            "https://shell.example.com",
            "https://999.999.999.999",
            "https://123.456",
            "http://0127.0.0.1:8080/ssh.txt",
            "https://shell.enclava.dev/ssh.txt",
            "https://shell.enclava.dev?ignored=true",
            "https://shell.enclava.dev#frag",
            "http://localhost:8080/path?ignored=true",
        ] {
            assert!(
                app_url_from_app_domain(domain).is_err(),
                "{domain} should be rejected"
            );
        }
        assert_eq!(
            app_url_from_app_domain("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            app_url_from_app_domain("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn ssh_command_parser_requires_nonzero_tcp_port() {
        assert!(valid_ssh_command("ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.TCP.EU.NGROK.IO."));
        assert!(!valid_ssh_command("ssh -p 00123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command(" ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh  -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.tcp.eu.ngrok.io "));
        assert!(!valid_ssh_command("ssh -p nope user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 0 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p +123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 1e2 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 000123 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@"));
        assert!(!valid_ssh_command("ssh -p 17958 user@example.com"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.tcp.example.com"));
        assert!(!valid_ssh_command("ssh -p 17958 user@6.foo.eu.ngrok.io"));
        assert!(!valid_ssh_command(
            "ssh -p 17958 user@6.tcp.eu.extra.ngrok.io"
        ));
        assert!(!valid_ssh_command(
            "ssh -p 17958 user@6.tcp.eu.ngrok.example"
        ));
    }

    #[test]
    fn paas_ssh_command_poll_retries_only_transient_api_errors() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(should_retry_paas_ssh_command_error(&ApiError::Api {
                status,
                code: None,
                message: "temporary".to_string(),
            }));
        }

        for status in [400, 401, 403, 404, 409, 422] {
            assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
                status,
                code: None,
                message: "permanent".to_string(),
            }));
        }
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("cap_response_invalid".to_string()),
            message: "CAP app response included an invalid app domain".to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_missing".to_string()),
            message: "Hosted Debian SSH app is missing its stored stable SSH endpoint expectation"
                .to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_invalid".to_string()),
            message: "Hosted Debian SSH app has invalid stored stable SSH endpoint expectation"
                .to_string(),
        }));
        assert!(!should_retry_paas_ssh_command_error(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn paas_ssh_command_api_errors_are_actionable_for_stable_ssh_contract_failures() {
        let missing = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_missing".to_string()),
            message: "stored endpoint missing".to_string(),
        })
        .unwrap();
        assert!(missing.contains("Stable SSH endpoint metadata is missing"));
        assert!(missing.contains("Redeploy the template"));

        let invalid = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("stable_ssh_endpoint_invalid".to_string()),
            message: "stored endpoint invalid".to_string(),
        })
        .unwrap();
        assert!(invalid.contains("Stable SSH endpoint metadata is invalid"));
        assert!(invalid.contains("Redeploy the template"));

        let cap_invalid = paas_ssh_command_api_error_message(&ApiError::Api {
            status: 502,
            code: Some("cap_response_invalid".to_string()),
            message: "CAP app /ssh.txt returned an invalid stable SSH endpoint command".to_string(),
        })
        .unwrap();
        assert!(cap_invalid.contains(
            "Stable SSH endpoint API rejected malformed, non-canonical, or mismatched workload output"
        ));
        assert!(cap_invalid.contains(
            "Support must fix non-canonical stable SSH endpoint API or workload output at the template boundary"
        ));
        assert!(!cap_invalid.contains(&["Stable SSH", " broker rejected"].join("")));
        assert!(!cap_invalid.contains(&["stable", "endpoint metadata was stored"].join(" ")));

        assert!(
            paas_ssh_command_api_error_message(&ApiError::Api {
                status: 425,
                code: Some("ssh_command_not_available".to_string()),
                message: "pending".to_string(),
            })
            .is_none()
        );
    }

    #[test]
    fn stable_ssh_template_create_errors_are_actionable_for_missing_managed_ngrok_env() {
        let missing = stable_ssh_managed_ngrok_setup_error_message(&ApiError::Api {
            status: 503,
            code: Some("service_unavailable".to_string()),
            message: "service_unavailable: DEBIAN_SSH_NGROK_AUTHTOKEN is not configured"
                .to_string(),
        })
        .unwrap();

        assert!(missing.contains("PaaS is missing its managed ngrok authtoken"));
        assert!(missing.contains("inject DEBIAN_SSH_NGROK_AUTHTOKEN"));
        assert!(missing.contains(
            "Do not pass an ngrok token through the CLI, local text/token file, or release env"
        ));

        assert!(
            stable_ssh_managed_ngrok_setup_error_message(&ApiError::Api {
                status: 502,
                code: Some("cap_write_failed".to_string()),
                message: "CAP write failed".to_string(),
            })
            .is_none()
        );
    }

    #[test]
    fn ssh_command_response_validation_allows_pending_and_validates_ready() {
        let expected_endpoint = "6.tcp.eu.ngrok.io:17958";
        let expected_app_url = "https://shell.enclava.dev";
        let pending = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        validate_ssh_command_response(&pending, expected_endpoint, expected_app_url).unwrap();
        let err = validate_ssh_command_response(&pending, "example.com:22", expected_app_url)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("expected stable SSH endpoint is invalid")
        );
        let err = validate_ssh_command_response(&pending, expected_endpoint, "").unwrap_err();
        assert!(err.to_string().contains("expected app URL is invalid"));

        let noncanonical_api_stable_endpoint = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "tcp://6.TCP.EU.NGROK.IO.:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(
            &noncanonical_api_stable_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("stable_ssh_endpoint"));
        assert!(err.to_string().contains("is not canonical"));

        let mismatched_api_stable_endpoint = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17959".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(
            &mismatched_api_stable_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains(
            "stable_ssh_endpoint 6.tcp.eu.ngrok.io:17959 does not match expected stable SSH endpoint"
        ));

        let pending_with_app_url = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        validate_ssh_command_response(
            &pending_with_app_url,
            expected_endpoint,
            "shell.enclava.dev",
        )
        .unwrap();

        let pending_with_blank_app_url = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some(" ".to_string()),
        };
        let err = validate_ssh_command_response(
            &pending_with_blank_app_url,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url is invalid"));

        let pending_with_command = SshCommandResponse {
            status: "pending".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &pending_with_command,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains(
            "included ready-only stable SSH endpoint command fields while status was not ready"
        ));

        let unknown = SshCommandResponse {
            status: "degraded".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(&unknown, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("returned unknown status: degraded")
        );

        let ready = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        validate_ssh_command_response(
            &ready,
            "tcp://6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev/",
        )
        .unwrap();

        let noncanonical_command = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.TCP.EU.NGROK.IO.".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_command,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid stable SSH endpoint command")
        );

        let noncanonical_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("tcp://6.TCP.EU.NGROK.IO.:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response endpoint"));
        assert!(err.to_string().contains("is not canonical"));

        let missing_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &missing_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("did not include endpoint for ready stable SSH endpoint command")
        );

        let mismatched_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(
            &mismatched_reported_endpoint,
            expected_endpoint,
            expected_app_url,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );

        let overlong_host_label = "a".repeat(64);
        let overlong_host = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some(format!(
                "ssh -p 17958 user@{overlong_host_label}.tcp.eu.ngrok.io"
            )),
            endpoint: Some(format!("{overlong_host_label}.tcp.eu.ngrok.io:17958")),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&overlong_host, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid stable SSH endpoint command")
        );

        let mismatched = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(&mismatched, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(err.to_string().contains("does not match reserved endpoint"));

        let noncanonical_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://Shell.Enclava.Dev/ssh.txt?ignored=true#frag".to_string()),
        };
        let err = validate_ssh_command_response(
            &noncanonical_app_url,
            expected_endpoint,
            "shell.enclava.dev",
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url"));
        assert!(err.to_string().contains("is not canonical"));

        let mismatched_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://wrong.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&mismatched_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("app_url https://wrong.enclava.dev does not match expected app URL")
        );

        let invalid_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("ssh://shell.enclava.dev".to_string()),
        };
        let err =
            validate_ssh_command_response(&invalid_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(err.to_string().contains("response app_url is invalid"));

        let missing_app_url = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: None,
        };
        let err =
            validate_ssh_command_response(&missing_app_url, expected_endpoint, expected_app_url)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("did not include app_url for ready stable SSH endpoint command")
        );

        let missing = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: None,
            endpoint: None,
            app_url: Some("https://shell.enclava.dev".to_string()),
        };
        let err = validate_ssh_command_response(&missing, expected_endpoint, expected_app_url)
            .unwrap_err();
        assert!(err.to_string().contains("ready without a command"));
    }

    #[test]
    fn deploy_output_surfaces_stable_ssh_details_for_humans() {
        let output = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.enclava.dev",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            false,
        )
        .unwrap();

        assert!(output.contains("  Template:   debian-ssh-ngrok"));
        assert!(output.contains("  Instance:   shell"));
        assert!(output.contains("  URL:        https://shell.enclava.dev"));
        assert!(output.contains("  Deploy:     deploy-123"));
        assert!(output.contains("  Stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
        assert!(
            output.contains("  Stable SSH endpoint command: ssh -p 17958 user@6.tcp.eu.ngrok.io")
        );
        assert!(output.contains("  Verified stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
    }

    #[test]
    fn deploy_output_json_is_machine_readable() {
        let output = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.enclava.dev",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            true,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "template": "debian-ssh-ngrok",
                "instance": "shell",
                "app_url": "https://shell.enclava.dev",
                "deployment_id": "deploy-123",
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
                "stable_endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_status": "ready",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_path": "/apps/shell/ssh-command"
            })
        );
    }

    #[test]
    fn deploy_output_canonicalizes_and_validates_stable_endpoint() {
        let output = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.enclava.dev",
            "deploy-123",
            Some("tcp://6.TCP.EU.NGROK.IO.:00123"),
            None,
            None,
            true,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["stable_ssh_endpoint"], "6.tcp.eu.ngrok.io:123");
        assert_eq!(value["stable_endpoint"], "6.tcp.eu.ngrok.io:123");
        assert_eq!(value["ssh_command_status"], "pending");
        assert_eq!(value["endpoint"], serde_json::Value::Null);

        let err = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.enclava.dev",
            "deploy-123",
            Some("example.com:22"),
            None,
            None,
            true,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("stable SSH endpoint output is invalid")
        );
    }

    #[test]
    fn deploy_output_normalizes_app_url_for_stable_ssh_handoff() {
        let human = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://Shell.Enclava.Dev./",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            false,
        )
        .unwrap();
        assert!(human.contains("  URL:        https://shell.enclava.dev"));
        assert!(!human.contains("Shell.Enclava.Dev"));
        assert!(!human.contains("/ssh.txt"));

        let json = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://Shell.Enclava.Dev./",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            true,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["app_url"], "https://shell.enclava.dev");
    }

    #[test]
    fn deploy_output_rejects_mismatched_endpoint_api_endpoint() {
        let err = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.enclava.dev",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17959 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            false,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );
    }

    #[test]
    fn ssh_command_output_surfaces_endpoint_for_humans() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let output = ssh_command_response_output(
            "shell",
            &response,
            "tcp://6.TCP.EU.NGROK.IO.:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap();

        assert!(output.contains("  Status:     ready"));
        assert!(output.contains("  URL:        https://shell.enclava.dev"));
        assert!(output.contains("  Stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
        assert!(
            output.contains("  Stable SSH endpoint command: ssh -p 17958 user@6.tcp.eu.ngrok.io")
        );
        assert!(output.contains("  Verified stable SSH endpoint: 6.tcp.eu.ngrok.io:17958"));
    }

    #[test]
    fn cli_stable_ssh_human_copy_is_endpoint_first() {
        let template_source = include_str!("template.rs");
        let app_source = include_str!("app.rs");
        let stale_summary = ["Stable SSH", ":"].join("");

        assert!(
            !template_source.contains(&stale_summary),
            "template CLI output should spell out Stable SSH endpoint"
        );
        assert!(
            !app_source.contains(&stale_summary),
            "app CLI output should spell out Stable SSH endpoint"
        );
        assert!(template_source.contains("Stable SSH endpoint: {hint}"));
        assert!(template_source.contains("Stable SSH endpoint: {endpoint}"));
        assert!(template_source.contains("Stable SSH endpoint command: {command}"));
        let stale_command_label = ["  Com", "mand:    "].concat();
        assert!(!template_source.contains(&stale_command_label));
        assert!(app_source.contains("Stable SSH endpoint: {endpoint}"));
        assert!(
            app_source.contains(
                "Stable SSH endpoint metadata missing; redeploy the template so PaaS reserves a stable SSH endpoint"
            )
        );
        assert!(
            app_source.contains(
                "Stable SSH endpoint metadata invalid; redeploy the template so PaaS reserves a stable SSH endpoint"
            )
        );
    }

    #[test]
    fn ssh_command_output_json_is_machine_readable() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let output = ssh_command_response_output(
            "shell",
            &response,
            "tcp://6.TCP.EU.NGROK.IO.:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "app_name": "shell",
                "status": "ready",
                "app_url": "https://shell.enclava.dev",
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
                "stable_endpoint": "6.tcp.eu.ngrok.io:17958",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958"
            })
        );
    }

    #[test]
    fn ssh_command_output_rejects_noncanonical_app_url() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://Shell.Enclava.Dev./ssh.txt?ignored=true#frag".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response app_url"));
        assert!(err.to_string().contains("is not canonical"));
    }

    #[test]
    fn ssh_command_output_rejects_mismatched_endpoint_api_app_url() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://wrong.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            false,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("app_url https://wrong.enclava.dev does not match expected app URL")
        );
    }

    #[test]
    fn ssh_command_output_rejects_mismatched_endpoint_api_endpoint() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match endpoint parsed from stable SSH endpoint command")
        );
    }

    #[test]
    fn ssh_command_output_rejects_reserved_endpoint_mismatch() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            stable_ssh_endpoint: "6.tcp.eu.ngrok.io:17958".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: Some("https://shell.enclava.dev".to_string()),
        };

        let err = ssh_command_response_output(
            "shell",
            &response,
            "6.tcp.eu.ngrok.io:17958",
            "https://shell.enclava.dev",
            true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not match reserved endpoint"));
    }

    #[test]
    fn template_input_summary_surfaces_stable_ssh_endpoint() {
        let mut template = hosted_template_with_stable_ssh();
        template.config_keys.push(HostedTemplateConfigKey {
            key: "NGROK_AUTHTOKEN".to_string(),
            label: "ngrok auth token".to_string(),
            description: "Malformed registry response that exposes a managed key.".to_string(),
            input_type: "password".to_string(),
            required: true,
            secret: true,
            default_value: None,
            validation: Some(HostedTemplateConfigValidation {
                format: Some("single_token".to_string()),
                example: None,
                max_bytes: Some(4096),
                max_items: None,
                allowed_algorithms: vec![],
            }),
        });

        assert_eq!(
            template_required_inputs(&template).as_deref(),
            Some("SSH public keys")
        );
        assert_eq!(
            template_optional_inputs(&template).as_deref(),
            Some("Stable SSH endpoint (auto-reserved; optional --stable-ssh-endpoint)")
        );
        assert_eq!(
            template_paas_managed_config_summary(&template).as_deref(),
            Some(
                "NGROK_AUTHTOKEN (PaaS-owned; sourced from PaaS deployment env DEBIAN_SSH_NGROK_AUTHTOKEN)"
            )
        );
        assert_eq!(
            stable_ssh_endpoint_hint(&template).as_deref(),
            Some(
                "PaaS reserves one automatically; pass --stable-ssh-endpoint 6.tcp.eu.ngrok.io:17958 only to import an existing reserved endpoint"
            )
        );
    }

    #[test]
    fn debian_ssh_config_pairs_only_write_customer_owned_keys() {
        let pairs = debian_ssh_config_pairs("ssh-ed25519 AAAA".to_string());

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "DEBIAN_SSH_AUTHORIZED_KEYS");
    }

    #[test]
    fn stable_ssh_template_config_delivery_retries_only_transient_failures() {
        assert!(should_refresh_template_config_token(&TeeError::Tee {
            status: 401,
            message: "expired token".to_string(),
        }));
        assert!(!should_retry_template_config_tee_error(&TeeError::Tee {
            status: 401,
            message: "expired token".to_string(),
        }));
        for status in [408, 409, 425, 429, 500, 503] {
            assert!(should_retry_template_config_tee_error(&TeeError::Tee {
                status,
                message: "transient".to_string(),
            }));
            assert!(should_retry_template_config_sync_error(&ApiError::Api {
                status,
                code: Some("transient".to_string()),
                message: "transient".to_string(),
            }));
        }
        assert!(
            should_retry_template_config_sync_error(&ApiError::Api {
                status: 503,
                code: None,
                message: "proxy unavailable while refreshing config token".to_string(),
            }),
            "config token refresh uses the same transient PaaS retry classifier"
        );
        for status in [400, 403, 404, 422] {
            assert!(!should_retry_template_config_tee_error(&TeeError::Tee {
                status,
                message: "permanent".to_string(),
            }));
            assert!(!should_retry_template_config_sync_error(&ApiError::Api {
                status,
                code: Some("permanent".to_string()),
                message: "permanent".to_string(),
            }));
        }
        assert!(!should_retry_template_config_sync_error(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn config_token_refresh_honors_replacement_tee_url() {
        let current = "https://old.enclava.dev/.well-known/confidential/config";
        let refreshed = ConfigTokenResponse {
            token: "next-token".to_string(),
            tee_url: Some("https://NEW.Enclava.Dev./.well-known/confidential".to_string()),
            expires_at: None,
            expires_in_seconds: None,
        };

        assert_eq!(
            refreshed_template_config_endpoint_url(&refreshed, current).unwrap(),
            "https://new.enclava.dev/.well-known/confidential/config"
        );

        let without_tee_url = ConfigTokenResponse {
            token: "next-token".to_string(),
            tee_url: None,
            expires_at: None,
            expires_in_seconds: None,
        };
        assert_eq!(
            refreshed_template_config_endpoint_url(&without_tee_url, current).unwrap(),
            current
        );
    }

    #[test]
    fn ssh_public_key_validation_requires_public_key_blob() {
        validate_ssh_public_keys(VALID_ED25519_PUBLIC_KEY, None).unwrap();

        let err = validate_ssh_public_keys("ssh-ed25519 cmFuZG9tLWJhc2U2NA==", None).unwrap_err();

        assert!(err.to_string().contains("malformed SSH public key"));
    }
}
