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
        CreateTemplateInstanceRequest, HostedTemplate, HostedTemplateConfigKey, SshCommandResponse,
    },
    config::{self, CliPaths},
    tee_client::TeeClient,
};

const DEBIAN_SSH_NGROK_TEMPLATE: &str = "debian-ssh-ngrok";
const DEFAULT_SSH_TIMEOUT_SECONDS: u64 = 600;

#[derive(Subcommand)]
pub enum TemplateCommand {
    /// List hosted templates available to the active organization
    List,
    /// Deploy a hosted template instance
    Deploy(TemplateDeployArgs),
    /// Fetch the PaaS-rendered SSH command for a hosted template app
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
    /// ngrok auth token. Prefer --ngrok-authtoken-file to avoid shell history.
    #[arg(long)]
    pub ngrok_authtoken: Option<String>,
    /// File containing the ngrok auth token.
    #[arg(long = "ngrok-authtoken-file", value_name = "PATH")]
    pub ngrok_authtoken_file: Option<PathBuf>,
    /// Reserved ngrok TCP address for a stable SSH command, e.g. 6.tcp.eu.ngrok.io:17958.
    #[arg(long = "ngrok-tcp-url")]
    pub ngrok_tcp_url: Option<String>,
    /// Do not wait for the PaaS SSH command after config delivery.
    #[arg(long)]
    pub no_wait: bool,
    /// Seconds to wait for the PaaS SSH command.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// Print machine-readable JSON with deployment and SSH command details.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct TemplateSshCommandArgs {
    /// Instance/app name to inspect
    #[arg(long)]
    pub name: String,
    /// Reserved ngrok TCP address expected in the returned stable SSH command.
    #[arg(long = "ngrok-tcp-url")]
    pub ngrok_tcp_url: Option<String>,
    /// Wait until PaaS reports the SSH command as ready.
    #[arg(long)]
    pub wait: bool,
    /// Seconds to wait for the PaaS SSH command when --wait is set.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
    /// Print machine-readable JSON including the parsed SSH endpoint.
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
        if let Some(summary) = template_required_inputs(&template) {
            println!("    Required inputs: {summary}");
        }
        if let Some(summary) = template_optional_inputs(&template) {
            println!("    Optional inputs: {summary}");
        }
        if let Some(hint) = stable_ssh_endpoint_hint(&template) {
            println!("    Stable SSH: {hint}");
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
    let ngrok_authtoken = read_ngrok_authtoken(
        args.ngrok_authtoken.as_deref(),
        args.ngrok_authtoken_file.as_ref(),
    )?;
    let stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_ngrok_tcp_url)
        .transpose()?;

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

    let response = api
        .create_template_instance(&CreateTemplateInstanceRequest {
            template_slug: args.template.clone(),
            instance_name: instance_name.clone(),
            config: serde_json::json!({}),
        })
        .await?;
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
    let tee = TeeClient::from_config_url(tee_url);
    let (_attestation, tee) = tee.attest_receipt_key().await?;

    let config_pairs =
        debian_ssh_config_pairs(ngrok_authtoken, public_keys, stable_endpoint.as_ref());
    for (key, value) in &config_pairs {
        tee.config_set(key, value, &token.token).await?;
        api.sync_config_key(&instance_name, key, false).await?;
    }
    pb.set_position(2);

    let app_domain = response
        .cap
        .get("app_domain")
        .and_then(serde_json::Value::as_str)
        .ok_or("template response did not include app_domain")?
        .to_string();
    let mut app_url = app_url_from_app_domain(&app_domain)?;
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
        if stable_endpoint.is_some() {
            pb.set_message("Waiting for stable SSH command...");
        } else {
            pb.set_message("Waiting for SSH command...");
        }
        let response = wait_for_paas_ssh_command(
            &api,
            &instance_name,
            stable_endpoint.as_deref(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await?;
        if let Some(url) = response.app_url {
            app_url = url;
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
            stable_endpoint.as_deref(),
            ssh_command.as_deref(),
            ssh_endpoint.as_deref(),
            args.json,
        )?
    );
    Ok(())
}

async fn ssh_command(args: TemplateSshCommandArgs) -> Result<(), Box<dyn std::error::Error>> {
    let instance_name = normalize_slug(&args.name)?;
    let stable_endpoint = args
        .ngrok_tcp_url
        .as_deref()
        .map(normalize_ngrok_tcp_url)
        .transpose()?;
    let api = build_api_client()?;
    let response = if args.wait {
        wait_for_paas_ssh_command(
            &api,
            &instance_name,
            stable_endpoint.as_deref(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await?
    } else {
        let response = api.get_template_ssh_command(&instance_name).await?;
        validate_ssh_command_response(&response, stable_endpoint.as_deref())?;
        response
    };
    print!(
        "{}",
        ssh_command_response_output(&instance_name, &response, args.json)?
    );
    Ok(())
}

fn template_key<'a>(
    template: &'a HostedTemplate,
    key: &str,
) -> Option<&'a HostedTemplateConfigKey> {
    template.config_keys.iter().find(|entry| entry.key == key)
}

fn template_required_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, true)
}

fn template_optional_inputs(template: &HostedTemplate) -> Option<String> {
    template_input_summary(template, false)
}

fn template_input_summary(template: &HostedTemplate, required: bool) -> Option<String> {
    let labels = template
        .config_keys
        .iter()
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
        return format!("{} (--ngrok-tcp-url)", entry.label);
    }
    entry.label.clone()
}

fn stable_ssh_endpoint_hint(template: &HostedTemplate) -> Option<String> {
    let entry = template.config_keys.iter().find(|entry| {
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
        "pass --ngrok-tcp-url {example} for a stable command"
    ))
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

fn debian_ssh_config_pairs(
    ngrok_authtoken: String,
    public_keys: String,
    stable_endpoint: Option<&String>,
) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(endpoint) = stable_endpoint {
        pairs.push(("NGROK_TCP_URL", endpoint.clone()));
    }
    pairs.push(("NGROK_AUTHTOKEN", ngrok_authtoken));
    pairs.push(("DEBIAN_SSH_AUTHORIZED_KEYS", public_keys));
    pairs
}

fn read_ngrok_authtoken(
    direct: Option<&str>,
    file: Option<&PathBuf>,
) -> Result<String, Box<dyn std::error::Error>> {
    let token = if let Some(value) = direct {
        value.to_string()
    } else if let Some(path) = file {
        fs::read_to_string(path)
            .map_err(|err| format!("failed to read ngrok token file {}: {err}", path.display()))?
    } else if let Ok(value) = std::env::var("NGROK_AUTHTOKEN") {
        value
    } else {
        return Err(
            "ngrok auth token is required; pass --ngrok-authtoken, --ngrok-authtoken-file, or set NGROK_AUTHTOKEN"
                .into(),
        );
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        Err("ngrok auth token cannot be empty".into())
    } else {
        Ok(token)
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

fn normalize_ngrok_tcp_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
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
        return Err("reserved ngrok TCP address must look like 6.tcp.eu.ngrok.io:17958".into());
    };
    let port: u16 = port_text
        .parse()
        .map_err(|_| "reserved ngrok TCP address must include a valid TCP port")?;
    if port == 0 || !is_ngrok_tcp_host(host) {
        return Err("reserved ngrok TCP address must look like 6.tcp.eu.ngrok.io:17958".into());
    }
    Ok(format!("{host}:{port}"))
}

fn is_ngrok_tcp_host(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    if !matches!(labels.len(), 4 | 5) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
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
    let base = if app_domain.contains("://") {
        app_domain.to_string()
    } else {
        format!("https://{app_domain}")
    };
    let mut url = reqwest::Url::parse(&base)
        .map_err(|error| format!("template response included an invalid app_domain: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err("template response included an invalid app_domain".into());
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

async fn wait_for_paas_ssh_command(
    api: &ApiClient,
    app_name: &str,
    stable_endpoint: Option<&str>,
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
            Err(error) => return Err(error.into()),
        };
        if response.status == "ready" {
            validate_ssh_command_response(&response, stable_endpoint)?;
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(format!("timed out waiting for PaaS SSH command for app {app_name}").into())
}

fn validate_ssh_command_response(
    response: &SshCommandResponse,
    stable_endpoint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.status == "ready" {
        let command = response
            .command
            .as_deref()
            .ok_or("PaaS reported SSH command ready without a command")?;
        if !valid_ssh_command(command) {
            return Err(format!("PaaS returned an invalid SSH command: {command}").into());
        }
        if let Some(reported_endpoint) = response.endpoint.as_deref() {
            ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
        }
        if let Some(endpoint) = stable_endpoint {
            ensure_ssh_command_matches_endpoint(command, endpoint)?;
        }
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
    let endpoint = display_ssh_endpoint(ssh_command, ssh_endpoint)?;
    if json {
        let output = serde_json::json!({
            "template": template_slug,
            "instance": instance_name,
            "app_url": app_url,
            "deployment_id": deployment_id,
            "stable_endpoint": stable_endpoint,
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
        format!("  URL:        {app_url}"),
        format!("  Deploy:     {deployment_id}"),
    ];
    if let Some(endpoint) = stable_endpoint {
        lines.push(format!("  Stable SSH: {endpoint}"));
    }
    if let Some(command) = ssh_command {
        lines.push(format!("  SSH:        {command}"));
        if let Some(endpoint) = endpoint {
            lines.push(format!("  Endpoint:   {endpoint}"));
        }
    } else {
        lines.push(format!(
            "  SSH:        pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn ssh_command_response_output(
    instance_name: &str,
    response: &SshCommandResponse,
    json: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    validate_ssh_command_response(response, None)?;
    let endpoint = display_ssh_endpoint(response.command.as_deref(), response.endpoint.as_deref())?;
    if json {
        let output = serde_json::json!({
            "app_name": instance_name,
            "status": response.status.as_str(),
            "app_url": response.app_url.as_deref(),
            "command": response.command.as_deref(),
            "endpoint": endpoint,
        });
        return Ok(format!("{}\n", serde_json::to_string_pretty(&output)?));
    }

    let mut lines = vec![format!("  Status:     {}", response.status)];
    if let Some(app_url) = response.app_url.as_deref() {
        lines.push(format!("  URL:        {app_url}"));
    }
    if let Some(command) = response.command.as_deref() {
        lines.push(format!("  SSH:        {command}"));
        if let Some(endpoint) = endpoint {
            lines.push(format!("  Endpoint:   {endpoint}"));
        }
    } else {
        lines.push(format!(
            "  SSH:        pending via PaaS /apps/{instance_name}/ssh-command"
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
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

fn valid_ssh_command(command: &str) -> bool {
    parse_ssh_endpoint(command).is_some()
}

fn ssh_endpoint_string(command: &str) -> Option<String> {
    let (host, port) = parse_ssh_endpoint(command)?;
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
        .ok_or_else(|| format!("could not parse SSH command: {command}"))?;
    if let Some(reported_endpoint) = reported_endpoint {
        ensure_reported_ssh_endpoint_matches_command(command, reported_endpoint)?;
        return Ok(Some(reported_endpoint.to_string()));
    }
    Ok(Some(command_endpoint))
}

fn parse_ssh_endpoint(command: &str) -> Option<(&str, &str)> {
    let parts = command.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "ssh" || parts[1] != "-p" {
        return None;
    }
    if parts[2]
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .is_none()
    {
        return None;
    }
    let host = parts[3].strip_prefix("user@")?;
    if host.is_empty() {
        return None;
    }
    Some((host, parts[2]))
}

fn ensure_reported_ssh_endpoint_matches_command(
    command: &str,
    reported_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let command_endpoint = ssh_endpoint_string(command)
        .ok_or_else(|| format!("could not parse SSH command: {command}"))?;
    if reported_endpoint == command_endpoint {
        return Ok(());
    }
    Err(format!(
        "PaaS SSH endpoint {reported_endpoint} does not match SSH command endpoint {command_endpoint}"
    )
    .into())
}

fn ensure_ssh_command_matches_endpoint(
    command: &str,
    endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((host, port)) = parse_ssh_endpoint(command) else {
        return Err(format!("could not parse SSH command: {command}").into());
    };
    let expected = normalize_ngrok_tcp_url(endpoint)?;
    let actual = format!("{host}:{port}");
    if actual == expected {
        Ok(())
    } else {
        Err(format!("SSH command {actual} does not match reserved endpoint {expected}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_cli::api_types::HostedTemplateConfigValidation;

    const VALID_ED25519_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlL21WHthjyXNuxzes5bVqCCqgyWDuMvXcWhOxRGL1P cli-test@example";

    fn hosted_template_with_stable_ssh() -> HostedTemplate {
        HostedTemplate {
            slug: "debian-ssh-ngrok".to_string(),
            name: "Debian SSH over ngrok".to_string(),
            description: "SSH template".to_string(),
            version: "2026-06-18".to_string(),
            image: "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".to_string(),
            config_keys: vec![
                HostedTemplateConfigKey {
                    key: "NGROK_AUTHTOKEN".to_string(),
                    label: "ngrok auth token".to_string(),
                    description: "Token used by the workload.".to_string(),
                    input_type: "password".to_string(),
                    required: true,
                    secret: true,
                    default_value: None,
                    validation: None,
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
                HostedTemplateConfigKey {
                    key: "NGROK_TCP_URL".to_string(),
                    label: "Stable SSH endpoint".to_string(),
                    description: "Optional reserved ngrok TCP address.".to_string(),
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
            normalize_ngrok_tcp_url("1.tcp.ngrok.io:22222").unwrap(),
            "1.tcp.ngrok.io:22222"
        );
    }

    #[test]
    fn ngrok_tcp_url_rejects_non_ngrok_hosts() {
        assert!(normalize_ngrok_tcp_url("example.com:22").is_err());
        assert!(normalize_ngrok_tcp_url("tcp.eu.ngrok.io:17958").is_err());
        assert!(normalize_ngrok_tcp_url("6.tcp.eu.extra.ngrok.io:17958").is_err());
    }

    #[test]
    fn template_instance_name_uses_server_slug_rules() {
        assert_eq!(normalize_slug(" Shell-01 ").unwrap(), "shell-01");
        assert!(normalize_slug("1234").is_err());
        assert!(normalize_slug("-shell").is_err());
        assert!(normalize_slug("shell_01").is_err());
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
    }

    #[test]
    fn app_url_normalizes_domain_and_full_url() {
        assert_eq!(
            app_url_from_app_domain("shell.example.test").unwrap(),
            "https://shell.example.test"
        );
        assert_eq!(
            app_url_from_app_domain("http://localhost:8080/path?ignored=true").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn app_url_rejects_invalid_app_domains() {
        for domain in [
            "",
            "ftp://shell.example.test",
            "https://user:pass@shell.example.test",
            "not a host",
        ] {
            assert!(
                app_url_from_app_domain(domain).is_err(),
                "{domain} should be rejected"
            );
        }
    }

    #[test]
    fn ssh_command_parser_requires_nonzero_tcp_port() {
        assert!(valid_ssh_command("ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p nope user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 0 user@6.tcp.eu.ngrok.io"));
        assert!(!valid_ssh_command("ssh -p 17958 user@"));
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
        assert!(!should_retry_paas_ssh_command_error(
            &ApiError::NotAuthenticated
        ));
    }

    #[test]
    fn ssh_command_response_validation_allows_pending_and_validates_ready() {
        let pending = SshCommandResponse {
            status: "pending".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        validate_ssh_command_response(&pending, Some("6.tcp.eu.ngrok.io:17958")).unwrap();

        let ready = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.example.test".to_string()),
        };
        validate_ssh_command_response(&ready, Some("tcp://6.tcp.eu.ngrok.io:17958")).unwrap();

        let missing_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: None,
            app_url: Some("https://shell.example.test".to_string()),
        };
        validate_ssh_command_response(&missing_reported_endpoint, None).unwrap();

        let mismatched_reported_endpoint = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: None,
        };
        let err = validate_ssh_command_response(&mismatched_reported_endpoint, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match SSH command endpoint")
        );

        let mismatched = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17959".to_string()),
            app_url: None,
        };
        let err = validate_ssh_command_response(&mismatched, Some("6.tcp.eu.ngrok.io:17958"))
            .unwrap_err();
        assert!(err.to_string().contains("does not match reserved endpoint"));

        let missing = SshCommandResponse {
            status: "ready".to_string(),
            command: None,
            endpoint: None,
            app_url: None,
        };
        let err = validate_ssh_command_response(&missing, None).unwrap_err();
        assert!(err.to_string().contains("ready without a command"));
    }

    #[test]
    fn deploy_output_surfaces_stable_ssh_details_for_humans() {
        let output = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.example.test",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17958 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            false,
        )
        .unwrap();

        assert!(output.contains("  Template:   debian-ssh-ngrok"));
        assert!(output.contains("  Instance:   shell"));
        assert!(output.contains("  URL:        https://shell.example.test"));
        assert!(output.contains("  Deploy:     deploy-123"));
        assert!(output.contains("  Stable SSH: 6.tcp.eu.ngrok.io:17958"));
        assert!(output.contains("  SSH:        ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(output.contains("  Endpoint:   6.tcp.eu.ngrok.io:17958"));
    }

    #[test]
    fn deploy_output_json_is_machine_readable() {
        let output = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.example.test",
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
                "app_url": "https://shell.example.test",
                "deployment_id": "deploy-123",
                "stable_endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_status": "ready",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958",
                "ssh_command_path": "/apps/shell/ssh-command"
            })
        );
    }

    #[test]
    fn deploy_output_rejects_mismatched_broker_endpoint() {
        let err = deploy_response_output(
            "debian-ssh-ngrok",
            "shell",
            "https://shell.example.test",
            "deploy-123",
            Some("6.tcp.eu.ngrok.io:17958"),
            Some("ssh -p 17959 user@6.tcp.eu.ngrok.io"),
            Some("6.tcp.eu.ngrok.io:17958"),
            false,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match SSH command endpoint")
        );
    }

    #[test]
    fn ssh_command_output_surfaces_endpoint_for_humans() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.example.test".to_string()),
        };

        let output = ssh_command_response_output("shell", &response, false).unwrap();

        assert!(output.contains("  Status:     ready"));
        assert!(output.contains("  URL:        https://shell.example.test"));
        assert!(output.contains("  SSH:        ssh -p 17958 user@6.tcp.eu.ngrok.io"));
        assert!(output.contains("  Endpoint:   6.tcp.eu.ngrok.io:17958"));
    }

    #[test]
    fn ssh_command_output_json_is_machine_readable() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17958 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.example.test".to_string()),
        };

        let output = ssh_command_response_output("shell", &response, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "app_name": "shell",
                "status": "ready",
                "app_url": "https://shell.example.test",
                "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
                "endpoint": "6.tcp.eu.ngrok.io:17958"
            })
        );
    }

    #[test]
    fn ssh_command_output_rejects_mismatched_broker_endpoint() {
        let response = SshCommandResponse {
            status: "ready".to_string(),
            command: Some("ssh -p 17959 user@6.tcp.eu.ngrok.io".to_string()),
            endpoint: Some("6.tcp.eu.ngrok.io:17958".to_string()),
            app_url: Some("https://shell.example.test".to_string()),
        };

        let err = ssh_command_response_output("shell", &response, true).unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match SSH command endpoint")
        );
    }

    #[test]
    fn template_input_summary_surfaces_stable_ssh_endpoint() {
        let template = hosted_template_with_stable_ssh();

        assert_eq!(
            template_required_inputs(&template).as_deref(),
            Some("ngrok auth token, SSH public keys")
        );
        assert_eq!(
            template_optional_inputs(&template).as_deref(),
            Some("Stable SSH endpoint (--ngrok-tcp-url)")
        );
        assert_eq!(
            stable_ssh_endpoint_hint(&template).as_deref(),
            Some("pass --ngrok-tcp-url 6.tcp.eu.ngrok.io:17958 for a stable command")
        );
    }

    #[test]
    fn debian_ssh_config_pairs_write_stable_endpoint_before_required_keys() {
        let endpoint = "6.tcp.eu.ngrok.io:17958".to_string();
        let pairs = debian_ssh_config_pairs(
            "ngrok-token".to_string(),
            "ssh-ed25519 AAAA".to_string(),
            Some(&endpoint),
        );

        assert_eq!(pairs[0], ("NGROK_TCP_URL", endpoint));
        assert_eq!(pairs[1].0, "NGROK_AUTHTOKEN");
        assert_eq!(pairs[2].0, "DEBIAN_SSH_AUTHORIZED_KEYS");

        let dynamic_pairs = debian_ssh_config_pairs(
            "ngrok-token".to_string(),
            "ssh-ed25519 AAAA".to_string(),
            None,
        );
        assert_eq!(dynamic_pairs[0].0, "NGROK_AUTHTOKEN");
        assert_eq!(dynamic_pairs[1].0, "DEBIAN_SSH_AUTHORIZED_KEYS");
    }

    #[test]
    fn ssh_public_key_validation_requires_public_key_blob() {
        validate_ssh_public_keys(VALID_ED25519_PUBLIC_KEY, None).unwrap();

        let err = validate_ssh_public_keys("ssh-ed25519 cmFuZG9tLWJhc2U2NA==", None).unwrap_err();

        assert!(err.to_string().contains("malformed SSH public key"));
    }
}
