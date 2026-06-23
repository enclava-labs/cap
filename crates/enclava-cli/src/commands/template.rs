use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use base64::Engine as _;
use clap::{Args, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use enclava_cli::{
    api_client::ApiClient,
    api_types::{CreateTemplateInstanceRequest, HostedTemplate, HostedTemplateConfigKey},
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
    /// Do not wait for /ssh.txt after config delivery.
    #[arg(long)]
    pub no_wait: bool,
    /// Seconds to wait for /ssh.txt.
    #[arg(long, default_value_t = DEFAULT_SSH_TIMEOUT_SECONDS)]
    pub ssh_timeout_seconds: u64,
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

    let pb = ProgressBar::new(4);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")?
            .progress_chars("=> "),
    );
    pb.set_message("Creating template instance...");

    let response = api
        .create_template_instance(&CreateTemplateInstanceRequest {
            template_slug: args.template.clone(),
            instance_name: args.name.clone(),
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
        api.sync_config_key(&args.name, key, false).await?;
    }
    pb.set_position(2);

    let app_domain = response
        .cap
        .get("app_domain")
        .and_then(serde_json::Value::as_str)
        .ok_or("template response did not include app_domain")?
        .to_string();
    let deployment_id = response
        .deployment
        .cap_deployment_id
        .as_deref()
        .unwrap_or("pending")
        .to_string();

    let ssh_command = if args.no_wait {
        pb.set_position(4);
        None
    } else {
        pb.set_position(3);
        if stable_endpoint.is_some() {
            pb.set_message("Waiting for stable SSH command...");
        } else {
            pb.set_message("Waiting for SSH command...");
        }
        let command = wait_for_ssh_command(
            &app_domain,
            stable_endpoint.as_deref(),
            Duration::from_secs(args.ssh_timeout_seconds),
        )
        .await?;
        pb.set_position(4);
        Some(command)
    };
    pb.finish_with_message("Template deployed");

    println!();
    println!("  Template:   {}", response.template.slug);
    println!("  Instance:   {}", args.name);
    println!("  URL:        https://{app_domain}");
    println!("  Deploy:     {deployment_id}");
    if let Some(endpoint) = stable_endpoint {
        println!("  Stable SSH: {endpoint}");
    }
    if let Some(command) = ssh_command {
        println!("  SSH:        {command}");
    } else {
        println!("  SSH:        pending at https://{app_domain}/ssh.txt");
    }
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
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| format!("line {} has a malformed SSH public key", index + 1))?;
    }
    if count == 0 {
        Err("at least one SSH public key is required".into())
    } else {
        Ok(())
    }
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

async fn wait_for_ssh_command(
    app_domain: &str,
    stable_endpoint: Option<&str>,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let url = format!("https://{}/ssh.txt", app_domain.trim_end_matches('/'));
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            let command = response.text().await?.trim().to_string();
            if valid_ssh_command(&command) {
                if let Some(endpoint) = stable_endpoint {
                    ensure_ssh_command_matches_endpoint(&command, endpoint)?;
                }
                return Ok(command);
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(format!("timed out waiting for SSH command at {url}").into())
}

fn valid_ssh_command(command: &str) -> bool {
    parse_ssh_endpoint(command).is_some()
}

fn parse_ssh_endpoint(command: &str) -> Option<(&str, &str)> {
    let parts = command.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "ssh" || parts[1] != "-p" {
        return None;
    }
    let host = parts[3].strip_prefix("user@")?;
    Some((host, parts[2]))
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

    fn hosted_template_with_stable_ssh() -> HostedTemplate {
        HostedTemplate {
            slug: "debian-ssh-ngrok".to_string(),
            name: "Debian SSH over ngrok".to_string(),
            description: "SSH template".to_string(),
            version: "2026-06-18".to_string(),
            image: "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
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
}
