use clap::Subcommand;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::CreateChallengeRequest;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};

#[derive(Subcommand)]
pub enum DomainsCommand {
    /// Request a TXT verification challenge for a custom domain
    Add {
        /// Domain name (e.g., app.example.com)
        domain: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// Verify a previously-added domain after publishing the TXT record
    Verify {
        /// Domain name to verify
        domain: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// List domains for an app
    List {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Print machine-readable JSON on stdout instead of the human report
        #[arg(long)]
        json: bool,
    },
    /// Remove a custom domain
    Remove {
        /// Domain name to remove
        domain: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
}

fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

fn build_api_client() -> Result<ApiClient, Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    Ok(ApiClient::from_config(&cli_config, &creds))
}

pub async fn run(cmd: DomainsCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        DomainsCommand::Add { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let req = CreateChallengeRequest {
                domain: domain.clone(),
            };
            let resp = api.create_domain_challenge(&app_name, &req).await?;

            println!("Domain challenge created for: {domain}");
            println!();
            println!("Publish this TXT record at your DNS provider:");
            println!("  Name:  {}", resp.txt_record_name);
            println!("  Value: {}", resp.txt_record_value);
            println!();
            println!("Expires at: {}", resp.expires_at);
            println!();
            println!("Once published, run:");
            println!("  enclava domains verify {domain} --app {app_name}");
        }

        DomainsCommand::Verify { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let resp = api.verify_domain(&app_name, &domain).await?;
            println!(
                "Domain '{}' verified for {app_name} at {}.",
                resp.domain, resp.verified_at,
            );
        }

        DomainsCommand::List { app, json } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let resp = api.get_domain(&app_name).await?;

            if json {
                // Stable shape: the API domain object as-is — every field
                // always present, absent domains `null`.
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::to_value(&resp)?)?
                );
                return Ok(());
            }

            println!("Domains for {app_name}:");
            println!("  Platform: https://{}", resp.platform_domain);
            if let Some(tee) = &resp.tee_domain {
                println!("  TEE:      https://{tee}");
            }
            if let Some(custom) = &resp.custom_domain {
                println!("  Custom:   https://{custom}");
            }
        }

        DomainsCommand::Remove { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            api.delete_custom_domain(&app_name, &domain).await?;
            println!("Custom domain '{domain}' removed from {app_name}.");
        }
    }
    Ok(())
}
