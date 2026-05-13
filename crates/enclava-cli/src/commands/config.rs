use clap::Subcommand;

use enclava_cli::api_client::ApiClient;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::tee_client::TeeClient;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Set one or more config secrets (delivered direct to TEE)
    Set {
        /// KEY=VALUE pairs
        #[arg(required = true)]
        vars: Vec<String>,
    },
    /// List config key names (values never leave the TEE)
    Get {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// Remove a config secret
    Unset {
        /// Key to remove
        key: String,
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

fn build_api_client() -> Result<(ApiClient, CliPaths, config::CliConfig), Box<dyn std::error::Error>>
{
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths, cli_config))
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid format '{s}': expected KEY=VALUE"))?;
    if key.is_empty() {
        return Err("key cannot be empty".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}

pub async fn run(cmd: ConfigCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ConfigCommand::Set { vars } => {
            let pairs: Vec<(String, String)> = vars
                .iter()
                .map(|v| parse_key_value(v))
                .collect::<Result<Vec<_>, _>>()?;

            let app_name = {
                let config = AppConfig::find_and_load()?;
                config.app.name
            };

            let (api, _paths, _cli_config) = build_api_client()?;
            let app = api.get_app(&app_name).await?;

            // Get config token from API (authorization)
            let token_resp = api.get_config_token(&app_name).await?;

            // Write directly to TEE (value delivery)
            let tee = token_resp
                .tee_url
                .as_deref()
                .map(TeeClient::from_config_url)
                .unwrap_or_else(|| {
                    let tee_domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
                    TeeClient::new(tee_domain)
                });
            for (key, value) in &pairs {
                tee.config_set(key, value, &token_resp.token).await?;
                api.sync_config_key(&app_name, key, false).await?;
                println!("Set {key}");
            }

            println!("Config updated ({} key(s)).", pairs.len());
        }

        ConfigCommand::Get { app } => {
            let app_name = resolve_app_name(&app)?;
            let (api, _paths, _cli_config) = build_api_client()?;

            let resp = api.list_config_keys(&app_name).await?;

            if resp.keys.is_empty() {
                println!("No config keys set for {app_name}.");
            } else {
                println!("Config keys for {app_name}:");
                for key_meta in &resp.keys {
                    println!("  {} (updated: {})", key_meta.key, key_meta.updated_at);
                }
            }
        }

        ConfigCommand::Unset { key, app } => {
            let app_name = resolve_app_name(&app)?;
            let (api, _paths, _cli_config) = build_api_client()?;
            let app_info = api.get_app(&app_name).await?;

            // Get config token from API
            let token_resp = api.get_config_token(&app_name).await?;

            // Delete from TEE
            let tee = token_resp
                .tee_url
                .as_deref()
                .map(TeeClient::from_config_url)
                .unwrap_or_else(|| {
                    let tee_domain = app_info
                        .custom_domain
                        .as_deref()
                        .unwrap_or(&app_info.domain);
                    TeeClient::new(tee_domain)
                });
            tee.config_unset(&key, &token_resp.token).await?;

            // Delete metadata from API
            api.delete_config_meta(&app_name, &key).await?;

            println!("Unset {key}.");
        }
    }
    Ok(())
}
