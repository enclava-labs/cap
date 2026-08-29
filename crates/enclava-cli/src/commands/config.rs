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
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
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
        ConfigCommand::Set { vars, app } => {
            let pairs: Vec<(String, String)> = vars
                .iter()
                .map(|v| parse_key_value(v))
                .collect::<Result<Vec<_>, _>>()?;

            let app_name = resolve_app_name(&app)?;

            let (api, _paths, _cli_config) = build_api_client()?;
            let app = api.get_app(&app_name).await?;

            // Get config token from API (authorization)
            let token_resp = api.get_config_token(&app_name).await?;

            // Write directly to TEE (value delivery)
            let tee = token_resp
                .tee_url
                .as_deref()
                .map(|tee_url| {
                    TeeClient::from_config_url_with_resolve_ip(tee_url, token_resp.tee_resolve_ip)
                })
                .unwrap_or_else(|| {
                    let tee_domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
                    TeeClient::new_with_resolve_ip(tee_domain, token_resp.tee_resolve_ip)
                });
            let (_attestation, tee) = tee.attest_receipt_key().await?;
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
                .map(|tee_url| {
                    TeeClient::from_config_url_with_resolve_ip(tee_url, token_resp.tee_resolve_ip)
                })
                .unwrap_or_else(|| {
                    let tee_domain = app_info.tee_domain.as_deref().unwrap_or(&app_info.domain);
                    TeeClient::new_with_resolve_ip(tee_domain, token_resp.tee_resolve_ip)
                });
            let (_attestation, tee) = tee.attest_receipt_key().await?;
            tee.config_unset(&key, &token_resp.token).await?;

            // Delete metadata from API
            api.delete_config_meta(&app_name, &key).await?;

            println!("Unset {key}.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_key_value;

    #[test]
    fn parse_key_value_accepts_equals_in_value() {
        assert_eq!(
            parse_key_value("TOKEN=a=b").unwrap(),
            ("TOKEN".to_string(), "a=b".to_string())
        );
    }

    #[test]
    fn config_set_accepts_explicit_app_without_local_config() {
        use clap::Parser as _;

        let cli = crate::commands::Cli::try_parse_from([
            "enclava",
            "config",
            "set",
            "DEBIAN_SSH_AUTHORIZED_KEYS=ssh-ed25519 test",
            "--app",
            "shell",
        ])
        .expect("config set should accept an explicit hosted app");
        let crate::commands::Command::Config(super::ConfigCommand::Set { vars, app }) = cli.command
        else {
            panic!("expected config set command");
        };
        assert_eq!(vars.len(), 1);
        assert_eq!(app.as_deref(), Some("shell"));
        assert_eq!(super::resolve_app_name(&app).unwrap(), "shell");
    }

    #[test]
    fn config_set_attests_before_writing_values() {
        let source = include_str!("config.rs");
        let set_start = source
            .find("ConfigCommand::Set { vars, app } =>")
            .expect("set command branch exists");
        let get_start = source[set_start..]
            .find("ConfigCommand::Get")
            .expect("get command branch follows set")
            + set_start;
        let body = &source[set_start..get_start];

        let attest = body
            .find("attest_receipt_key")
            .expect("config set must attest the TEE TLS leaf");
        let config_set = body
            .find("config_set")
            .expect("config set must write values");
        assert!(
            attest < config_set,
            "config set must verify attestation/SPKI binding before writing config"
        );
    }

    #[test]
    fn config_unset_attests_before_deleting_value() {
        let source = include_str!("config.rs");
        let unset_start = source
            .find("ConfigCommand::Unset { key, app } =>")
            .expect("unset command branch exists");
        let body = &source[unset_start..];

        let attest = body
            .find("attest_receipt_key")
            .expect("config unset must attest the TEE TLS leaf");
        let config_unset = body
            .find("config_unset")
            .expect("config unset must delete value");
        assert!(
            attest < config_unset,
            "config unset must verify attestation/SPKI binding before deleting config"
        );
    }
}
