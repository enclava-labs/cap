use clap::Subcommand;

use enclava_cli::api_client::{ApiClient, ApiError};
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::tee_client::TeeClient;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Set one or more config secrets (written to the TEE config store; applied at the workload's next boot)
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
    /// Remove a config secret (takes effect at the workload's next boot)
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

/// Config values are consumed by the workload at boot (injected env / config
/// files); a running process keeps previously-consumed values until it
/// restarts, so there is no non-disruptive live re-application path.
pub(crate) const CONFIG_APPLICATION_NOTE: &str = "Note: config values apply to the workload at its next boot (restart/redeploy; in password mode, after the subsequent unlock) — a running app may keep using previously-consumed values until then.";

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

            let token_resp = api.get_config_token(&app_name).await?;

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
            let mut note_printed = false;
            for (key, value) in &pairs {
                tee.config_set(key, value, &token_resp.token).await?;
                // The value is live in the TEE store from here on; emit the
                // application note before any later step can fail the command.
                if !note_printed {
                    println!("{CONFIG_APPLICATION_NOTE}");
                    note_printed = true;
                }
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
            // Read-only lookups first (review on #307): a token without
            // apps:read must fail HERE, cleanly, not after the store delete —
            // every step below may mutate.
            let app_info = api.get_app(&app_name).await?;

            // Store first, guest second (#304): the required-key guard lives
            // on the meta delete, so it must be able to refuse BEFORE the
            // TEE key is removed — a refused unset must mutate nothing. The
            // meta delete is idempotent (204 whether or not the row existed),
            // so a retry after a TEE-side failure re-runs it harmlessly and
            // retries the TEE delete.
            match api.delete_config_meta(&app_name, &key).await {
                Ok(()) => {}
                // Indeterminate outcome (review on #307): transport errors,
                // and gateway/server 5xx — the request may have reached and
                // been applied upstream — leave the store possibly unset
                // while the TEE copy certainly remains. Same partial state
                // as a TEE-side failure below; the retry is safe either way.
                Err(
                    error @ (ApiError::Http(_)
                    | ApiError::Api {
                        status: 500..=599, ..
                    }),
                ) => {
                    eprintln!(
                        "Warning: the outcome of removing {key} from the config store for app \
                         {app_name} is unknown ({error}) — it may already be unset there. Retry \
                         with `enclava config unset {key} --app {app_name}` (the store delete is \
                         idempotent) to complete the removal."
                    );
                    return Err(error.into());
                }
                // A definite client-side answer (guard refusal, unknown app,
                // permissions): nothing was mutated — propagate as-is.
                Err(error) => return Err(error.into()),
            }

            // Every remaining step reads or mutates the TEE. Any failure in
            // the phase leaves the partial state (store unset, delivered copy
            // possibly still in place) — so the whole phase reports it, not
            // just the final TEE delete.
            let tee_phase: Result<(), Box<dyn std::error::Error>> = async {
                let token_resp = api.get_config_token(&app_name).await?;

                let tee = token_resp
                    .tee_url
                    .as_deref()
                    .map(|tee_url| {
                        TeeClient::from_config_url_with_resolve_ip(
                            tee_url,
                            token_resp.tee_resolve_ip,
                        )
                    })
                    .unwrap_or_else(|| {
                        let tee_domain = app_info.tee_domain.as_deref().unwrap_or(&app_info.domain);
                        TeeClient::new_with_resolve_ip(tee_domain, token_resp.tee_resolve_ip)
                    });
                let (_attestation, tee) = tee.attest_receipt_key().await?;
                tee.config_unset(&key, &token_resp.token).await?;
                Ok(())
            }
            .await;
            if let Err(error) = tee_phase {
                // The store is already unset; the guest may keep the delivered
                // copy until this succeeds. Fail toward availability with the
                // state spelled out: the command exits non-zero and the
                // suggested retry completes the TEE-side removal. A running
                // workload keeps its already-consumed value until restart —
                // removing the stored key never revokes it from the process.
                eprintln!(
                    "Warning: {key} was removed from the config store for app \
                     {app_name}, but the TEE copy could not be removed ({error}). Retry with \
                     `enclava config unset {key} --app {app_name}` to complete the removal; a \
                     running workload keeps using its already-consumed value until it restarts."
                );
                return Err(error);
            }
            // The key is removed from the TEE store from here on; emit the
            // application note before any later step can fail the command.
            println!("{CONFIG_APPLICATION_NOTE}");

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

    // Runtime coverage for the ordering contracts the removed source-text
    // pins used to assert: attestation gates every TEE mutation, and the
    // store-side meta delete is the refusal gate that must run before any
    // TEE deletion (#304, review on #307). The development JSON attestation
    // path lets a local TLS stub stand in for the TEE.

    fn app_response() -> serde_json::Value {
        serde_json::json!({
            "id": "11111111-2222-3333-4444-555555555555",
            "name": "shell",
            "namespace": "team",
            "instance_id": "inst-1",
            "domain": "shell.enclava.dev",
            "status": "running",
            "unlock_mode": "password",
            "created_at": "2026-10-01T00:00:00Z"
        })
    }

    #[tokio::test]
    async fn config_set_and_unset_attest_before_mutating_and_gate_the_store_delete() {
        use crate::commands::app::tests::{
            dev_json_attestation_body, enable_dev_json_attestation, isolated_state_env,
            spawn_json_api_stub, spawn_local_tls_server,
        };

        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tee_events = events.clone();
        let tee_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tee_address = spawn_local_tls_server(tee_requests, move |path| {
            if path.starts_with("/.well-known/confidential/attestation") {
                tee_events.lock().unwrap().push("tee:attest".to_string());
                (200, dev_json_attestation_body(path))
            } else if path.ends_with("/config/K") {
                tee_events.lock().unwrap().push(format!("tee:write {path}"));
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        })
        .await;
        let api_events = events.clone();
        let api_address = spawn_json_api_stub(events.clone(), move |path| {
            let (status, body) = if path == "/apps/shell" {
                (200, app_response())
            } else if path == "/apps/shell/config-token" {
                api_events
                    .lock()
                    .unwrap()
                    .push("api:config-token".to_string());
                (
                    200,
                    serde_json::json!({
                        "token": "config-jwt",
                        "tee_url": format!("https://localhost:{}", tee_address.port()),
                        "tee_resolve_ip": "127.0.0.1"
                    }),
                )
            } else if path == "/apps/shell/config/sync" {
                api_events.lock().unwrap().push("api:sync".to_string());
                (200, serde_json::json!({}))
            } else if path == "/apps/shell/config/K/meta" {
                api_events
                    .lock()
                    .unwrap()
                    .push("api:meta-delete".to_string());
                (204, serde_json::json!({}))
            } else {
                (404, serde_json::json!({}))
            };
            (status, body)
        })
        .await;

        let _env = isolated_state_env(&format!("http://{api_address}"), false);
        enable_dev_json_attestation();

        super::run(super::ConfigCommand::Set {
            vars: vec!["K=v".to_string()],
            app: Some("shell".to_string()),
        })
        .await
        .expect("config set against stubbed API+TEE");
        super::run(super::ConfigCommand::Unset {
            key: "K".to_string(),
            app: Some("shell".to_string()),
        })
        .await
        .expect("config unset against stubbed API+TEE");

        let recorded = events.lock().unwrap().clone();
        let position = |needle: &str| {
            recorded
                .iter()
                .position(|event| event.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing from {recorded:?}"))
        };
        // set: config token -> attestation -> TEE write -> metadata sync.
        let set_attest = position("tee:attest");
        let set_write = position("tee:write /.well-known/confidential/config/K");
        assert!(
            position("api:config-token") < set_attest
                && set_attest < set_write
                && set_write < position("api:sync"),
            "config set must attest the TEE before writing values: {recorded:?}"
        );
        // unset: app lookup -> store meta delete -> attestation -> TEE delete.
        assert_eq!(
            recorded[0], "GET /apps/shell ",
            "the read-only capability lookup must precede every mutation: {recorded:?}"
        );
        let meta_delete = position("api:meta-delete");
        let unset_lookup = recorded
            .iter()
            .rposition(|event| event.starts_with("GET /apps/shell"))
            .expect("unset must look up the app first");
        let unset_attest = recorded
            .iter()
            .rposition(|event| event == "tee:attest")
            .expect("unset must attest");
        let unset_delete = recorded
            .iter()
            .rposition(|event| event.contains("tee:write"))
            .expect("unset must delete the TEE key");
        assert!(
            unset_lookup < meta_delete && meta_delete < unset_attest && unset_attest < unset_delete,
            "config unset must run the store-side guard and attestation before the TEE delete: {recorded:?}"
        );
    }

    #[tokio::test]
    async fn config_unset_refusal_mutates_nothing() {
        use crate::commands::app::tests::{
            isolated_state_env, spawn_json_api_stub, spawn_local_tls_server,
        };

        let tee_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tee_address =
            spawn_local_tls_server(tee_requests.clone(), |_| (200, "{}".to_string())).await;
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let api_address = spawn_json_api_stub(events.clone(), move |path| {
            if path == "/apps/shell" {
                (200, app_response())
            } else if path == "/apps/shell/config/K/meta" {
                // The store-side guard refuses (e.g. required-key guard or a
                // permission denial): a definite client-side answer, so the
                // command must stop without touching anything else.
                (403, serde_json::json!({}))
            } else if path == "/apps/shell/config-token" {
                (
                    200,
                    serde_json::json!({
                        "token": "config-jwt",
                        "tee_url": format!("https://localhost:{}", tee_address.port()),
                        "tee_resolve_ip": "127.0.0.1"
                    }),
                )
            } else {
                (404, serde_json::json!({}))
            }
        })
        .await;

        let _env = isolated_state_env(&format!("http://{api_address}"), false);

        let result = super::run(super::ConfigCommand::Unset {
            key: "K".to_string(),
            app: Some("shell".to_string()),
        })
        .await;

        assert!(result.is_err(), "a refused meta delete must fail the unset");
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["GET /apps/shell ", "DELETE /apps/shell/config/K/meta "],
            "no config-token fetch may follow the refused guard"
        );
        assert!(
            tee_requests.lock().unwrap().is_empty(),
            "a refused unset must mutate nothing: no TEE connection at all"
        );
    }

    #[tokio::test]
    async fn config_set_never_writes_to_an_unattested_tee() {
        use crate::commands::app::tests::{
            isolated_state_env, spawn_json_api_stub, spawn_local_tls_server,
        };

        let tee_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tee_address = spawn_local_tls_server(tee_requests.clone(), |path| {
            if path.starts_with("/.well-known/confidential/attestation") {
                // Attestation rejection: no write may reach this endpoint.
                (500, "{}".to_string())
            } else {
                (200, "{}".to_string())
            }
        })
        .await;
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let api_address = spawn_json_api_stub(events, move |path| {
            if path == "/apps/shell" {
                (200, app_response())
            } else if path == "/apps/shell/config-token" {
                (
                    200,
                    serde_json::json!({
                        "token": "config-jwt",
                        "tee_url": format!("https://localhost:{}", tee_address.port()),
                        "tee_resolve_ip": "127.0.0.1"
                    }),
                )
            } else {
                (404, serde_json::json!({}))
            }
        })
        .await;

        let _env = isolated_state_env(&format!("http://{api_address}"), false);

        let result = super::run(super::ConfigCommand::Set {
            vars: vec!["K=v".to_string()],
            app: Some("shell".to_string()),
        })
        .await;

        assert!(result.is_err(), "failed attestation must abort the set");
        assert!(
            tee_requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request.starts_with("GET /.well-known/confidential/attestation")),
            "only the attestation request may reach the TEE: {:?}",
            tee_requests.lock().unwrap()
        );
    }
}
