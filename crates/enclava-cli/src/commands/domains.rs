use clap::Subcommand;

use enclava_cli::api_client::{ApiClient, ApiError};
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
            let needs_cname = resp.acme_cname_name.is_some() && resp.acme_cname_target.is_some();
            if let (Some(cname_name), Some(cname_target)) =
                (&resp.acme_cname_name, &resp.acme_cname_target)
            {
                println!();
                println!("Also publish this CNAME record (required for the TLS certificate):");
                println!("  Name:      {cname_name}");
                println!("  Points at: {cname_target}");
            }
            // The challenge records prove ownership and delegate the
            // certificate; neither one sends traffic to the app. Best
            // effort: the challenge itself is already created.
            if let Ok(summary) = api.get_domain(&app_name).await {
                println!();
                println!("To send traffic to the app, point the domain itself at it:");
                println!("  Name:      {domain}");
                println!("  Points at: {}", summary.platform_domain);
                println!("  (a CNAME record; on an apex domain use your provider's ALIAS/ANAME)");
            }
            println!();
            println!("Expires at: {}", resp.expires_at);
            println!();
            if needs_cname {
                println!("Once the TXT and the certificate CNAME are published, run:");
            } else {
                println!("Once the TXT record is published, run:");
            }
            println!("  enclava domains verify {domain} --app {app_name}");
        }

        DomainsCommand::Verify { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let resp = match api.verify_domain(&app_name, &domain).await {
                Ok(resp) => resp,
                Err(error) => {
                    if let Some(hint) = verify_refusal_hint(&error, &domain) {
                        eprintln!("Hint: {hint}");
                    }
                    return Err(error.into());
                }
            };
            println!(
                "Domain '{}' verified for {app_name} at {}.",
                resp.domain, resp.verified_at,
            );
            // Verify routes the hostname; the certificate's hostname list is
            // part of the signed deployment, so it only reaches the workload
            // with the next deploy.
            println!();
            println!("To serve HTTPS on {}:", resp.domain);
            println!("  - Not deployed yet: run `enclava deploy`.");
            println!(
                "  - Already deployed: the app restarts to pick up the route (unlock it again if it"
            );
            println!(
                "    uses password unlock), then run `enclava deploy` to issue the certificate."
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

/// What to tell the user when verify is refused because the ownership TXT
/// record was not found or did not match (HTTP 412). The hosted API reduces
/// the refusal to a generic code, so the CLI names the record itself.
fn verify_refusal_hint(error: &ApiError, domain: &str) -> Option<String> {
    match error {
        ApiError::Api { status: 412, .. } => Some(format!(
            "the TXT record at _enclava-challenge.{domain} was not found or does not match the challenge. DNS changes can take a few minutes to become visible; check the record's name and value, then run verify again."
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(status: u16) -> ApiError {
        ApiError::Api {
            status,
            code: Some("cap_operation_rejected".to_string()),
            message: "cap_operation_rejected".to_string(),
            idempotency_disposition: None,
        }
    }

    #[test]
    fn verify_refusal_hint_names_the_txt_record_only_for_a_412() {
        let hint = verify_refusal_hint(&refusal(412), "app.example.com").expect("412 has a hint");
        assert!(hint.contains("_enclava-challenge.app.example.com"));
        assert!(hint.contains("can take a few minutes"));
        for other in [409, 422, 500] {
            assert_eq!(
                verify_refusal_hint(&refusal(other), "app.example.com"),
                None
            );
        }
        assert_eq!(
            verify_refusal_hint(&ApiError::NotAuthenticated, "app.example.com"),
            None
        );
    }
}
