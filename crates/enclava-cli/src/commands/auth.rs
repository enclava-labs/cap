use clap::Args;
use dialoguer::{Input, Password, Select};
use std::process::Command;
use std::time::Duration;

use enclava_cli::api_client::{ApiClient, ApiError};
use enclava_cli::api_types::{
    AuthDiscoveryResponse, DeviceLoginPollRequest, DeviceLoginStartRequest, LoginRequest,
    SignupRequest,
};
use enclava_cli::config::{self, CliPaths, Credentials};

#[derive(Args)]
pub struct LoginArgs {
    /// Do not try to open a browser; print the URL and code only
    #[arg(long)]
    pub no_browser: bool,
    /// Override the platform API URL for this login
    #[arg(long)]
    pub api_url: Option<String>,
    /// Preferred organization name for approval
    #[arg(long)]
    pub org: Option<String>,
    /// Request explicit hosted workload log access for this CLI session
    #[arg(long = "approve-logs")]
    pub approve_logs: bool,
    /// Authenticate with Nostr identity (NIP-98)
    #[arg(long)]
    pub nostr: bool,
    /// Authenticate with email + password
    #[arg(long)]
    pub email: bool,
}

fn auth_method_error(
    discovery: Option<&AuthDiscoveryResponse>,
    provider: &str,
    action: &str,
) -> Option<String> {
    let discovery = discovery?;
    if discovery.auth_methods.contains(&provider.to_string()) {
        return None;
    }
    if discovery.auth_methods.len() == 1 && discovery.auth_methods[0] == "device_code" {
        Some(format!(
            "this target only supports device-code {action}; use `enclava login` and approve the device code in your browser"
        ))
    } else {
        Some(format!(
            "this target does not support {provider} {action}; supported methods: {}",
            discovery.auth_methods.join(", ")
        ))
    }
}

fn auth_discovery_or_legacy(
    result: Result<AuthDiscoveryResponse, ApiError>,
) -> Result<Option<AuthDiscoveryResponse>, Box<dyn std::error::Error>> {
    match result {
        Ok(discovery) => Ok(Some(discovery)),
        Err(ApiError::Api {
            status: 404 | 405, ..
        }) => Ok(None),
        Err(ApiError::Http(e)) if !e.is_decode() => Ok(None),
        Err(e) => Err(Box::new(e)),
    }
}

pub async fn signup() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;

    let client = ApiClient::new(&cli_config.api_url, None);
    let discovery = auth_discovery_or_legacy(client.auth_discovery().await)?;
    if let Some(discovery) = discovery.as_ref() {
        let email_unsupported = auth_method_error(Some(discovery), "email", "sign up").is_some();
        let nostr_unsupported = auth_method_error(Some(discovery), "nostr", "sign up").is_some();
        if email_unsupported && nostr_unsupported {
            return Err(if discovery.auth_methods == ["device_code"] {
                "this target only supports device-code/browser registration; use `enclava login`"
                    .into()
            } else {
                format!(
                    "this target does not support direct sign up; supported methods: {}",
                    discovery.auth_methods.join(", ")
                )
                .into()
            });
        }
    }

    let methods = vec!["Email", "Nostr (npub)"];
    let selection = Select::new()
        .with_prompt("Sign up with")
        .items(&methods)
        .default(0)
        .interact()?;

    let req = match selection {
        0 => {
            let email: String = Input::new().with_prompt("Email").interact_text()?;
            let password = Password::new()
                .with_prompt("Password")
                .with_confirmation("Confirm password", "Passwords don't match")
                .interact()?;
            let display_name: String = Input::new()
                .with_prompt("Display name (optional)")
                .allow_empty(true)
                .interact_text()?;

            SignupRequest {
                provider: "email".to_string(),
                email: Some(email),
                password: Some(password),
                npub: None,
                display_name: if display_name.is_empty() {
                    None
                } else {
                    Some(display_name)
                },
            }
        }
        1 => {
            let npub: String = Input::new()
                .with_prompt("Nostr public key (npub1...)")
                .interact_text()?;

            SignupRequest {
                provider: "nostr".to_string(),
                email: None,
                password: None,
                npub: Some(npub),
                display_name: None,
            }
        }
        _ => unreachable!(),
    };

    if let Some(err) = auth_method_error(discovery.as_ref(), &req.provider, "sign up") {
        return Err(err.into());
    }
    let resp = client.signup(&req).await?;

    // Save credentials
    let creds = Credentials {
        session_token: Some(resp.token),
        api_key: None,
        user_id: Some(resp.user_id.to_string()),
        active_org_id: Some(resp.org_id.to_string()),
        active_org_name: Some(resp.org_name.clone()),
    };
    config::save_credentials(&paths, &creds)?;

    // Save org
    let mut updated_config = cli_config;
    updated_config.org = Some(resp.org_name.clone());
    updated_config.org_id = Some(resp.org_id.to_string());
    config::save_config(&paths, &updated_config)?;

    println!("Account created. Logged in as {}.", resp.org_name);
    Ok(())
}

pub async fn login(args: LoginArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let mut cli_config = config::load_config(&paths)?;
    if let Some(api_url) = args.api_url.as_deref() {
        cli_config.api_url = api_url.trim_end_matches('/').to_string();
        config::save_config(&paths, &cli_config)?;
    }

    // Check for existing session
    let existing_creds = config::load_credentials(&paths)?;
    if existing_creds.session_token.is_some() {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Already logged in. Replace existing session?")
            .default(true)
            .interact()?;
        if !confirm {
            println!("Login cancelled.");
            return Ok(());
        }
    }

    if !args.email && !args.nostr {
        return device_login(args, paths, cli_config).await;
    }

    let use_nostr = if args.nostr {
        true
    } else if args.email {
        false
    } else {
        let methods = vec!["Email", "Nostr (npub)"];
        let selection = Select::new()
            .with_prompt("Log in with")
            .items(&methods)
            .default(0)
            .interact()?;
        selection == 1
    };

    let client = ApiClient::new(&cli_config.api_url, None);
    let provider = if use_nostr { "nostr" } else { "email" };
    let discovery = auth_discovery_or_legacy(client.auth_discovery().await)?;
    if let Some(err) = auth_method_error(discovery.as_ref(), provider, "log in") {
        return Err(err.into());
    }

    let req = if use_nostr {
        let npub: String = Input::new()
            .with_prompt("Nostr public key (npub1...)")
            .interact_text()?;
        let nsec_str: String = Password::new()
            .with_prompt("Nostr private key (nsec1...)")
            .interact()?;

        // Parse the secret key from nsec bech32
        let secret_key =
            nostr::SecretKey::parse(&nsec_str).map_err(|e| format!("invalid nsec key: {e}"))?;
        let keys = nostr::Keys::new(secret_key);

        // Verify the npub matches the nsec
        let expected_pubkey = keys.public_key();
        let provided_pubkey =
            nostr::PublicKey::parse(&npub).map_err(|e| format!("invalid npub: {e}"))?;
        if expected_pubkey != provided_pubkey {
            return Err("npub does not match nsec".into());
        }

        // Construct NIP-98 HTTP Auth event (kind 27235)
        let api_url = format!("{}/auth/login", cli_config.api_url);
        let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
            .tag(
                nostr::Tag::parse(["u".to_string(), api_url])
                    .map_err(|e| format!("tag error: {e}"))?,
            )
            .tag(
                nostr::Tag::parse(["method".to_string(), "POST".to_string()])
                    .map_err(|e| format!("tag error: {e}"))?,
            )
            .sign_with_keys(&keys)
            .map_err(|e| format!("failed to sign NIP-98 event: {e}"))?;

        let signed_event_json = nostr::JsonUtil::as_json(&event);

        LoginRequest {
            provider: "nostr".to_string(),
            email: None,
            password: None,
            npub: Some(npub),
            nostr_event: Some(signed_event_json),
        }
    } else {
        let email: String = Input::new().with_prompt("Email").interact_text()?;
        let password = Password::new().with_prompt("Password").interact()?;

        LoginRequest {
            provider: "email".to_string(),
            email: Some(email),
            password: Some(password),
            npub: None,
            nostr_event: None,
        }
    };

    let resp = client.login(&req).await?;

    // Save credentials
    let creds = Credentials {
        session_token: Some(resp.token),
        api_key: None,
        user_id: Some(resp.user_id.to_string()),
        active_org_id: Some(resp.org_id.to_string()),
        active_org_name: Some(resp.org_name.clone()),
    };
    config::save_credentials(&paths, &creds)?;

    // Save org
    let mut updated_config = cli_config;
    updated_config.org = Some(resp.org_name.clone());
    updated_config.org_id = Some(resp.org_id.to_string());
    config::save_config(&paths, &updated_config)?;

    println!("Logged in. Active org: {}", resp.org_name);
    Ok(())
}

async fn device_login(
    args: LoginArgs,
    paths: CliPaths,
    cli_config: config::CliConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = ApiClient::new(&cli_config.api_url, None);
    let start = client
        .start_device_login(&DeviceLoginStartRequest {
            org: args.org.clone(),
            requested_org_slug: args.org.clone(),
            requested_scopes: device_login_scopes(args.approve_logs),
        })
        .await?;

    println!("Open this URL to sign in:");
    println!("  {}", start.verification_uri);
    println!();
    println!("Code:");
    println!("  {}", start.user_code);
    println!();

    if !args.no_browser && try_open_browser(&start.verification_uri_complete) {
        println!("Opened browser. Waiting for approval...");
    } else {
        println!("Waiting for approval...");
    }

    let mut interval = start.interval.max(1) as u64;
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let poll = client
            .poll_device_login(&DeviceLoginPollRequest {
                device_code: start.device_code.clone(),
            })
            .await?;

        match poll.status.as_str() {
            "approved" => {
                let auth = poll
                    .auth
                    .ok_or("device login approved without session payload")?;
                let creds = Credentials {
                    session_token: Some(auth.token),
                    api_key: None,
                    user_id: Some(auth.user_id.clone()),
                    active_org_id: Some(auth.org_id.clone()),
                    active_org_name: Some(auth.org_name.clone()),
                };
                config::save_credentials(&paths, &creds)?;

                let mut updated_config = cli_config;
                updated_config.org = Some(auth.org_name.clone());
                updated_config.org_id = Some(auth.org_id.clone());
                config::save_config(&paths, &updated_config)?;

                let api = ApiClient::from_config(&updated_config, &creds);
                let me = api.get_current_user().await?;
                println!("Logged in as {}", me.display_name);
                println!("Active org: {}", me.active_org.name);
                return Ok(());
            }
            "pending" => {
                interval = poll.interval.max(1) as u64;
            }
            "slow_down" => {
                interval = poll.interval.max(interval as i64 + 1) as u64;
            }
            "denied" | "expired" => {
                return Err(poll
                    .error
                    .unwrap_or_else(|| format!("device login {}", poll.status))
                    .into());
            }
            other => return Err(format!("unexpected device login status: {other}").into()),
        }
    }
}

fn device_login_scopes(approve_logs: bool) -> Vec<String> {
    let mut scopes = vec![
        "apps:read".to_string(),
        "apps:write".to_string(),
        "org:admin".to_string(),
    ];
    if approve_logs {
        scopes.push("apps:logs".to_string());
    }
    scopes
}

/// Device-login URLs must be https and free of characters that any platform
/// shell (notably `cmd.exe` for the Windows `start` builtin) would interpret
/// as metacharacters. The URL arrives from the API server; a hostile or
/// compromised API must not gain command execution through the CLI.
fn browser_safe_device_url(url: &str) -> bool {
    // Scheme decided on the parsed host (an exact-loopback http URL is the
    // only non-https exception): a string-prefix test would accept
    // `http://localhost.evil.example` / `http://localhost@evil.example`.
    if !(url.starts_with("https://") || enclava_cli::api_client::loopback_http_url(url)) {
        return false;
    }
    !url.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '&' | '^' | '|' | '%' | '"' | '<' | '>' | '!' | '(' | ')')
    })
}

fn try_open_browser(url: &str) -> bool {
    if !browser_safe_device_url(url) {
        return false;
    }
    let quoted = format!("\"{url}\"");
    let commands: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("open", &[url])]
    } else if cfg!(target_os = "windows") {
        // Quoted so cmd.exe treats the URL as a single literal token; the
        // charset check above removes the remaining cmd metacharacters.
        &[("cmd", &["/C", "start", "", quoted.as_str()])]
    } else {
        &[("xdg-open", &[url])]
    };

    commands
        .iter()
        .any(|(program, args)| Command::new(program).args(*args).spawn().is_ok())
}

pub async fn whoami() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    let me = api.get_current_user().await?;

    println!("User: {} ({})", me.display_name, me.user_id);
    println!(
        "Active org: {} ({}) [{}]",
        me.active_org.name, me.active_org.id, me.active_org.role
    );
    if me.orgs.len() > 1 {
        println!("Organizations:");
        for org in me.orgs {
            println!("  {} ({}) [{}]", org.name, org.id, org.role);
        }
    }
    Ok(())
}

pub async fn logout() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let mut creds = config::load_credentials(&paths)?;
    creds.session_token = None;
    creds.user_id = None;
    creds.active_org_id = None;
    creds.active_org_name = None;
    config::save_credentials(&paths, &creds)?;
    println!("Logged out. Local recovery keys were left in place.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ApiError, AuthDiscoveryResponse, auth_discovery_or_legacy, auth_method_error,
        browser_safe_device_url,
    };

    fn discovery(methods: &[&str]) -> AuthDiscoveryResponse {
        AuthDiscoveryResponse {
            api_mode: "standalone".to_string(),
            api_url: "https://api.example".to_string(),
            cli_login_url: "https://api.example/auth/login".to_string(),
            device_start_url: "https://api.example/auth/device/start".to_string(),
            device_poll_url: "https://api.example/auth/device/poll".to_string(),
            auth_methods: methods.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[test]
    fn auth_method_error_allows_legacy_standalone_when_discovery_unavailable() {
        assert!(auth_method_error(None, "email", "log in").is_none());
        assert!(auth_method_error(None, "nostr", "log in").is_none());
    }

    #[test]
    fn auth_method_error_rejects_email_and_nostr_for_device_code_only_target() {
        let d = discovery(&["device_code"]);
        let email = auth_method_error(Some(&d), "email", "log in").unwrap();
        let nostr = auth_method_error(Some(&d), "nostr", "log in").unwrap();
        assert!(email.contains("device-code"));
        assert!(email.contains("enclava login"));
        assert!(nostr.contains("device-code"));
    }

    #[test]
    fn auth_method_error_preserves_email_and_nostr_for_standalone_targets() {
        let d = discovery(&["email", "nostr"]);
        assert!(auth_method_error(Some(&d), "email", "log in").is_none());
        assert!(auth_method_error(Some(&d), "nostr", "log in").is_none());
    }

    #[test]
    fn auth_method_error_allows_advertised_method_and_rejects_others() {
        let d = discovery(&["device_code", "email"]);
        assert!(auth_method_error(Some(&d), "email", "log in").is_none());
        let nostr = auth_method_error(Some(&d), "nostr", "log in").unwrap();
        assert!(nostr.contains("supported methods"));
        assert!(nostr.contains("device_code") && nostr.contains("email"));
    }

    #[test]
    fn auth_discovery_or_legacy_treats_404_and_405_as_unavailable() {
        assert!(
            auth_discovery_or_legacy(Err(ApiError::Api {
                status: 404,
                code: None,
                message: "HTTP 404".to_string(),
            }))
            .unwrap()
            .is_none()
        );
        assert!(
            auth_discovery_or_legacy(Err(ApiError::Api {
                status: 405,
                code: None,
                message: "HTTP 405".to_string(),
            }))
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn auth_discovery_or_legacy_propagates_other_api_errors() {
        assert!(
            auth_discovery_or_legacy(Err(ApiError::Api {
                status: 500,
                code: None,
                message: "HTTP 500".to_string(),
            }))
            .is_err()
        );
    }

    #[test]
    fn auth_discovery_or_legacy_returns_discovery_on_success() {
        let d = discovery(&["email", "nostr"]);
        assert!(auth_discovery_or_legacy(Ok(d)).unwrap().is_some());
    }

    #[test]
    fn accepts_https_device_urls() {
        assert!(browser_safe_device_url(
            "https://api.enclava.dev/device/approve?user_code=ABCD-EFGH"
        ));
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(!browser_safe_device_url("file:///etc/passwd"));
        assert!(!browser_safe_device_url("javascript:alert(1)"));
    }

    #[test]
    fn rejects_cmd_metacharacters() {
        assert!(!browser_safe_device_url("https://evil.example/a&calc.exe"));
        assert!(!browser_safe_device_url("https://evil.example/a%PATH%b"));
        assert!(!browser_safe_device_url("https://evil.example/a|b"));
        assert!(!browser_safe_device_url("https://evil.example/a^b"));
        assert!(!browser_safe_device_url("https://evil.example/a b"));
    }
}
