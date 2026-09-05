use clap::Args;
use dialoguer::{Input, Password, Select};
use std::process::Command;
use std::time::Duration;

use enclava_cli::api_client::{ApiClient, ApiError, validated_discovered_api_url};
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

const DIRECT_PROVIDERS: &[(&str, &str)] = &[("Email", "email"), ("Nostr (npub)", "nostr")];

fn auth_method_error(
    discovery: Option<&AuthDiscoveryResponse>,
    provider: &str,
    action: &str,
) -> Option<String> {
    let discovery = discovery?;
    if discovery.auth_methods.is_empty() {
        return Some(format!(
            "this target returned no supported {action} methods; check the API URL or contact support"
        ));
    }
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
        Err(e) => Err(Box::new(e)),
    }
}

fn supported_methods(
    discovery: Option<&AuthDiscoveryResponse>,
    action: &str,
) -> Vec<(&'static str, &'static str)> {
    match discovery {
        None => DIRECT_PROVIDERS.to_vec(),
        Some(_) => DIRECT_PROVIDERS
            .iter()
            .copied()
            .filter(|(_, provider)| auth_method_error(discovery, provider, action).is_none())
            .collect(),
    }
}

fn default_uses_device_login(discovery: Option<&AuthDiscoveryResponse>) -> bool {
    discovery.is_none_or(|d| d.auth_methods.iter().any(|method| method == "device_code"))
}

fn auth_api_url(
    configured_api_url: &str,
    discovery: Option<&AuthDiscoveryResponse>,
) -> Result<String, ApiError> {
    let raw = discovery
        .and_then(|value| value.api_url.as_deref())
        .unwrap_or(configured_api_url);
    Ok(validated_discovered_api_url(raw)?
        .trim_end_matches('/')
        .to_string())
}

fn no_supported_method_error(discovery: Option<&AuthDiscoveryResponse>, action: &str) -> String {
    match discovery {
        None => format!("no {action} methods are advertised by this target"),
        Some(d) if d.auth_methods.is_empty() => format!(
            "this target returned no supported {action} methods; check the API URL or contact support"
        ),
        Some(d) if d.auth_methods.len() == 1 && d.auth_methods[0] == "device_code" => {
            if action == "sign up" {
                "this target only supports device-code/browser registration; use `enclava login`"
                    .into()
            } else {
                format!(
                    "this target only supports device-code {action}; use `enclava login` and approve the device code in your browser"
                )
            }
        }
        Some(d) => format!(
            "this target does not support direct {action}; supported methods: {}",
            d.auth_methods.join(", ")
        ),
    }
}

pub async fn signup() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;

    let discovery_client = ApiClient::new(&cli_config.api_url, None);
    let discovery = auth_discovery_or_legacy(discovery_client.auth_discovery().await)?;

    let available = supported_methods(discovery.as_ref(), "sign up");
    if available.is_empty() {
        return Err(no_supported_method_error(discovery.as_ref(), "sign up").into());
    }

    let provider = if available.len() == 1 {
        available[0].1
    } else {
        let labels: Vec<_> = available.iter().map(|(l, _)| *l).collect();
        let selection = Select::new()
            .with_prompt("Sign up with")
            .items(&labels)
            .default(0)
            .interact()?;
        available[selection].1
    };

    if let Some(err) = auth_method_error(discovery.as_ref(), provider, "sign up") {
        return Err(err.into());
    }
    let auth_api_url = auth_api_url(&cli_config.api_url, discovery.as_ref())?;
    let client = ApiClient::new(&auth_api_url, None);

    let req = if provider == "email" {
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
    } else {
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
    };

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
    updated_config.api_url = auth_api_url;
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

    let discovery_client = ApiClient::new(&cli_config.api_url, None);
    let discovery = auth_discovery_or_legacy(discovery_client.auth_discovery().await)?;

    let use_nostr = if !args.email && !args.nostr {
        if default_uses_device_login(discovery.as_ref()) {
            return device_login(args, paths, cli_config, discovery).await;
        }

        let available = supported_methods(discovery.as_ref(), "log in");
        if available.is_empty() {
            return Err(no_supported_method_error(discovery.as_ref(), "log in").into());
        }

        let provider = if available.len() == 1 {
            available[0].1
        } else {
            let labels: Vec<_> = available.iter().map(|(l, _)| *l).collect();
            let selection = Select::new()
                .with_prompt("Log in with")
                .items(&labels)
                .default(0)
                .interact()?;
            available[selection].1
        };

        provider == "nostr"
    } else {
        args.nostr
    };

    let provider = if use_nostr { "nostr" } else { "email" };
    if let Some(err) = auth_method_error(discovery.as_ref(), provider, "log in") {
        return Err(err.into());
    }
    let auth_api_url = auth_api_url(&cli_config.api_url, discovery.as_ref())?;
    let client = ApiClient::new(&auth_api_url, None);

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
        let api_url = client.auth_login_url();
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
    updated_config.api_url = auth_api_url;
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
    discovery: Option<AuthDiscoveryResponse>,
) -> Result<(), Box<dyn std::error::Error>> {
    let authenticated_api_url = auth_api_url(&cli_config.api_url, discovery.as_ref())?;
    let client = ApiClient::new(&authenticated_api_url, None);
    let start_request = DeviceLoginStartRequest {
        org: args.org.clone(),
        requested_org_slug: args.org.clone(),
        requested_scopes: device_login_scopes(args.approve_logs),
    };
    let start = match discovery
        .as_ref()
        .and_then(|d| d.device_start_url.as_deref())
    {
        Some(endpoint_url) => {
            client
                .start_device_login_at(endpoint_url, &start_request)
                .await?
        }
        None => client.start_device_login(&start_request).await?,
    };

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
        let poll_request = DeviceLoginPollRequest {
            device_code: start.device_code.clone(),
        };
        let poll = match discovery
            .as_ref()
            .and_then(|d| d.device_poll_url.as_deref())
        {
            Some(endpoint_url) => {
                client
                    .poll_device_login_at(endpoint_url, &poll_request)
                    .await?
            }
            None => client.poll_device_login(&poll_request).await?,
        };

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

                let mut updated_config = cli_config;
                updated_config.api_url = authenticated_api_url;
                updated_config.org = Some(auth.org_name.clone());
                updated_config.org_id = Some(auth.org_id.clone());

                config::save_credentials(&paths, &creds)?;
                config::save_config(&paths, &updated_config)?;
                let api = ApiClient::from_config(&updated_config, &creds);
                match api.get_current_user().await {
                    Ok(me) => {
                        println!("Logged in as {}", me.display_name);
                        println!("Active org: {}", me.active_org.name);
                    }
                    Err(error) => {
                        println!("Logged in. Active org: {}", auth.org_name);
                        eprintln!("Warning: could not load the current profile: {error}");
                    }
                }
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
        ApiClient, ApiError, AuthDiscoveryResponse, LoginArgs, auth_api_url,
        auth_discovery_or_legacy, auth_method_error, browser_safe_device_url,
        default_uses_device_login, device_login, no_supported_method_error, supported_methods,
    };
    use enclava_cli::config::{self, CliConfig, CliPaths};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn discovery(methods: &[&str]) -> AuthDiscoveryResponse {
        AuthDiscoveryResponse {
            api_mode: Some("standalone".to_string()),
            api_url: Some("https://api.example".to_string()),
            cli_login_url: Some("https://api.example/auth/login".to_string()),
            device_start_url: Some("https://api.example/auth/device/start".to_string()),
            device_poll_url: Some("https://api.example/auth/device/poll".to_string()),
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
    fn auth_method_error_gives_actionable_empty_methods_message() {
        let d = discovery(&[]);
        let err = auth_method_error(Some(&d), "email", "log in").unwrap();
        assert!(err.contains("no supported"));
        assert!(err.contains("check the API URL or contact support"));
    }

    #[test]
    fn auth_discovery_or_legacy_treats_404_and_405_as_unavailable() {
        let discovery = auth_discovery_or_legacy(Err(ApiError::Api {
            status: 404,
            code: None,
            message: "HTTP 404".to_string(),
        }))
        .unwrap();
        assert!(discovery.is_none());

        let discovery = auth_discovery_or_legacy(Err(ApiError::Api {
            status: 405,
            code: None,
            message: "HTTP 405".to_string(),
        }))
        .unwrap();
        assert!(discovery.is_none());
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

    #[tokio::test]
    async fn auth_discovery_or_legacy_returns_transport_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let client = ApiClient::new(&format!("http://{addr}"), None);
        let result = client.auth_discovery().await;
        assert!(auth_discovery_or_legacy(result).is_err());
    }

    #[test]
    fn supported_methods_returns_all_when_discovery_unavailable() {
        let methods = supported_methods(None, "sign up");
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn supported_methods_filters_to_advertised_choices() {
        let d = discovery(&["device_code", "email"]);
        let methods = supported_methods(Some(&d), "sign up");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].1, "email");
    }

    #[test]
    fn supported_methods_returns_empty_for_device_code_only() {
        let d = discovery(&["device_code"]);
        let methods = supported_methods(Some(&d), "sign up");
        assert!(methods.is_empty());
    }

    #[test]
    fn default_login_uses_device_flow_only_when_legacy_or_advertised() {
        assert!(default_uses_device_login(None));
        assert!(default_uses_device_login(Some(&discovery(&[
            "email",
            "device_code"
        ]))));
        assert!(!default_uses_device_login(Some(&discovery(&["email"]))));
        assert!(!default_uses_device_login(Some(&discovery(&[]))));
    }

    #[test]
    fn auth_api_url_prefers_and_validates_discovery() {
        let mut d = discovery(&["email"]);
        d.api_url = Some("https://split-api.example/v1/".to_string());
        let api_url = auth_api_url("https://frontend.example", Some(&d)).unwrap();
        assert_eq!(api_url, "https://split-api.example/v1");
        assert_eq!(
            ApiClient::new(&api_url, None).auth_login_url(),
            "https://split-api.example/v1/auth/login"
        );

        d.api_url = Some("http://split-api.example".to_string());
        assert!(auth_api_url("https://frontend.example", Some(&d)).is_err());
        assert_eq!(
            auth_api_url("https://legacy.example/", None).unwrap(),
            "https://legacy.example"
        );
    }

    #[tokio::test]
    async fn approved_device_session_survives_profile_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let responses = [
                (
                    "201 Created",
                    r#"{"device_code":"device-secret","user_code":"ABCD-EFGH","verification_uri":"https://auth.example/cli/login","verification_uri_complete":"https://auth.example/cli/login?user_code=ABCD-EFGH","expires_in":600,"interval":1}"#,
                ),
                (
                    "200 OK",
                    r#"{"status":"approved","interval":1,"expires_in":599,"error":null,"auth":{"token":"redeemed-token","user_id":"user-id","org_id":"org-id","org_name":"example-org"}}"#,
                ),
                ("503 Service Unavailable", r#"{"message":"retry later"}"#),
            ];
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
            }
            requests
        });

        let temp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(temp.path().join("state")).unwrap();
        let configured = CliConfig {
            api_url: "http://127.0.0.1:9".to_string(),
            org: None,
            org_id: None,
        };
        let base = format!("http://{addr}");
        let discovery = AuthDiscoveryResponse {
            api_mode: Some("hosted".to_string()),
            api_url: Some(base.clone()),
            cli_login_url: None,
            device_start_url: Some(format!("{base}/remote/device/start")),
            device_poll_url: Some(format!("{base}/remote/device/poll")),
            auth_methods: vec!["device_code".to_string()],
        };

        device_login(
            LoginArgs {
                no_browser: true,
                api_url: None,
                org: None,
                approve_logs: false,
                nostr: false,
                email: false,
            },
            paths.clone(),
            configured,
            Some(discovery),
        )
        .await
        .unwrap();

        let saved_credentials = config::load_credentials(&paths).unwrap();
        assert_eq!(
            saved_credentials.session_token.as_deref(),
            Some("redeemed-token")
        );
        assert_eq!(config::load_config(&paths).unwrap().api_url, base);
        let requests = handle.join().unwrap();
        assert!(requests[0].starts_with("POST /remote/device/start "));
        assert!(requests[1].starts_with("POST /remote/device/poll "));
        assert!(requests[2].starts_with("GET /users/me "));
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("authorization: bearer redeemed-token")
        );
    }

    #[test]
    fn no_supported_method_error_is_actionable_for_empty_auth_methods() {
        let d = discovery(&[]);
        let err = no_supported_method_error(Some(&d), "log in");
        assert!(err.contains("no supported"));
        assert!(err.contains("check the API URL or contact support"));
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
