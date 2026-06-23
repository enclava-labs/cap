use enclava_cli::{
    api_client::{ApiClient, ApiError},
    api_types::CreateTemplateInstanceRequest,
};
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn client_without_auth_returns_not_authenticated() {
    let client = ApiClient::new("https://api.enclava.dev", None);
    // Verify construction works without auth token.
    let _ = client;
}

#[test]
fn client_with_auth_constructs() {
    let client = ApiClient::new("https://api.enclava.dev", Some("test-token".to_string()));
    let _ = client;
}

#[test]
fn client_from_config() {
    let config = enclava_cli::config::CliConfig {
        api_url: "https://custom.api.dev".to_string(),
        org: None,
        org_id: None,
    };
    let creds = enclava_cli::config::Credentials {
        session_token: Some("jwt-test".to_string()),
        api_key: None,
        ..Default::default()
    };
    let client = ApiClient::from_config(&config, &creds);
    let _ = client;
}

#[test]
fn api_error_display() {
    let err = ApiError::Api {
        status: 404,
        code: None,
        message: "app not found".to_string(),
    };
    assert!(err.to_string().contains("404"));
    assert!(err.to_string().contains("app not found"));
}

#[test]
fn not_authenticated_error_display() {
    let err = ApiError::NotAuthenticated;
    assert!(err.to_string().contains("login"));
}

#[tokio::test]
async fn sync_config_key_posts_metadata_callback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    client
        .sync_config_key("demo", "P0_KEY", false)
        .await
        .unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /apps/demo/config/sync "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains(r#""key_name":"P0_KEY""#));
    assert!(request.contains(r#""deleted":false"#));
}

#[tokio::test]
async fn list_templates_gets_hosted_templates_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"[{"slug":"debian-ssh-ngrok","name":"Debian SSH over ngrok","description":"SSH template","version":"2026-06-18","image":"ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_keys":[]}]"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let templates = client.list_templates().await.unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /templates "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert_eq!(templates[0].slug, "debian-ssh-ngrok");
}

#[tokio::test]
async fn create_template_instance_posts_hosted_route_with_idempotency_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"{"template":{"slug":"debian-ssh-ngrok","name":"Debian SSH over ngrok","description":"SSH template","version":"2026-06-18","image":"ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_keys":[]},"app":{"name":"shell"},"deployment":{"cap_deployment_id":"deploy-1","status":"pending"},"config_token":{"token":"redacted","tee_url":"https://shell.tee.example/.well-known/confidential/config","expires_in_seconds":300},"cap":{"app_domain":"shell.example"}}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let response = client
        .create_template_instance(&CreateTemplateInstanceRequest {
            template_slug: "debian-ssh-ngrok".to_string(),
            instance_name: "shell".to_string(),
            config: serde_json::json!({}),
        })
        .await
        .unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /template-instances "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains("idempotency-key: template-instance-debian-ssh-ngrok-shell"));
    assert!(request.contains(r#""template_slug":"debian-ssh-ngrok""#));
    assert!(request.contains(r#""instance_name":"shell""#));
    assert!(request.contains(r#""config":{}"#));
    assert_eq!(
        response.config_token.unwrap().tee_url.as_deref(),
        Some("https://shell.tee.example/.well-known/confidential/config")
    );
}

#[tokio::test]
async fn get_template_ssh_command_uses_hosted_paas_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"{"status":"ready","command":"ssh -p 17958 user@6.tcp.eu.ngrok.io","app_url":"https://shell.example.test"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let response = client.get_template_ssh_command("shell").await.unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /apps/shell/ssh-command "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert_eq!(
        response.command.as_deref(),
        Some("ssh -p 17958 user@6.tcp.eu.ngrok.io")
    );
    assert_eq!(
        response.app_url.as_deref(),
        Some("https://shell.example.test")
    );
}

#[tokio::test]
async fn api_errors_preserve_paas_error_code() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"{"code":"cap_response_invalid","message":"CAP app response included an invalid app domain"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let err = client.get_template_ssh_command("shell").await.unwrap_err();

    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /apps/shell/ssh-command "));
    match err {
        ApiError::Api {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 502);
            assert_eq!(code.as_deref(), Some("cap_response_invalid"));
            assert!(message.contains("CAP app response included an invalid app domain"));
        }
        other => panic!("unexpected error: {other}"),
    }
}
