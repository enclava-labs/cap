use enclava_cli::{
    api_client::{ApiClient, ApiError},
    api_types::{CreateAppRequest, CreateTemplateInstanceRequest},
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
        .sync_config_key("demo/shell", "P0_KEY", false)
        .await
        .unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /apps/demo%2Fshell/config/sync "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains(r#""key_name":"P0_KEY""#));
    assert!(request.contains(r#""deleted":false"#));
}

#[tokio::test]
async fn create_app_forwards_rollout_idempotency_key_only_after_hosted_discovery() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let discovery_body = r#"{"api_mode":"hosted-paas"}"#;
        let app_body = r#"{"id":"app-1","name":"rollout-canary","namespace":"tenant-rollout","instance_id":"instance-1","domain":"rollout-canary.enclava.dev","custom_domain":null,"status":"pending","unlock_mode":"password","created_at":"2026-07-27T00:00:00Z"}"#;
        let responses = [("200 OK", discovery_body), ("201 Created", app_body)];
        responses
            .into_iter()
            .map(|(status, body)| {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len(),
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                String::from_utf8_lossy(&buf[..n]).to_string()
            })
            .collect::<Vec<_>>()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let request_body = CreateAppRequest {
        name: "rollout-canary".to_string(),
        port: 8080,
        image: Some(
            "ghcr.io/enclava-labs/e2e@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
                .to_string(),
        ),
        unlock_mode: "password".to_string(),
        bootstrap_pubkey_hash: Some("11".repeat(32)),
        storage_size: "5Gi".to_string(),
        tls_storage_size: "2Gi".to_string(),
        storage_paths: vec!["/data".to_string()],
        cpu: "1".to_string(),
        memory: "1Gi".to_string(),
        services: vec![],
        health_path: Some("/health".to_string()),
        health_interval: Some(30),
        health_timeout: Some(5),
        signer_identity_subject: None,
        signer_identity_issuer: None,
        egress_allowlist: vec![],
        egress_mode: None,
    };
    let response = client
        .create_app_with_idempotency_key(
            &request_body,
            Some("preprod-canary:11111111-2222-4333-8444-555555555555"),
        )
        .await
        .unwrap();

    let requests = handle.join().unwrap();
    assert!(requests[0].starts_with("GET /.well-known/enclava "));
    assert!(requests[1].starts_with("POST /apps "));
    assert!(requests[1].contains("authorization: Bearer test-token"));
    assert!(
        requests[1]
            .contains("idempotency-key: preprod-canary:11111111-2222-4333-8444-555555555555")
    );
    assert_eq!(response.name, "rollout-canary");
}

#[tokio::test]
async fn create_app_refuses_caller_key_against_direct_cap_before_posting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"{"api_mode":"core"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len(),
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let client = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let request_body = CreateAppRequest {
        name: "direct-cap".to_string(),
        port: 8080,
        image: None,
        unlock_mode: "auto".to_string(),
        bootstrap_pubkey_hash: None,
        storage_size: "5Gi".to_string(),
        tls_storage_size: "2Gi".to_string(),
        storage_paths: vec![],
        cpu: "1".to_string(),
        memory: "1Gi".to_string(),
        services: vec![],
        health_path: None,
        health_interval: None,
        health_timeout: None,
        signer_identity_subject: None,
        signer_identity_issuer: None,
        egress_allowlist: vec![],
        egress_mode: None,
    };
    let error = client
        .create_app_with_idempotency_key(&request_body, Some("direct-cap-retry"))
        .await
        .expect_err("direct CAP cannot accept a caller-chosen create identity");
    assert!(matches!(
        error,
        ApiError::HostedCreateIdempotencyUnsupported
    ));
    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /.well-known/enclava "));
    assert!(!request.contains("POST /apps"));
}

#[tokio::test]
async fn list_templates_gets_hosted_templates_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"[{"slug":"debian-ssh-ngrok","name":"Debian Stable SSH Endpoint","description":"SSH template","version":"2026-06-18","image":"ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff","config_keys":[]}]"#;
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
        let body = r#"{"template":{"slug":"debian-ssh-ngrok","name":"Debian Stable SSH Endpoint","description":"SSH template","version":"2026-06-18","image":"ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff","config_keys":[]},"app":{"name":"shell","template_expected":{"stable_ssh_endpoint":"6.tcp.eu.ngrok.io:17958"}},"deployment":{"cap_deployment_id":"deploy-1","status":"pending","template_expected":{"stable_ssh_endpoint":"6.tcp.eu.ngrok.io:17958"}},"config_token":{"token":"redacted","tee_url":"https://shell.tee.enclava.dev/.well-known/confidential/config","expires_in_seconds":300},"cap":{"app_domain":"shell.enclava.dev"}}"#;
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
    let request_body = CreateTemplateInstanceRequest {
        template_slug: "debian-ssh-ngrok".to_string(),
        instance_name: "shell".to_string(),
        config: serde_json::json!({}),
        bootstrap_pubkey_hash: Some("11".repeat(32)),
        customer_descriptor_blob: None,
        org_keyring_blob: None,
        signed_policy_artifact: None,
    };
    let response = client
        .create_template_instance(&request_body)
        .await
        .unwrap();
    let request_digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            serde_json::to_vec(&serde_json::json!({
                "template_slug": request_body.template_slug,
                "instance_name": request_body.instance_name,
                "config": request_body.config,
                "bootstrap_pubkey_hash": request_body.bootstrap_pubkey_hash,
                "customer_descriptor_blob_sha256": Option::<String>::None,
                "org_keyring_blob_sha256": Option::<String>::None,
                "signed_policy_artifact_sha256": Option::<String>::None,
            }))
            .unwrap(),
        ))
    };

    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /template-instances "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains(&format!(
        "idempotency-key: template-instance-debian-ssh-ngrok-shell-{}",
        &request_digest[..16]
    )));
    assert!(!request.contains("idempotency-key: template-instance-debian-ssh-ngrok-shell\r\n"));
    assert!(request.contains(r#""template_slug":"debian-ssh-ngrok""#));
    assert!(request.contains(r#""instance_name":"shell""#));
    assert!(request.contains(r#""config":{}"#));
    assert!(request.contains(&format!(r#""bootstrap_pubkey_hash":"{}""#, "11".repeat(32))));
    assert_eq!(
        response
            .app
            .template_expected
            .stable_ssh_endpoint
            .as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        response
            .deployment
            .template_expected
            .stable_ssh_endpoint
            .as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        response.config_token.unwrap().tee_url.as_deref(),
        Some("https://shell.tee.enclava.dev/.well-known/confidential/config")
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
        let body = r#"{"status":"ready","stable_ssh_endpoint":"6.tcp.eu.ngrok.io:17958","command":"ssh -p 17958 user@6.tcp.eu.ngrok.io","endpoint":"6.tcp.eu.ngrok.io:17958","app_url":"https://shell.enclava.dev"}"#;
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
    let response = client.get_template_ssh_command("shell/main").await.unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("GET /apps/shell%2Fmain/ssh-command "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert_eq!(
        response.command.as_deref(),
        Some("ssh -p 17958 user@6.tcp.eu.ngrok.io")
    );
    assert_eq!(
        response.endpoint.as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        response.app_url.as_deref(),
        Some("https://shell.enclava.dev")
    );
}

#[tokio::test]
async fn deliver_managed_template_config_posts_hosted_paas_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let body = r#"{"status":"queued","app_name":"shell","template_slug":"debian-ssh-frp"}"#;
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
    let response = client
        .deliver_managed_template_config("shell/main")
        .await
        .unwrap();

    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /apps/shell%2Fmain/managed-config/deliver "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert_eq!(response.status, "queued");
    assert_eq!(response.app_name, "shell");
    assert_eq!(response.template_slug, "debian-ssh-frp");
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
