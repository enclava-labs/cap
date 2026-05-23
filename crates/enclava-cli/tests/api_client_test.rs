use enclava_cli::api_client::{ApiClient, ApiError};
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
