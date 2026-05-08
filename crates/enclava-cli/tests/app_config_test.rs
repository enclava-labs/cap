#[test]
fn parse_minimal_toml() {
    let toml_str = r#"
[app]
name = "my-api"
port = 8080
"#;
    let config = enclava_cli::app_config::AppConfig::parse(toml_str).unwrap();
    assert_eq!(config.app.name, "my-api");
    assert_eq!(config.app.port, 8080);
    // Defaults
    assert_eq!(config.storage.paths, vec!["/data"]);
    assert_eq!(config.storage.size, "5Gi");
    assert_eq!(config.storage.tls_size, "2Gi");
    assert_eq!(config.unlock.mode, "password");
    assert!(config.services.is_empty());
    assert_eq!(config.resources.cpu, "1");
    assert_eq!(config.resources.memory, "1Gi");
    assert!(config.health.is_none());
}

#[test]
fn parse_full_toml() {
    let toml_str = r#"
[app]
name = "my-saas"
port = 3000

[storage]
paths = ["/app/data", "/app/uploads"]
size = "10Gi"
tls_size = "4Gi"

[unlock]
mode = "password"

[services.redis]
image = "redis:7-alpine"
port = 6379

[services.postgres]
image = "postgres:16-alpine"
port = 5432
storage_paths = ["/var/lib/postgresql/data"]

[resources]
cpu = "2"
memory = "4Gi"

[health]
path = "/health"
interval = 30
timeout = 5
"#;
    let config = enclava_cli::app_config::AppConfig::parse(toml_str).unwrap();
    assert_eq!(config.app.name, "my-saas");
    assert_eq!(config.app.port, 3000);
    assert_eq!(config.storage.paths, vec!["/app/data", "/app/uploads"]);
    assert_eq!(config.storage.size, "10Gi");
    assert_eq!(config.storage.tls_size, "4Gi");
    assert_eq!(config.unlock.mode, "password");
    assert_eq!(config.services.len(), 2);
    assert_eq!(config.services["redis"].image, "redis:7-alpine");
    assert_eq!(config.services["redis"].port, Some(6379));
    assert_eq!(
        config.services["postgres"].storage_paths,
        Some(vec!["/var/lib/postgresql/data".to_string()])
    );
    assert_eq!(config.resources.cpu, "2");
    assert_eq!(config.resources.memory, "4Gi");
    let health = config.health.as_ref().unwrap();
    assert_eq!(health.path, "/health");
    assert_eq!(health.interval, 30);
    assert_eq!(health.timeout, 5);
}

#[test]
fn parse_rejects_empty_name() {
    let toml_str = r#"
[app]
name = ""
port = 3000
"#;
    let err = enclava_cli::app_config::AppConfig::parse(toml_str).unwrap_err();
    assert!(err.to_string().contains("name"));
}

#[test]
fn parse_rejects_invalid_unlock_mode() {
    let toml_str = r#"
[app]
name = "test"
port = 3000

[unlock]
mode = "magic"
"#;
    let err = enclava_cli::app_config::AppConfig::parse(toml_str).unwrap_err();
    assert!(err.to_string().contains("unlock"));
}

#[test]
fn load_from_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("enclava.toml");
    std::fs::write(
        &path,
        r#"
[app]
name = "file-test"
port = 9090
"#,
    )
    .unwrap();
    let config = enclava_cli::app_config::AppConfig::load(&path).unwrap();
    assert_eq!(config.app.name, "file-test");
    assert_eq!(config.app.port, 9090);
}

#[test]
fn load_missing_file_returns_error() {
    let path = std::path::PathBuf::from("/nonexistent/enclava.toml");
    let err = enclava_cli::app_config::AppConfig::load(&path).unwrap_err();
    assert!(err.to_string().contains("enclava.toml"));
}
