#[test]
fn init_generates_valid_toml() {
    // The generated TOML should parse successfully
    let toml_str = r#"
[app]
name = "test-app"
port = 3000

[storage]
paths = ["/data"]
size = "5Gi"

[unlock]
mode = "password"

[resources]
cpu = "1"
memory = "1Gi"

[health]
path = "/health"
interval = 30
timeout = 5
"#;
    let config = enclava_cli::app_config::AppConfig::parse(toml_str).unwrap();
    assert_eq!(config.app.name, "test-app");
}
