use std::fs;

#[test]
fn cli_state_directory_can_be_isolated() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("isolated");
    let paths = enclava_cli::config::CliPaths::from_root(state.clone()).unwrap();
    enclava_cli::config::save_credentials(
        &paths,
        &enclava_cli::config::Credentials {
            session_token: Some("test-session".into()),
            ..Default::default()
        },
    )
    .unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_enclava"))
        .arg("logout")
        .env("ENCLAVA_STATE_DIR", &state)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(
        enclava_cli::config::load_credentials(&paths)
            .unwrap()
            .session_token
            .is_none()
    );
}

#[test]
fn cli_paths_from_explicit_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".enclava");
    let paths = enclava_cli::config::CliPaths::from_root(root.clone()).unwrap();
    assert_eq!(paths.root, root);
    assert_eq!(paths.config, root.join("config.toml"));
    assert_eq!(paths.credentials, root.join("credentials.toml"));
    assert_eq!(paths.keys_dir, root.join("keys"));
    assert_eq!(paths.recovery_seed, root.join("recovery.seed"));
}

#[test]
fn ensure_dirs_creates_structure() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".enclava");
    let paths = enclava_cli::config::CliPaths::from_root(root.clone()).unwrap();
    paths.ensure_dirs().unwrap();
    assert!(root.exists());
    assert!(paths.keys_dir.exists());
    assert!(paths.sessions_dir.exists());
}

#[test]
fn load_missing_config_returns_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = enclava_cli::config::CliPaths::from_root(tmp.path().join(".enclava")).unwrap();
    let config = enclava_cli::config::load_config(&paths).unwrap();
    assert_eq!(config.api_url, "https://api.enclava.dev");
    assert!(config.org.is_none());
    assert!(config.org_id.is_none());
}

#[test]
fn save_and_load_config_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = enclava_cli::config::CliPaths::from_root(tmp.path().join(".enclava")).unwrap();
    let config = enclava_cli::config::CliConfig {
        api_url: "https://custom.api.dev".to_string(),
        org: Some("my-team".to_string()),
        org_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
    };
    enclava_cli::config::save_config(&paths, &config).unwrap();
    let loaded = enclava_cli::config::load_config(&paths).unwrap();
    assert_eq!(loaded.api_url, "https://custom.api.dev");
    assert_eq!(loaded.org.as_deref(), Some("my-team"));
    assert_eq!(
        loaded.org_id.as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
}

#[test]
fn save_and_load_credentials_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = enclava_cli::config::CliPaths::from_root(tmp.path().join(".enclava")).unwrap();
    let creds = enclava_cli::config::Credentials {
        session_token: Some("jwt-abc".to_string()),
        api_key: None,
        user_id: Some("user-1".to_string()),
        active_org_id: Some("org-1".to_string()),
        active_org_name: Some("personal".to_string()),
    };
    enclava_cli::config::save_credentials(&paths, &creds).unwrap();
    let loaded = enclava_cli::config::load_credentials(&paths).unwrap();
    assert_eq!(loaded.session_token.as_deref(), Some("jwt-abc"));
    assert!(loaded.api_key.is_none());
    assert_eq!(loaded.user_id.as_deref(), Some("user-1"));
    assert_eq!(loaded.active_org_id.as_deref(), Some("org-1"));
    assert_eq!(loaded.active_org_name.as_deref(), Some("personal"));
}

#[test]
fn auth_token_prefers_session_over_api_key() {
    let creds = enclava_cli::config::Credentials {
        session_token: Some("session".to_string()),
        api_key: Some("key".to_string()),
        ..Default::default()
    };
    assert_eq!(creds.auth_token(), Some("session"));
}

#[test]
fn auth_token_falls_back_to_api_key() {
    let creds = enclava_cli::config::Credentials {
        session_token: None,
        api_key: Some("key".to_string()),
        ..Default::default()
    };
    assert_eq!(creds.auth_token(), Some("key"));
}

#[test]
fn bootstrap_key_path_is_org_scoped() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = enclava_cli::config::CliPaths::from_root(tmp.path().join(".enclava")).unwrap();
    let key_path = paths.bootstrap_key_path("acme", "my-app");
    assert!(key_path.to_string_lossy().contains("keys/acme/my-app.key"));
}

#[cfg(unix)]
#[test]
fn credentials_file_has_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = enclava_cli::config::CliPaths::from_root(tmp.path().join(".enclava")).unwrap();
    let creds = enclava_cli::config::Credentials {
        session_token: Some("secret".to_string()),
        api_key: None,
        ..Default::default()
    };
    enclava_cli::config::save_credentials(&paths, &creds).unwrap();
    let meta = fs::metadata(&paths.credentials).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "credentials file should be 0600, got {mode:o}");
}
