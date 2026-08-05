use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Global CLI configuration stored at ~/.enclava/config.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Platform API base URL
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// Active organization name (None = personal org)
    pub org: Option<String>,
    /// Active organization UUID, when known from browser/device login.
    #[serde(default)]
    pub org_id: Option<String>,
}

fn default_api_url() -> String {
    "https://api.enclava.dev".to_string()
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            org: None,
            org_id: None,
        }
    }
}

/// Credentials stored at ~/.enclava/credentials.toml
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    /// Active session JWT (from login)
    pub session_token: Option<String>,
    /// Long-lived API key (for CI/programmatic use)
    pub api_key: Option<String>,
    /// Authenticated platform user UUID, when known.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Active organization UUID tied to the saved session, when known.
    #[serde(default)]
    pub active_org_id: Option<String>,
    /// Active organization name tied to the saved session, when known.
    #[serde(default)]
    pub active_org_name: Option<String>,
}

impl Credentials {
    /// Returns the auth token to use for API requests.
    /// Prefers session_token over api_key.
    pub fn auth_token(&self) -> Option<&str> {
        self.session_token.as_deref().or(self.api_key.as_deref())
    }
}

/// Resolved paths for the CLI state directory.
#[derive(Debug, Clone)]
pub struct CliPaths {
    /// Root: ~/.enclava/
    pub root: PathBuf,
    /// ~/.enclava/config.toml
    pub config: PathBuf,
    /// ~/.enclava/credentials.toml
    pub credentials: PathBuf,
    /// ~/.enclava/keys/ (bootstrap keypairs for password-mode apps)
    pub keys_dir: PathBuf,
    /// ~/.enclava/sessions/ (reserved for future session state)
    pub sessions_dir: PathBuf,
    /// ~/.enclava/recovery.seed (random local seed for deterministic deploy keys)
    pub recovery_seed: PathBuf,
}

impl CliPaths {
    /// Resolve paths using the user's home directory.
    pub fn resolve() -> Result<Self, ConfigError> {
        if let Some(root) = std::env::var_os("ENCLAVA_STATE_DIR") {
            return Self::from_root(root.into());
        }
        let home = dirs::home_dir().ok_or(ConfigError::NoHomeDir)?;
        Self::from_root(home.join(".enclava"))
    }

    /// Resolve paths from an explicit root (for testing).
    pub fn from_root(root: PathBuf) -> Result<Self, ConfigError> {
        Ok(Self {
            config: root.join("config.toml"),
            credentials: root.join("credentials.toml"),
            keys_dir: root.join("keys"),
            sessions_dir: root.join("sessions"),
            recovery_seed: root.join("recovery.seed"),
            root,
        })
    }

    /// Ensure the state directory and subdirectories exist.
    pub fn ensure_dirs(&self) -> Result<(), ConfigError> {
        for dir in [&self.root, &self.keys_dir, &self.sessions_dir] {
            std::fs::create_dir_all(dir).map_err(|e| ConfigError::Io {
                path: dir.clone(),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Path to the bootstrap keypair for a password-mode app.
    /// Scoped by org to prevent collisions: ~/.enclava/keys/{org}/{app}.key
    pub fn bootstrap_key_path(&self, org: &str, app: &str) -> PathBuf {
        self.keys_dir.join(org).join(format!("{app}.key"))
    }
}

/// Load config from ~/.enclava/config.toml, returning defaults if the file
/// does not exist.
pub fn load_config(paths: &CliPaths) -> Result<CliConfig, ConfigError> {
    load_toml_or_default(&paths.config)
}

/// Load credentials from ~/.enclava/credentials.toml, returning empty
/// credentials if the file does not exist.
pub fn load_credentials(paths: &CliPaths) -> Result<Credentials, ConfigError> {
    load_toml_or_default(&paths.credentials)
}

/// Save config to ~/.enclava/config.toml.
pub fn save_config(paths: &CliPaths, config: &CliConfig) -> Result<(), ConfigError> {
    save_toml(&paths.config, config)
}

/// Save credentials to ~/.enclava/credentials.toml.
/// The file is created with restricted permissions (owner read/write only).
pub fn save_credentials(paths: &CliPaths, creds: &Credentials) -> Result<(), ConfigError> {
    paths.ensure_dirs()?;
    let content = toml::to_string_pretty(creds).map_err(ConfigError::SerializeToml)?;
    let path = &paths.credentials;

    // Use atomic write to prevent race conditions
    let temp_path = path.with_extension("tmp");

    // Write to temporary file first
    std::fs::write(&temp_path, &content).map_err(|e| ConfigError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    // Set permissions before moving to final location
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&temp_path, perms).map_err(|e| ConfigError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    }

    // Atomic rename to final location
    std::fs::rename(&temp_path, path).map_err(|e| ConfigError::Io {
        path: path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Save a password-mode bootstrap private key with owner-only permissions.
pub fn save_bootstrap_key(
    paths: &CliPaths,
    org: &str,
    app: &str,
    private_key_hex: &str,
) -> Result<PathBuf, ConfigError> {
    paths.ensure_dirs()?;
    let path = paths.bootstrap_key_path(org, app);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let temp_path = path.with_extension("tmp");
    std::fs::write(&temp_path, private_key_hex).map_err(|e| ConfigError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&temp_path, perms).map_err(|e| ConfigError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    }

    std::fs::rename(&temp_path, &path).map_err(|e| ConfigError::Io {
        path: path.clone(),
        source: e,
    })?;

    Ok(path)
}

fn load_toml_or_default<T: Default + serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(content) => toml::from_str(&content).map_err(|e| ConfigError::ParseToml {
            path: path.to_path_buf(),
            source: e,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn save_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let content = toml::to_string_pretty(value).map_err(ConfigError::SerializeToml)?;
    std::fs::write(path, content).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not determine home directory")]
    NoHomeDir,
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    ParseToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("failed to serialize config: {0}")]
    SerializeToml(toml::ser::Error),
}
