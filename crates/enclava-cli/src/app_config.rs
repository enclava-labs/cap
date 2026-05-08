use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Parsed `enclava.toml` -- the developer-facing app configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub app: AppSection,
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub unlock: UnlockSection,
    #[serde(default)]
    pub services: HashMap<String, ServiceSection>,
    #[serde(default)]
    pub resources: ResourcesSection,
    pub health: Option<HealthSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSection {
    pub name: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSection {
    #[serde(default = "default_storage_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_storage_size")]
    pub size: String,
    #[serde(default = "default_tls_size")]
    pub tls_size: String,
}

fn default_storage_paths() -> Vec<String> {
    vec!["/data".to_string()]
}

fn default_storage_size() -> String {
    "5Gi".to_string()
}

fn default_tls_size() -> String {
    "2Gi".to_string()
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            paths: default_storage_paths(),
            size: default_storage_size(),
            tls_size: default_tls_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockSection {
    #[serde(default = "default_unlock_mode")]
    pub mode: String,
}

fn default_unlock_mode() -> String {
    "password".to_string()
}

impl Default for UnlockSection {
    fn default() -> Self {
        Self {
            mode: default_unlock_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSection {
    pub image: String,
    pub port: Option<u16>,
    pub storage_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesSection {
    #[serde(default = "default_cpu")]
    pub cpu: String,
    #[serde(default = "default_memory")]
    pub memory: String,
}

fn default_cpu() -> String {
    "1".to_string()
}

fn default_memory() -> String {
    "1Gi".to_string()
}

impl Default for ResourcesSection {
    fn default() -> Self {
        Self {
            cpu: default_cpu(),
            memory: default_memory(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSection {
    pub path: String,
    #[serde(default = "default_health_interval")]
    pub interval: u32,
    #[serde(default = "default_health_timeout")]
    pub timeout: u32,
}

fn default_health_interval() -> u32 {
    30
}

fn default_health_timeout() -> u32 {
    5
}

#[derive(Debug, thiserror::Error)]
pub enum AppConfigError {
    #[error("failed to read enclava.toml at {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse enclava.toml: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("validation error: {0}")]
    Validation(String),
}

impl AppConfig {
    /// Parse an `AppConfig` from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, AppConfigError> {
        let config: Self = toml::from_str(toml_str)?;
        config.validate()?;
        Ok(config)
    }

    /// Load and parse `enclava.toml` from the given path.
    pub fn load(path: &Path) -> Result<Self, AppConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| AppConfigError::ReadFile {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::parse(&content)
    }

    /// Find and load `enclava.toml` from the current directory.
    pub fn find_and_load() -> Result<Self, AppConfigError> {
        let cwd = std::env::current_dir().map_err(|e| AppConfigError::ReadFile {
            path: ".".to_string(),
            source: e,
        })?;
        Self::load(&cwd.join("enclava.toml"))
    }

    fn validate(&self) -> Result<(), AppConfigError> {
        if self.app.name.is_empty() {
            return Err(AppConfigError::Validation(
                "app name cannot be empty".to_string(),
            ));
        }

        let name_valid = self
            .app
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && self
                .app
                .name
                .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit());

        if !name_valid {
            return Err(AppConfigError::Validation(format!(
                "app name '{}' must be lowercase alphanumeric with hyphens",
                self.app.name
            )));
        }

        match self.unlock.mode.as_str() {
            "auto" | "password" => {}
            other => {
                return Err(AppConfigError::Validation(format!(
                    "unlock mode must be 'auto' or 'password', got '{other}'"
                )));
            }
        }

        Ok(())
    }
}
