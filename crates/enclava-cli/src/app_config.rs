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
    #[serde(default)]
    pub egress: EgressSection,
    /// Unrecognised top-level keys, kept only so `validate` can name them.
    #[serde(flatten, skip_serializing)]
    pub unknown: HashMap<String, toml::Value>,
}

/// Outbound network posture for the workload, fixed at `enclava create`.
///
/// `mode = "restricted"` (default) allows only platform endpoints plus the
/// `allowlist` hostnames. `mode = "public_internet"` allows any public IPv4
/// address; private, link-local and metadata ranges stay blocked, and the
/// policy grants no general IPv6 egress.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressSection {
    /// `None` takes the server default (restricted).
    #[serde(default, deserialize_with = "deserialize_egress_mode")]
    pub mode: Option<enclava_engine::types::EgressMode>,
    /// `allow` is accepted as an alias: existing canary files already use it.
    #[serde(default, alias = "allow")]
    pub allowlist: Vec<EgressAllowSection>,
}

/// Parses `mode` at load time so an unusable value can never reach the create
/// request as "unset". An empty string is rejected rather than read as
/// restricted: egress is fixed at create time, so a blank is likely a mistake.
fn deserialize_egress_mode<'de, D>(
    deserializer: D,
) -> Result<Option<enclava_engine::types::EgressMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Err(serde::de::Error::custom(
            "invalid egress_mode \"\"; expected restricted or public_internet",
        ));
    }
    raw.parse().map(Some).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAllowSection {
    pub host: String,
    /// TCP ports; defaults to `[443]` when omitted.
    pub ports: Option<Vec<u16>>,
}

impl EgressSection {
    /// Canonical mode string for the create request, or `None` to take the
    /// server default (restricted).
    pub fn mode_for_request(&self) -> Option<String> {
        self.mode.map(|mode| mode.as_str().to_string())
    }

    /// Allowlist rules for the create request, with omitted ports set to 443
    /// (the server default, made explicit so the request is self-describing).
    pub fn allowlist_for_request(&self) -> Vec<crate::api_types::HostedTemplateEgressRule> {
        self.allowlist
            .iter()
            .map(|rule| crate::api_types::HostedTemplateEgressRule {
                host: rule.host.clone(),
                ports: rule.ports.clone().unwrap_or_else(|| vec![443]),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSection {
    pub name: String,
    pub port: u16,
    #[serde(default)]
    pub command: Vec<String>,
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

pub fn default_storage_paths() -> Vec<String> {
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

        if self.app.command.iter().any(|arg| arg.is_empty()) {
            return Err(AppConfigError::Validation(
                "app command entries cannot be empty".to_string(),
            ));
        }

        // Unknown top-level tables are rejected: egress is fixed at create
        // time, so a misspelled `[egres]` must not silently create a
        // restricted app.
        if let Some(unknown) = self.unknown.keys().min() {
            return Err(AppConfigError::Validation(format!(
                "unknown enclava.toml section or key '{unknown}'; expected one of: \
                 app, storage, unlock, services, resources, health, egress"
            )));
        }

        for rule in &self.egress.allowlist {
            if rule.host.trim().is_empty() || rule.host.trim() != rule.host {
                return Err(AppConfigError::Validation(format!(
                    "[egress] allowlist host {:?} must be a non-empty hostname without surrounding whitespace",
                    rule.host
                )));
            }
            if let Some(ports) = &rule.ports
                && (ports.is_empty() || ports.contains(&0))
            {
                return Err(AppConfigError::Validation(format!(
                    "[egress] allowlist ports for {} must be between 1 and 65535",
                    rule.host
                )));
            }
        }

        Ok(())
    }
}
