use enclava_common::validate::validate_http_path;
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
    pub egress: EgressSection,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressSection {
    #[serde(default)]
    pub allow: Vec<EgressRuleConfig>,
}

impl EgressSection {
    pub fn to_engine_rules(&self) -> Vec<enclava_engine::types::EgressRule> {
        self.allow
            .iter()
            .map(|rule| enclava_engine::types::EgressRule {
                host: rule.host.clone(),
                ports: rule.ports.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRuleConfig {
    pub host: String,
    #[serde(default = "default_egress_ports")]
    pub ports: Vec<u16>,
}

fn default_egress_ports() -> Vec<u16> {
    vec![443]
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

        for rule in &self.egress.allow {
            validate_egress_rule(rule)?;
        }
        if let Some(health) = &self.health {
            validate_http_path(&health.path)
                .map_err(|e| AppConfigError::Validation(e.to_string()))?;
            if !(1..=300).contains(&health.interval) {
                return Err(AppConfigError::Validation(
                    "health interval must be between 1 and 300 seconds".to_string(),
                ));
            }
            if !(1..=60).contains(&health.timeout) {
                return Err(AppConfigError::Validation(
                    "health timeout must be between 1 and 60 seconds".to_string(),
                ));
            }
            if health.timeout > health.interval {
                return Err(AppConfigError::Validation(
                    "health timeout must be less than or equal to health interval".to_string(),
                ));
            }
        }

        Ok(())
    }
}

fn validate_egress_rule(rule: &EgressRuleConfig) -> Result<(), AppConfigError> {
    let host = rule.host.trim();
    if host.is_empty() {
        return Err(AppConfigError::Validation(
            "egress host cannot be empty".to_string(),
        ));
    }
    if host != rule.host {
        return Err(AppConfigError::Validation(format!(
            "egress host '{}' cannot contain surrounding whitespace",
            rule.host
        )));
    }
    if host.contains("://") || host.contains('/') || host.contains(':') || host.contains('*') {
        return Err(AppConfigError::Validation(format!(
            "egress host '{host}' must be a hostname, not a URL, wildcard, or host:port"
        )));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(AppConfigError::Validation(format!(
            "egress host '{host}' must be a DNS hostname"
        )));
    }
    if !host.contains('.') || !host.split('.').all(valid_dns_label) {
        return Err(AppConfigError::Validation(format!(
            "egress host '{host}' must be a valid DNS hostname"
        )));
    }
    if rule.ports.is_empty() {
        return Err(AppConfigError::Validation(format!(
            "egress ports cannot be empty for host '{host}'"
        )));
    }
    if rule.ports.contains(&0) {
        return Err(AppConfigError::Validation(format!(
            "egress ports must be between 1 and 65535 for host '{host}'"
        )));
    }
    Ok(())
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        && label
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && label
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_egress_allowlist_rules() {
        let config = AppConfig::parse(
            r#"
[app]
name = "tee-router"
port = 8000
command = ["/usr/local/bin/app"]

[egress]
allow = [
  { host = "inference.tinfoil.sh", ports = [443] },
  { host = "rekor.sigstore.dev" }
]
"#,
        )
        .unwrap();

        assert_eq!(config.egress.allow.len(), 2);
        assert_eq!(config.egress.allow[0].host, "inference.tinfoil.sh");
        assert_eq!(config.egress.allow[0].ports, vec![443]);
        assert_eq!(config.egress.allow[1].host, "rekor.sigstore.dev");
        assert_eq!(config.egress.allow[1].ports, vec![443]);
    }

    #[test]
    fn rejects_empty_egress_host() {
        let err = AppConfig::parse(
            r#"
[app]
name = "tee-router"
port = 8000

[egress]
allow = [{ host = "", ports = [443] }]
"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("egress host cannot be empty"),
            "{err}"
        );
    }

    #[test]
    fn rejects_empty_egress_ports() {
        let err = AppConfig::parse(
            r#"
[app]
name = "tee-router"
port = 8000

[egress]
allow = [{ host = "inference.tinfoil.sh", ports = [] }]
"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("egress ports cannot be empty"),
            "{err}"
        );
    }
}
