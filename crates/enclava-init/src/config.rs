//! enclava-init configuration loaded from `/etc/enclava-init/config.toml`.
//!
//! The ConfigMap that backs this file is generated alongside the StatefulSet
//! by `enclava-engine::manifest::enclava_init_config`. Two LUKS volumes are
//! always opened: the durable app/state device and the disposable tls-state
//! device used by Caddy.

use serde::Deserialize;
use std::path::Path;

use crate::errors::{InitError, Result};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Autounlock,
    Password,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VolumeConfig {
    pub device: String,
    pub mapping_name: String,
    pub mount_path: String,
    pub hkdf_info: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct AppBindMountConfig {
    pub subdir: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub mode: Mode,
    pub state: VolumeConfig,
    pub tls_state: VolumeConfig,

    #[serde(default = "default_unlock_socket")]
    pub unlock_socket: String,

    #[serde(default = "default_state_root")]
    pub state_root: String,

    #[serde(default = "default_attempts_path")]
    pub attempts_path: String,

    #[serde(default = "default_app_uid")]
    pub app_uid: u32,

    #[serde(default = "default_app_gid")]
    pub app_gid: u32,

    #[serde(default)]
    pub managed_config_gid: Option<u32>,

    #[serde(default)]
    pub managed_config_dir_mode: Option<u32>,

    #[serde(default = "default_caddy_uid")]
    pub caddy_uid: u32,

    #[serde(default = "default_caddy_gid")]
    pub caddy_gid: u32,

    #[serde(default)]
    pub app_bind_mounts: Vec<AppBindMountConfig>,

    #[serde(default)]
    pub kbs_url: Option<String>,

    #[serde(default)]
    pub kbs_resource_path: Option<String>,

    #[serde(default)]
    pub argon2_salt_hex: Option<String>,

    #[serde(default)]
    pub trustee_policy_read_available: bool,

    #[serde(default)]
    pub workload_artifacts_url: Option<String>,

    #[serde(default)]
    pub workload_artifacts_ca_cert_pem: Option<String>,

    #[serde(default)]
    pub tls_certificate_broker_url: Option<String>,

    #[serde(default)]
    pub tls_certificate_hostnames: Vec<String>,

    #[serde(default)]
    pub trustee_policy_url: Option<String>,

    #[serde(default = "default_kbs_attestation_token_url")]
    pub kbs_attestation_token_url: String,

    #[serde(default)]
    pub cc_init_data_path: Option<String>,

    #[serde(default)]
    pub platform_trustee_policy_pubkey_hex: Option<String>,

    #[serde(default)]
    pub signing_service_pubkey_hex: Option<String>,

    #[serde(default)]
    pub signing_service_trusted_pubkeys_json: Option<String>,
}

fn default_unlock_socket() -> String {
    "/run/enclava/unlock.sock".to_string()
}

fn default_state_root() -> String {
    "/state".to_string()
}

fn default_attempts_path() -> String {
    "/run/enclava/unlock-attempts".to_string()
}

fn default_app_uid() -> u32 {
    10001
}

fn default_app_gid() -> u32 {
    10001
}

fn default_caddy_uid() -> u32 {
    10002
}

fn default_caddy_gid() -> u32 {
    10002
}

fn default_kbs_attestation_token_url() -> String {
    "http://127.0.0.1:8006/aa/token?token_type=kbs".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| InitError::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_minimal_autounlock_config() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            r#"
mode = "autounlock"
kbs-url = "http://kbs"
kbs-resource-path = "default/x/wrap-owner"

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#,
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.mode, Mode::Autounlock);
        assert_eq!(c.state.device, "/dev/csi0");
        assert_eq!(c.tls_state.device, "/dev/csi1");
        assert_eq!(c.app_uid, 10001);
        assert_eq!(c.caddy_uid, 10002);
        assert_eq!(
            c.kbs_attestation_token_url,
            "http://127.0.0.1:8006/aa/token?token_type=kbs"
        );
        assert!(c.tls_certificate_broker_url.is_none());
        assert!(c.tls_certificate_hostnames.is_empty());
        assert!(c.app_bind_mounts.is_empty());
    }

    #[test]
    fn parses_tls_certificate_broker_config() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            r#"
mode = "autounlock"
kbs-url = "http://kbs"
kbs-resource-path = "default/x/wrap-owner"
tls-certificate-broker-url = "http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
tls-certificate-hostnames = ["app.example.test"]

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#,
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(
            c.tls_certificate_broker_url.as_deref(),
            Some("http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate")
        );
        assert_eq!(c.tls_certificate_hostnames, vec!["app.example.test"]);
    }

    #[test]
    fn parses_ownership_and_bind_mounts() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            r#"
mode = "autounlock"
app-uid = 20001
app-gid = 20002
caddy-uid = 20003
caddy-gid = 20004
kbs-url = "http://kbs"
kbs-resource-path = "default/x/wrap-owner"

[[app-bind-mounts]]
subdir = "app-data"
mount-path = "/app/data"

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#,
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.app_uid, 20001);
        assert_eq!(c.app_gid, 20002);
        assert_eq!(c.caddy_uid, 20003);
        assert_eq!(c.caddy_gid, 20004);
        assert_eq!(
            c.app_bind_mounts,
            vec![AppBindMountConfig {
                subdir: "app-data".to_string(),
                mount_path: "/app/data".to_string(),
            }]
        );
    }
}
