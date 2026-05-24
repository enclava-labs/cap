use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::{trustee_verify, writes};

pub const CERT_RELATIVE_PATH: &str = "certificates/tls.crt";
pub const KEY_RELATIVE_PATH: &str = "certificates/tls.key";

#[derive(Debug, Serialize)]
struct CertificateRequest<'a> {
    hostnames: &'a [String],
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

pub fn provision_static_tls_certificate(cfg: &Config, persistent_root: &Path) -> Result<()> {
    let Some(broker_url) = cfg.tls_certificate_broker_url.as_deref() else {
        return Ok(());
    };
    if cfg.tls_certificate_hostnames.is_empty() {
        return Err(anyhow!(
            "tls-certificate-broker-url requires tls-certificate-hostnames"
        ));
    }

    let cert_path = cert_path(persistent_root);
    let key_path = key_path(persistent_root);
    if cert_path.is_file() && key_path.is_file() {
        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "static TLS certificate already present; skipping issuance"
        );
        return Ok(());
    }

    let key_pair = load_or_generate_key(&key_path)?;
    let csr_der = build_csr_der(&cfg.tls_certificate_hostnames, &key_pair)?;
    let token = trustee_verify::resolve_kbs_attestation_token(
        std::env::var("KBS_ATTESTATION_TOKEN").ok().as_deref(),
        &cfg.kbs_attestation_token_url,
        Duration::from_secs(15),
    )
    .context("resolving KBS attestation token for TLS certificate broker")?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .context("building TLS certificate broker client")?;
    let request = CertificateRequest {
        hostnames: &cfg.tls_certificate_hostnames,
        csr_der_base64: base64::engine::general_purpose::STANDARD.encode(csr_der),
        cc_init_data_hash: local_cc_init_data_hash(cfg)?,
    };
    let response = client
        .post(broker_url)
        .header("Authorization", format!("Attestation {token}"))
        .json(&request)
        .send()
        .with_context(|| format!("requesting TLS certificate from {broker_url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "TLS certificate broker returned HTTP {status}: {body}"
        ));
    }
    let body: CertificateResponse = response
        .json()
        .context("decoding TLS certificate broker response")?;
    if !body
        .certificate_chain_pem
        .contains("-----BEGIN CERTIFICATE-----")
    {
        return Err(anyhow!(
            "TLS certificate broker returned no PEM certificate"
        ));
    }
    writes::atomic_write(&cert_path, body.certificate_chain_pem.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(())
}

pub fn cert_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(CERT_RELATIVE_PATH)
}

pub fn key_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(KEY_RELATIVE_PATH)
}

fn load_or_generate_key(path: &Path) -> Result<KeyPair> {
    if path.is_file() {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading TLS private key {}", path.display()))?;
        return KeyPair::from_pem(&pem)
            .with_context(|| format!("parsing TLS private key {}", path.display()));
    }
    let key_pair = KeyPair::generate().context("generating TLS private key")?;
    writes::atomic_write(path, key_pair.serialize_pem().as_bytes(), 0o600)
        .with_context(|| format!("writing TLS private key {}", path.display()))?;
    Ok(key_pair)
}

fn build_csr_der(hostnames: &[String], key_pair: &KeyPair) -> Result<Vec<u8>> {
    let mut params =
        CertificateParams::new(hostnames.to_vec()).context("building TLS CSR parameters")?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(key_pair)
        .context("serializing TLS CSR")?;
    Ok(csr.der().as_ref().to_vec())
}

fn local_cc_init_data_hash(cfg: &Config) -> Result<Option<String>> {
    let Some(path) = cfg.cc_init_data_path.as_deref() else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).with_context(|| format!("reading cc_init_data from {path}"))?;
    Ok(Some(hex::encode(Sha256::digest(&bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn certificate_paths_match_caddyfile_static_tls_paths() {
        let root = Path::new("/state/tls-state/tenant-ingress");
        assert_eq!(
            cert_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.crt")
        );
        assert_eq!(
            key_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.key")
        );
    }

    #[test]
    fn generated_key_is_persisted_and_reused_for_csrs() {
        let dir = tempdir().unwrap();
        let key_path = key_path(dir.path());
        let hosts = vec!["app.example.test".to_string()];

        let first_key = load_or_generate_key(&key_path).unwrap();
        let first_pem = std::fs::read_to_string(&key_path).unwrap();
        let first_csr = build_csr_der(&hosts, &first_key).unwrap();
        let second_key = load_or_generate_key(&key_path).unwrap();
        let second_pem = std::fs::read_to_string(&key_path).unwrap();
        let second_csr = build_csr_der(&hosts, &second_key).unwrap();

        assert!(KeyPair::from_pem(&first_pem).is_ok());
        assert_eq!(first_pem, second_pem);
        assert!(!first_csr.is_empty());
        assert!(!second_csr.is_empty());
    }

    #[test]
    fn local_cc_init_data_hash_reads_signed_runtime_toml() {
        let dir = tempdir().unwrap();
        let cc_path = dir.path().join("cc-init-data.toml");
        std::fs::write(&cc_path, b"descriptor_core_hash = \"abc\"\n").unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
mode = "autounlock"
cc-init-data-path = "{}"

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
                cc_path.display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&cfg_path).unwrap();

        assert_eq!(
            local_cc_init_data_hash(&cfg).unwrap(),
            Some(hex::encode(Sha256::digest(
                b"descriptor_core_hash = \"abc\"\n"
            )))
        );
    }
}
