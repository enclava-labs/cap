//! The vault's certificate authority.
//!
//! The CA key is generated where the vault runs and never leaves it. The
//! workload trusts the CA certificate; the vault mints a short-lived leaf
//! for each origin it intercepts. The key is persisted next to the store so
//! a vault restart does not invalidate the certificate the workload already
//! loaded.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

use crate::store::write_atomic;

const CA_COMMON_NAME: &str = "Enclava Vault CA";
const CA_KEY_FILE: &str = "ca.key.pem";
const CA_CERT_FILE: &str = "ca.crt.pem";
const CA_LIFETIME: time::Duration = time::Duration::days(3650);
const LEAF_LIFETIME: time::Duration = time::Duration::hours(24);
/// A cached leaf is replaced well before it expires.
const LEAF_REFRESH: Duration = Duration::from_secs(12 * 60 * 60);
const CLOCK_SKEW: time::Duration = time::Duration::minutes(5);

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
}

pub struct VaultCa {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<HashMap<String, (Instant, Arc<ServerConfig>)>>,
}

impl VaultCa {
    /// A new CA that exists only in memory.
    pub fn generate() -> Result<Self, CaError> {
        let (ca, _key_pem) = Self::generate_with_key()?;
        Ok(ca)
    }

    /// Loads the CA from `dir`, creating and persisting one on first use.
    pub fn load_or_generate(dir: &Path) -> Result<Self, CaError> {
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);
        match (
            fs::read_to_string(&key_path),
            fs::read_to_string(&cert_path),
        ) {
            (Ok(key_pem), Ok(cert_pem)) => {
                let key = KeyPair::from_pem(&key_pem)?;
                // The issuer only needs the subject name and the key; both
                // are fixed, so the stored certificate does not have to be
                // parsed back.
                Ok(Self::assemble(Issuer::new(ca_params()?, key), cert_pem))
            }
            (Err(key_err), Err(cert_err))
                if key_err.kind() == io::ErrorKind::NotFound
                    && cert_err.kind() == io::ErrorKind::NotFound =>
            {
                let (ca, key_pem) = Self::generate_with_key()?;
                write_atomic(&key_path, key_pem.as_bytes())?;
                write_atomic(&cert_path, ca.cert_pem.as_bytes())?;
                Ok(ca)
            }
            // One file without the other, or an unreadable file: refuse to
            // guess rather than silently replace the CA the workload trusts.
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
        }
    }

    fn generate_with_key() -> Result<(Self, zeroize::Zeroizing<String>), CaError> {
        let key = KeyPair::generate()?;
        let key_pem = zeroize::Zeroizing::new(key.serialize_pem());
        let mut params = ca_params()?;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + CA_LIFETIME;
        let cert_pem = params.self_signed(&key)?.pem();
        Ok((Self::assemble(Issuer::new(params, key), cert_pem), key_pem))
    }

    fn assemble(issuer: Issuer<'static, KeyPair>, cert_pem: String) -> Self {
        Self {
            issuer,
            cert_pem,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            leaves: Mutex::new(HashMap::new()),
        }
    }

    /// The CA certificate the workload must trust, PEM encoded.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// TLS server configuration presenting a leaf for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let mut leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((minted, config)) = leaves.get(host)
            && minted.elapsed() < LEAF_REFRESH
        {
            return Ok(config.clone());
        }
        let config = Arc::new(self.mint(host)?);
        leaves.insert(host.to_owned(), (Instant::now(), config.clone()));
        Ok(config)
    }

    fn mint(&self, host: &str) -> Result<ServerConfig, CaError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + LEAF_LIFETIME;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;

        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn ca_params() -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name = name;
    // Path length 0: this CA signs leaves only.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn persisted_ca_is_reused_and_key_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let first = VaultCa::load_or_generate(dir.path()).unwrap();
        let second = VaultCa::load_or_generate(dir.path()).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        assert!(first.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let mode = fs::metadata(dir.path().join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn half_a_ca_is_an_error_not_a_silent_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        VaultCa::load_or_generate(dir.path()).unwrap();
        fs::remove_file(dir.path().join(CA_KEY_FILE)).unwrap();
        assert!(VaultCa::load_or_generate(dir.path()).is_err());
    }

    #[test]
    fn leaf_configs_are_cached_per_host() {
        let ca = VaultCa::generate().unwrap();
        let a = ca.server_config("api.example.com").unwrap();
        let again = ca.server_config("api.example.com").unwrap();
        let other = ca.server_config("other.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &again));
        assert!(!Arc::ptr_eq(&a, &other));
    }
}
