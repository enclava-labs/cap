//! The vault's certificate authority.
//!
//! The CA key is generated where the vault runs and never leaves it. The
//! workload trusts the CA certificate; the vault mints a short-lived leaf
//! for each origin it intercepts. Key and certificate are persisted together
//! in one file next to the store, so a vault restart does not invalidate the
//! certificate the workload already loaded.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::store::{lock_dir, write_atomic, write_atomic_mode};

const CA_COMMON_NAME: &str = "Enclava Vault CA";
/// Private key followed by the certificate, both PEM. One file, so the pair
/// is always published together.
const CA_FILE: &str = "ca.pem";
const CERT_MARKER: &str = "-----BEGIN CERTIFICATE-----";
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
    #[error("stored CA is unusable: {0}")]
    Corrupt(&'static str),
    #[error("refusing to export the CA certificate into the store directory")]
    ExportIntoStore,
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
    ///
    /// The store lock is held throughout, so processes that start together
    /// against an empty store all end up with the same CA.
    pub fn load_or_generate(dir: &Path) -> Result<Self, CaError> {
        let _lock = lock_dir(dir)?;
        let path = dir.join(CA_FILE);
        match fs::read_to_string(&path) {
            Ok(bundle) => Self::from_bundle(&Zeroizing::new(bundle)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (ca, key_pem) = Self::generate_with_key()?;
                let mut bundle = Zeroizing::new(String::new());
                bundle.push_str(&key_pem);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
                bundle.push_str(&ca.cert_pem);
                write_atomic(&path, bundle.as_bytes())?;
                Ok(ca)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn from_bundle(bundle: &str) -> Result<Self, CaError> {
        let at = bundle
            .find(CERT_MARKER)
            .ok_or(CaError::Corrupt("no certificate"))?;
        let (key_pem, cert_pem) = bundle.split_at(at);
        // rcgen's error is dropped on purpose: it must not quote key text.
        let key = KeyPair::from_pem(key_pem).map_err(|_| CaError::Corrupt("unreadable key"))?;
        let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|_| CaError::Corrupt("unreadable certificate"))?;

        // Leaves are signed with `key` and checked against `cert`. If the
        // two do not belong together, every client would reject them.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let signing_key = provider
            .key_provider
            .load_private_key(pkcs8(&key))
            .map_err(|_| CaError::Corrupt("unusable key"))?;
        CertifiedKey::new(vec![cert], signing_key)
            .keys_match()
            .map_err(|_| CaError::Corrupt("key does not match certificate"))?;

        // The issuer only needs the subject name and the key. Both are
        // fixed, so the stored certificate does not have to be parsed back.
        Ok(Self::assemble(
            Issuer::new(ca_params()?, key),
            cert_pem.to_owned(),
        ))
    }

    fn generate_with_key() -> Result<(Self, Zeroizing<String>), CaError> {
        let key = KeyPair::generate()?;
        let key_pem = Zeroizing::new(key.serialize_pem());
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

    /// Writes the CA certificate to `path`, world-readable, for the
    /// workload to trust.
    ///
    /// The store directory holds the CA key, so nothing is exported into
    /// it, however the path is spelled. The file is renamed into place: if
    /// `path` is a link to the key file, the link is replaced and the key
    /// file is left alone.
    pub fn export_cert(&self, store_dir: &Path, path: &Path) -> Result<(), CaError> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if resolve(parent)?.starts_with(resolve(store_dir)?) {
            return Err(CaError::ExportIntoStore);
        }
        fs::create_dir_all(parent)?;
        write_atomic_mode(path, self.cert_pem.as_bytes(), 0o644)?;
        Ok(())
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
        // Drop every stale leaf while here, so hosts that are no longer
        // used do not stay cached for the life of the process.
        leaves.retain(|_, (minted, _)| minted.elapsed() < LEAF_REFRESH);
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

        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], pkcs8(&key))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Canonical form of `path`, following symlinks in the part that exists and
/// keeping the part that does not.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(canonical) => {
                return Ok(missing
                    .iter()
                    .rev()
                    .fold(canonical, |path, part| path.join(part)));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(e);
                };
                missing.push(name);
                existing = parent;
            }
            Err(e) => return Err(e),
        }
    }
}

fn pkcs8(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
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
    fn persisted_ca_is_reused_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let first = VaultCa::load_or_generate(dir.path()).unwrap();
        let second = VaultCa::load_or_generate(dir.path()).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        assert!(first.cert_pem().starts_with(CERT_MARKER));
        let mode = fs::metadata(dir.path().join(CA_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn concurrent_first_start_agrees_on_one_ca() {
        let dir = tempfile::tempdir().unwrap();
        let starts: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.path().to_owned();
                std::thread::spawn(move || {
                    VaultCa::load_or_generate(&dir)
                        .unwrap()
                        .cert_pem()
                        .to_owned()
                })
            })
            .collect();
        let certs: Vec<String> = starts.into_iter().map(|s| s.join().unwrap()).collect();
        let stored = VaultCa::load_or_generate(dir.path()).unwrap();
        assert!(certs.iter().all(|cert| cert == stored.cert_pem()));
    }

    #[test]
    fn key_that_does_not_match_the_certificate_is_refused() {
        let ours = tempfile::tempdir().unwrap();
        let theirs = tempfile::tempdir().unwrap();
        VaultCa::load_or_generate(ours.path()).unwrap();
        VaultCa::load_or_generate(theirs.path()).unwrap();
        let read = |dir: &Path| fs::read_to_string(dir.join(CA_FILE)).unwrap();
        let (our_key, _) = read(ours.path())
            .split_once(CERT_MARKER)
            .map(|(k, c)| (k.to_owned(), c.to_owned()))
            .unwrap();
        let their_bundle = read(theirs.path());
        let their_cert = &their_bundle[their_bundle.find(CERT_MARKER).unwrap()..];
        fs::write(ours.path().join(CA_FILE), format!("{our_key}{their_cert}")).unwrap();

        let error = VaultCa::load_or_generate(ours.path()).err().unwrap();
        assert!(matches!(
            error,
            CaError::Corrupt("key does not match certificate")
        ));
    }

    #[test]
    fn unreadable_ca_file_is_an_error_not_a_silent_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CA_FILE), "not a pem bundle").unwrap();
        assert!(matches!(
            VaultCa::load_or_generate(dir.path()).err().unwrap(),
            CaError::Corrupt(_)
        ));
        assert_eq!(
            fs::read_to_string(dir.path().join(CA_FILE)).unwrap(),
            "not a pem bundle"
        );
    }

    #[test]
    fn certificate_is_exported_world_readable_outside_the_store() {
        let store = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let ca = VaultCa::load_or_generate(store.path()).unwrap();
        let path = out.path().join("new/dir/ca.crt");
        ca.export_cert(store.path(), &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), ca.cert_pem());
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn export_never_touches_the_stored_key() {
        let store = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let ca = VaultCa::load_or_generate(store.path()).unwrap();
        let bundle_path = store.path().join(CA_FILE);
        let bundle = fs::read_to_string(&bundle_path).unwrap();

        // Straight at the bundle, into a new directory under the store, and
        // through a symlink to the store directory.
        let alias = out.path().join("alias");
        std::os::unix::fs::symlink(store.path(), &alias).unwrap();
        for inside in [
            bundle_path.clone(),
            store.path().join("sub/ca.crt"),
            alias.join(CA_FILE),
        ] {
            let error = ca.export_cert(store.path(), &inside).err().unwrap();
            assert!(
                matches!(error, CaError::ExportIntoStore),
                "{}",
                inside.display()
            );
        }
        assert!(!store.path().join("sub").exists());

        // A link outside the store that points at the bundle is replaced,
        // not written through.
        let link = out.path().join("ca.crt");
        std::os::unix::fs::symlink(&bundle_path, &link).unwrap();
        ca.export_cert(store.path(), &link).unwrap();
        assert_eq!(fs::read_to_string(&link).unwrap(), ca.cert_pem());
        assert!(
            !fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        assert_eq!(fs::read_to_string(&bundle_path).unwrap(), bundle);
        VaultCa::load_or_generate(store.path()).unwrap();
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
