//! Per-user CLI Ed25519 keypair management (Phase 7 — D10).
//!
//! On first authenticated command the CLI generates an Ed25519 keypair and
//! stores the seed at `~/.enclava/keys/<user_id>.priv` mode 0600. The public
//! half is registered with the platform via `POST /users/me/public-keys`
//! (API-side endpoint pending — see TODO(phase-7-api)).

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::config::CliPaths;

const BACKUP_KDF_MEMORY_KIB: u32 = 19_456;
const BACKUP_KDF_ITERATIONS: u32 = 2;
const BACKUP_KDF_PARALLELISM: u32 = 1;
const RECOVERY_BACKUP_VERSION_SEED_ONLY: u8 = 1;
const RECOVERY_BACKUP_VERSION_WITH_MNEMONICS: u8 = 2;

#[derive(Debug, Error)]
pub enum KeysError {
    #[error("home directory not available")]
    NoHome,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key file (expected 32 bytes, got {0})")]
    InvalidLength(usize),
    #[error("signature verification failed: {0}")]
    Verify(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid recovery backup: {0}")]
    InvalidBackup(String),
    #[error("key file `{0}` is world-readable; refusing to load (expected mode 0600)")]
    InsecurePermissions(PathBuf),
    #[error("Windows is not supported in v1 — keypair storage requires POSIX mode bits")]
    UnsupportedPlatform,
}

/// A user's signing key. The secret seed is zeroed on drop.
#[derive(Debug)]
pub struct UserSigningKey {
    pub user_id: Uuid,
    pub public: VerifyingKey,
    secret: SigningKey,
    // Retain raw seed bytes alongside the dalek SigningKey so we can zero
    // them ourselves on drop. SigningKey itself does not implement Zeroize
    // in dalek 2.x, but the seed it derives from does.
    seed: [u8; 32],
}

impl UserSigningKey {
    pub fn generate(user_id: Uuid) -> Self {
        let secret = SigningKey::generate(&mut OsRng);
        let seed = secret.to_bytes();
        let public = secret.verifying_key();
        Self {
            user_id,
            public,
            secret,
            seed,
        }
    }

    pub fn from_seed(user_id: Uuid, seed: [u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(&seed);
        let public = secret.verifying_key();
        Self {
            user_id,
            public,
            secret,
            seed,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    pub fn verify(public: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<(), KeysError> {
        public
            .verify(message, sig)
            .map_err(|e| KeysError::Verify(e.to_string()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryBackupMetadata {
    pub org_id: Option<String>,
    pub org_name: Option<String>,
    pub owner_fingerprint: Option<String>,
}

/// A per-app LUKS recovery mnemonic carried inside the encrypted backup payload.
/// These are secret and live under the AEAD ciphertext, never in cleartext envelope fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBackupMnemonic {
    pub app: String,
    pub mnemonic: String,
}

/// Plaintext result of decrypting a recovery backup: the org-wide deploy-key seed
/// plus any captured per-app LUKS recovery mnemonics.
#[derive(Debug, Clone)]
pub struct DecryptedBackup {
    pub seed: [u8; 32],
    pub mnemonics: Vec<RecoveryBackupMnemonic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBackup {
    pub version: u8,
    pub kind: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_fingerprint: Option<String>,
    pub seed_fingerprint: String,
    pub kdf: RecoveryBackupKdf,
    pub cipher: RecoveryBackupCipher,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBackupKdf {
    pub name: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBackupCipher {
    pub name: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryBackupPayload {
    version: u8,
    recovery_seed: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    /// Per-app LUKS recovery mnemonics (payload v2). `#[serde(default)]` keeps v1
    /// backups (no mnemonics field) decryptable — they yield an empty map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mnemonics: Option<Vec<RecoveryBackupMnemonic>>,
}

impl Drop for UserSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Resolve the per-user keys directory, creating it (mode 0700) if needed.
pub fn keys_dir() -> Result<PathBuf, KeysError> {
    let home = dirs::home_dir().ok_or(KeysError::NoHome)?;
    let dir = home.join(".enclava").join("keys");
    fs::create_dir_all(&dir)?;
    set_dir_perms_0700(&dir)?;
    Ok(dir)
}

fn recovery_seed_path(paths: &CliPaths) -> &Path {
    &paths.recovery_seed
}

fn key_path_for(user_id: &Uuid) -> Result<PathBuf, KeysError> {
    Ok(keys_dir()?.join(format!("{user_id}.priv")))
}

#[cfg(unix)]
fn set_file_perms_0600(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms_0700(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn assert_mode_0600(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeysError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_file_perms_0600(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn set_dir_perms_0700(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn assert_mode_0600(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

/// Generate a fresh keypair and persist it under `~/.enclava/keys/<user_id>.priv`.
/// Refuses to overwrite an existing file.
pub fn create_and_store(user_id: Uuid) -> Result<UserSigningKey, KeysError> {
    let path = key_path_for(&user_id)?;
    if path.exists() {
        return load(user_id);
    }
    let key = UserSigningKey::generate(user_id);
    fs::write(&path, key.seed)?;
    set_file_perms_0600(&path)?;
    Ok(key)
}

pub fn store_seed_at(path: &Path, seed: &[u8; 32], force: bool) -> Result<(), KeysError> {
    if path.exists() && !force {
        return Err(KeysError::InvalidBackup(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        )));
    }
    write_secret_atomic(path, seed)
}

/// Atomically write secret bytes to `path` (file mode 0600, parent dir 0700) via a
/// `.tmp` rename so a crash never leaves a partial secret on disk.
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_perms_0700(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    set_file_perms_0600(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn load_recovery_seed(paths: &CliPaths) -> Result<Option<[u8; 32]>, KeysError> {
    let path = recovery_seed_path(paths);
    if !path.exists() {
        return Ok(None);
    }
    assert_mode_0600(path)?;
    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err(KeysError::InvalidLength(bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

pub fn load_or_create_recovery_seed(paths: &CliPaths) -> Result<[u8; 32], KeysError> {
    if let Some(seed) = load_recovery_seed(paths)? {
        return Ok(seed);
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    store_seed_at(recovery_seed_path(paths), &seed, false)?;
    Ok(seed)
}

pub fn seed_fingerprint(seed: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(seed))
}

pub fn derive_ed25519_seed(recovery_seed: &[u8; 32], info: &str) -> Result<[u8; 32], KeysError> {
    let hk = Hkdf::<Sha256>::new(Some(b"enclava/v1"), recovery_seed);
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|e| KeysError::Crypto(e.to_string()))?;
    Ok(out)
}

pub fn derive_org_owner_key(
    user_id: Uuid,
    org_id: Uuid,
    recovery_seed: &[u8; 32],
) -> Result<UserSigningKey, KeysError> {
    let seed = derive_ed25519_seed(recovery_seed, &format!("org-owner/{org_id}"))?;
    Ok(UserSigningKey::from_seed(user_id, seed))
}

pub fn derive_app_bootstrap_seed(
    org_id: Uuid,
    app_name: &str,
    recovery_seed: &[u8; 32],
) -> Result<[u8; 32], KeysError> {
    derive_ed25519_seed(recovery_seed, &format!("app-bootstrap/{org_id}/{app_name}"))
}

/// Path to the stored LUKS recovery mnemonic for a password-mode app.
/// Scoped by org to match bootstrap keys: `~/.enclava/keys/{org}/{app}.mnemonic`.
pub fn app_mnemonic_path(paths: &CliPaths, org: &str, app: &str) -> PathBuf {
    paths.keys_dir.join(org).join(format!("{app}.mnemonic"))
}

/// Persist a recovery mnemonic to local state (mode 0600, atomic). Overwrites any
/// existing entry for the app — a fresh redeploy mints a new mnemonic and voids the old.
pub fn store_app_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
) -> Result<(), KeysError> {
    write_secret_atomic(&app_mnemonic_path(paths, org, app), mnemonic.as_bytes())
}

/// Load a stored recovery mnemonic for an app, if present. Refuses world-readable files.
pub fn load_app_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
) -> Result<Option<String>, KeysError> {
    let path = app_mnemonic_path(paths, org, app);
    if !path.exists() {
        return Ok(None);
    }
    assert_mode_0600(&path)?;
    Ok(Some(fs::read_to_string(&path)?.trim().to_string()))
}

/// Enumerate `(app, mnemonic)` pairs stored for an org, sorted by app name.
/// Used by `key backup` to bundle every captured mnemonic. A mnemonic file with
/// insecure permissions is an error (propagated) rather than silently skipped, so a
/// backup can never quietly drop an app's recovery material. Empty entries are skipped.
pub fn list_app_mnemonics(paths: &CliPaths, org: &str) -> Result<Vec<(String, String)>, KeysError> {
    let dir = paths.keys_dir.join(org);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("mnemonic") {
            continue;
        }
        let Some(app) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if assert_mode_0600(&path).is_err() {
            return Err(KeysError::InsecurePermissions(path));
        }
        let mnemonic = fs::read_to_string(&path)?.trim().to_string();
        if !mnemonic.is_empty() {
            out.push((app, mnemonic));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Enumerate org directories that contain at least one stored app mnemonic.
/// Used by logged-out backup to fail loudly instead of creating a deploy-key-only
/// backup while local storage recovery material exists.
pub fn list_app_mnemonic_orgs(paths: &CliPaths) -> Result<Vec<String>, KeysError> {
    let mut orgs = Vec::new();
    if !paths.keys_dir.exists() {
        return Ok(orgs);
    }

    for entry in fs::read_dir(&paths.keys_dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let Some(org) = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let mut has_mnemonic = false;
        for entry in fs::read_dir(&path)? {
            if entry?.path().extension().and_then(|e| e.to_str()) == Some("mnemonic") {
                has_mnemonic = true;
                break;
            }
        }
        if has_mnemonic {
            orgs.push(org);
        }
    }

    orgs.sort();
    Ok(orgs)
}

fn backup_key(passphrase: &str, kdf: &RecoveryBackupKdf) -> Result<[u8; 32], KeysError> {
    if kdf.name != "argon2id" {
        return Err(KeysError::InvalidBackup(format!(
            "unsupported kdf {}",
            kdf.name
        )));
    }
    let salt = STANDARD
        .decode(&kdf.salt)
        .map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|e| KeysError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| KeysError::Crypto(e.to_string()))?;
    Ok(key)
}

pub fn encrypt_recovery_backup(
    seed: &[u8; 32],
    passphrase: &str,
) -> Result<RecoveryBackup, KeysError> {
    encrypt_recovery_backup_with_metadata(seed, passphrase, RecoveryBackupMetadata::default(), &[])
}

pub fn encrypt_recovery_backup_with_metadata(
    seed: &[u8; 32],
    passphrase: &str,
    metadata: RecoveryBackupMetadata,
    mnemonics: &[RecoveryBackupMnemonic],
) -> Result<RecoveryBackup, KeysError> {
    if passphrase.is_empty() {
        return Err(KeysError::InvalidBackup(
            "backup passphrase cannot be empty".to_string(),
        ));
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let kdf = RecoveryBackupKdf {
        name: "argon2id".to_string(),
        salt: STANDARD.encode(salt),
        memory_kib: BACKUP_KDF_MEMORY_KIB,
        iterations: BACKUP_KDF_ITERATIONS,
        parallelism: BACKUP_KDF_PARALLELISM,
    };
    let cipher_params = RecoveryBackupCipher {
        name: "xchacha20-poly1305".to_string(),
        nonce: STANDARD.encode(nonce),
    };
    let created_at = chrono::Utc::now().to_rfc3339();
    let backup_version = if mnemonics.is_empty() {
        RECOVERY_BACKUP_VERSION_SEED_ONLY
    } else {
        RECOVERY_BACKUP_VERSION_WITH_MNEMONICS
    };
    let payload = RecoveryBackupPayload {
        version: backup_version,
        recovery_seed: STANDARD.encode(seed),
        created_at: created_at.clone(),
        notes: None,
        mnemonics: if mnemonics.is_empty() {
            None
        } else {
            Some(mnemonics.to_vec())
        },
    };
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    let key = backup_key(passphrase, &kdf)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| KeysError::Crypto(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), payload_bytes.as_slice())
        .map_err(|e| KeysError::Crypto(e.to_string()))?;
    Ok(RecoveryBackup {
        version: backup_version,
        kind: "enclava-recovery-backup".to_string(),
        created_at,
        org_id: metadata.org_id,
        org_name: metadata.org_name,
        owner_fingerprint: metadata.owner_fingerprint,
        seed_fingerprint: seed_fingerprint(seed),
        kdf,
        cipher: cipher_params,
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_recovery_backup(
    backup: &RecoveryBackup,
    passphrase: &str,
) -> Result<DecryptedBackup, KeysError> {
    if !matches!(
        backup.version,
        RECOVERY_BACKUP_VERSION_SEED_ONLY | RECOVERY_BACKUP_VERSION_WITH_MNEMONICS
    ) {
        return Err(KeysError::InvalidBackup(format!(
            "unsupported version {}",
            backup.version
        )));
    }
    if backup.kind != "enclava-recovery-backup" {
        return Err(KeysError::InvalidBackup(format!(
            "unsupported kind {}",
            backup.kind
        )));
    }
    if backup.cipher.name != "xchacha20-poly1305" {
        return Err(KeysError::InvalidBackup(
            "unsupported backup crypto parameters".to_string(),
        ));
    }
    let nonce = STANDARD
        .decode(&backup.cipher.nonce)
        .map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    if nonce.len() != 24 {
        return Err(KeysError::InvalidBackup(
            "nonce must be 24 bytes".to_string(),
        ));
    }
    let ciphertext = STANDARD
        .decode(&backup.ciphertext)
        .map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    let key = backup_key(passphrase, &backup.kdf)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| KeysError::Crypto(e.to_string()))?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| KeysError::InvalidBackup("wrong passphrase or corrupted backup".into()))?;
    let payload: RecoveryBackupPayload =
        serde_json::from_slice(&plaintext).map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    if !matches!(
        payload.version,
        RECOVERY_BACKUP_VERSION_SEED_ONLY | RECOVERY_BACKUP_VERSION_WITH_MNEMONICS
    ) {
        return Err(KeysError::InvalidBackup(format!(
            "unsupported payload version {}",
            payload.version
        )));
    }
    if payload.version != backup.version {
        return Err(KeysError::InvalidBackup(format!(
            "backup envelope version {} does not match payload version {}",
            backup.version, payload.version
        )));
    }
    let seed_bytes = STANDARD
        .decode(payload.recovery_seed)
        .map_err(|e| KeysError::InvalidBackup(e.to_string()))?;
    if seed_bytes.len() != 32 {
        return Err(KeysError::InvalidBackup(format!(
            "seed must decrypt to 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    if seed_fingerprint(&seed) != backup.seed_fingerprint {
        return Err(KeysError::InvalidBackup(
            "seed fingerprint mismatch".to_string(),
        ));
    }
    let mnemonics = payload.mnemonics.unwrap_or_default();
    if backup.version == RECOVERY_BACKUP_VERSION_SEED_ONLY && !mnemonics.is_empty() {
        return Err(KeysError::InvalidBackup(
            "v1 recovery backups cannot contain mnemonics".to_string(),
        ));
    }
    Ok(DecryptedBackup { seed, mnemonics })
}

/// Load the stored keypair for `user_id`. Refuses to read files with insecure
/// permissions; refuses on Windows entirely.
pub fn load(user_id: Uuid) -> Result<UserSigningKey, KeysError> {
    let path = key_path_for(&user_id)?;
    assert_mode_0600(&path)?;
    let bytes = fs::read(&path)?;
    if bytes.len() != 32 {
        return Err(KeysError::InvalidLength(bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let secret = SigningKey::from_bytes(&seed);
    let public = secret.verifying_key();
    Ok(UserSigningKey {
        user_id,
        public,
        secret,
        seed,
    })
}

/// Stub client function for `POST /users/me/public-keys`.
/// TODO(phase-7-api): wire to enclava-api once the endpoint is implemented.
pub struct RegisterPublicKeyRequest {
    pub user_id: Uuid,
    pub public_key: VerifyingKey,
    pub label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialise tests that mutate $HOME (test impacts a shared global).
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn with_isolated_home<F: FnOnce()>(f: F) {
        let _guard = HOME_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn round_trip_create_load_sign_verify() {
        with_isolated_home(|| {
            let user = Uuid::new_v4();
            let key = create_and_store(user).unwrap();
            let sig = key.sign(b"hello");
            UserSigningKey::verify(&key.public, b"hello", &sig).unwrap();

            let loaded = load(user).unwrap();
            assert_eq!(loaded.public.to_bytes(), key.public.to_bytes());
            UserSigningKey::verify(&loaded.public, b"hello", &sig).unwrap();
        });
    }

    #[test]
    fn recovery_seed_derivation_is_deterministic_and_domain_separated() {
        let seed = [42u8; 32];
        let user = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let org = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let owner_a = derive_org_owner_key(user, org, &seed).unwrap();
        let owner_b = derive_org_owner_key(user, org, &seed).unwrap();
        let app_seed = derive_app_bootstrap_seed(org, "demo", &seed).unwrap();

        assert_eq!(owner_a.public.to_bytes(), owner_b.public.to_bytes());
        assert_ne!(owner_a.public.to_bytes(), app_seed);
    }

    #[test]
    fn encrypted_recovery_backup_round_trips() {
        let seed = [7u8; 32];
        let backup = encrypt_recovery_backup(&seed, "correct horse battery staple").unwrap();
        let restored = decrypt_recovery_backup(&backup, "correct horse battery staple").unwrap();

        assert_eq!(backup.version, RECOVERY_BACKUP_VERSION_SEED_ONLY);
        assert_eq!(restored.seed, seed);
        assert!(restored.mnemonics.is_empty());
        assert!(decrypt_recovery_backup(&backup, "wrong passphrase").is_err());
    }

    #[test]
    fn encrypted_recovery_backup_round_trips_mnemonics() {
        let seed = [7u8; 32];
        let mnemonics = vec![
            RecoveryBackupMnemonic {
                app: "shell1".into(),
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            },
            RecoveryBackupMnemonic {
                app: "shell2".into(),
                mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow".into(),
            },
        ];
        let backup = encrypt_recovery_backup_with_metadata(
            &seed,
            "correct horse battery staple",
            RecoveryBackupMetadata::default(),
            &mnemonics,
        )
        .unwrap();
        let restored = decrypt_recovery_backup(&backup, "correct horse battery staple").unwrap();

        assert_eq!(backup.version, RECOVERY_BACKUP_VERSION_WITH_MNEMONICS);
        assert_eq!(restored.seed, seed);
        assert_eq!(restored.mnemonics, mnemonics);
        // Mnemonics live inside the AEAD ciphertext, never in cleartext envelope fields.
        let raw = serde_json::to_string(&backup).unwrap();
        assert!(!raw.contains("abandon"));
        assert!(!raw.contains("legal winner"));
        assert!(decrypt_recovery_backup(&backup, "wrong passphrase").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn app_mnemonic_store_load_list_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        store_app_mnemonic(
            &paths,
            "org-a",
            "shell2",
            "zone zone zone zone zone zone zone zone zone zone zone zone",
        )
        .unwrap();
        store_app_mnemonic(&paths, "org-a", "shell1", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        // other org is excluded
        store_app_mnemonic(
            &paths,
            "org-b",
            "shell9",
            "vote fence fence fence fence fence fence fence fence fence fence fence",
        )
        .unwrap();

        assert_eq!(
            load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())
        );

        let listed = list_app_mnemonics(&paths, "org-a").unwrap();
        assert_eq!(
            listed,
            vec![
                ("shell1".to_string(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
                ("shell2".to_string(), "zone zone zone zone zone zone zone zone zone zone zone zone".to_string()),
            ]
        );
        assert_eq!(
            list_app_mnemonic_orgs(&paths).unwrap(),
            vec!["org-a".to_string(), "org-b".to_string()]
        );
        // absent app / absent org return None / empty
        assert!(
            load_app_mnemonic(&paths, "org-a", "nope")
                .unwrap()
                .is_none()
        );
        assert!(list_app_mnemonics(&paths, "org-c").unwrap().is_empty());
    }

    #[test]
    fn encrypted_recovery_backup_carries_only_non_secret_metadata_outside_ciphertext() {
        let seed = [9u8; 32];
        let backup = encrypt_recovery_backup_with_metadata(
            &seed,
            "correct horse battery staple",
            RecoveryBackupMetadata {
                org_id: Some("22222222-2222-2222-2222-222222222222".to_string()),
                org_name: Some("demo".to_string()),
                owner_fingerprint: Some("owner-fp".to_string()),
            },
            &[],
        )
        .unwrap();

        assert_eq!(backup.kind, "enclava-recovery-backup");
        assert_eq!(backup.org_name.as_deref(), Some("demo"));
        assert_eq!(backup.owner_fingerprint.as_deref(), Some("owner-fp"));
        assert_eq!(backup.kdf.name, "argon2id");
        assert_eq!(backup.cipher.name, "xchacha20-poly1305");
        assert_ne!(backup.ciphertext, hex::encode(seed));
        assert_eq!(
            decrypt_recovery_backup(&backup, "correct horse battery staple")
                .unwrap()
                .seed,
            seed
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_key_file() {
        with_isolated_home(|| {
            use std::os::unix::fs::PermissionsExt;
            let user = Uuid::new_v4();
            let _ = create_and_store(user).unwrap();
            let path = key_path_for(&user).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let err = load(user).unwrap_err();
            assert!(matches!(err, KeysError::InsecurePermissions(_)));
        });
    }
}
