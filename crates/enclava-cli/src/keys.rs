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
use enclava_common::validate::validate_app_name;
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
    #[error("{0}")]
    Message(String),
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
    #[error("keypair storage permissions are not supported on this platform")]
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

#[cfg(not(any(unix, windows)))]
fn set_dir_perms_0700(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
fn assert_mode_0600(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

/// Windows counterpart of the unix mode-0600 load-time check: the file's
/// owner must be the current user (an owner can always rewrite the DACL) and
/// every DACL ACE must grant exactly the current user. Native SID comparison
/// throughout — immune to account-name casing and console-codepage encoding.
/// Fail-closed: absent/null DACLs, foreign ACEs, or a foreign owner all
/// reject.
#[cfg(windows)]
pub fn verify_owner_only_acl(path: &Path) -> Result<(), KeysError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    let ours = owner_sid()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    unsafe {
        let mut psid_owner: PSID = std::ptr::null_mut();
        let mut pdacl: *mut ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut psid_owner,
            std::ptr::null_mut(),
            &mut pdacl,
            std::ptr::null_mut(),
            &mut psd,
        );
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc as i32).into());
        }
        let _sd = SecurityDescriptor(psd);

        let insecure = || KeysError::InsecurePermissions(path.to_path_buf());
        if psid_owner.is_null() || EqualSid(psid_owner, ours.as_ptr() as *mut _) == 0 {
            return Err(insecure());
        }
        // An absent DACL means default access (everyone); never accept it.
        if pdacl.is_null() {
            return Err(insecure());
        }
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            pdacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if info.AceCount == 0 {
            return Err(insecure());
        }
        for i in 0..info.AceCount {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(pdacl, i, &mut ace) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
            if ace.Header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
                || EqualSid(
                    std::ptr::from_ref(&ace.SidStart) as *mut _,
                    ours.as_ptr() as *mut _,
                ) == 0
            {
                return Err(insecure());
            }
        }
        Ok(())
    }
}

/// Windows equivalent of chmod 0600/0700, done in-process: replace the
/// object's DACL with a protected, owner-only one. `SetNamedSecurityInfo`
/// with `PROTECTED_DACL` swaps the whole DACL — inherited ACEs are cut and
/// foreign *explicit* ACEs are dropped, unlike `icacls /grant:r`, which only
/// edits grants for the named account and leaves other explicit ACEs intact.
#[cfg(windows)]
fn restrict_acl_to_user(path: &Path, inheritable: bool) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let sid = owner_sid()?;
    let acl = owner_only_dacl(&sid, inheritable)?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // Owner + whole-DACL replacement in one call: a foreign owner could
    // otherwise rewrite the DACL right back. Setting the owner requires
    // WRITE_OWNER, which a user-owned directory may legitimately lack — but
    // then the owner is already us and a DACL-only update is equivalent.
    // A genuinely foreign owner fails both paths and we refuse the directory.
    let mut rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sid.as_ptr() as *mut _,
            std::ptr::null_mut(),
            acl.as_ptr().cast(),
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    if path_owner_is_user(path)? {
        rc = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.as_ptr().cast(),
                std::ptr::null_mut(),
            )
        };
        if rc == 0 {
            return Ok(());
        }
    }
    // The most recent failure, not the superseded owner-update one.
    Err(std::io::Error::from_raw_os_error(rc as i32))
}

/// Whether `path`'s owner SID is the current user's.
#[cfg(windows)]
fn path_owner_is_user(path: &Path) -> std::io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast()) };
        }
    }

    let ours = owner_sid()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    unsafe {
        let mut psid_owner: PSID = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut psid_owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut psd,
        );
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let _sd = SecurityDescriptor(psd);
        Ok(!psid_owner.is_null() && EqualSid(psid_owner, ours.as_ptr() as *mut _) != 0)
    }
}

/// The current user's SID (raw bytes) from the process token.
#[cfg(windows)]
fn owner_sid() -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    unsafe {
        let mut handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let _token = Token(handle);

        let mut needed: u32 = 0;
        GetTokenInformation(handle, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            handle,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let len = GetLengthSid(user.User.Sid) as usize;
        if len == 0 || len > buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed SID from process token",
            ));
        }
        Ok(std::slice::from_raw_parts(user.User.Sid.cast(), len).to_vec())
    }
}

/// An absolute ACL granting exactly `sid` full control, optionally inherited
/// by children (directories).
#[cfg(windows)]
fn owner_only_dacl(sid: &[u8], inheritable: bool) -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::GENERIC_ALL;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        InitializeAcl, OBJECT_INHERIT_ACE,
    };

    // ACL header + fixed ACE part + SID, minus the u32 the ACE's SidStart
    // member overlaps with.
    let len = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid.len()
        - std::mem::size_of::<u32>();
    let mut acl = vec![0u8; len];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(acl_ptr, len as u32, ACL_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if inheritable {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    if unsafe {
        AddAccessAllowedAceEx(
            acl_ptr,
            ACL_REVISION,
            flags,
            GENERIC_ALL,
            sid.as_ptr() as *mut _,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(acl)
}

/// Create a new file whose owner-only DACL is applied in the `CreateFile`
/// call itself: there is no instant at which the file exists with a different
/// (e.g. inherited) descriptor, so no racing open of any kind is possible.
#[cfg(windows)]
fn create_file_with_owner_dacl(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, SECURITY_ATTRIBUTES, SetSecurityDescriptorDacl,
    };
    use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let sid = owner_sid()?;
    let acl = owner_only_dacl(&sid, false)?;
    let mut sd = [0u8; 64]; // >= SECURITY_DESCRIPTOR_MIN_LENGTH
    let sd_ptr = sd.as_mut_ptr().cast::<std::ffi::c_void>();
    if unsafe { InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Present (non-null) DACL containing only the owner ACE, marked
    // SE_DACL_PROTECTED so inheritable parent ACEs (SYSTEM, Administrators,
    // ...) are NOT merged into the new file's effective DACL.
    if unsafe { SetSecurityDescriptorDacl(sd_ptr, 1, acl.as_ptr().cast(), 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    use windows_sys::Win32::Security::{
        SE_DACL_PROTECTED, SetSecurityDescriptorControl, SetSecurityDescriptorOwner,
    };
    if unsafe { SetSecurityDescriptorControl(sd_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Pin the owner to the current user: with UAC, objects created by an
    // admin-token process default to being owned by BUILTIN\Administrators,
    // which the load-time owner check would (rightly) reject.
    if unsafe { SetSecurityDescriptorOwner(sd_ptr, sid.as_ptr() as *mut _, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr.cast(),
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0, // no sharing while we hold the handle
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_handle(handle.cast()) })
}

/// Create a new secret file: owner-only DACL at creation (see
/// `create_file_with_owner_dacl`), then an independent re-read of the
/// descriptor (`GetNamedSecurityInfo`, a different API family than the
/// construction path) *before* any secret is written. If descriptor
/// construction were ever wrong, this fails closed and removes the
/// still-empty file.
#[cfg(windows)]
pub fn create_secret_file(path: &Path) -> std::io::Result<std::fs::File> {
    let file = create_file_with_owner_dacl(path)?;
    if let Err(err) = verify_owner_only_acl(path) {
        // Drop the unshared handle first, or the deletion hits a sharing
        // violation and an empty file is left behind.
        drop(file);
        let _ = fs::remove_file(path);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to write secret to {}: ACL verification failed: {err}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn set_dir_perms_0700(path: &Path) -> Result<(), KeysError> {
    restrict_acl_to_user(path, true)?;
    Ok(())
}

#[cfg(windows)]
fn assert_mode_0600(path: &Path) -> Result<(), KeysError> {
    verify_owner_only_acl(path)
}

/// Restrict an existing directory (and, via inheritance, its future
/// children) to the current user — the Windows counterpart of mode 0700.
/// Replaces the entire DACL, so foreign explicit ACEs are removed too.
#[cfg(windows)]
pub fn restrict_dir_to_user(path: &Path) -> std::io::Result<()> {
    restrict_acl_to_user(path, true)
}

/// Generate a fresh keypair and persist it under `~/.enclava/keys/<user_id>.priv`.
/// Refuses to overwrite an existing file.
pub fn create_and_store(user_id: Uuid) -> Result<UserSigningKey, KeysError> {
    let path = key_path_for(&user_id)?;
    if path.exists() {
        return load(user_id);
    }
    let key = UserSigningKey::generate(user_id);
    write_restricted(&path, &key.seed)?;
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

/// Write secret bytes to `path` in a file that is owner-only from birth:
/// the empty file is restricted *before* the secret is written, so no other
/// local account can observe the material at any instant. On ACL failure the
/// still-empty file is removed again. The write is flushed to stable storage
/// (`sync_all`) before the function returns, so a reported success is durable.
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(windows)]
    let mut file = create_secret_file(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(KeysError::UnsupportedPlatform);
    #[cfg(any(unix, windows))]
    {
        use std::io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}

/// Atomically write secret bytes to `path` (file mode 0600, parent dir 0700) via a
/// `.tmp` rename so a crash never leaves a partial secret on disk.
/// The rename also replaces an existing destination on Windows: std passes
/// MOVEFILE_REPLACE_EXISTING, so `store_seed_at(force = true)` works everywhere.
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_perms_0700(parent)?;
    }
    write_secret_file(path, bytes)
}

/// Write secret bytes to `path` (owner-only from birth, replacing any
/// existing destination) via a `.tmp` rename. Unlike `write_secret_atomic`
/// this does NOT restrict the parent directory, for user-chosen output
/// locations such as recovery-backup files. On unix the rename is made durable
/// by flushing the parent directory; on other platforms the file contents are
/// synced but rename durability is NOT provided — callers that require it must
/// gate on [`secret_rename_durability_supported`] (claim sink preparation does).
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    let tmp = path.with_extension("tmp");
    // Never follow a pre-planted file: remove and recreate below.
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    write_restricted(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Read a secret (password, passphrase) from a file: content is used verbatim
/// except for a trailing newline, and an empty file is rejected so a truncated
/// secret source can never silently become an empty credential.
pub fn read_secret_file(path: &Path, kind: &str) -> Result<String, KeysError> {
    let value = fs::read_to_string(path)
        .map_err(|err| {
            KeysError::Message(format!(
                "failed to read {kind} file {}: {err}",
                path.display()
            ))
        })?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if value.is_empty() {
        return Err(KeysError::Message(format!(
            "{kind} file {} is empty",
            path.display()
        )));
    }
    Ok(value)
}
/// The directory containing `path`'s entry, normalized for bare relative
/// filenames (`""` from `Path::new("backup.json").parent()`, or `None` for a
/// root path) to the current directory `"."` so the sync target can be opened.
fn normalize_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => Path::new("."),
    }
}

/// Flush one directory's entry table (unix: open read-only + `sync_all`).
/// Exercised for every directory mutation whose durability matters.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let dir = std::fs::OpenOptions::new().read(true).open(dir)?;
    dir.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Flush the directory entry for a just-renamed secret so the rename itself
/// survives a crash, not only the file contents (unix). `write_restricted`
/// already `sync_all`s the data before the rename. Failures propagate on unix.
///
/// Other platforms have no verified directory-flush primitive in this codebase,
/// so this is a no-op there: rename durability is NOT provided, only file-level
/// durability. That is acceptable for legacy key/backup writes, but anything
/// that must prove durable completion (the one-time recovery-mnemonic sink)
/// rejects those platforms up front via [`secret_rename_durability_supported`].
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    sync_dir(normalize_parent(path))
}

/// Whether durable completion of a secret's atomic rename can be proven on this
/// platform: unix flushes the parent directory after the rename. No verified
/// native equivalent exists here for Windows, so claim sink preparation (and
/// thus ownership claims) fail closed there instead of pretending the one-time
/// recovery mnemonic was durably persisted.
pub fn secret_rename_durability_supported() -> bool {
    cfg!(unix)
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

pub fn generate_recovery_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
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

fn validate_app_mnemonic_name(app: &str) -> Result<(), KeysError> {
    validate_app_name(app).map_err(|e| {
        KeysError::InvalidBackup(format!("invalid recovery mnemonic app name `{app}`: {e}"))
    })
}

/// Persist a recovery mnemonic to local state (mode 0600, atomic, durable).
/// Overwrites any existing entry for the app — a fresh redeploy mints a new
/// mnemonic and voids the old.
pub fn store_app_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
    mnemonic: &str,
) -> Result<(), KeysError> {
    validate_app_mnemonic_name(app)?;
    write_secret_atomic(&app_mnemonic_path(paths, org, app), mnemonic.as_bytes())
}

/// Prepare and validate the local sink for the post-claim recovery-mnemonic
/// write. Must run BEFORE the ownership claim is sent: the TEE returns the
/// mnemonic exactly once and rejects a second claim, so a destination that only
/// fails afterwards loses the mnemonic permanently.
///
/// Validates the two REAL paths the store uses — the destination
/// `{app}.mnemonic` and the atomic-write temp `{app}.tmp` — and proves the sink
/// by exercising every durability operation the post-claim store depends on:
/// owner-only file creation + file fsync, directory fsync (the operation that
/// makes the store's rename durable), and entry removal, all through the real
/// temp path and its real parent directory. Any directory entries
/// `create_dir_all` just created (a fresh org dir, or the keys dir/state root on
/// a first run) are flushed up the ancestor chain, because a file fsync never
/// makes directory creation durable. An existing regular file at the
/// destination is a prior mnemonic backup and is left untouched (the post-claim
/// store replaces it atomically); directories or symlinks at either real path
/// are rejected fail-closed. The probe contains no secret material and is
/// removed again on both outcomes.
pub fn prepare_app_mnemonic_sink(paths: &CliPaths, org: &str, app: &str) -> Result<(), KeysError> {
    prepare_app_mnemonic_sink_with_dir_sync(paths, org, app, &|dir: &Path| sync_dir(dir))
}

/// Testable core of [`prepare_app_mnemonic_sink`] with the directory-sync
/// primitive injected, so a filesystem that rejects directory fsync (the review
/// reproduction: an LD_PRELOAD shim failing `fsync` only on directory fds) can
/// be simulated in-process and must abort preparation BEFORE the claim.
fn prepare_app_mnemonic_sink_with_dir_sync(
    paths: &CliPaths,
    org: &str,
    app: &str,
    dir_sync: &dyn Fn(&Path) -> std::io::Result<()>,
) -> Result<(), KeysError> {
    const PROBE_BYTES: &[u8] = b"claim sink writability probe (not a secret)";

    if !secret_rename_durability_supported() {
        // Claims cannot risk an unpersistable one-time mnemonic: reject before
        // the claim is sent rather than after ownership committed.
        return Err(KeysError::InvalidBackup(
            "claim sink preparation is unsupported on this platform: durable completion of \
             the recovery-mnemonic write cannot be proven here (no verified directory-flush \
             primitive). Run the ownership claim on a platform with proven secret-rename \
             durability (unix)"
                .to_string(),
        ));
    }

    validate_app_mnemonic_name(app)?;
    let dest = app_mnemonic_path(paths, org, app);
    // `write_secret_file` stages the atomic write at `{app}.tmp` and renames it
    // onto `{app}.mnemonic`; both real paths must be safe before the claim.
    let tmp = dest.with_extension("tmp");
    let Some(parent) = dest.parent() else {
        return Err(KeysError::InvalidBackup(format!(
            "recovery mnemonic path {} has no parent directory",
            dest.display()
        )));
    };
    fs::create_dir_all(parent)?;
    set_dir_perms_0700(parent)?;

    // Destination: an existing regular file is a prior mnemonic backup — keep it
    // (the store's rename replaces it atomically; a pre-claim probe rename would
    // clobber it). A directory or symlink makes that rename fail or unsafe, and
    // a probe that ignored the real destination would pass here only to strand
    // the one-time mnemonic after ownership commits.
    if let Ok(meta) = fs::symlink_metadata(&dest)
        && !meta.file_type().is_file()
    {
        return Err(KeysError::InvalidBackup(format!(
            "recovery mnemonic destination {} is occupied by a directory or symlink; \
             refusing to claim into it",
            dest.display()
        )));
    }

    // Atomic-write temp path: a leftover regular file is a crashed write temp;
    // remove it exactly like the store would. A directory or symlink there
    // cannot be removed by the store and would fail every post-claim attempt.
    if let Ok(meta) = fs::symlink_metadata(&tmp) {
        if !meta.file_type().is_file() {
            return Err(KeysError::InvalidBackup(format!(
                "recovery mnemonic temp path {} is occupied by a directory or symlink; \
                 refusing to claim into it",
                tmp.display()
            )));
        }
        fs::remove_file(&tmp)?;
    }

    // Durability of any just-created directory entries: flush the sink
    // directory and every ancestor up to the filesystem root. A filesystem that
    // rejects directory fsync must fail HERE, before the claim is sent, instead
    // of passing preparation and dooming the post-claim store (review P1).
    //
    // The walk starts from the canonicalized (absolute, symlink-resolved)
    // location: the state root may itself be relative (`ENCLAVA_STATE_DIR=
    // fresh-state` is supported by `CliPaths::resolve`), and a purely textual
    // parent walk stops at the empty parent without ever flushing the current
    // directory that holds the newly created state root's entry.
    let mut ancestor = Some(fs::canonicalize(parent)?);
    while let Some(dir) = ancestor {
        dir_sync(&dir)?;
        ancestor = dir.parent().map(|parent| parent.to_path_buf());
    }

    // Exercise the full durability pipeline through the REAL temp path: create
    // owner-only + file fsync (`write_restricted`), directory fsync (the exact
    // operation the store's rename durability relies on), entry removal, and a
    // final directory fsync. Any failure aborts preparation; the probe is
    // cleaned up best-effort and never touches the destination.
    write_restricted(&tmp, PROBE_BYTES)?;
    let flushed = dir_sync(parent)
        .and_then(|()| fs::remove_file(&tmp))
        .and_then(|()| dir_sync(parent));
    if let Err(err) = flushed {
        let _ = fs::remove_file(&tmp);
        return Err(KeysError::Io(err));
    }
    Ok(())
}

/// Load a stored recovery mnemonic for an app, if present. Refuses world-readable files.
pub fn load_app_mnemonic(
    paths: &CliPaths,
    org: &str,
    app: &str,
) -> Result<Option<String>, KeysError> {
    validate_app_mnemonic_name(app)?;
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
        validate_app_mnemonic_name(&app)?;
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

    #[cfg(windows)]
    #[test]
    fn write_restricted_roundtrip_and_verify() {
        // End-to-end runtime coverage for the native DACL path: create,
        // verify, reload. Runs on the windows CI runner.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        write_restricted(&path, &[7u8; 32]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), &[7u8; 32]);
        verify_owner_only_acl(&path).unwrap();
        assert_mode_0600(&path).unwrap();
    }

    // Serialise tests that mutate $HOME (test impacts a shared global).
    static HOME_LOCK: Mutex<()> = Mutex::new(());
    // Serialise tests that change the process working directory.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

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

    // Unix-only premise: preparation succeeds and the probe cleans up. On
    // platforms without proven secret-rename durability, production fails
    // closed before any path check (see
    // prepare_app_mnemonic_sink_requires_proven_rename_durability), so this
    // success-path contract is asserted only where durability is proven.
    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_proves_writability_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        prepare_app_mnemonic_sink(&paths, "org-a", "shell1").expect("sink must be ready");

        let org_dir = paths.keys_dir.join("org-a");
        assert!(org_dir.is_dir(), "org directory must be prepared");
        let leftovers: Vec<_> = fs::read_dir(&org_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe must be removed from the real temp path, found {leftovers:?}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&org_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "prepared sink directory must be owner-only");
        }

        // The prepared sink accepts the real post-claim store.
        store_app_mnemonic(&paths, "org-a", "shell1", "synthetic mnemonic").unwrap();
        assert_eq!(
            load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("synthetic mnemonic".to_string())
        );
    }

    // Unix-only premise: the path-specific rejection. On non-Unix the
    // platform refusal fires before path checks, so the directory-occupied
    // contract is asserted only where preparation reaches the path checks.
    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_rejects_directory_at_real_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        // A directory at the REAL destination passes no probe at a distinct name
        // but guarantees the post-claim rename fails; it must be rejected now.
        fs::create_dir_all(paths.keys_dir.join("org-a").join("shell1.mnemonic")).unwrap();

        let err = prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
            .expect_err("destination directory must be rejected before the claim");
        assert!(err.to_string().contains("shell1.mnemonic"));
        // Nothing was touched: the blocking directory is still there.
        assert!(
            paths
                .keys_dir
                .join("org-a")
                .join("shell1.mnemonic")
                .is_dir()
        );
    }

    // Unix-only premise: the path-specific rejection (see the destination
    // variant above for the non-Unix ordering).
    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_rejects_directory_at_real_temp_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        fs::create_dir_all(paths.keys_dir.join("org-a").join("shell1.tmp")).unwrap();

        let err = prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
            .expect_err("temp-path directory must be rejected before the claim");
        assert!(err.to_string().contains("shell1.tmp"));
        assert!(paths.keys_dir.join("org-a").join("shell1.tmp").is_dir());
    }

    // Unix-only premise: an existing backup is preserved and a stale temp is
    // removed while preparation succeeds. Non-Unix never reaches these paths.
    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_preserves_existing_backup_and_removes_stale_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        store_app_mnemonic(&paths, "org-a", "shell1", "prior backup mnemonic").unwrap();
        // A stale regular temp from a crashed write must be cleaned, not kept.
        fs::write(paths.keys_dir.join("org-a").join("shell1.tmp"), "stale").unwrap();

        prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
            .expect("existing regular backup must not block preparation");

        // The prior backup is preserved byte-for-byte; only the stale temp is gone.
        assert_eq!(
            load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("prior backup mnemonic".to_string())
        );
        assert!(!paths.keys_dir.join("org-a").join("shell1.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_rejects_symlinks_at_either_real_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        let org_dir = paths.keys_dir.join("org-a");
        fs::create_dir_all(&org_dir).unwrap();
        let outside = tmp.path().join("planted-target");
        fs::write(&outside, "planted").unwrap();

        std::os::unix::fs::symlink(&outside, org_dir.join("shell1.mnemonic")).unwrap();
        let err = prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
            .expect_err("symlinked destination must be rejected");
        assert!(err.to_string().contains("directory or symlink"));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "planted");

        std::os::unix::fs::symlink(&outside, org_dir.join("shell1.tmp")).unwrap();
        let err = prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
            .expect_err("symlinked temp path must be rejected");
        assert!(err.to_string().contains("directory or symlink"));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "planted");
    }

    #[test]
    fn prepare_app_mnemonic_sink_requires_proven_rename_durability() {
        if secret_rename_durability_supported() {
            // Unix: preparation proceeds past the durability gate.
            let tmp = tempfile::tempdir().unwrap();
            let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
            prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
                .expect("unix provides proven rename durability");
        } else {
            // Platforms without a verified directory-flush primitive must fail
            // closed with an actionable error, not pretend durability -- and
            // the refusal must fire BEFORE any path work, so no directory is
            // created and no probe touches the filesystem at all.
            let tmp = tempfile::tempdir().unwrap();
            let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
            let err = prepare_app_mnemonic_sink(&paths, "org-a", "shell1")
                .expect_err("unsupported platforms must reject claim sink preparation");
            assert!(matches!(err, KeysError::InvalidBackup(_)));
            let msg = err.to_string();
            assert!(msg.contains("durable completion"));
            assert!(msg.contains("unix"));
            assert!(
                !paths.keys_dir.exists(),
                "the non-Unix refusal must precede any filesystem mutation"
            );
            assert!(
                !paths.keys_dir.join("org-a").exists(),
                "no sink directory may be created on refusal"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_fails_closed_when_directory_sync_is_rejected() {
        // Behavioral reversal of the review reproduction (LD_PRELOAD shim that
        // fails fsync() only on directory fds): preparation must abort BEFORE
        // the claim instead of passing and dooming the post-claim store.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        store_app_mnemonic(&paths, "org-a", "shell1", "prior backup mnemonic").unwrap();

        let reject_dir_sync = |_: &Path| Err(std::io::Error::from_raw_os_error(22)); // EINVAL, like the shim
        let err =
            prepare_app_mnemonic_sink_with_dir_sync(&paths, "org-a", "shell1", &reject_dir_sync)
                .expect_err("directory-sync rejection must abort preparation");
        assert!(matches!(err, KeysError::Io(_)));

        // The old backup is untouched and no probe leftover occupies the real
        // temp path; nothing was exposed.
        assert_eq!(
            load_app_mnemonic(&paths, "org-a", "shell1").unwrap(),
            Some("prior backup mnemonic".to_string())
        );
        assert!(!paths.keys_dir.join("org-a").join("shell1.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_fails_closed_when_directory_sync_fails_late() {
        // A filesystem that accepts the ancestor flushes but rejects the sync
        // after the probe write must still abort preparation (never report the
        // sink prepared on a directory-sync failure) and clean the probe up.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        let org_dir = paths.keys_dir.join("org-a");

        let org_dir_syncs = std::cell::Cell::new(0u32);
        let flaky = |dir: &Path| {
            if dir == org_dir {
                let seen = org_dir_syncs.get();
                org_dir_syncs.set(seen + 1);
                if seen >= 1 {
                    return Err(std::io::Error::from_raw_os_error(5)); // EIO on 2nd org-dir sync
                }
            }
            Ok(())
        };
        let err = prepare_app_mnemonic_sink_with_dir_sync(&paths, "org-a", "shell1", &flaky)
            .expect_err("late directory-sync failure must abort preparation");
        assert!(matches!(err, KeysError::Io(_)));

        // First sync = ancestor walk, second = probe pipeline: the probe ran and
        // its failure aborted preparation without leaving the temp occupied.
        assert!(org_dir_syncs.get() >= 2);
        assert!(!paths.keys_dir.join("org-a").join("shell1.tmp").exists());
    }

    #[test]
    fn write_secret_file_relative_output_path_succeeds() {
        // Behavioral reversal of the review reproduction: a bare relative
        // output path (key backup's `--out backup.json`) used to write and
        // rename the file and then report ENOENT, because sync_parent_dir
        // opened the empty parent path "". cwd is process-global, so serialize
        // like the HOME mutations above and restore before asserting.
        let _guard = CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = write_secret_file(Path::new("backup.json"), b"synthetic nonsecret");
        let _ = std::env::set_current_dir(prev);

        result.expect("relative backup output path must succeed end-to-end");
        let written = tmp.path().join("backup.json");
        assert_eq!(fs::read(&written).unwrap(), b"synthetic nonsecret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&written).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "relative output must stay owner-only");
        }
        assert!(!tmp.path().join("backup.tmp").exists(), "no stray temp");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_flushes_newly_created_directory_ancestors() {
        // Directory creation is only durable once the PARENT entry table is
        // flushed; a file fsync never does that. Preparation of a fresh org dir
        // must flush the sink dir, the keys dir holding its entry, and the
        // state root holding the keys dir's entry, before reporting prepared.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();

        let flushed = std::cell::RefCell::new(Vec::new());
        let recorder = |dir: &Path| {
            flushed.borrow_mut().push(dir.to_path_buf());
            Ok(())
        };
        prepare_app_mnemonic_sink_with_dir_sync(&paths, "org-a", "shell1", &recorder)
            .expect("recording syncs must succeed");

        let flushed = flushed.into_inner();
        let canon = |p: &Path| fs::canonicalize(p).unwrap();
        assert!(flushed.contains(&canon(&paths.keys_dir.join("org-a"))));
        assert!(flushed.contains(&canon(&paths.keys_dir)));
        assert!(flushed.contains(&canon(tmp.path())));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_app_mnemonic_sink_flushes_directory_holding_relative_state_root() {
        // Review reproduction: `ENCLAVA_STATE_DIR=fresh-state` is supported
        // (config.rs resolves the raw value), so the whole keystore chain is
        // relative. A textual parent walk flushed fresh-state/keys/org-a,
        // fresh-state/keys and fresh-state but stopped at the empty parent
        // without ever flushing the current directory holding the new state
        // root's entry — leaving the state root creation non-durable. The walk
        // must reach the directory containing the relative state root.
        let _guard = CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let paths = CliPaths::from_root(std::path::PathBuf::from("fresh-state")).unwrap();
        let flushed = std::cell::RefCell::new(Vec::new());
        let recorder = |dir: &Path| {
            flushed.borrow_mut().push(dir.to_path_buf());
            Ok(())
        };
        let prepared =
            prepare_app_mnemonic_sink_with_dir_sync(&paths, "org-a", "shell1", &recorder);
        let _ = std::env::set_current_dir(prev);
        prepared.expect("relative state root preparation must succeed");

        let flushed = flushed.into_inner();
        let cwd = fs::canonicalize(tmp.path()).unwrap();
        let state_root = cwd.join("fresh-state");
        assert!(flushed.contains(&state_root.join("keys").join("org-a")));
        assert!(flushed.contains(&state_root.join("keys")));
        assert!(flushed.contains(&state_root));
        // The previously-missed flush: the current directory that holds the
        // newly created state root's entry.
        assert!(
            flushed.contains(&cwd),
            "must flush the directory holding a relative state root: {flushed:?}"
        );
    }

    #[test]
    fn prepare_app_mnemonic_sink_rejects_invalid_app_names() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().to_path_buf()).unwrap();
        assert!(prepare_app_mnemonic_sink(&paths, "org-a", "../escape").is_err());
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

    #[cfg(unix)]
    #[test]
    fn app_mnemonic_store_rejects_invalid_app_name_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CliPaths::from_root(tmp.path().join("state")).unwrap();

        let err = store_app_mnemonic(&paths, "org-a", "../escape", "mnemonic")
            .unwrap_err()
            .to_string();

        assert!(err.contains("invalid recovery mnemonic app name"));
        assert!(!tmp.path().join("state/keys/escape.mnemonic").exists());
        assert!(!tmp.path().join("escape.mnemonic").exists());
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
