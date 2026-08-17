//! Owner-signed organization keyring (Phase 7 — D10 / D11).
//!
//! TOFU on owner pubkey: on first encounter the user verifies the owner's
//! Ed25519 fingerprint out-of-band; subsequent fetches verify against the
//! cached pubkey at `~/.enclava/state/<org_id>/owner_pubkey`.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::keys::UserSigningKey;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("home directory not available")]
    NoHome,
    #[error("invalid signature length")]
    BadSignature,
    #[error("invalid pubkey")]
    BadPubkey,
    #[error("signature verification failed: {0}")]
    Verify(String),
    #[error("owner pubkey mismatch: cached fingerprint differs from candidate; refusing to update")]
    TofuMismatch,
    #[error(
        "keyring rollback refused: cached keyring is v{cached} but fetched keyring is v{incoming}; a compromised API can replay old signed keyrings. Clear ~/.enclava/state/<org_id>/ if this is an intentional reset."
    )]
    Rollback { cached: u64, incoming: u64 },
    #[error("keyring not yet trusted; run `enclava org keyring trust` to confirm owner pubkey")]
    Untrusted,
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Deployer,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Deployer => "deployer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub user_id: Uuid,
    #[serde(with = "pubkey_hex")]
    pub pubkey: VerifyingKey,
    pub role: Role,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKeyring {
    pub org_id: Uuid,
    pub version: u64,
    pub members: Vec<Member>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKeyringEnvelope {
    pub keyring: OrgKeyring,
    #[serde(with = "sig_hex")]
    pub signature: Signature,
    #[serde(with = "pubkey_hex")]
    pub signing_pubkey: VerifyingKey,
}

mod pubkey_hex {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(k: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(k.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| D::Error::custom("bad len"))?;
        VerifyingKey::from_bytes(&arr).map_err(D::Error::custom)
    }
}

mod sig_hex {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 64] = bytes.try_into().map_err(|_| D::Error::custom("bad len"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

/// CE-v1 canonical bytes for one Member (32-byte hash, used as a record value).
fn canonical_member_hash(m: &Member) -> [u8; 32] {
    let role = m.role.as_str().as_bytes().to_vec();
    let added = m.added_at.to_rfc3339().into_bytes();
    let pk = m.pubkey.to_bytes();
    ce_v1_hash(&[
        ("user_id", m.user_id.as_bytes().as_slice()),
        ("pubkey", &pk),
        ("role", &role),
        ("added_at", &added),
    ])
}

/// Canonical bytes for the members list: each member hashed individually,
/// hashes concatenated in user_id-sorted order, then CE-v1 hashed once more.
fn canonical_members_hash(members: &[Member]) -> [u8; 32] {
    let mut sorted: Vec<&Member> = members.iter().collect();
    sorted.sort_by_key(|m| m.user_id);
    let per_member: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|m| (m.user_id.to_string(), canonical_member_hash(m)))
        .collect();
    let records: Vec<(&str, &[u8])> = per_member
        .iter()
        .map(|(label, h)| (label.as_str(), h.as_slice()))
        .collect();
    ce_v1_hash(&records)
}

/// Raw CE-v1 bytes signed by the org owner (the input to Ed25519).
pub fn canonical_keyring_bytes(k: &OrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&k.members);
    let version_be = k.version.to_be_bytes();
    let updated = k.updated_at.to_rfc3339().into_bytes();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", k.org_id.as_bytes().as_slice()),
        ("version", &version_be),
        ("members", &members_hash),
        ("updated_at", &updated),
    ])
}

/// Sign a keyring with the given owner key, producing a verifiable envelope.
pub fn sign_keyring(owner: &UserSigningKey, keyring: OrgKeyring) -> OrgKeyringEnvelope {
    let bytes = canonical_keyring_bytes(&keyring);
    let signature = owner.sign(&bytes);
    OrgKeyringEnvelope {
        keyring,
        signature,
        signing_pubkey: owner.public,
    }
}

pub fn single_member_keyring(
    org_id: Uuid,
    version: u64,
    member_key: &UserSigningKey,
    role: Role,
    updated_at: DateTime<Utc>,
) -> OrgKeyring {
    OrgKeyring {
        org_id,
        version,
        members: vec![Member {
            user_id: member_key.user_id,
            pubkey: member_key.public,
            role,
            added_at: updated_at,
        }],
        updated_at,
    }
}

/// Verify an envelope against an explicit trusted owner pubkey.
pub fn verify_keyring<'e>(
    envelope: &'e OrgKeyringEnvelope,
    trusted_owner: &VerifyingKey,
) -> Result<&'e OrgKeyring, KeyringError> {
    if envelope.signing_pubkey.to_bytes() != trusted_owner.to_bytes() {
        return Err(KeyringError::TofuMismatch);
    }
    let bytes = canonical_keyring_bytes(&envelope.keyring);
    trusted_owner
        .verify(&bytes, &envelope.signature)
        .map_err(|e| KeyringError::Verify(e.to_string()))?;
    Ok(&envelope.keyring)
}

fn state_dir(org_id: &Uuid) -> Result<PathBuf, KeyringError> {
    let root = crate::config::CliPaths::resolve()
        .map_err(|_| KeyringError::NoHome)?
        .root;
    let dir = root.join("state").join(org_id.to_string());
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

fn owner_pubkey_path(org_id: &Uuid) -> Result<PathBuf, KeyringError> {
    Ok(state_dir(org_id)?.join("owner_pubkey"))
}

fn keyring_envelope_path(org_id: &Uuid) -> Result<PathBuf, KeyringError> {
    Ok(state_dir(org_id)?.join("org_keyring.json"))
}

pub fn load_trusted_owner(org_id: &Uuid) -> Result<Option<VerifyingKey>, KeyringError> {
    let path = owner_pubkey_path(org_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    if bytes.len() != 32 {
        return Err(KeyringError::BadPubkey);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Some(
        VerifyingKey::from_bytes(&arr).map_err(|_| KeyringError::BadPubkey)?,
    ))
}

/// Persist a freshly-trusted owner pubkey under the per-org state dir.
/// Refuses to overwrite a different existing pubkey (returns `TofuMismatch`).
pub fn store_trusted_owner(org_id: &Uuid, pubkey: &VerifyingKey) -> Result<(), KeyringError> {
    let path = owner_pubkey_path(org_id)?;
    if path.exists() {
        let existing = load_trusted_owner(org_id)?;
        if existing.map(|k| k.to_bytes()) != Some(pubkey.to_bytes()) {
            return Err(KeyringError::TofuMismatch);
        }
        return Ok(());
    }
    fs::write(&path, pubkey.to_bytes())?;
    set_file_0600(&path);
    Ok(())
}

/// Atomically replace a pinned owner after the remote owner-signed rotation succeeds.
pub fn rotate_trusted_owner(
    org_id: &Uuid,
    expected: &VerifyingKey,
    replacement: &VerifyingKey,
) -> Result<(), KeyringError> {
    if load_trusted_owner(org_id)?.map(|key| key.to_bytes()) != Some(expected.to_bytes()) {
        return Err(KeyringError::TofuMismatch);
    }
    let path = owner_pubkey_path(org_id)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, replacement.to_bytes())?;
    set_file_0600(&tmp);
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn load_keyring_envelope(org_id: &Uuid) -> Result<OrgKeyringEnvelope, KeyringError> {
    let raw = fs::read_to_string(keyring_envelope_path(org_id)?)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Cache a keyring envelope, refusing rollbacks: a fetched envelope whose
/// version is older than the cached one is a replay (a validly-signed but
/// stale keyring, e.g. re-adding a removed deployer) and is rejected.
/// Equal versions are accepted (idempotent refetch).
pub fn store_keyring_envelope(
    org_id: &Uuid,
    envelope: &OrgKeyringEnvelope,
) -> Result<PathBuf, KeyringError> {
    if let Ok(cached) = load_keyring_envelope(org_id)
        && cached.keyring.version > envelope.keyring.version
    {
        return Err(KeyringError::Rollback {
            cached: cached.keyring.version,
            incoming: envelope.keyring.version,
        });
    }
    store_keyring_envelope_force(org_id, envelope)
}

/// Cache a keyring envelope without rollback protection. Only for explicit
/// recovery/bootstrap flows where the local cache is being deliberately
/// re-established.
pub fn store_keyring_envelope_force(
    org_id: &Uuid,
    envelope: &OrgKeyringEnvelope,
) -> Result<PathBuf, KeyringError> {
    let path = keyring_envelope_path(org_id)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(envelope)?)?;
    set_file_0600(&tmp);
    fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn keyring_fingerprint(keyring: &OrgKeyring) -> [u8; 32] {
    Sha256::digest(canonical_keyring_bytes(keyring)).into()
}

pub fn keyring_fingerprint_hex(keyring: &OrgKeyring) -> String {
    hex::encode(keyring_fingerprint(keyring))
}

pub fn member_allows_deploy(keyring: &OrgKeyring, pubkey: &VerifyingKey) -> bool {
    let pubkey = pubkey.to_bytes();
    keyring.members.iter().any(|member| {
        member.pubkey.to_bytes() == pubkey
            && matches!(member.role, Role::Owner | Role::Admin | Role::Deployer)
    })
}

#[cfg(unix)]
fn set_file_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_file_0600(_: &Path) {}

/// Hex fingerprint suitable for out-of-band confirmation (full SHA-256-like
/// hex of the raw 32-byte pubkey, grouped 4-by-4 for readability).
pub fn fingerprint(pubkey: &VerifyingKey) -> String {
    hex::encode(pubkey.to_bytes())
}

// TODO(phase-7-api): client stubs for the upload/fetch endpoints. Names match
// the API request shape we expect — body and signing match D10.
pub struct UploadKeyringRequest<'a> {
    pub envelope: &'a OrgKeyringEnvelope,
}

pub struct FetchKeyringResponse {
    pub envelope: OrgKeyringEnvelope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap()
    }

    fn sample_keyring(owner: &UserSigningKey) -> OrgKeyring {
        OrgKeyring {
            org_id: Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
            version: 1,
            members: vec![Member {
                user_id: owner.user_id,
                pubkey: owner.public,
                role: Role::Owner,
                added_at: fixed_time(),
            }],
            updated_at: fixed_time(),
        }
    }

    #[test]
    fn signing_and_verifying_round_trips() {
        let owner = UserSigningKey::generate(Uuid::new_v4());
        let keyring = sample_keyring(&owner);
        let env = sign_keyring(&owner, keyring);
        verify_keyring(&env, &owner.public).unwrap();
    }

    #[test]
    fn tampered_keyring_fails_verification() {
        let owner = UserSigningKey::generate(Uuid::new_v4());
        let mut env = sign_keyring(&owner, sample_keyring(&owner));
        env.keyring.version = 99;
        let err = verify_keyring(&env, &owner.public).unwrap_err();
        assert!(matches!(err, KeyringError::Verify(_)));
    }

    #[test]
    fn member_order_is_canonicalized_by_user_id() {
        let owner = UserSigningKey::generate(Uuid::new_v4());
        let user_a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let user_b = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let m_a = Member {
            user_id: user_a,
            pubkey: owner.public,
            role: Role::Admin,
            added_at: fixed_time(),
        };
        let m_b = Member {
            user_id: user_b,
            pubkey: owner.public,
            role: Role::Deployer,
            added_at: fixed_time(),
        };

        let h_ab = canonical_members_hash(&[m_a.clone(), m_b.clone()]);
        let h_ba = canonical_members_hash(&[m_b, m_a]);
        assert_eq!(h_ab, h_ba, "member order must not affect canonical hash");
    }

    #[test]
    fn wrong_owner_pubkey_rejected() {
        let owner_a = UserSigningKey::generate(Uuid::new_v4());
        let owner_b = UserSigningKey::generate(Uuid::new_v4());
        let env = sign_keyring(&owner_a, sample_keyring(&owner_a));
        let err = verify_keyring(&env, &owner_b.public).unwrap_err();
        assert!(matches!(err, KeyringError::TofuMismatch));
    }

    #[test]
    fn keyring_state_uses_configured_cli_root() {
        let _guard = env_state_lock();
        let temp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ENCLAVA_STATE_DIR", temp.path()) };
        let org_id = Uuid::new_v4();
        let dir = state_dir(&org_id).unwrap();
        unsafe { std::env::remove_var("ENCLAVA_STATE_DIR") };
        assert_eq!(dir, temp.path().join("state").join(org_id.to_string()));
    }

    fn env_state_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap()
    }

    #[test]
    fn keyring_store_refuses_version_rollback() {
        let _guard = env_state_lock();
        let temp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ENCLAVA_STATE_DIR", temp.path()) };
        let org_id = Uuid::new_v4();

        let owner = UserSigningKey::from_seed(Uuid::new_v4(), [0x11; 32]);
        let mut v3 = sample_keyring(&owner);
        v3.version = 3;
        let envelope_v3 = sign_keyring(&owner, v3);
        store_keyring_envelope(&org_id, &envelope_v3).unwrap();

        // Same version (idempotent refetch) is accepted.
        store_keyring_envelope(&org_id, &envelope_v3).unwrap();

        // An older, still-validly-signed keyring replayed by a compromised
        // API must be refused.
        let mut v2 = sample_keyring(&owner);
        v2.version = 2;
        let envelope_v2 = sign_keyring(&owner, v2);
        let err = store_keyring_envelope(&org_id, &envelope_v2).unwrap_err();
        assert!(matches!(
            err,
            KeyringError::Rollback {
                cached: 3,
                incoming: 2
            }
        ));

        // Newer versions are accepted; the explicit force path bypasses the
        // check for documented recovery flows.
        let mut v4 = sample_keyring(&owner);
        v4.version = 4;
        store_keyring_envelope(&org_id, &sign_keyring(&owner, v4)).unwrap();
        store_keyring_envelope_force(&org_id, &envelope_v2).unwrap();

        unsafe { std::env::remove_var("ENCLAVA_STATE_DIR") };
    }
}
