use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const LOG_ENCRYPTION_ALGORITHM: &str = "x25519-hpke-v1";
pub const LOG_FRAME_VERSION: &str = "enclava-log-frame-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEncryptionPublicKey {
    pub key_id: String,
    pub public_key_base64url: String,
    pub public_key_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEncryptionKeyPair {
    pub private_key_base64url: String,
    pub public_key_base64url: String,
    pub public_key_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct EncryptedLogFrame {
    pub version: String,
    pub algorithm: String,
    pub key_id: String,
    pub org_id: String,
    pub app_name: String,
    pub deployment_id: String,
    pub recipient_public_key_sha256: String,
    pub sender_public_key_base64url: String,
    pub nonce_base64url: String,
    pub sequence: u64,
    pub stream: String,
    pub container: String,
    pub timestamp: String,
    pub ciphertext_base64url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogFrameContext {
    pub org_id: String,
    pub app_name: String,
    pub deployment_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LogEncryptionError {
    #[error("unsupported log encryption algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid log encryption key id")]
    InvalidKeyId,
    #[error("invalid log encryption public key")]
    InvalidPublicKey,
    #[error("invalid log encryption private key")]
    InvalidPrivateKey,
    #[error("invalid encrypted log frame")]
    InvalidFrame,
    #[error("encrypted log frame is for another key")]
    WrongKey,
    #[error("failed to encrypt log frame")]
    Encrypt,
    #[error("failed to decrypt log frame")]
    Decrypt,
}

#[derive(Serialize)]
struct FrameAad<'a> {
    version: &'a str,
    algorithm: &'a str,
    key_id: &'a str,
    org_id: &'a str,
    app_name: &'a str,
    deployment_id: &'a str,
    recipient_public_key_sha256: &'a str,
    sender_public_key_base64url: &'a str,
    nonce_base64url: &'a str,
    sequence: u64,
    stream: &'a str,
    container: &'a str,
    timestamp: &'a str,
}

pub fn generate_log_keypair() -> LogEncryptionKeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    let private_bytes = private.to_bytes();
    let public_bytes = public.to_bytes();
    LogEncryptionKeyPair {
        private_key_base64url: URL_SAFE_NO_PAD.encode(private_bytes),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public_bytes),
        public_key_sha256: public_key_sha256(&public_bytes),
    }
}

pub fn public_key_sha256(public_key: &[u8]) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
    )
}

pub fn validate_public_key(
    key_id: impl Into<String>,
    public_key_base64url: impl Into<String>,
    public_key_sha256_value: impl Into<String>,
) -> Result<LogEncryptionPublicKey, LogEncryptionError> {
    let key_id = key_id.into();
    if key_id.trim().is_empty()
        || key_id.len() > 128
        || !key_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(LogEncryptionError::InvalidKeyId);
    }
    let public_key_base64url = public_key_base64url.into();
    let public_key = decode_fixed::<32>(&public_key_base64url)
        .map_err(|_| LogEncryptionError::InvalidPublicKey)?;
    let normalized = URL_SAFE_NO_PAD.encode(public_key);
    if normalized != public_key_base64url {
        return Err(LogEncryptionError::InvalidPublicKey);
    }
    let public_key_sha256_value = public_key_sha256_value.into();
    if public_key_sha256_value != public_key_sha256(&public_key) {
        return Err(LogEncryptionError::InvalidPublicKey);
    }
    Ok(LogEncryptionPublicKey {
        key_id,
        public_key_base64url,
        public_key_sha256: public_key_sha256_value,
    })
}

pub fn encrypt_log_frame(
    recipient: &LogEncryptionPublicKey,
    context: &LogFrameContext,
    sequence: u64,
    stream: impl Into<String>,
    container: impl Into<String>,
    timestamp: impl Into<String>,
    plaintext: &[u8],
) -> Result<EncryptedLogFrame, LogEncryptionError> {
    let public_key = decode_fixed::<32>(&recipient.public_key_base64url)
        .map_err(|_| LogEncryptionError::InvalidPublicKey)?;
    let recipient_public = PublicKey::from(public_key);
    let sender_private = StaticSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_private);
    let shared = sender_private.diffie_hellman(&recipient_public);
    let sender_public_key_base64url = URL_SAFE_NO_PAD.encode(sender_public.to_bytes());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_base64url = URL_SAFE_NO_PAD.encode(nonce);
    let mut frame = EncryptedLogFrame {
        version: LOG_FRAME_VERSION.to_string(),
        algorithm: LOG_ENCRYPTION_ALGORITHM.to_string(),
        key_id: recipient.key_id.clone(),
        org_id: context.org_id.clone(),
        app_name: context.app_name.clone(),
        deployment_id: context.deployment_id.clone(),
        recipient_public_key_sha256: recipient.public_key_sha256.clone(),
        sender_public_key_base64url,
        nonce_base64url,
        sequence,
        stream: stream.into(),
        container: container.into(),
        timestamp: timestamp.into(),
        ciphertext_base64url: String::new(),
    };
    validate_frame_metadata(&frame)?;
    let key = derive_frame_key(
        shared.as_bytes(),
        &recipient.public_key_sha256,
        &frame.sender_public_key_base64url,
        &frame.key_id,
    );
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aad = frame_aad(&frame)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| LogEncryptionError::Encrypt)?;
    frame.ciphertext_base64url = URL_SAFE_NO_PAD.encode(ciphertext);
    Ok(frame)
}

pub fn decrypt_log_frame(
    private_key_base64url: &str,
    frame: &EncryptedLogFrame,
) -> Result<Vec<u8>, LogEncryptionError> {
    validate_frame_metadata(frame)?;
    let private_key = decode_fixed::<32>(private_key_base64url)
        .map_err(|_| LogEncryptionError::InvalidPrivateKey)?;
    let private = StaticSecret::from(private_key);
    let public = PublicKey::from(&private);
    if frame.recipient_public_key_sha256 != public_key_sha256(&public.to_bytes()) {
        return Err(LogEncryptionError::WrongKey);
    }
    let sender_public_key = decode_fixed::<32>(&frame.sender_public_key_base64url)
        .map_err(|_| LogEncryptionError::InvalidFrame)?;
    let sender_public = PublicKey::from(sender_public_key);
    let shared = private.diffie_hellman(&sender_public);
    let nonce =
        decode_fixed::<12>(&frame.nonce_base64url).map_err(|_| LogEncryptionError::InvalidFrame)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(frame.ciphertext_base64url.as_bytes())
        .map_err(|_| LogEncryptionError::InvalidFrame)?;
    let key = derive_frame_key(
        shared.as_bytes(),
        &frame.recipient_public_key_sha256,
        &frame.sender_public_key_base64url,
        &frame.key_id,
    );
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aad = frame_aad(frame)?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| LogEncryptionError::Decrypt)
}

fn validate_frame_metadata(frame: &EncryptedLogFrame) -> Result<(), LogEncryptionError> {
    if frame.version != LOG_FRAME_VERSION || frame.algorithm != LOG_ENCRYPTION_ALGORITHM {
        return Err(LogEncryptionError::UnsupportedAlgorithm);
    }
    if frame.key_id.trim().is_empty()
        || frame.key_id.len() > 128
        || !frame
            .key_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(LogEncryptionError::InvalidFrame);
    }
    for value in [
        &frame.stream,
        &frame.container,
        &frame.timestamp,
        &frame.org_id,
        &frame.app_name,
        &frame.deployment_id,
        &frame.sender_public_key_base64url,
        &frame.nonce_base64url,
        &frame.recipient_public_key_sha256,
    ] {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(LogEncryptionError::InvalidFrame);
        }
    }
    if !matches!(frame.stream.as_str(), "stdout" | "stderr") {
        return Err(LogEncryptionError::InvalidFrame);
    }
    Ok(())
}

fn frame_aad(frame: &EncryptedLogFrame) -> Result<Vec<u8>, LogEncryptionError> {
    serde_json::to_vec(&FrameAad {
        version: &frame.version,
        algorithm: &frame.algorithm,
        key_id: &frame.key_id,
        org_id: &frame.org_id,
        app_name: &frame.app_name,
        deployment_id: &frame.deployment_id,
        recipient_public_key_sha256: &frame.recipient_public_key_sha256,
        sender_public_key_base64url: &frame.sender_public_key_base64url,
        nonce_base64url: &frame.nonce_base64url,
        sequence: frame.sequence,
        stream: &frame.stream,
        container: &frame.container,
        timestamp: &frame.timestamp,
    })
    .map_err(|_| LogEncryptionError::InvalidFrame)
}

fn derive_frame_key(
    shared_secret: &[u8; 32],
    recipient_public_key_sha256: &str,
    sender_public_key_base64url: &str,
    key_id: &str,
) -> [u8; 32] {
    let salt = Sha256::digest(
        [
            b"enclava-log-frame-salt-v1".as_slice(),
            recipient_public_key_sha256.as_bytes(),
            sender_public_key_base64url.as_bytes(),
            key_id.as_bytes(),
        ]
        .concat(),
    );
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut out = [0u8; 32];
    hk.expand(b"enclava-log-frame-key-v1", &mut out)
        .expect("32-byte HKDF output is valid");
    out
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], base64::DecodeError> {
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes())?;
    decoded
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypair_encrypts_and_decrypts_frame() {
        let keypair = generate_log_keypair();
        let recipient = validate_public_key(
            "logs-prod",
            &keypair.public_key_base64url,
            &keypair.public_key_sha256,
        )
        .unwrap();
        let context = LogFrameContext {
            org_id: "org-123".to_string(),
            app_name: "secure-app".to_string(),
            deployment_id: "deploy-123".to_string(),
        };
        let frame = encrypt_log_frame(
            &recipient,
            &context,
            7,
            "stdout",
            "app",
            "2026-07-05T12:00:00Z",
            b"tenant secret",
        )
        .unwrap();

        assert_ne!(frame.ciphertext_base64url, "tenant secret");
        assert_eq!(frame.org_id, "org-123");
        assert_eq!(frame.app_name, "secure-app");
        assert_eq!(frame.deployment_id, "deploy-123");
        let plaintext = decrypt_log_frame(&keypair.private_key_base64url, &frame).unwrap();
        assert_eq!(plaintext, b"tenant secret");
    }

    #[test]
    fn decrypt_rejects_tampered_routing_context() {
        let keypair = generate_log_keypair();
        let recipient = validate_public_key(
            "logs-prod",
            &keypair.public_key_base64url,
            &keypair.public_key_sha256,
        )
        .unwrap();
        let context = LogFrameContext {
            org_id: "org-123".to_string(),
            app_name: "secure-app".to_string(),
            deployment_id: "deploy-123".to_string(),
        };
        let mut frame = encrypt_log_frame(
            &recipient,
            &context,
            1,
            "stdout",
            "app",
            "2026-07-05T12:00:00Z",
            b"x",
        )
        .unwrap();
        frame.deployment_id = "deploy-456".to_string();

        let err = decrypt_log_frame(&keypair.private_key_base64url, &frame).unwrap_err();
        assert!(matches!(err, LogEncryptionError::Decrypt));
    }

    #[test]
    fn decrypt_rejects_wrong_private_key() {
        let keypair = generate_log_keypair();
        let other = generate_log_keypair();
        let recipient = validate_public_key(
            "logs-prod",
            &keypair.public_key_base64url,
            &keypair.public_key_sha256,
        )
        .unwrap();
        let context = LogFrameContext {
            org_id: "org-123".to_string(),
            app_name: "secure-app".to_string(),
            deployment_id: "deploy-123".to_string(),
        };
        let frame = encrypt_log_frame(
            &recipient,
            &context,
            1,
            "stdout",
            "app",
            "2026-07-05T12:00:00Z",
            b"x",
        )
        .unwrap();

        let err = decrypt_log_frame(&other.private_key_base64url, &frame).unwrap_err();
        assert!(matches!(err, LogEncryptionError::WrongKey));
    }
}
