//! API key creation, hashing, and validation.
//!
//! New API keys are prefixed with "enclava_" and use a 128-bit lookup
//! prefix plus HMAC-SHA256 over a 256-bit secret. Legacy "enc_" Argon2 keys
//! remain verifiable during the migration window.

use crate::auth::email::verify_password;
use base64::Engine;
use chrono::{DateTime, Utc};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Valid API key scopes.
pub const VALID_SCOPES: &[&str] = &["apps:read", "apps:write", "config:write", "org:admin"];

/// Database row for API key lookup.
type ApiKeyRow = (
    Uuid,
    Uuid,
    Uuid,
    String,
    String,
    Vec<String>,
    Option<DateTime<Utc>>,
);

const HMAC_KEY_PREFIX: &str = "enclava_";
const LEGACY_KEY_PREFIX: &str = "enc_";
const HMAC_HASH_FORMAT: &str = "hmac_v1";
const LEGACY_HASH_FORMAT: &str = "argon2_legacy";

#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("name is required")]
    NameRequired,
    #[error("API key not found or expired")]
    NotFound,
    #[error("API key does not have required scope: {0}")]
    InsufficientScope(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("hashing error: {0}")]
    Hash(String),
    #[error("missing API_KEY_HMAC_PEPPER or API_KEY_HMAC_PEPPER_BASE64")]
    MissingPepper,
    #[error("invalid API key format")]
    InvalidFormat,
}

/// Result of creating a new API key.
#[derive(Debug)]
pub struct CreatedApiKey {
    pub id: Uuid,
    /// The raw key -- shown once, never stored.
    pub raw_key: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// Generate a random API key string.
fn generate_raw_key() -> String {
    let mut rng = rand::rngs::OsRng;
    let mut prefix = [0u8; 16];
    let mut secret = [0u8; 32];
    rng.fill(&mut prefix);
    rng.fill(&mut secret);
    format!(
        "{HMAC_KEY_PREFIX}{}_{}",
        BASE32_NOPAD.encode(&prefix),
        BASE32_NOPAD.encode(&secret)
    )
}

/// Create a new API key for an org.
pub async fn create_api_key(
    pool: &PgPool,
    org_id: Uuid,
    created_by: Uuid,
    name: &str,
    scopes: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> Result<CreatedApiKey, ApiKeyError> {
    if name.is_empty() {
        return Err(ApiKeyError::NameRequired);
    }

    for scope in scopes {
        if !VALID_SCOPES.contains(&scope.as_str()) {
            return Err(ApiKeyError::InvalidScope(scope.clone()));
        }
    }

    let raw_key = generate_raw_key();
    let parsed = parse_hmac_key(&raw_key)?;
    let pepper = load_current_pepper()?;
    let key_hash = hmac_sha256_hex(&parsed.secret, &pepper)?;
    let key_prefix = parsed.prefix_encoded;
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO api_keys (
            id, org_id, created_by, key_hash, key_prefix, name, scopes, expires_at, hash_format
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(org_id)
    .bind(created_by)
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(name)
    .bind(scopes)
    .bind(expires_at)
    .bind(HMAC_HASH_FORMAT)
    .execute(pool)
    .await?;

    Ok(CreatedApiKey {
        id,
        raw_key,
        name: name.to_string(),
        scopes: scopes.to_vec(),
    })
}

/// Validated API key result.
#[derive(Debug, Clone)]
pub struct ValidatedApiKey {
    pub id: Uuid,
    pub org_id: Uuid,
    pub created_by: Uuid,
    pub scopes: Vec<String>,
}

/// Validate an API key against database. Returns key metadata if valid.
pub async fn validate_api_key(
    pool: &PgPool,
    raw_key: &str,
) -> Result<ValidatedApiKey, ApiKeyError> {
    let lookup = parse_lookup(raw_key)?;

    let candidates: Vec<ApiKeyRow> = sqlx::query_as(
        "SELECT id, org_id, created_by, key_hash, COALESCE(hash_format, 'argon2_legacy'),
                scopes, expires_at
         FROM api_keys WHERE key_prefix = $1",
    )
    .bind(&lookup.key_prefix)
    .fetch_all(pool)
    .await?;

    // Filter expired keys first
    let valid_candidates: Vec<(Uuid, Uuid, Uuid, String, String, Vec<String>)> = candidates
        .into_iter()
        .filter_map(
            |(id, org_id, created_by, key_hash, hash_format, scopes, expires_at)| {
                if let Some(exp) = expires_at
                    && exp < Utc::now()
                {
                    return None;
                }
                Some((id, org_id, created_by, key_hash, hash_format, scopes))
            },
        )
        .collect();

    for (id, org_id, created_by, key_hash, hash_format, scopes) in valid_candidates {
        let valid = match (&lookup.material, hash_format.as_str()) {
            (LookupMaterial::Hmac { secret }, HMAC_HASH_FORMAT) => {
                verify_hmac_key(secret, &key_hash)?
            }
            (LookupMaterial::Legacy, LEGACY_HASH_FORMAT) => {
                verify_password(raw_key, &key_hash).map_err(|e| ApiKeyError::Hash(e.to_string()))?
            }
            _ => false,
        };

        if valid {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;

            return Ok(ValidatedApiKey {
                id,
                org_id,
                created_by,
                scopes,
            });
        }
    }

    Err(ApiKeyError::NotFound)
}

/// Check that a validated key has a required scope.
pub fn require_scope(key: &ValidatedApiKey, scope: &str) -> Result<(), ApiKeyError> {
    if key.scopes.iter().any(|s| s == scope) {
        Ok(())
    } else {
        Err(ApiKeyError::InsufficientScope(scope.to_string()))
    }
}

/// Returns true when a token has an API-key prefix rather than a session JWT.
pub(crate) fn is_api_key_candidate(token: &str) -> bool {
    token.starts_with(HMAC_KEY_PREFIX) || token.starts_with(LEGACY_KEY_PREFIX)
}

/// Revoke an API key.
pub async fn revoke_api_key(
    pool: &PgPool,
    key_id: Uuid,
    org_id: Uuid,
) -> Result<bool, ApiKeyError> {
    let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND org_id = $2")
        .bind(key_id)
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

struct ParsedHmacKey {
    prefix_encoded: String,
    secret: Vec<u8>,
}

enum LookupMaterial {
    Hmac { secret: Vec<u8> },
    Legacy,
}

struct ParsedLookup {
    key_prefix: String,
    material: LookupMaterial,
}

fn parse_lookup(raw_key: &str) -> Result<ParsedLookup, ApiKeyError> {
    if raw_key.starts_with(HMAC_KEY_PREFIX) {
        let parsed = parse_hmac_key(raw_key)?;
        return Ok(ParsedLookup {
            key_prefix: parsed.prefix_encoded,
            material: LookupMaterial::Hmac {
                secret: parsed.secret,
            },
        });
    }

    if raw_key.starts_with(LEGACY_KEY_PREFIX) && raw_key.len() >= 8 {
        return Ok(ParsedLookup {
            key_prefix: raw_key[..8].to_string(),
            material: LookupMaterial::Legacy,
        });
    }

    Err(ApiKeyError::NotFound)
}

fn parse_hmac_key(raw_key: &str) -> Result<ParsedHmacKey, ApiKeyError> {
    let rest = raw_key
        .strip_prefix(HMAC_KEY_PREFIX)
        .ok_or(ApiKeyError::InvalidFormat)?;
    let (prefix_encoded, secret_encoded) =
        rest.split_once('_').ok_or(ApiKeyError::InvalidFormat)?;
    let prefix = BASE32_NOPAD
        .decode(prefix_encoded.as_bytes())
        .map_err(|_| ApiKeyError::InvalidFormat)?;
    let secret = BASE32_NOPAD
        .decode(secret_encoded.as_bytes())
        .map_err(|_| ApiKeyError::InvalidFormat)?;
    if prefix.len() != 16 || secret.len() != 32 {
        return Err(ApiKeyError::InvalidFormat);
    }
    Ok(ParsedHmacKey {
        prefix_encoded: prefix_encoded.to_string(),
        secret,
    })
}

fn load_current_pepper() -> Result<Vec<u8>, ApiKeyError> {
    if let Ok(b64) = std::env::var("API_KEY_HMAC_PEPPER_BASE64") {
        return decode_base64_pepper(b64.trim());
    }

    if let Ok(value) = std::env::var("API_KEY_HMAC_PEPPER") {
        return decode_raw_or_hex_pepper(value.trim(), "API_KEY_HMAC_PEPPER");
    }

    Err(ApiKeyError::MissingPepper)
}

fn load_accepted_peppers() -> Result<Vec<Vec<u8>>, ApiKeyError> {
    let mut peppers = vec![load_current_pepper()?];
    if let Ok(extra) = std::env::var("API_KEY_HMAC_PEPPER_PREVIOUS") {
        for value in extra.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            if let Ok(decoded) = hex::decode(value)
                && decoded.len() >= 32
            {
                peppers.push(decoded);
                continue;
            }
            let raw = value.as_bytes().to_vec();
            if raw.len() < 32 {
                return Err(ApiKeyError::Hash(
                    "API_KEY_HMAC_PEPPER_PREVIOUS entries must be at least 32 bytes".to_string(),
                ));
            }
            peppers.push(raw);
        }
    }
    Ok(peppers)
}

fn decode_base64_pepper(value: &str) -> Result<Vec<u8>, ApiKeyError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| ApiKeyError::Hash(format!("invalid API_KEY_HMAC_PEPPER_BASE64: {e}")))?;
    if decoded.len() < 32 {
        return Err(ApiKeyError::Hash(
            "API_KEY_HMAC_PEPPER_BASE64 must decode to at least 32 bytes".to_string(),
        ));
    }
    Ok(decoded)
}

fn decode_raw_or_hex_pepper(value: &str, name: &str) -> Result<Vec<u8>, ApiKeyError> {
    if let Ok(decoded) = hex::decode(value)
        && decoded.len() >= 32
    {
        return Ok(decoded);
    }
    let raw = value.as_bytes().to_vec();
    if raw.len() >= 32 {
        return Ok(raw);
    }
    Err(ApiKeyError::Hash(format!(
        "{name} must be at least 32 raw bytes or 32 decoded hex bytes"
    )))
}

fn hmac_sha256_hex(secret: &[u8], pepper: &[u8]) -> Result<String, ApiKeyError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
        .map_err(|e| ApiKeyError::Hash(format!("invalid API key HMAC pepper: {e}")))?;
    mac.update(secret);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_hmac_key(secret: &[u8], stored_hex: &str) -> Result<bool, ApiKeyError> {
    let stored = hex::decode(stored_hex)
        .map_err(|e| ApiKeyError::Hash(format!("stored API key HMAC is not hex: {e}")))?;
    for pepper in load_accepted_peppers()? {
        let candidate = hex::decode(hmac_sha256_hex(secret, &pepper)?)
            .map_err(|e| ApiKeyError::Hash(format!("computed API key HMAC is not hex: {e}")))?;
        if candidate.ct_eq(&stored).into() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hmac_key_has_128_bit_prefix_and_256_bit_secret() {
        let key = generate_raw_key();
        assert!(key.starts_with(HMAC_KEY_PREFIX));
        let parts: Vec<&str> = key
            .strip_prefix(HMAC_KEY_PREFIX)
            .unwrap()
            .split('_')
            .collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 26);
        assert_eq!(parts[1].len(), 52);

        let parsed = parse_hmac_key(&key).unwrap();
        assert_eq!(parsed.prefix_encoded.len(), 26);
        assert_eq!(parsed.secret.len(), 32);
    }

    #[test]
    fn legacy_lookup_uses_short_prefix_for_migration_window() {
        let parsed = parse_lookup("enc_0123456789abcdef").unwrap();
        assert_eq!(parsed.key_prefix, "enc_0123");
        assert!(matches!(parsed.material, LookupMaterial::Legacy));
    }

    #[test]
    fn api_key_candidate_accepts_new_and_legacy_prefixes() {
        assert!(is_api_key_candidate(
            "enclava_ABCDEFG234567ABCDEFG234_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(is_api_key_candidate("enc_0123456789abcdef"));
        assert!(!is_api_key_candidate("eyJhbGciOiJIUzI1NiJ9.jwt"));
    }

    #[test]
    fn hmac_lookup_uses_base32_prefix_only() {
        let key = generate_raw_key();
        let parsed = parse_hmac_key(&key).unwrap();
        let lookup = parse_lookup(&key).unwrap();
        assert_eq!(lookup.key_prefix, parsed.prefix_encoded);
        assert!(!lookup.key_prefix.starts_with(HMAC_KEY_PREFIX));
        assert!(matches!(lookup.material, LookupMaterial::Hmac { .. }));
    }

    #[test]
    fn invalid_hmac_key_lengths_are_rejected() {
        let short_material = format!("{}{}_{}", HMAC_KEY_PREFIX, "A".repeat(26), "A".repeat(51));
        assert!(matches!(
            parse_hmac_key(&short_material),
            Err(ApiKeyError::InvalidFormat)
        ));

        let short_prefix = format!("{}{}_{}", HMAC_KEY_PREFIX, "A".repeat(25), "A".repeat(52));
        assert!(matches!(
            parse_hmac_key(&short_prefix),
            Err(ApiKeyError::InvalidFormat)
        ));
    }

    #[test]
    fn hmac_verification_is_exact() {
        let secret = [7u8; 32];
        let pepper = [9u8; 32];
        let good = hmac_sha256_hex(&secret, &pepper).unwrap();
        let bad = hmac_sha256_hex(&[8u8; 32], &pepper).unwrap();
        let stored = hex::decode(&good).unwrap();
        assert_eq!(hex::decode(good).unwrap().ct_eq(&stored).unwrap_u8(), 1);
        assert_eq!(hex::decode(bad).unwrap().ct_eq(&stored).unwrap_u8(), 0);
    }

    #[test]
    fn pepper_decoding_accepts_raw_hex_and_base64_values() {
        let raw = "01234567890123456789012345678901";
        assert_eq!(
            decode_raw_or_hex_pepper(raw, "API_KEY_HMAC_PEPPER").unwrap(),
            raw.as_bytes()
        );

        let hex_value = "0909090909090909090909090909090909090909090909090909090909090909";
        assert_eq!(
            decode_raw_or_hex_pepper(hex_value, "API_KEY_HMAC_PEPPER").unwrap(),
            vec![9u8; 32]
        );

        let b64_value = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(decode_base64_pepper(&b64_value).unwrap(), vec![7u8; 32]);
    }
}
