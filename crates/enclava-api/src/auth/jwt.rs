use chrono::{Duration, Utc};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Issuer claim baked into every API-issued token.
pub const TOKEN_ISSUER: &str = "enclava-cap";
/// Audience for browser/CLI session tokens.
pub const SESSION_AUDIENCE: &str = "enclava:session";
/// Audience for short-lived config tokens consumed by the TEE.
pub const CONFIG_AUDIENCE: &str = "enclava:config";
/// Audience for signer rotation confirmation tokens.
pub const SIGNER_ROTATION_AUDIENCE: &str = "enclava:signer-rotation";

/// `typ` claim value for session tokens.
pub const SESSION_TYP: &str = "session";
/// `typ` claim value for config tokens.
pub const CONFIG_TYP: &str = "config";
/// `typ` claim value for signer rotation confirmation tokens.
pub const SIGNER_ROTATION_TYP: &str = "signer-rotation";

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String, // user_id
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigTokenClaims {
    pub sub: String, // user_id
    pub org_id: String,
    pub app_id: String,
    pub instance_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
}

#[derive(Debug)]
pub struct IssuedConfigToken {
    pub token: String,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ConfigTokenIssuance {
    pub receipt_version: i16,
    pub issued_at: chrono::DateTime<Utc>,
    pub jti: String,
    pub resource_id: Uuid,
    pub instance_id: String,
}

pub const CONFIG_TOKEN_TTL_SECONDS: i64 = 5 * 60;
pub const CONFIG_TOKEN_RECEIPT_VERSION: i16 = 1;

#[derive(Debug, Clone)]
pub struct SignerRotationTokenInput {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub previous_subject: String,
    pub previous_issuer: String,
    pub new_subject: String,
    pub new_issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignerRotationClaims {
    pub sub: String,
    pub org_id: String,
    pub app_id: String,
    pub previous_subject: String,
    pub previous_issuer: String,
    pub new_subject: String,
    pub new_issuer: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token encoding failed: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
    #[error("token expired")]
    Expired,
    #[error("invalid token")]
    Invalid,
    #[error("key encoding failed: {0}")]
    KeyEncoding(String),
}

/// Generate a secure HMAC key for JWT signing.
pub fn generate_hmac_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn new_jti() -> String {
    Uuid::new_v4().to_string()
}

fn session_validator() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[SESSION_AUDIENCE]);
    validation
}

fn config_validator() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[CONFIG_AUDIENCE]);
    validation
}

fn signer_rotation_validator() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[SIGNER_ROTATION_AUDIENCE]);
    validation
}

/// Issue a session JWT (HS256, signed with a dedicated HMAC key).
/// Session tokens last 24 hours.
pub fn issue_session_token(hmac_key: &[u8; 32], user_id: Uuid) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = SessionClaims {
        sub: user_id.to_string(),
        exp: (now + Duration::hours(24)).timestamp(),
        iat: now.timestamp(),
        iss: TOKEN_ISSUER.to_string(),
        aud: SESSION_AUDIENCE.to_string(),
        typ: SESSION_TYP.to_string(),
        jti: new_jti(),
        org_id: None,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(hmac_key),
    )?;
    Ok(token)
}

/// Verify and decode a session JWT.
pub fn verify_session_token(hmac_key: &[u8; 32], token: &str) -> Result<SessionClaims, JwtError> {
    let validation = session_validator();
    let data = decode::<SessionClaims>(token, &DecodingKey::from_secret(hmac_key), &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        })?;

    if data.claims.typ != SESSION_TYP {
        return Err(JwtError::Invalid);
    }

    Ok(data.claims)
}

/// Issue a short-lived config token (5 minutes) for CLI -> TEE config writes.
/// Uses Ed25519 (EdDSA) so the TEE can verify with the public key embedded in cc_init_data.
pub fn issue_config_token(
    signing_key: &SigningKey,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    instance_id: &str,
    scopes: Vec<String>,
) -> Result<String, JwtError> {
    issue_config_token_with_expiry(signing_key, user_id, org_id, app_id, instance_id, scopes)
        .map(|issued| issued.token)
}

/// Issue a config token together with the exact whole-second expiry encoded
/// in its signed `exp` claim.
pub fn issue_config_token_with_expiry(
    signing_key: &SigningKey,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    instance_id: &str,
    scopes: Vec<String>,
) -> Result<IssuedConfigToken, JwtError> {
    let issued_at =
        chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).ok_or(JwtError::Invalid)?;
    issue_config_token_for_issuance(
        signing_key,
        user_id,
        org_id,
        app_id,
        instance_id,
        scopes,
        &ConfigTokenIssuance {
            receipt_version: CONFIG_TOKEN_RECEIPT_VERSION,
            issued_at,
            jti: new_jti(),
            resource_id: app_id,
            instance_id: instance_id.to_string(),
        },
    )
}

/// Issue the exact config JWT described by a durable, non-secret issuance
/// receipt. Ed25519 signing is deterministic, so the same claims regenerate
/// the same compact bearer without storing it.
pub fn issue_config_token_for_issuance(
    signing_key: &SigningKey,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    instance_id: &str,
    scopes: Vec<String>,
    issuance: &ConfigTokenIssuance,
) -> Result<IssuedConfigToken, JwtError> {
    if issuance.receipt_version != CONFIG_TOKEN_RECEIPT_VERSION
        || issuance.resource_id != app_id
        || issuance.instance_id != instance_id
    {
        return Err(JwtError::Invalid);
    }
    let issued_at = chrono::DateTime::from_timestamp(issuance.issued_at.timestamp(), 0)
        .ok_or(JwtError::Invalid)?;
    let expires_at = issued_at + Duration::seconds(CONFIG_TOKEN_TTL_SECONDS);
    let claims = ConfigTokenClaims {
        sub: user_id.to_string(),
        org_id: org_id.to_string(),
        app_id: app_id.to_string(),
        instance_id: instance_id.to_string(),
        scopes,
        exp: expires_at.timestamp(),
        iat: issued_at.timestamp(),
        iss: TOKEN_ISSUER.to_string(),
        aud: CONFIG_AUDIENCE.to_string(),
        typ: CONFIG_TYP.to_string(),
        jti: issuance.jti.clone(),
    };

    let secret = signing_key
        .to_pkcs8_der()
        .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_der(secret.as_bytes()),
    )?;
    Ok(IssuedConfigToken {
        token,
        issued_at,
        expires_at,
    })
}

/// Verify a config token using an Ed25519 verifying key. Used in tests and
/// for any future API-side verification path; the TEE has its own verifier.
pub fn verify_config_token(
    verifying_key: &VerifyingKey,
    token: &str,
) -> Result<ConfigTokenClaims, JwtError> {
    use base64::Engine;
    let validation = config_validator();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let key = DecodingKey::from_ed_components(&x).map_err(JwtError::Encode)?;
    let data =
        decode::<ConfigTokenClaims>(token, &key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        })?;

    if data.claims.typ != CONFIG_TYP {
        return Err(JwtError::Invalid);
    }
    Ok(data.claims)
}

pub fn issue_signer_rotation_token(
    hmac_key: &[u8; 32],
    input: &SignerRotationTokenInput,
    ttl: Duration,
) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = SignerRotationClaims {
        sub: input.user_id.to_string(),
        org_id: input.org_id.to_string(),
        app_id: input.app_id.to_string(),
        previous_subject: input.previous_subject.clone(),
        previous_issuer: input.previous_issuer.clone(),
        new_subject: input.new_subject.clone(),
        new_issuer: input.new_issuer.clone(),
        exp: (now + ttl).timestamp(),
        iat: now.timestamp(),
        iss: TOKEN_ISSUER.to_string(),
        aud: SIGNER_ROTATION_AUDIENCE.to_string(),
        typ: SIGNER_ROTATION_TYP.to_string(),
        jti: new_jti(),
    };

    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(hmac_key),
    )?)
}

pub fn verify_signer_rotation_token(
    hmac_key: &[u8; 32],
    token: &str,
    expected: &SignerRotationTokenInput,
) -> Result<SignerRotationClaims, JwtError> {
    let validation = signer_rotation_validator();
    let data =
        decode::<SignerRotationClaims>(token, &DecodingKey::from_secret(hmac_key), &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::Invalid,
            })?;
    let claims = data.claims;

    if claims.typ != SIGNER_ROTATION_TYP
        || claims.sub != expected.user_id.to_string()
        || claims.org_id != expected.org_id.to_string()
        || claims.app_id != expected.app_id.to_string()
        || claims.previous_subject != expected.previous_subject
        || claims.previous_issuer != expected.previous_issuer
        || claims.new_subject != expected.new_subject
        || claims.new_issuer != expected.new_issuer
    {
        return Err(JwtError::Invalid);
    }

    Ok(claims)
}

/// Get the Ed25519 verifying (public) key as base64 for embedding in cc_init_data.
pub fn public_key_base64(signing_key: &SigningKey) -> String {
    use base64::Engine;
    let vk: VerifyingKey = signing_key.verifying_key();
    base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_config_token_produces_compact_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let token = issue_config_token(
            &signing_key,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-instance",
            vec!["config:write".to_string()],
        )
        .expect("failed to issue config token");

        assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn session_token_round_trip_includes_required_claims() {
        let key = generate_hmac_key();
        let user = Uuid::new_v4();
        let token = issue_session_token(&key, user).unwrap();
        let claims = verify_session_token(&key, &token).unwrap();
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.aud, SESSION_AUDIENCE);
        assert_eq!(claims.typ, SESSION_TYP);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn config_token_round_trip_includes_required_claims() {
        let signing = SigningKey::generate(&mut OsRng);
        let token = issue_config_token(
            &signing,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-instance",
            vec!["config:write".into()],
        )
        .unwrap();
        let claims = verify_config_token(&signing.verifying_key(), &token).unwrap();
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.aud, CONFIG_AUDIENCE);
        assert_eq!(claims.typ, CONFIG_TYP);
        assert_eq!(claims.instance_id, "test-instance");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn deterministic_config_token_matches_receipt_and_signed_expiry_exactly() {
        let signing = SigningKey::generate(&mut OsRng);
        let issued_at = chrono::DateTime::parse_from_rfc3339("2026-07-18T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let issuance = ConfigTokenIssuance {
            receipt_version: CONFIG_TOKEN_RECEIPT_VERSION,
            issued_at,
            jti: "11111111-2222-8333-8444-555555555555".to_string(),
            resource_id: app_id,
            instance_id: "test-instance".to_string(),
        };
        let first = issue_config_token_for_issuance(
            &signing,
            user_id,
            org_id,
            app_id,
            "test-instance",
            vec!["config:write".to_string()],
            &issuance,
        )
        .unwrap();
        let duplicate = issue_config_token_for_issuance(
            &signing,
            user_id,
            org_id,
            app_id,
            "test-instance",
            vec!["config:write".to_string()],
            &issuance,
        )
        .unwrap();

        assert_eq!(duplicate.token, first.token);
        assert_eq!(first.issued_at, issued_at);
        assert_eq!(first.expires_at - first.issued_at, Duration::minutes(5));
        let claims = verify_config_token(&signing.verifying_key(), &first.token)
            .expect_err("the fixed historical token is expired at verification time");
        assert!(matches!(claims, JwtError::Expired));

        let validation = config_validator();
        assert_eq!(validation.leeway, 0);
        let decoding_key = {
            use base64::Engine;
            let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing.verifying_key().to_bytes());
            DecodingKey::from_ed_components(&x).unwrap()
        };
        let mut claim_validation = config_validator();
        claim_validation.validate_exp = false;
        let decoded = decode::<ConfigTokenClaims>(&first.token, &decoding_key, &claim_validation)
            .unwrap()
            .claims;
        assert_eq!(decoded.iat, first.issued_at.timestamp());
        assert_eq!(decoded.exp, first.expires_at.timestamp());
        assert_eq!(decoded.exp - decoded.iat, CONFIG_TOKEN_TTL_SECONDS);
        assert_eq!(decoded.jti, issuance.jti);
    }

    #[test]
    fn config_token_validator_rejects_immediately_after_signed_expiry() {
        let signing = SigningKey::generate(&mut OsRng);
        let issued_at = chrono::DateTime::from_timestamp(
            Utc::now().timestamp() - CONFIG_TOKEN_TTL_SECONDS - 1,
            0,
        )
        .unwrap();
        let app_id = Uuid::new_v4();
        let token = issue_config_token_for_issuance(
            &signing,
            Uuid::new_v4(),
            Uuid::new_v4(),
            app_id,
            "expired-instance",
            vec!["config:write".to_string()],
            &ConfigTokenIssuance {
                receipt_version: CONFIG_TOKEN_RECEIPT_VERSION,
                issued_at,
                jti: Uuid::new_v4().to_string(),
                resource_id: app_id,
                instance_id: "expired-instance".to_string(),
            },
        )
        .unwrap();
        assert!(matches!(
            verify_config_token(&signing.verifying_key(), &token.token),
            Err(JwtError::Expired)
        ));
    }

    #[test]
    fn session_validator_rejects_config_token() {
        // Cross-audience swap: a config token must not pass session checks.
        let hmac = generate_hmac_key();
        let signing = SigningKey::generate(&mut OsRng);
        let config_token = issue_config_token(
            &signing,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-instance",
            vec!["config:write".into()],
        )
        .unwrap();
        // Different signing material AND different audience: should fail.
        assert!(verify_session_token(&hmac, &config_token).is_err());
    }

    #[test]
    fn token_with_wrong_audience_rejected() {
        use jsonwebtoken::{EncodingKey, Header};
        let key = generate_hmac_key();
        let now = Utc::now();
        let claims = SessionClaims {
            sub: Uuid::new_v4().to_string(),
            exp: (now + Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            iss: TOKEN_ISSUER.to_string(),
            aud: "evil:audience".to_string(),
            typ: SESSION_TYP.to_string(),
            jti: Uuid::new_v4().to_string(),
            org_id: None,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        assert!(matches!(
            verify_session_token(&key, &token),
            Err(JwtError::Invalid)
        ));
    }

    #[test]
    fn token_missing_iss_rejected() {
        use jsonwebtoken::{EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct NoIss {
            sub: String,
            exp: i64,
            iat: i64,
            aud: String,
            typ: String,
        }
        let key = generate_hmac_key();
        let now = Utc::now();
        let claims = NoIss {
            sub: Uuid::new_v4().to_string(),
            exp: (now + Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            aud: SESSION_AUDIENCE.to_string(),
            typ: SESSION_TYP.to_string(),
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        assert!(matches!(
            verify_session_token(&key, &token),
            Err(JwtError::Invalid)
        ));
    }

    fn signer_rotation_input() -> SignerRotationTokenInput {
        SignerRotationTokenInput {
            user_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            previous_subject: "repo:old/app:ref:refs/heads/main".to_string(),
            previous_issuer: "https://token.actions.githubusercontent.com".to_string(),
            new_subject: "repo:new/app:ref:refs/heads/main".to_string(),
            new_issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    #[test]
    fn signer_rotation_token_round_trip_is_bound_to_rotation_fields() {
        let key = generate_hmac_key();
        let input = signer_rotation_input();
        let token = issue_signer_rotation_token(&key, &input, Duration::minutes(10)).unwrap();
        let claims = verify_signer_rotation_token(&key, &token, &input).unwrap();

        assert_eq!(claims.aud, SIGNER_ROTATION_AUDIENCE);
        assert_eq!(claims.typ, SIGNER_ROTATION_TYP);
        assert_eq!(claims.sub, input.user_id.to_string());
        assert_eq!(claims.app_id, input.app_id.to_string());
        assert_eq!(claims.previous_subject, input.previous_subject);
        assert_eq!(claims.new_subject, input.new_subject);
    }

    #[test]
    fn signer_rotation_token_rejects_session_token() {
        let key = generate_hmac_key();
        let input = signer_rotation_input();
        let session = issue_session_token(&key, input.user_id).unwrap();

        assert!(matches!(
            verify_signer_rotation_token(&key, &session, &input),
            Err(JwtError::Invalid)
        ));
    }

    #[test]
    fn signer_rotation_token_rejects_changed_new_subject() {
        let key = generate_hmac_key();
        let input = signer_rotation_input();
        let token = issue_signer_rotation_token(&key, &input, Duration::minutes(10)).unwrap();
        let mut tampered_expected = input.clone();
        tampered_expected.new_subject = "repo:attacker/app:ref:refs/heads/main".to_string();

        assert!(matches!(
            verify_signer_rotation_token(&key, &token, &tampered_expected),
            Err(JwtError::Invalid)
        ));
    }
}
