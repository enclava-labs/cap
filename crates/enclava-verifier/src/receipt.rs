use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
use serde::{Deserialize, Serialize};

use crate::{AppraisalResult, AppraiserPolicy, canonical_result_sha256};

#[derive(Debug, Deserialize, Serialize)]
pub struct AppraisalResponse {
    pub result: AppraisalResult,
    pub result_sha256: String,
    pub receipt: Option<SignedReceipt>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedReceipt {
    pub key_id: String,
    pub appraised_at: u64,
    pub expires_at: u64,
    pub public_key_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("malformed appraisal response")]
    MalformedResponse,
    #[error("appraisal result hash mismatch")]
    ResultHashMismatch,
    #[error("appraisal receipt is missing")]
    Missing,
    #[error("appraiser key is not independently trusted")]
    KeyUntrusted,
    #[error("appraiser key is revoked")]
    KeyRevoked,
    #[error("appraiser key is not yet valid")]
    KeyNotYetValid,
    #[error("appraiser key is expired")]
    KeyExpired,
    #[error("appraisal receipt time is invalid")]
    TimeInvalid,
    #[error("appraisal receipt is expired")]
    Expired,
    #[error("appraisal receipt signature is invalid")]
    SignatureInvalid,
}

impl ReceiptError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MalformedResponse => "APPRAISER_RESPONSE_MALFORMED",
            Self::ResultHashMismatch => "APPRAISER_RESULT_HASH_MISMATCH",
            Self::Missing => "APPRAISER_RECEIPT_MISSING",
            Self::KeyUntrusted => "APPRAISER_KEY_UNTRUSTED",
            Self::KeyRevoked => "APPRAISER_KEY_REVOKED",
            Self::KeyNotYetValid => "APPRAISER_KEY_NOT_YET_VALID",
            Self::KeyExpired => "APPRAISER_KEY_EXPIRED",
            Self::TimeInvalid => "APPRAISER_RECEIPT_TIME_INVALID",
            Self::Expired => "APPRAISER_RECEIPT_EXPIRED",
            Self::SignatureInvalid => "APPRAISER_RECEIPT_SIGNATURE_INVALID",
        }
    }
}

pub fn verify_appraisal_response(
    response_bytes: &[u8],
    policy: &AppraiserPolicy,
    now_unix_seconds: u64,
) -> Result<AppraisalResponse, ReceiptError> {
    let response: AppraisalResponse =
        serde_json::from_slice(response_bytes).map_err(|_| ReceiptError::MalformedResponse)?;
    let result_hash = canonical_result_sha256(&response.result);
    if response.result_sha256 != hex::encode(result_hash) {
        return Err(ReceiptError::ResultHashMismatch);
    }
    let receipt = response.receipt.as_ref().ok_or(ReceiptError::Missing)?;
    let key = policy
        .keys
        .iter()
        .find(|key| key.key_id == receipt.key_id)
        .ok_or(ReceiptError::KeyUntrusted)?;
    if key.revoked {
        return Err(ReceiptError::KeyRevoked);
    }
    if receipt.appraised_at < key.not_before_unix_seconds {
        return Err(ReceiptError::KeyNotYetValid);
    }
    if receipt.appraised_at > key.not_after_unix_seconds
        || receipt.expires_at > key.not_after_unix_seconds
    {
        return Err(ReceiptError::KeyExpired);
    }
    if receipt.expires_at < receipt.appraised_at
        || receipt.expires_at - receipt.appraised_at > policy.maximum_receipt_lifetime_seconds
        || receipt.appraised_at > now_unix_seconds.saturating_add(policy.clock_skew_seconds)
    {
        return Err(ReceiptError::TimeInvalid);
    }
    if now_unix_seconds > receipt.expires_at.saturating_add(policy.clock_skew_seconds) {
        return Err(ReceiptError::Expired);
    }
    let trusted_key: [u8; 32] = general_purpose::STANDARD
        .decode(&key.public_key_base64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ReceiptError::KeyUntrusted)?;
    if general_purpose::STANDARD
        .decode(&receipt.public_key_base64)
        .ok()
        .as_deref()
        != Some(trusted_key.as_slice())
    {
        return Err(ReceiptError::KeyUntrusted);
    }
    let verifying_key =
        VerifyingKey::from_bytes(&trusted_key).map_err(|_| ReceiptError::KeyUntrusted)?;
    let signature = general_purpose::STANDARD
        .decode(&receipt.signature_base64)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(ReceiptError::SignatureInvalid)?;
    verifying_key
        .verify(
            &appraisal_receipt_bytes(
                &response.result,
                result_hash,
                receipt.appraised_at,
                receipt.expires_at,
                &receipt.key_id,
            ),
            &signature,
        )
        .map_err(|_| ReceiptError::SignatureInvalid)?;
    Ok(response)
}

pub fn appraisal_receipt_bytes(
    result: &AppraisalResult,
    result_hash: [u8; 32],
    appraised_at: u64,
    expires_at: u64,
    key_id: &str,
) -> Vec<u8> {
    let result_hash = hex::encode(result_hash);
    let appraised_at = appraised_at.to_string();
    let expires_at = expires_at.to_string();
    ce_v1_bytes(&[
        ("purpose", b"enclava-appraisal-receipt-v1"),
        ("result_sha256", result_hash.as_bytes()),
        ("bundle_sha256", result.bundle_sha256.as_bytes()),
        ("policy_sha256", result.policy_sha256.as_bytes()),
        ("challenge_nonce", result.challenge_nonce.as_bytes()),
        ("target_origin", result.target_origin.as_bytes()),
        ("appraised_at", appraised_at.as_bytes()),
        ("expires_at", expires_at.as_bytes()),
        ("verifier_version", result.verifier_version.as_bytes()),
        ("key_id", key_id.as_bytes()),
    ])
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::Verdict;

    fn response(signing_key: &SigningKey, key_id: &str, appraised_at: u64) -> Vec<u8> {
        let result = AppraisalResult {
            verdict: Verdict::Fail,
            bundle_sha256: "11".repeat(32),
            policy_sha256: "22".repeat(32),
            target_origin: "https://example.com".into(),
            challenge_nonce: "33".repeat(32),
            verified_at: appraised_at,
            verifier_version: "0.1.0".into(),
            checks: vec![],
            warnings: vec![],
        };
        let result_hash = canonical_result_sha256(&result);
        let signature = signing_key.sign(&appraisal_receipt_bytes(
            &result,
            result_hash,
            appraised_at,
            appraised_at + 300,
            key_id,
        ));
        serde_json::to_vec(&AppraisalResponse {
            result,
            result_sha256: hex::encode(result_hash),
            receipt: Some(SignedReceipt {
                key_id: key_id.into(),
                appraised_at,
                expires_at: appraised_at + 300,
                public_key_base64: general_purpose::STANDARD
                    .encode(signing_key.verifying_key().as_bytes()),
                signature_base64: general_purpose::STANDARD.encode(signature.to_bytes()),
            }),
        })
        .unwrap()
    }

    fn policy(keys: &[(&SigningKey, &str, bool)]) -> AppraiserPolicy {
        AppraiserPolicy {
            keys: keys
                .iter()
                .map(|(key, id, revoked)| crate::AppraiserKeyPolicy {
                    key_id: (*id).into(),
                    public_key_base64: general_purpose::STANDARD
                        .encode(key.verifying_key().as_bytes()),
                    not_before_unix_seconds: 900,
                    not_after_unix_seconds: 2_000,
                    revoked: *revoked,
                })
                .collect(),
            maximum_receipt_lifetime_seconds: 300,
            clock_skew_seconds: 5,
        }
    }

    #[test]
    fn accepts_independently_pinned_rotation_overlap_key() {
        let old = SigningKey::from_bytes(&[7; 32]);
        let new = SigningKey::from_bytes(&[8; 32]);
        let policy = policy(&[(&old, "old", false), (&new, "new", false)]);
        assert!(verify_appraisal_response(&response(&new, "new", 1_000), &policy, 1_001).is_ok());
    }

    #[test]
    fn rejects_response_only_expired_and_revoked_keys() {
        let key = SigningKey::from_bytes(&[7; 32]);
        assert_eq!(
            verify_appraisal_response(&response(&key, "new", 1_000), &policy(&[]), 1_001)
                .unwrap_err(),
            ReceiptError::KeyUntrusted
        );
        let mut expired = policy(&[(&key, "new", false)]);
        expired.keys[0].not_after_unix_seconds = 999;
        assert_eq!(
            verify_appraisal_response(&response(&key, "new", 1_000), &expired, 1_001).unwrap_err(),
            ReceiptError::KeyExpired
        );
        assert_eq!(
            verify_appraisal_response(
                &response(&key, "new", 1_000),
                &policy(&[(&key, "new", true)]),
                1_001
            )
            .unwrap_err(),
            ReceiptError::KeyRevoked
        );
    }
}
