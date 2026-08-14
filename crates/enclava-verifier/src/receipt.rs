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
    #[error("appraisal receipt policy is not the pinned policy")]
    PolicyMismatch,
    #[error("appraisal receipt challenge nonce is not the pinned nonce")]
    NonceMismatch,
    #[error("appraisal receipt target origin is not the pinned origin")]
    OriginMismatch,
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
            Self::PolicyMismatch => "APPRAISER_RECEIPT_POLICY_MISMATCH",
            Self::NonceMismatch => "APPRAISER_RECEIPT_NONCE_MISMATCH",
            Self::OriginMismatch => "APPRAISER_RECEIPT_ORIGIN_MISMATCH",
        }
    }
}

/// The values a relying party chose itself and expects to see echoed in a
/// signed appraisal receipt. The appraiser is a public signing oracle: it
/// signs results for whatever policy and evidence a requester supplies, so a
/// receipt is only meaningful when the consumer pins these fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedReceipt<'a> {
    /// sha256 (hex) of the exact policy document the relying party appraised
    /// under (must equal `AppraisalResult.policy_sha256`).
    pub policy_sha256: Option<&'a str>,
    /// The challenge nonce the relying party issued for this appraisal.
    pub challenge_nonce: Option<&'a str>,
    /// The target origin the relying party expected to be appraised.
    pub target_origin: Option<&'a str>,
}

impl ExpectedReceipt<'_> {
    fn matches(&self, result: &AppraisalResult) -> Result<(), ReceiptError> {
        if let Some(expected) = self.policy_sha256
            && result.policy_sha256 != expected
        {
            return Err(ReceiptError::PolicyMismatch);
        }
        if let Some(expected) = self.challenge_nonce
            && result.challenge_nonce != expected
        {
            return Err(ReceiptError::NonceMismatch);
        }
        if let Some(expected) = self.target_origin
            && result.target_origin != expected
        {
            return Err(ReceiptError::OriginMismatch);
        }
        Ok(())
    }
}

/// Verifies a signed appraisal response AND binds it to the relying party's
/// own choices. This is the function consumers should call; a validly-signed
/// PASS receipt produced under an attacker-chosen policy, nonce, or origin is
/// rejected here.
pub fn verify_appraisal_response_pinned(
    response_bytes: &[u8],
    policy: &AppraiserPolicy,
    now_unix_seconds: u64,
    expected: &ExpectedReceipt<'_>,
) -> Result<AppraisalResponse, ReceiptError> {
    let response = verify_appraisal_response(response_bytes, policy, now_unix_seconds)?;
    expected.matches(&response.result)?;
    Ok(response)
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

    #[test]
    fn pinned_verification_rejects_attacker_chosen_policy_nonce_origin() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy = policy(&[(&key, "new", false)]);
        let bytes = response(&key, "new", 1_000);

        // Matching expectations pass.
        assert!(
            verify_appraisal_response_pinned(
                &bytes,
                &policy,
                1_001,
                &ExpectedReceipt {
                    policy_sha256: Some(&"22".repeat(32)),
                    challenge_nonce: Some(&"33".repeat(32)),
                    target_origin: Some("https://example.com"),
                },
            )
            .is_ok()
        );

        // A validly-signed receipt appraised under a DIFFERENT policy (the
        // appraiser signs whatever policy the requester posts) must be
        // rejected when the relying party pinned its own policy hash.
        assert_eq!(
            verify_appraisal_response_pinned(
                &bytes,
                &policy,
                1_001,
                &ExpectedReceipt {
                    policy_sha256: Some(&"44".repeat(32)),
                    ..Default::default()
                },
            )
            .unwrap_err(),
            ReceiptError::PolicyMismatch
        );
        assert_eq!(
            verify_appraisal_response_pinned(
                &bytes,
                &policy,
                1_001,
                &ExpectedReceipt {
                    challenge_nonce: Some(&"55".repeat(32)),
                    ..Default::default()
                },
            )
            .unwrap_err(),
            ReceiptError::NonceMismatch
        );
        assert_eq!(
            verify_appraisal_response_pinned(
                &bytes,
                &policy,
                1_001,
                &ExpectedReceipt {
                    target_origin: Some("https://attacker.example"),
                    ..Default::default()
                },
            )
            .unwrap_err(),
            ReceiptError::OriginMismatch
        );
    }
}
