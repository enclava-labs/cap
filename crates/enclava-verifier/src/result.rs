use enclava_common::canonical::ce_v1_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckOutcome {
    Pass,
    Fail,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub id: String,
    pub outcome: CheckOutcome,
    pub observed: Option<String>,
    pub expected: Option<String>,
    pub reason_code: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AppraisalResult {
    pub verdict: Verdict,
    pub bundle_sha256: String,
    pub policy_sha256: String,
    pub target_origin: String,
    pub challenge_nonce: String,
    pub verified_at: u64,
    pub verifier_version: String,
    pub checks: Vec<CheckResult>,
    pub warnings: Vec<String>,
}

pub fn canonical_result_bytes(result: &AppraisalResult) -> Vec<u8> {
    let verified_at = result.verified_at.to_string();
    let checks = result
        .checks
        .iter()
        .map(canonical_check_bytes)
        .collect::<Vec<_>>();
    let warnings = result
        .warnings
        .iter()
        .map(|warning| warning.as_bytes())
        .collect::<Vec<_>>();
    let mut records = vec![
        ("purpose", b"enclava-appraisal-result-v1".as_slice()),
        ("verdict", verdict_name(result.verdict).as_bytes()),
        ("bundle_sha256", result.bundle_sha256.as_bytes()),
        ("policy_sha256", result.policy_sha256.as_bytes()),
        ("target_origin", result.target_origin.as_bytes()),
        ("challenge_nonce", result.challenge_nonce.as_bytes()),
        ("verified_at", verified_at.as_bytes()),
        ("verifier_version", result.verifier_version.as_bytes()),
    ];
    records.extend(checks.iter().map(|check| ("check", check.as_slice())));
    records.extend(warnings.iter().map(|warning| ("warning", *warning)));
    ce_v1_bytes(&records)
}

pub fn canonical_result_sha256(result: &AppraisalResult) -> [u8; 32] {
    Sha256::digest(canonical_result_bytes(result)).into()
}

fn canonical_check_bytes(check: &CheckResult) -> Vec<u8> {
    ce_v1_bytes(&[
        ("id", check.id.as_bytes()),
        ("outcome", outcome_name(check.outcome).as_bytes()),
        (
            "observed_present",
            if check.observed.is_some() { b"1" } else { b"0" },
        ),
        (
            "observed",
            check.observed.as_deref().unwrap_or_default().as_bytes(),
        ),
        (
            "expected_present",
            if check.expected.is_some() { b"1" } else { b"0" },
        ),
        (
            "expected",
            check.expected.as_deref().unwrap_or_default().as_bytes(),
        ),
        ("reason_code", check.reason_code.as_bytes()),
    ])
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
    }
}

fn outcome_name(outcome: CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Pass => "PASS",
        CheckOutcome::Fail => "FAIL",
        CheckOutcome::Skipped => "SKIPPED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_changes_with_context_check() {
        let mut result = AppraisalResult {
            verdict: Verdict::Inconclusive,
            bundle_sha256: "00".repeat(32),
            policy_sha256: "11".repeat(32),
            target_origin: "https://app.example".into(),
            challenge_nonce: "22".repeat(32),
            verified_at: 1_770_000_000,
            verifier_version: env!("CARGO_PKG_VERSION").into(),
            checks: vec![],
            warnings: vec![],
        };
        let before = canonical_result_sha256(&result);
        result.checks.push(CheckResult {
            id: "transport.tls_channel_spki".into(),
            outcome: CheckOutcome::Skipped,
            observed: None,
            expected: None,
            reason_code: "CHANNEL_SPKI_UNAVAILABLE".into(),
        });
        assert_ne!(before, canonical_result_sha256(&result));
    }

    #[test]
    fn canonical_hash_distinguishes_absent_and_empty_values() {
        let mut check = CheckResult {
            id: "test".into(),
            outcome: CheckOutcome::Skipped,
            observed: None,
            expected: None,
            reason_code: "TEST".into(),
        };
        let absent = canonical_check_bytes(&check);
        check.observed = Some(String::new());
        assert_ne!(absent, canonical_check_bytes(&check));
    }
}
