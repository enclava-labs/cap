use super::{TeeClient, accepts_invalid_tee_certs, normalize_unlock_mode};
use sev::parser::ByteParser;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[test]
fn normalizes_plain_domain_to_confidential_base() {
    let tee = TeeClient::new("app.enclava.dev");
    assert_eq!(
        tee.url("/status"),
        "https://app.enclava.dev/.well-known/confidential/status"
    );
}

#[test]
fn accepts_api_returned_confidential_base() {
    let tee = TeeClient::new("https://app.enclava.dev/.well-known/confidential");
    assert_eq!(
        tee.url("/bootstrap/challenge"),
        "https://app.enclava.dev/.well-known/confidential/bootstrap/challenge"
    );
}

#[test]
fn accepts_api_returned_config_base() {
    let tee = TeeClient::from_config_url("https://app.enclava.dev/.well-known/confidential/config");
    assert_eq!(
        tee.url("/config/MY_KEY"),
        "https://app.enclava.dev/.well-known/confidential/config/MY_KEY"
    );
}

#[test]
fn ownership_client_timeout_covers_live_rollout_budget() {
    let tee = TeeClient::new_for_ownership("app.enclava.dev");

    assert!(
        tee.timeout >= Duration::from_secs(600),
        "ownership requests must cover slow Kata first boot within the CAP rollout budget"
    );
}

#[test]
fn ownership_connect_override_preserves_public_tee_domain() {
    let tee = TeeClient::new_for_ownership_with_connect_override(
        "https://app.tenant.tee.enclava.dev/.well-known/confidential",
        "app.cap-tenant-app.svc.cluster.local",
        8081,
    );

    assert_eq!(
        tee.url("/status"),
        "https://app.tenant.tee.enclava.dev:8081/.well-known/confidential/status"
    );
    assert_eq!(
        tee.logical_host_for_attestation().unwrap(),
        "app.tenant.tee.enclava.dev"
    );
}

#[test]
fn challenge_response_accepts_live_proxy_shape() {
    let parsed: super::ChallengeResponse = serde_json::from_value(serde_json::json!({
        "challenge": "abc",
        "nonce": "abc",
        "expires_in_seconds": 300.0
    }))
    .expect("parse challenge");
    assert_eq!(parsed.nonce, "abc");
    assert_eq!(parsed.ttl_seconds, 300);
}

#[test]
fn only_claimed_ownership_state_means_owner_claim_succeeded() {
    assert!(super::claim_state_json_is_successful(
        &serde_json::json!({"ownership_state": "claimed", "unlock_state": "locked"})
    ));
    assert!(super::claim_state_json_is_successful(
        &serde_json::json!({"state": "claimed"})
    ));
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"state": "locked"})
    ));
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"ownership_state": "locked"})
    ));
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"unlock_state": "unlocked"})
    ));
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"state": "unclaimed"})
    ));
}

#[test]
fn staging_tls_mode_accepts_invalid_tee_certs() {
    let _guard = env_lock();
    unsafe {
        std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
        std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
    }
    assert!(accepts_invalid_tee_certs());
    unsafe {
        std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
    }
}

#[test]
fn default_tls_mode_requires_valid_tee_certs() {
    let _guard = env_lock();
    unsafe {
        std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
    }
    assert!(!accepts_invalid_tee_certs());
}

#[test]
fn change_password_body_matches_attestation_proxy_contract() {
    assert_eq!(
        super::change_password_body("old", "new"),
        serde_json::json!({
            "old_password": "old",
            "new_password": "new",
        })
    );
}

#[test]
fn unlock_mode_receipt_modes_are_stable() {
    assert_eq!(normalize_unlock_mode("password"), "password");
    assert_eq!(normalize_unlock_mode("auto-unlock"), "auto");
    assert_eq!(normalize_unlock_mode("auto"), "auto");
}

#[tokio::test]
async fn verifies_attestation_evidence_report_data_binding() {
    let expected = [0x42; 64];
    let evidence = super::AttestationEvidence {
        payload_b64: String::new(),
        json: Some(serde_json::json!({
            "attestation_report": {
                "report_data": hex::encode(expected),
            }
        })),
    };

    super::verify_evidence_report_data_with_json_fallback(&evidence, b"", &expected, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_attestation_evidence_report_data_mismatch() {
    let expected = [0x42; 64];
    let evidence = super::AttestationEvidence {
        payload_b64: String::new(),
        json: Some(serde_json::json!({
            "attestation_report": {
                "report_data": hex::encode([0x24; 64]),
            }
        })),
    };

    assert!(
        super::verify_evidence_report_data_with_json_fallback(&evidence, b"", &expected, true)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_json_only_attestation_evidence_by_default() {
    let expected = [0x42; 64];
    let evidence = super::AttestationEvidence {
        payload_b64: String::new(),
        json: Some(serde_json::json!({
            "attestation_report": {
                "report_data": hex::encode(expected),
            }
        })),
    };

    let err =
        super::verify_evidence_report_data_with_json_fallback(&evidence, b"", &expected, false)
            .await
            .unwrap_err();
    assert!(err.to_string().contains("raw AMD SNP report"));
}

#[test]
fn extracts_coco_structured_snp_report_bytes() {
    let mut report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(25),
        cpuid_mod_id: Some(160),
        cpuid_step: Some(2),
        ..Default::default()
    };
    report.report_data = [0x42; 64];

    let expected = report.to_bytes().unwrap().as_ref().to_vec();
    let evidence = serde_json::json!({
        "attestation_report": serde_json::to_value(report).unwrap(),
    });

    assert_eq!(
        super::extract_snp_report_bytes(&evidence).unwrap(),
        expected
    );
}

#[test]
fn extracts_coco_cert_chain_by_cert_type() {
    let evidence = serde_json::json!({
        "cert_chain": [
            {"cert_type": "ASK", "data": [4, 5, 6]},
            {"cert_type": "VCEK", "data": [7, 8, 9]},
            {"cert_type": "ARK", "data": [1, 2, 3]}
        ]
    });

    let chain = super::extract_snp_der_chain(&evidence).unwrap();
    assert_eq!(chain.ark_der, vec![1, 2, 3]);
    assert_eq!(chain.ask_der, vec![4, 5, 6]);
    assert_eq!(chain.vcek_der, vec![7, 8, 9]);
}

#[test]
fn builds_amd_kds_vcek_url_from_snp_report() {
    let report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(25),
        cpuid_mod_id: Some(160),
        cpuid_step: Some(2),
        reported_tcb: sev::firmware::host::TcbVersion {
            fmc: None,
            bootloader: 10,
            tee: 0,
            snp: 24,
            microcode: 84,
        },
        chip_id: [0xab; 64],
        ..Default::default()
    };

    let url = super::amd_kds_vcek_url(&report, "https://kdsintf.amd.com/").unwrap();

    assert_eq!(
        url,
        format!(
            "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=10&teeSPL=00&snpSPL=24&ucodeSPL=84",
            "ab".repeat(64)
        )
    );
}

#[test]
fn amd_kds_vcek_retries_rate_limits_and_server_errors() {
    assert!(super::amd_kds_vcek_should_retry(
        reqwest::StatusCode::TOO_MANY_REQUESTS
    ));
    assert!(super::amd_kds_vcek_should_retry(
        reqwest::StatusCode::BAD_GATEWAY
    ));
    assert!(!super::amd_kds_vcek_should_retry(
        reqwest::StatusCode::BAD_REQUEST
    ));
}

#[test]
fn loads_builtin_amd_snp_ca_chain_for_report_generation() {
    let report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(25),
        cpuid_mod_id: Some(160),
        cpuid_step: Some(2),
        ..Default::default()
    };

    let (ark_der, ask_der) = super::builtin_snp_ca_der_chain(&report).unwrap();

    assert!(ark_der.starts_with(&[0x30]));
    assert!(ask_der.starts_with(&[0x30]));
}
