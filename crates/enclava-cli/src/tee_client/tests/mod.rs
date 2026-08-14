use super::{
    TeeClient, TeeError, accepts_invalid_tee_certs, is_tee_tcp_connect_error, normalize_unlock_mode,
};
use sev::parser::ByteParser;
use std::net::IpAddr;
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
fn paas_provided_edge_resolve_ip_is_preserved() {
    let resolve_ip: IpAddr = "95.217.56.248".parse().unwrap();
    let tee = TeeClient::from_config_url_with_resolve_ip(
        "https://app.enclava.dev/.well-known/confidential/config",
        Some(resolve_ip),
    );
    let ownership = TeeClient::new_for_ownership_with_resolve_ip(
        "https://app.enclava.dev/.well-known/confidential",
        Some(resolve_ip),
    );

    assert_eq!(tee.resolve_ip, Some(resolve_ip));
    assert_eq!(ownership.resolve_ip, Some(resolve_ip));
}

#[test]
fn private_resolve_ip_fallback_is_limited_to_tcp_connect_errors() {
    assert!(is_tee_tcp_connect_error(&TeeError::Attestation(
        "TEE TCP connect timed out".to_string()
    )));
    assert!(!is_tee_tcp_connect_error(&TeeError::Attestation(
        "TEE TLS handshake failed: invalid certificate".to_string()
    )));
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
fn ownership_probe_client_uses_short_timeout_and_preserves_resolve_ip() {
    let resolve_ip: IpAddr = "95.217.56.248".parse().unwrap();
    let probe =
        TeeClient::new_for_ownership_probe_with_resolve_ip("app.enclava.dev", Some(resolve_ip));
    let claim = TeeClient::new_for_ownership_with_resolve_ip("app.enclava.dev", Some(resolve_ip));

    assert_eq!(probe.resolve_ip, Some(resolve_ip));
    assert_eq!(probe.timeout, Duration::from_secs(15));
    assert!(
        probe.timeout < claim.timeout,
        "readiness probes must not inherit the long claim/unlock request timeout"
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
fn claim_response_captures_owner_seed_mnemonic_from_live_proxy_shape() {
    // Exact shape of the attestation-proxy claim-success (HTTP 200) body. The
    // recovery mnemonic only ever leaves the TEE under the `owner_seed_mnemonic`
    // key; if this parse stops populating `mnemonic`, `recover` becomes
    // unsatisfiable for every app claimed while the mismatch exists.
    let parsed: super::ClaimResponse = serde_json::from_value(serde_json::json!({
        "status": "CLAIM_ACCEPTED",
        "state": "unlocked",
        "owner_public_key": "x",
        "owner_seed_mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "warning": null
    }))
    .expect("parse claim success");
    assert_eq!(parsed.status, "CLAIM_ACCEPTED");
    assert_eq!(
        parsed.mnemonic.as_deref(),
        Some(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ),
        "the one-time recovery mnemonic must survive claim-response deserialization"
    );
}

#[test]
fn post_claim_ownership_states_mean_owner_claim_succeeded() {
    for field in ["ownership_state", "state"] {
        for state in ["locked", "unlocking", "unlocked"] {
            assert!(
                super::claim_state_json_is_successful(&serde_json::json!({ (field): state })),
                "{field}={state} should mean ownership was claimed"
            );
        }

        for state in ["unclaimed", "error"] {
            assert!(
                !super::claim_state_json_is_successful(&serde_json::json!({ (field): state })),
                "{field}={state} should not mean a successful claim"
            );
        }
    }

    // `ownership_state` takes precedence over a legacy `state` field
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"ownership_state": "unclaimed", "state": "unlocked"})
    ));
    // neither recognized field present
    assert!(!super::claim_state_json_is_successful(
        &serde_json::json!({"unlock_state": "unlocked"})
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

#[test]
fn builtin_amd_ark_roots_are_pinned() {
    // Every generation the CLI can resolve must anchor evidence chains.
    let report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(25),
        cpuid_mod_id: Some(160),
        cpuid_step: Some(2),
        ..Default::default()
    };

    let (ark_der, _) = super::builtin_snp_ca_der_chain(&report).unwrap();
    assert!(super::ark_is_pinned_to_builtin_root(&ark_der));
}

#[test]
fn unanchored_ark_bytes_are_not_pinned() {
    assert!(!super::ark_is_pinned_to_builtin_root(&[0x30, 0x00, 0x01]));
    assert!(!super::ark_is_pinned_to_builtin_root(&[]));
}

#[tokio::test]
async fn evidence_chain_with_unpinned_ark_falls_back_to_kds_and_fails_closed() {
    // An attacker-controlled chain (ARK not matching a builtin AMD root) must
    // never be used for verification: the fallback path attempts an anchored
    // KDS fetch, which is unavailable here, so verification must fail rather
    // than silently trusting the embedded chain.
    let mut report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(25),
        cpuid_mod_id: Some(160),
        cpuid_step: Some(2),
        ..Default::default()
    };
    report.report_data = [0x42; 64];
    let report_bytes = report.to_bytes().unwrap().as_ref().to_vec();

    let evidence = super::AttestationEvidence {
        payload_b64: String::new(),
        json: Some(serde_json::json!({
            "attestation_report": {
                "report_data": hex::encode([0x42; 64]),
            },
            "cert_chain": [
                {"cert_type": "ARK", "data": [1, 2, 3]},
                {"cert_type": "ASK", "data": [4, 5, 6]},
                {"cert_type": "VCEK", "data": [7, 8, 9]}
            ],
            "raw_report": report_bytes,
        })),
    };

    let err =
        super::verify_evidence_report_data_with_json_fallback(&evidence, b"", &[0x42; 64], false)
            .await
            .unwrap_err();
    // Fail-closed: either the KDS fetch failed (offline test env) or chain
    // validation rejected the fabricated chain. Both are acceptable; silently
    // trusting the embedded chain is not.
    assert!(err.to_string().contains("KDS") || err.to_string().contains("DER"));
}

#[test]
fn snp_report_with_debug_policy_is_rejected() {
    let mut report = sev::firmware::guest::AttestationReport::default();
    assert!(crate::attestation::ensure_snp_report_production_policy(&report).is_ok());

    let mut policy = sev::firmware::guest::GuestPolicy::default();
    policy.set_debug_allowed(true);
    report.policy = policy;
    let err = crate::attestation::ensure_snp_report_production_policy(&report).unwrap_err();
    assert!(err.to_string().contains("DEBUG"));
}
