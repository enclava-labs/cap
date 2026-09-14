use super::{
    TeeClient, TeeError, accepts_invalid_tee_certs, is_tee_tcp_connect_error, normalize_unlock_mode,
};
use sev::parser::ByteParser;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
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
    assert!(!is_tee_tcp_connect_error(&TeeError::Attestation(
        "TEE TLS handshake timed out".to_string()
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

    // The development JSON evidence path yields no trusted launch identity:
    // callers fail closed on deployment binding.
    assert!(
        super::verify_evidence_report_data_with_json_fallback(&evidence, b"", &expected, true)
            .await
            .unwrap()
            .is_none()
    );
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

/// A currently-valid certificate body the cache must accept. The builtin ARK
/// only needs to parse as X.509 inside its validity window; chain validation
/// is exercised elsewhere.
fn valid_cert_der() -> Vec<u8> {
    sev::certs::snp::builtin::milan::ark()
        .unwrap()
        .to_der()
        .unwrap()
}

fn test_vcek_key(suffix: u8) -> super::VcekCacheKey {
    super::VcekCacheKey {
        product: "Genoa".to_string(),
        hw_id: hex::encode([suffix; 64]),
        fmc: None,
        bootloader: 1,
        tee: 2,
        snp: 3,
        microcode: suffix,
    }
}

/// Minimal HTTP/1 upstream counting requests. Each response is `status` plus
/// `body`; `retry_after` adds a `Retry-After` header when set.
async fn counting_upstream(
    status: &'static str,
    body: Vec<u8>,
    retry_after: Option<u64>,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let counter = counter.clone();
            let status = status.to_string();
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                let Ok(n) = stream.read(&mut request).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                counter.fetch_add(1, Ordering::Relaxed);
                let retry_after = retry_after
                    .map(|value| format!("Retry-After: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{retry_after}\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    (address, requests, server)
}

#[tokio::test]
async fn vcek_cache_collapses_concurrent_same_key_fills_and_serves_warm_hits() {
    let vcek = valid_cert_der();
    let (address, requests, server) = counting_upstream("200 OK", vcek.clone(), None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x51);
    let results = futures::future::join_all(
        (0..8).map(|_| super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)),
    )
    .await;
    assert!(results.iter().all(|result| result.is_ok()));
    for result in &results {
        assert_eq!(result.as_ref().unwrap().as_slice(), vcek.as_slice());
    }
    // Single-flight: eight concurrent callers share one upstream fill.
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    // Warm cache hit must not touch the upstream again.
    let warm = super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        .await
        .unwrap();
    assert_eq!(warm.as_slice(), vcek.as_slice());
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn vcek_cache_keeps_different_hwid_tcb_keys_separate() {
    let vcek = valid_cert_der();
    let (address, requests, server) = counting_upstream("200 OK", vcek, None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let mut key_a = test_vcek_key(0x52);
    let mut key_b = test_vcek_key(0x52);
    key_b.microcode += 1; // changed firmware/TCB must not reuse cached collateral
    for key in [&key_a, &key_b] {
        super::fetch_amd_kds_vcek_der_cached(&client, &url, key, None)
            .await
            .unwrap();
    }
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    key_a.hw_id = hex::encode([0x53; 64]);
    super::fetch_amd_kds_vcek_der_cached(&client, &url, &key_a, None)
        .await
        .unwrap();
    assert_eq!(requests.load(Ordering::Relaxed), 3);
    server.abort();
}

#[tokio::test]
async fn vcek_cache_never_stores_noncertificate_or_expired_bodies() {
    use x509_cert::der::{Decode, Encode};

    // A 200 body that is not a certificate must error and never be cached.
    let (address, requests, server) =
        counting_upstream("200 OK", b"not-a-certificate".to_vec(), None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x54);
    let error = super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not a certificate"));
    // The rejection is not cached: a second call retries the upstream.
    assert!(
        super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
            .await
            .is_err()
    );
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    server.abort();

    // A certificate outside its validity window is rejected the same way.
    let mut expired = x509_cert::Certificate::from_der(&valid_cert_der()).unwrap();
    expired.tbs_certificate.validity.not_after = expired.tbs_certificate.validity.not_before;
    let (address, requests, server) =
        counting_upstream("200 OK", expired.to_der().unwrap(), None).await;
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x55);
    let error = super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("validity period"));
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn vcek_fill_is_bounded_cancellable_and_error_responses_are_uncached() {
    // `Retry-After: 0` keeps the eight-attempt bound fast while exercising
    // the honored-hint path; each attempt still reaches the upstream.
    let (address, requests, server) =
        counting_upstream("429 Too Many Requests", b"rate limited".to_vec(), Some(0)).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x56);
    let error = super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("429"));
    // The 429 body is never cached as certificate bytes: the error path is
    // bounded at eight attempts and a second call retries the upstream.
    assert_eq!(requests.load(Ordering::Relaxed), 8);
    assert!(
        super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
            .await
            .is_err()
    );
    assert_eq!(requests.load(Ordering::Relaxed), 16);
    server.abort();

    // A large Retry-After sleep is cancellable, and cancellation releases the
    // fill lock so the next caller retries instead of waiting forever.
    let (address, requests, server) =
        counting_upstream("429 Too Many Requests", b"rate limited".to_vec(), Some(600)).await;
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x57);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        )
        .await
        .is_err()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            super::fetch_amd_kds_vcek_der_cached(&client, &url, &key, None)
        )
        .await
        .is_err()
    );
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    server.abort();
}

#[tokio::test]
async fn vcek_disk_cache_reuses_valid_material_and_rejects_corrupt_entries() {
    let directory = tempfile::tempdir().unwrap();
    let vcek = valid_cert_der();
    let (address, requests, server) = counting_upstream("200 OK", vcek.clone(), None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x58);
    let dir = Some(directory.path().to_path_buf());

    // The disk layer is the cross-process path: a second fill must reuse the
    // entry the first fill wrote, without an upstream request.
    let first = super::vcek_fill_from_upstream(&client, &url, &key, dir.clone())
        .await
        .unwrap();
    assert_eq!(first.as_slice(), vcek.as_slice());
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    let second = super::vcek_fill_from_upstream(&client, &url, &key, dir.clone())
        .await
        .unwrap();
    assert_eq!(second.as_slice(), vcek.as_slice());
    assert_eq!(requests.load(Ordering::Relaxed), 1);

    // A corrupt on-disk entry is removed and refetched, never returned.
    let (der_path, _) = super::vcek_disk_paths(directory.path(), &key);
    std::fs::write(&der_path, b"garbage").unwrap();
    let third = super::vcek_fill_from_upstream(&client, &url, &key, dir)
        .await
        .unwrap();
    assert_eq!(third.as_slice(), vcek.as_slice());
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    server.abort();
}

#[test]
fn vcek_disk_cache_rejects_oversized_files() {
    let directory = tempfile::tempdir().unwrap();
    let key = test_vcek_key(0x60);
    let (path, _) = super::vcek_disk_paths(directory.path(), &key);
    std::fs::File::create(&path)
        .unwrap()
        .set_len(1024 * 1024)
        .unwrap();
    assert!(super::vcek_disk_get(directory.path(), &key).is_none());
    assert!(!path.exists());
}

#[tokio::test]
async fn vcek_disk_lock_collapses_concurrent_fills_across_process_layers() {
    let directory = tempfile::tempdir().unwrap();
    let vcek = valid_cert_der();
    let (address, requests, server) = counting_upstream("200 OK", vcek, None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let key = test_vcek_key(0x59);
    // Bypassing the in-process mutex simulates two `enclava` processes:
    // concurrent fills must still collapse on the per-key file lock.
    let results = futures::future::join_all((0..4).map(|_| {
        super::vcek_fill_from_upstream(&client, &url, &key, Some(directory.path().to_path_buf()))
    }))
    .await;
    assert!(results.iter().all(|result| result.is_ok()));
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn vcek_disk_lock_pool_bounds_lock_files_across_failed_fills() {
    let directory = tempfile::tempdir().unwrap();
    let dir_path = directory.path().to_path_buf();
    let (address, _requests, server) =
        counting_upstream("400 Bad Request", b"upstream diagnostic".to_vec(), None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek");
    let dir = Some(dir_path.clone());

    // A legacy per-key orphan lock (no matching .der) is swept on the next
    // fill; one with a live .der sibling is left alone.
    let orphan_name = format!("vcek-{}.lock", "ab".repeat(32));
    let paired_name = format!("vcek-{}.lock", "cd".repeat(32));
    std::fs::write(dir_path.join(&orphan_name), b"").unwrap();
    std::fs::write(dir_path.join(&paired_name), b"").unwrap();
    std::fs::write(
        dir_path.join(format!("vcek-{}.der", "cd".repeat(32))),
        b"placeholder",
    )
    .unwrap();

    // Every fill fails before writing a `.der`: only the bounded lock pool
    // may accumulate, never one lock file per attempted identity.
    let fills = super::AMD_KDS_VCEK_LOCK_POOL_SLOTS as usize + 64;
    for suffix in 0..fills {
        let key = test_vcek_key(suffix as u8);
        super::vcek_fill_from_upstream(&client, &url, &key, dir.clone())
            .await
            .unwrap_err();
    }
    server.abort();

    let names: Vec<String> = std::fs::read_dir(&dir_path)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .collect();
    let locks = names.iter().filter(|name| name.ends_with(".lock")).count();
    assert!(
        locks <= super::AMD_KDS_VCEK_LOCK_POOL_SLOTS as usize + 1,
        "{fills} failed distinct-key fills must leave only pooled slots plus the paired legacy lock, got {locks}"
    );
    assert!(locks > 0, "pool slots were exercised");
    assert!(
        !names.iter().any(|name| name == &orphan_name),
        "orphan lock without a .der sibling must be swept"
    );
    assert!(
        names.iter().any(|name| name == &paired_name),
        "lock with a live .der sibling must be retained"
    );
    assert_eq!(
        names.iter().filter(|name| name.ends_with(".der")).count(),
        1,
        "failed fills never write certificate bytes"
    );
}

#[tokio::test]
async fn vcek_fetch_errors_do_not_leak_url_or_hwid() {
    let (address, _requests, server) =
        counting_upstream("400 Bad Request", b"upstream diagnostic".to_vec(), None).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/vcek/{}", "9f".repeat(64));
    let error = super::fetch_amd_kds_vcek_der(&client, &url)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("400"));
    assert!(!error.contains(&address.to_string()));
    assert!(!error.contains("9f"));
    assert!(!error.contains("upstream diagnostic"));
    server.abort();
}

#[test]
fn kds_retry_delay_honors_bounded_retry_after_and_jitter() {
    assert_eq!(
        super::amd_kds_vcek_sleep_duration(0, Some(Duration::from_secs(7))),
        Duration::from_secs(7)
    );
    assert_eq!(
        super::amd_kds_vcek_sleep_duration(0, Some(Duration::from_secs(3600))),
        Duration::from_secs(120)
    );
    for attempt in 0..8 {
        let delay = super::amd_kds_vcek_sleep_duration(attempt, None);
        let base = super::amd_kds_vcek_retry_delay(attempt);
        assert!(delay >= base / 2 && delay < base * 3 / 2);
    }
    for malformed in ["not-a-number", "", "-5", "99999999999999999999"] {
        let header = reqwest::header::HeaderValue::from_str(malformed);
        let parsed = header
            .as_ref()
            .ok()
            .and_then(|value| super::parse_retry_after(Some(value)));
        if let Ok(value) = malformed.parse::<u64>() {
            assert_eq!(parsed, Some(Duration::from_secs(value)));
        } else {
            assert_eq!(parsed, None);
        }
    }
}

#[test]
fn amd_kds_base_url_defaults_to_direct_amd_and_honors_override() {
    let _lock = env_lock();
    unsafe {
        std::env::remove_var(super::AMD_KDS_BASE_URL_ENV);
    }
    assert_eq!(super::amd_kds_base_url(), super::AMD_KDS_BASE_URL);
    unsafe {
        std::env::set_var(
            super::AMD_KDS_BASE_URL_ENV,
            "https://amd-kds-relay.example:8443",
        );
    }
    assert_eq!(
        super::amd_kds_base_url(),
        "https://amd-kds-relay.example:8443"
    );
    unsafe {
        std::env::remove_var(super::AMD_KDS_BASE_URL_ENV);
    }
}

#[test]
fn turin_vcek_url_uses_eight_byte_hwid_per_kds_spec() {
    let mut report = sev::firmware::guest::AttestationReport {
        version: 3,
        cpuid_fam_id: Some(0x1a),
        cpuid_mod_id: Some(0x02),
        reported_tcb: sev::firmware::host::TcbVersion {
            fmc: Some(3),
            bootloader: 1,
            tee: 2,
            snp: 4,
            microcode: 5,
        },
        ..Default::default()
    };
    report.chip_id[..8].copy_from_slice(&[0xcd; 8]);
    let url = super::amd_kds_vcek_url(&report, "https://kdsintf.amd.com").unwrap();
    assert_eq!(
        url,
        "https://kdsintf.amd.com/vcek/v1/Turin/cdcdcdcdcdcdcdcd?fmcSPL=03&blSPL=01&teeSPL=02&snpSPL=04&ucodeSPL=05"
    );
    // Nonzero padding past the first eight bytes is rejected.
    report.chip_id[9] = 1;
    assert!(super::amd_kds_vcek_url(&report, "https://kdsintf.amd.com").is_err());
}

#[test]
fn synthetic_launch_identity_is_test_support_only() {
    // The only construction path for a verified launch identity outside
    // attest_receipt_key() is this cfg(test)-gated setter: production builds
    // (debug or release) compile without it, so no caller can forge trust.
    let expected_measurement = enclava_common::descriptor::FirmwareMeasurement::Full([0x11; 48]);
    let client = TeeClient::new("app.enclava.dev");
    assert!(
        client.verified_launch_identity().is_none(),
        "ordinary clients must carry no verified launch identity"
    );

    let identity = super::VerifiedSnpLaunchIdentity {
        host_data: [0x09; 32],
        firmware_measurement: [0x11; 48],
    };
    let trusted = client.with_verified_launch_identity_for_tests([0x09; 32], [0x11; 48]);
    assert_eq!(trusted.verified_launch_identity(), Some(identity));
    assert!(super::launch_identity_binds_deployment(
        trusted.verified_launch_identity().as_ref(),
        &[0x09; 32],
        &expected_measurement
    ));
    // Matching HOST_DATA with a mismatched measurement never binds.
    let wrong_measurement = enclava_common::descriptor::FirmwareMeasurement::Full([0x22; 48]);
    assert!(!super::launch_identity_binds_deployment(
        trusted.verified_launch_identity().as_ref(),
        &[0x09; 32],
        &wrong_measurement
    ));
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

// --- terminal bootstrap diagnostics -----------------------------------------

const SYNTHETIC_SECRET_MARKER: &str = "SECRET-MARKER-6f2d1c";

fn terminal_error_body(
    code: &str,
    terminal: serde_json::Value,
    retry_after: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "ownership_state": "unclaimed",
        "unlock_state": "locked",
        "bootstrap_error": {
            "error": code,
            "terminal": terminal,
            "retry_after": retry_after,
        },
    })
}

#[test]
fn terminal_bootstrap_error_codes_are_the_stable_contract() {
    assert_eq!(
        super::TERMINAL_BOOTSTRAP_ERROR_CODES,
        [
            "acme_rate_limited",
            "acme_certificate_issuance_failed",
            "enclava_init_failed"
        ]
    );
}

#[test]
fn parses_each_recognized_terminal_bootstrap_error() {
    for code in super::TERMINAL_BOOTSTRAP_ERROR_CODES {
        let diagnostic = super::parse_terminal_bootstrap_error(&terminal_error_body(
            code,
            serde_json::Value::Bool(true),
            serde_json::Value::Null,
        ))
        .unwrap_or_else(|| panic!("{code} must be recognized"));
        assert_eq!(diagnostic.code(), code);
        assert_eq!(diagnostic.retry_after(), None);
        assert_eq!(diagnostic.stable_summary(), code);
    }
}

#[test]
fn absent_or_malformed_bootstrap_error_field_is_not_a_diagnostic() {
    // Absent field is the backward-compatible pre-proxy shape.
    assert!(
        super::parse_terminal_bootstrap_error(&serde_json::json!({
            "ownership_state": "unclaimed",
        }))
        .is_none()
    );
    for field in [
        serde_json::Value::Null,
        serde_json::Value::String("acme_rate_limited".into()),
        serde_json::Value::Bool(true),
        serde_json::json!([{ "error": "acme_rate_limited" }]),
    ] {
        let body = serde_json::json!({ "bootstrap_error": field });
        assert!(
            super::parse_terminal_bootstrap_error(&body).is_none(),
            "malformed bootstrap_error field must not authorize a decision"
        );
    }
}

#[test]
fn unknown_error_codes_or_non_terminal_markers_are_not_a_diagnostic() {
    // Unknown codes, arbitrary provider prose, and hostile text are ignored.
    for code in [
        "acme_dns_failed",
        "",
        "ACME_RATE_LIMITED",
        "acme_rate_limited ",
    ] {
        assert!(
            super::parse_terminal_bootstrap_error(&terminal_error_body(
                code,
                serde_json::Value::Bool(true),
                serde_json::Value::Null,
            ))
            .is_none(),
            "unknown code {code:?} must not authorize a stop"
        );
    }
    // terminal must be exactly boolean true.
    for terminal in [
        serde_json::Value::Bool(false),
        serde_json::Value::Null,
        serde_json::json!("true"),
        serde_json::json!(1),
    ] {
        assert!(
            super::parse_terminal_bootstrap_error(&terminal_error_body(
                "acme_rate_limited",
                terminal,
                serde_json::Value::Null,
            ))
            .is_none()
        );
    }
}

#[test]
fn preserves_elapsed_and_future_utc_retry_after_deadlines() {
    // An elapsed deadline does not erase the terminal failure: it is preserved
    // because a retry may now be attempted separately.
    let elapsed = super::parse_terminal_bootstrap_error(&terminal_error_body(
        "acme_rate_limited",
        serde_json::Value::Bool(true),
        serde_json::json!("2020-01-01T00:00:00Z"),
    ))
    .expect("elapsed deadline stays parseable");
    assert_eq!(
        elapsed
            .retry_after()
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "2020-01-01T00:00:00Z"
    );

    // A fixed near-term deadline: as real time passes it becomes elapsed,
    // which the parser still preserves.
    let future = super::parse_terminal_bootstrap_error(&terminal_error_body(
        "enclava_init_failed",
        serde_json::Value::Bool(true),
        serde_json::json!("2027-01-01T12:00:00+00:00"),
    ))
    .expect("bounded future deadline is parseable");
    assert_eq!(
        future
            .retry_after()
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "2027-01-01T12:00:00Z"
    );
}

#[test]
fn malformed_or_unbounded_retry_after_deadlines_reject_the_diagnostic() {
    for retry_after in [
        serde_json::json!("tomorrow"),
        serde_json::json!("2030-01-01T00:00:00"), // no offset: not RFC3339
        serde_json::json!("2030-01-01T02:00:00+02:00"), // not UTC
        serde_json::json!(1757430400),            // unix time is not RFC3339
        serde_json::Value::Bool(false),
        serde_json::json!({ "seconds": 5 }),
    ] {
        assert!(
            super::parse_terminal_bootstrap_error(&terminal_error_body(
                "acme_certificate_issuance_failed",
                serde_json::Value::Bool(true),
                retry_after,
            ))
            .is_none(),
            "malformed retry_after must not authorize a decision"
        );
    }

    // Broker bound: at most 365 days past the observation.
    let beyond = (chrono::Utc::now() + chrono::Duration::days(366))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(
        super::parse_terminal_bootstrap_error(&terminal_error_body(
            "acme_rate_limited",
            serde_json::Value::Bool(true),
            serde_json::json!(beyond),
        ))
        .is_none()
    );

    let within = (chrono::Utc::now() + chrono::Duration::days(364))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(
        super::parse_terminal_bootstrap_error(&terminal_error_body(
            "acme_rate_limited",
            serde_json::Value::Bool(true),
            serde_json::json!(within),
        ))
        .is_some()
    );
}

#[test]
fn stable_summary_prints_only_the_code_and_validated_deadline() {
    // Hostile provider detail must never reach the console: only the code and
    // the re-serialized UTC deadline are emitted.
    let body = serde_json::json!({
        "bootstrap_error": {
            "error": "acme_certificate_issuance_failed",
            "terminal": true,
            "retry_after": "2027-01-01T12:00:00+00:00",
            "detail": format!("\u{1b}[31m internal {SYNTHETIC_SECRET_MARKER} \u{1b}[0m"),
            "provider_message": format!("leaking {SYNTHETIC_SECRET_MARKER}"),
        }
    });
    let diagnostic = super::parse_terminal_bootstrap_error(&body).unwrap();
    let summary = diagnostic.stable_summary();
    assert_eq!(
        summary,
        "acme_certificate_issuance_failed (retry_after 2027-01-01T12:00:00Z)"
    );
    assert!(!summary.contains(SYNTHETIC_SECRET_MARKER));
    assert!(!summary.contains('\u{1b}'));

    // Unrecognized codes carrying hostile text produce no diagnostic at all.
    let hostile = serde_json::json!({
        "bootstrap_error": {
            "error": format!("acme_rate_limited {SYNTHETIC_SECRET_MARKER}"),
            "terminal": true,
            "retry_after": null,
        }
    });
    assert!(super::parse_terminal_bootstrap_error(&hostile).is_none());
}

#[test]
fn bootstrap_status_combines_claim_and_terminal_without_masking() {
    // Both signals come from the same body; callers decide precedence.
    let terminal_and_claimed = serde_json::json!({
        "ownership_state": "locked",
        "bootstrap_error": {
            "error": "enclava_init_failed",
            "terminal": true,
            "retry_after": null,
        },
    });
    let status = super::bootstrap_status_from_json(&terminal_and_claimed);
    assert!(status.claimed);
    assert_eq!(
        status.terminal_bootstrap_error.unwrap().code(),
        "enclava_init_failed"
    );

    let claimed_only = serde_json::json!({ "ownership_state": "unlocked" });
    let status = super::bootstrap_status_from_json(&claimed_only);
    assert!(status.claimed);
    assert!(status.terminal_bootstrap_error.is_none());

    let neither = serde_json::json!({ "ownership_state": "unclaimed" });
    let status = super::bootstrap_status_from_json(&neither);
    assert!(!status.claimed);
    assert!(status.terminal_bootstrap_error.is_none());
}

#[test]
fn recognized_terminal_body_is_parsed_from_bounded_json_slice() {
    // The bounded reader caps the accepted body size before parsing.
    let small = serde_json::to_vec(&terminal_error_body(
        "acme_rate_limited",
        serde_json::Value::Bool(true),
        serde_json::Value::Null,
    ))
    .unwrap();
    assert!(super::parse_terminal_bootstrap_error_body(&small).is_some());

    let mut oversized = small.clone();
    oversized.extend(std::iter::repeat_n(
        b' ',
        super::MAX_BOOTSTRAP_STATUS_BODY_BYTES + 1,
    ));
    assert!(
        super::parse_terminal_bootstrap_error_body(&oversized).is_none(),
        "oversized status bodies must be rejected before parsing"
    );
}
