//! enclava-init ConfigMap (Phase 5).

use enclava_engine::manifest::cc_init_data;
use enclava_engine::manifest::enclava_init_config::generate_enclava_init_configmap;
use enclava_engine::testutil::sample_app;
use enclava_engine::types::{LogEncryptionConfig, WorkloadSecurityProfile};

#[test]
fn cm_name_is_per_app() {
    let cm = generate_enclava_init_configmap(&sample_app());
    assert_eq!(cm.metadata.name.as_deref(), Some("test-app-enclava-init"));
}

#[test]
fn config_toml_has_both_volume_blocks() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("[state]"));
    assert!(toml_text.contains("[tls-state]"));
    assert!(toml_text.contains("state-root = \"/state\""));
    assert!(toml_text.contains("unlock-socket = \"/run/enclava-unlock/unlock.sock\""));
    assert!(toml_text.contains("attempts-path = \"/run/enclava-unlock/unlock-attempts\""));
    assert!(toml_text.contains("mount-path = \"/state\""));
    assert!(toml_text.contains("mount-path = \"/state/tls-state\""));
    assert!(toml_text.contains("hkdf-info = \"state-luks-key\""));
    assert!(toml_text.contains("hkdf-info = \"tls-state-luks-key\""));
}

#[test]
fn config_toml_has_runtime_ownership_and_app_bind_mounts() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("app-uid = 10001"));
    assert!(toml_text.contains("app-gid = 10001"));
    assert!(toml_text.contains("caddy-uid = 10002"));
    assert!(toml_text.contains("caddy-gid = 10002"));
    assert!(toml_text.contains("[[app-bind-mounts]]"));
    assert!(toml_text.contains("subdir = \"app-data\""));
    assert!(toml_text.contains("mount-path = \"/app/data\""));
}

#[test]
fn config_toml_uses_root_app_identity_for_platform_ssh_relay() {
    let mut app = sample_app();
    app.containers[0].workload_security_profile = WorkloadSecurityProfile::PlatformManagedSshRelay;
    let cm = generate_enclava_init_configmap(&app);
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();

    assert!(toml_text.contains("app-uid = 0"));
    assert!(toml_text.contains("app-gid = 0"));
    assert!(toml_text.contains("managed-config-gid = 0"));
    assert!(toml_text.contains("managed-config-dir-mode = 448"));
    assert!(!toml_text.contains("app-uid = 10001"));
    assert!(!toml_text.contains("app-gid = 10001"));
}

#[test]
fn config_toml_uses_root_app_identity_for_rootful_sudo() {
    let mut app = sample_app();
    app.containers[0].workload_security_profile = WorkloadSecurityProfile::RootfulSudo;
    let cm = generate_enclava_init_configmap(&app);
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();

    assert!(toml_text.contains("app-uid = 0"));
    assert!(toml_text.contains("app-gid = 0"));
    assert!(toml_text.contains("managed-config-gid = 0"));
    assert!(toml_text.contains("managed-config-dir-mode = 448"));
    assert!(!toml_text.contains("app-uid = 10001"));
    assert!(!toml_text.contains("app-gid = 10001"));
}

#[test]
fn config_toml_has_required_unlock_inputs() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("argon2-salt-hex = \""));
    assert!(toml_text.contains("kbs-url = \"http://127.0.0.1:8081/internal/owner-seed\""));
    assert!(toml_text.contains(
        "kbs-resource-path = \"default/cap-test-org-test-app-test-app-owner/seed-encrypted\""
    ));
    assert!(!toml_text.contains("workload-secret-seed"));
}

#[test]
fn config_toml_parses() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    let _: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");
}

#[test]
fn config_toml_renders_public_log_encryption_metadata_only() {
    let mut app = sample_app();
    app.log_encryption = Some(LogEncryptionConfig {
        algorithm: "x25519-hpke-v1".to_string(),
        key_id: "logs-prod".to_string(),
        public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
    });
    let cm = generate_enclava_init_configmap(&app);
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    let parsed: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");
    let log_encryption = parsed
        .get("log-encryption")
        .and_then(toml::Value::as_table)
        .expect("log-encryption table");

    assert_eq!(
        log_encryption
            .get("required")
            .and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        log_encryption
            .get("algorithm")
            .and_then(toml::Value::as_str),
        Some("x25519-hpke-v1")
    );
    assert_eq!(
        log_encryption.get("key-id").and_then(toml::Value::as_str),
        Some("logs-prod")
    );
    assert_eq!(
        log_encryption
            .get("public-key-base64url")
            .and_then(toml::Value::as_str),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
    assert_eq!(
        log_encryption
            .get("public-key-sha256")
            .and_then(toml::Value::as_str),
        Some("sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU")
    );
    let rendered_log_table = format!("{log_encryption:?}").to_ascii_lowercase();
    for forbidden in ["private", "secret", "seed", "mnemonic"] {
        assert!(
            !rendered_log_table.contains(forbidden),
            "log encryption config must not render private material hint {forbidden}"
        );
    }
}

#[test]
fn config_toml_places_runtime_keys_at_document_root() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    let parsed: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");
    let root = parsed.as_table().expect("config.toml root must be a table");
    let tls_state = root
        .get("tls-state")
        .and_then(toml::Value::as_table)
        .expect("tls-state must be a table");

    assert_eq!(
        root.get("kbs-url").and_then(toml::Value::as_str),
        Some("http://127.0.0.1:8081/internal/owner-seed")
    );
    assert_eq!(
        root.get("kbs-resource-path").and_then(toml::Value::as_str),
        Some("default/cap-test-org-test-app-test-app-owner/seed-encrypted")
    );
    assert_eq!(
        root.get("trustee-policy-read-available")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    assert!(!tls_state.contains_key("kbs-url"));
    assert!(!tls_state.contains_key("kbs-resource-path"));
    assert!(!tls_state.contains_key("trustee-policy-read-available"));
}

#[test]
fn config_toml_defaults_trustee_policy_read_to_false() {
    // Phase 3 patches haven't shipped; verification stays SKIPPED until then.
    let cm = generate_enclava_init_configmap(&sample_app());
    let data = cm.data.as_ref().unwrap();
    let toml_text = data.get("config.toml").unwrap();
    assert!(toml_text.contains("trustee-policy-read-available = false"));
    assert!(!data.contains_key("cc-init-data.toml"));
}

#[test]
fn config_toml_renders_receipt_verification_settings_when_enabled() {
    let mut app = sample_app();
    app.attestation.trustee_policy_read_available = true;
    app.attestation.workload_artifacts_ca_cert_pem = Some("test-ca".to_string());
    app.attestation.workload_artifacts_url =
        Some("https://cap-api.cap.svc.cluster.local/api/v1/workload/artifacts".to_string());
    app.attestation.tls_certificate_broker_url = Some(
        "http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate".to_string(),
    );
    app.attestation.trustee_policy_url =
        Some("http://kbs.trustee.svc/resource-policy/default/body".to_string());
    app.attestation.platform_trustee_policy_pubkey_hex = Some("11".repeat(32));
    app.attestation.signing_service_pubkey_hex = Some("11".repeat(32));
    app.attestation.signing_service_trusted_pubkeys_json =
        Some(format!(r#"{{"retiring-key":"{}"}}"#, "22".repeat(32)));

    let cm = generate_enclava_init_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let toml_text = data.get("config.toml").unwrap();
    let cc_toml = data.get("cc-init-data.toml").unwrap();

    assert!(toml_text.contains("trustee-policy-read-available = true"));
    assert!(toml_text.contains("cc-init-data-path = \"/etc/enclava-init/cc-init-data.toml\""));
    assert!(toml_text.contains(
        "workload-artifacts-url = \"https://cap-api.cap.svc.cluster.local/api/v1/workload/artifacts\""
    ));
    assert!(toml_text.contains(
        "tls-certificate-broker-url = \"http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate\""
    ));
    assert!(toml_text.contains("tls-certificate-hostnames = [\"test-app.abcd1234.enclava.dev\"]"));
    assert!(!toml_text.contains("trustee-policy-url"));
    assert!(
        toml_text.contains(
            "kbs-attestation-token-url = \"http://127.0.0.1:8006/aa/token?token_type=kbs\""
        )
    );
    assert!(toml_text.contains(&format!(
        "platform-trustee-policy-pubkey-hex = \"{}\"",
        "11".repeat(32)
    )));
    assert!(toml_text.contains(&format!(
        "signing-service-pubkey-hex = \"{}\"",
        "11".repeat(32)
    )));
    assert!(toml_text.contains("signing-service-trusted-pubkeys-json"));
    assert!(toml_text.contains("retiring-key"));
    assert_eq!(cc_toml, &cc_init_data::build_toml(&app));

    let parsed: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");
    let root = parsed.as_table().expect("config.toml root must be a table");
    assert_eq!(
        root.get("trustee-policy-read-available")
            .and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        root.get("workload-artifacts-url")
            .and_then(toml::Value::as_str),
        Some("https://cap-api.cap.svc.cluster.local/api/v1/workload/artifacts")
    );
    assert_eq!(
        root.get("tls-certificate-broker-url")
            .and_then(toml::Value::as_str),
        Some("http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate")
    );
    assert_eq!(
        root.get("tls-certificate-hostnames")
            .and_then(toml::Value::as_array)
            .map(|hosts| hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["test-app.abcd1234.enclava.dev"])
    );
    assert!(root.get("trustee-policy-url").is_none());
    assert!(
        !root
            .get("tls-state")
            .and_then(toml::Value::as_table)
            .unwrap()
            .contains_key("trustee-policy-read-available")
    );
}

#[test]
fn config_toml_allows_loopback_http_artifacts_without_ca_pin() {
    let mut app = sample_app();
    app.attestation.trustee_policy_read_available = true;
    app.attestation.workload_artifacts_url =
        Some("http://127.0.0.1:8081/api/v1/workload/artifacts".to_string());
    app.attestation.workload_artifacts_ca_cert_pem = None;

    let cm = generate_enclava_init_configmap(&app);
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    let parsed: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");

    assert_eq!(
        parsed
            .get("workload-artifacts-url")
            .and_then(toml::Value::as_str),
        Some("http://127.0.0.1:8081/api/v1/workload/artifacts")
    );
    assert!(
        !parsed
            .as_table()
            .unwrap()
            .contains_key("workload-artifacts-ca-cert-pem")
    );
}

#[test]
#[should_panic(
    expected = "missing required enclava-init config key workload-artifacts-ca-cert-pem"
)]
fn config_toml_still_requires_ca_pin_for_https_artifacts() {
    let mut app = sample_app();
    app.attestation.trustee_policy_read_available = true;
    app.attestation.workload_artifacts_url =
        Some("https://cap-api.cap.svc/api/v1/workload/artifacts".to_string());
    app.attestation.workload_artifacts_ca_cert_pem = None;

    let _ = generate_enclava_init_configmap(&app);
}

#[test]
fn config_toml_prefers_local_verification_artifacts_when_present() {
    let mut app = sample_app();
    app.attestation.trustee_policy_read_available = true;
    app.attestation.workload_artifacts_ca_cert_pem = Some("test-ca".to_string());
    app.attestation.workload_artifacts_url =
        Some("http://cap-api.cap.svc.cluster.local/api/v1/workload/artifacts".to_string());
    app.attestation.trustee_policy_url =
        Some("http://kbs.trustee.svc/resource-policy/default/body".to_string());
    app.attestation.local_workload_artifacts_json = Some("{\"bundle\":true}".to_string());
    app.attestation.local_trustee_policy_json = Some("{\"policy\":true}".to_string());

    let cm = generate_enclava_init_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let toml_text = data.get("config.toml").unwrap();

    assert_eq!(
        data.get("workload-artifacts.json").map(String::as_str),
        Some("{\"bundle\":true}")
    );
    assert_eq!(
        data.get("trustee-policy.json").map(String::as_str),
        Some("{\"policy\":true}")
    );
    assert!(
        toml_text.contains(
            "workload-artifacts-url = \"file:///etc/enclava-init/workload-artifacts.json\""
        )
    );
    assert!(
        toml_text.contains("trustee-policy-url = \"file:///etc/enclava-init/trustee-policy.json\"")
    );
}
