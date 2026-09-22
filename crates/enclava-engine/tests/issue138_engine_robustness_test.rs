//! Regression tests for enclava-labs/cap#138: the engine must not embed
//! untrusted/breakable content in TOML literal blocks, and must validate the
//! fields the manifest generators interpolate.

use base64::Engine;
use enclava_engine::manifest::cc_init_data::build_toml;
use enclava_engine::testutil::sample_app;
use enclava_engine::types::{EgressRule, GeneratedAgentPolicy, LogEncryptionConfig};
use enclava_engine::validate::{ValidationError, validate_app};
use sha2::{Digest, Sha256};

fn app_with_policy(policy_text: String) -> enclava_engine::types::ConfidentialApp {
    let mut app = sample_app();
    app.generated_agent_policy = Some(GeneratedAgentPolicy {
        policy_sha256: Sha256::digest(policy_text.as_bytes()).into(),
        policy_text,
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
    });
    app
}

// ---------------------------------------------------------------------------
// 1. policy_text embedded in a TOML literal must not be escapable (#138 item 1)
// ---------------------------------------------------------------------------

/// A signed policy containing the TOML literal-string terminator `'''` must
/// not break out of its `'''…'''` block: the TOML must still parse, the
/// embedded value must round-trip exactly, and no sibling keys (e.g. a
/// redefined `[data]` table) may be introduced by the payload.
#[test]
fn policy_text_with_triple_single_quotes_cannot_break_toml() {
    let breakout = "package agent_policy\n# '''\nimage_digest = \"attacker-controlled\"\n[data]\nkey = \"value\"\n'''\nsidecar_digests = \"overridden\"\n";
    let app = app_with_policy(breakout.to_string());
    let toml = build_toml(&app);

    let parsed: toml::Value = toml::from_str(&toml).expect("TOML must survive adversarial policy");
    let data = parsed.get("data").and_then(toml::Value::as_table).unwrap();

    // Round-trip: the embedded policy is exactly what was signed.
    assert_eq!(
        data.get("policy.rego").and_then(toml::Value::as_str),
        Some(breakout)
    );
    // No payload-injected key may land in [data].
    assert!(
        data.get("key").is_none(),
        "payload must not inject [data] keys"
    );
    // The escape attempt must not have overwritten platform-owned values.
    assert_ne!(
        data.get("image_digest").and_then(toml::Value::as_str),
        Some("attacker-controlled")
    );
    assert_ne!(
        data.get("sidecar_digests").and_then(toml::Value::as_str),
        Some("overridden")
    );
}

/// Benign policies must keep the historical `'''` literal embedding so the
/// cc_init_data bytes (and therefore descriptor signature hashes) are stable.
#[test]
fn benign_policy_keeps_literal_block_embedding() {
    let policy_text = "package agent_policy\n\ndefault CreateContainerRequest := false\n";
    let app = app_with_policy(policy_text.to_string());
    let toml = build_toml(&app);
    assert!(
        toml.contains("\"policy.rego\" = '''\n"),
        "benign policy must keep the literal block layout"
    );
    let parsed: toml::Value = toml::from_str(&toml).unwrap();
    assert_eq!(
        parsed
            .get("data")
            .and_then(toml::Value::as_table)
            .and_then(|data| data.get("policy.rego"))
            .and_then(toml::Value::as_str),
        Some(policy_text)
    );
}

// ---------------------------------------------------------------------------
// 3. unbounded resource requests / storage sizes must be validated (#138 item 3)
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_invalid_resource_quantities() {
    let mut app = sample_app();
    app.resources.cpu = "not-a-cpu".to_string();
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "cpu"
    ));

    app.resources.cpu = "1".to_string();
    app.resources.memory = "5".to_string(); // no unit suffix
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "memory"
    ));
}

#[test]
fn validate_rejects_invalid_storage_sizes() {
    let mut app = sample_app();
    app.storage.app_data.size = "banana".to_string();
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidStorageSize { field, .. }) if field == "storage.app_data.size"
    ));

    app.storage.app_data.size = "10Gi".to_string();
    app.storage.tls_data.size = "-5Gi".to_string();
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidStorageSize { field, .. }) if field == "storage.tls_data.size"
    ));
}

// ---------------------------------------------------------------------------
// 5. validate.rs coverage: domain, egress, attestation, log_encryption
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_invalid_platform_domain() {
    let mut app = sample_app();
    app.domain.platform_domain = "not_a_domain".to_string();
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidDomain { field, .. }) if field == "domain.platform_domain"
    ));
}

#[test]
fn validate_rejects_invalid_custom_domain() {
    let mut app = sample_app();
    app.domain.custom_domain = Some("app..example.com".to_string());
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidDomain { field, .. }) if field == "domain.custom_domain"
    ));
}

#[test]
fn validate_rejects_invalid_egress_allowlist_host() {
    let mut app = sample_app();
    app.egress_allowlist = vec![EgressRule {
        host: "10.0.0.5".to_string(), // IPs are not FQDNs
        ports: vec![443],
    }];
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidEgressAllowlist { index: 0, .. })
    ));
}

#[test]
fn validate_rejects_empty_egress_allowlist_ports() {
    let mut app = sample_app();
    app.egress_allowlist = vec![EgressRule {
        host: "api.example.com".to_string(),
        ports: vec![],
    }];
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidEgressAllowlist { index: 0, .. })
    ));
}

#[test]
fn validate_rejects_invalid_attestation_pubkey_hex() {
    let mut app = sample_app();
    app.attestation.trustee_policy_read_available = true;
    app.attestation.platform_trustee_policy_pubkey_hex = Some("nothex".to_string());
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidAttestationPubkey { field, .. })
            if field == "attestation.platform_trustee_policy_pubkey_hex"
    ));
}

#[test]
fn validate_rejects_mismatched_log_encryption_hash() {
    let mut app = sample_app();
    // A well-formed key with a deliberately wrong sha256 binding.
    let public_key_base64url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    app.log_encryption = Some(LogEncryptionConfig {
        algorithm: "x25519-hpke-v1".to_string(),
        key_id: "tenant-key-1".to_string(),
        public_key_base64url: public_key_base64url.to_string(),
        public_key_sha256: "sha256:0000000000000000000000000000000000000000000".to_string(),
    });
    assert!(matches!(
        validate_app(&app),
        Err(ValidationError::InvalidLogEncryption(_))
    ));
}

#[test]
fn validate_accepts_valid_log_encryption() {
    let mut app = sample_app();
    let public_key: [u8; 32] = [0x42; 32];
    let public_key_base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    app.log_encryption = Some(LogEncryptionConfig {
        algorithm: "x25519-hpke-v1".to_string(),
        key_id: "tenant-key-1".to_string(),
        public_key_base64url: public_key_base64url.clone(),
        public_key_sha256: enclava_common::log_encryption::public_key_sha256(&public_key),
    });
    assert!(validate_app(&app).is_ok());
}

// ---------------------------------------------------------------------------
// 4. PVC cleanup must select only CAP-owned PVCs (#138 item 4)
// ---------------------------------------------------------------------------

#[test]
fn volume_claim_templates_are_labeled_for_cleanup_selector() {
    use enclava_engine::manifest::volumes::{MANAGED_BY_LABEL, build_volume_claim_templates};

    let vcts = build_volume_claim_templates(&sample_app());
    assert!(!vcts.is_empty());
    for vct in &vcts {
        let labels = vct.metadata.labels.as_ref().expect("VCT must be labeled");
        assert_eq!(
            labels.get(MANAGED_BY_LABEL.0).map(String::as_str),
            Some(MANAGED_BY_LABEL.1),
            "VCT {} must carry the managed-by label",
            vct.metadata.name.as_deref().unwrap_or("<unnamed>")
        );
    }
}
