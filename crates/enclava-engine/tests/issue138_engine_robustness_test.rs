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
fn cap_vct_names_match_statefulset_pvc_pattern() {
    // PVCs created from the StatefulSet volumeClaimTemplates are named
    // `<vct>-<statefulset>-<ordinal>`. VCT metadata (labels) is immutable in
    // Kubernetes, so cleanup matches by name shape instead.
    use enclava_engine::manifest::volumes::{CAP_VCT_NAMES, build_volume_claim_templates};

    let vcts = build_volume_claim_templates(&sample_app());
    let vct_names: Vec<&str> = vcts
        .iter()
        .filter_map(|vct| vct.metadata.name.as_deref())
        .collect();
    assert_eq!(vct_names.as_slice(), CAP_VCT_NAMES);
    // VCTs must stay unlabeled: adding labels would 422 every redeploy of an
    // existing StatefulSet (spec.volumeClaimTemplates immutability).
    for vct in &vcts {
        assert!(
            vct.metadata.labels.is_none(),
            "VCT {} must not carry labels",
            vct.metadata.name.as_deref().unwrap_or("<unnamed>")
        );
    }
}

#[test]
fn validate_rejects_cpu_forms_the_api_never_writes() {
    let mut app = sample_app();
    for bad in ["1e2", "+5", "5.", ".5", "-1", "0"] {
        app.resources.cpu = bad.to_string();
        assert!(
            matches!(
                validate_app(&app),
                Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "cpu"
            ),
            "cpu={bad:?} must be rejected"
        );
    }
    app.resources.cpu = "250m".to_string();
    assert!(validate_app(&app).is_ok());
    app.resources.cpu = "1.5".to_string();
    assert!(validate_app(&app).is_ok());
}

#[test]
fn policy_text_with_control_characters_produces_valid_toml() {
    // Round 2 review: TOML literal strings forbid raw DEL (0x7F) and C0
    // controls other than tab/LF/CR — a body free of `'''` but containing
    // such bytes must still take the escaped basic-string fallback.
    let body = "package agent_policy\n\x07\x1FDEL:\x7F\n";
    let app = app_with_policy(body.to_string());
    let toml = build_toml(&app);

    let parsed: toml::Value =
        toml::from_str(&toml).expect("TOML must survive control-character policy");
    let data = parsed.get("data").and_then(toml::Value::as_table).unwrap();
    assert_eq!(
        data.get("policy.rego").and_then(toml::Value::as_str),
        Some(body)
    );
}

#[test]
fn validate_rejects_memory_and_storage_forms_the_api_never_writes() {
    // Round 2 review: the binary-quantity validator must use the API's
    // ScaledDecimal digit grammar, not f64 parsing.
    let mut app = sample_app();
    for bad in [
        "512Mi ", "+512Mi", "512e3Mi", "5.12e2Mi", ".5Gi", "5.Gi", "1e3Mi",
    ] {
        app.resources.memory = bad.to_string();
        assert!(
            matches!(
                validate_app(&app),
                Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "memory"
            ),
            "memory={bad:?} must be rejected"
        );
    }
    app.resources.memory = "512Mi".to_string();
    app.storage.app_data.size = "1.5Gi".to_string();
    assert!(validate_app(&app).is_ok());
}

#[test]
fn validate_rejects_egress_port_zero() {
    let mut app = sample_app();
    app.egress_allowlist = vec![EgressRule {
        host: "api.example.com".to_string(),
        ports: vec![0],
    }];
    assert!(
        validate_app(&app).is_err(),
        "egress port 0 must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 6. round-3 review follow-ups
// ---------------------------------------------------------------------------

/// Round 3 review (Devin 🟡 + Codex P2): a signed policy containing CR —
/// either CRLF line endings or a lone CR — must take the escaped
/// basic-string fallback. TOML multi-line literals normalize CRLF to LF, so
/// the literal path cannot round-trip CR-bearing bytes to the signed policy,
/// and a lone CR is invalid TOML outright.
#[test]
fn policy_text_with_carriage_returns_round_trips_via_basic_string() {
    for body in [
        "package agent_policy\r\nallow := true\r\n",
        "package agent_policy\nallow\r:= true\n",
    ] {
        let app = app_with_policy(body.to_string());
        let toml = build_toml(&app);
        let parsed: toml::Value =
            toml::from_str(&toml).expect("TOML must survive CR-bearing policy");
        assert_eq!(
            parsed
                .get("data")
                .and_then(toml::Value::as_table)
                .and_then(|data| data.get("policy.rego"))
                .and_then(toml::Value::as_str),
            Some(body),
            "CR-bearing policy must round-trip exactly"
        );
    }
}

/// Round 3 review (Devin 🟨 + Codex P2): quantities exceeding the API's
/// ScaledDecimal precision bounds (≤38 total digits, ≤24 fractional digits,
/// u128/checked-mul overflow) must be rejected by the engine gate too.
#[test]
fn validate_rejects_quantities_exceeding_api_precision_bounds() {
    let mut app = sample_app();
    // 39 total digits: parses fine as f64, rejected by ScaledDecimal::parse.
    app.resources.cpu = format!("{}2", "1".repeat(38));
    assert!(
        matches!(
            validate_app(&app),
            Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "cpu"
        ),
        "39-digit CPU quantity must be rejected"
    );
    // 25 fractional digits.
    app.resources.cpu = format!("1.{}1", "0".repeat(24));
    assert!(
        matches!(
            validate_app(&app),
            Err(ValidationError::InvalidResourceQuantity { field, .. }) if field == "cpu"
        ),
        "25-fractional-digit CPU quantity must be rejected"
    );
    // In-bounds values still pass (38 digits total, 24 fractional).
    app.resources.cpu = format!("{}2", "1".repeat(37));
    assert!(validate_app(&app).is_ok());
    app.resources.cpu = format!("1.{}1", "0".repeat(22));
    assert!(validate_app(&app).is_ok());
    // Storage: 39-digit coefficient with Ti suffix overflows u128 when
    // multiplied out, exactly as the API's checked_mul requires.
    app.storage.app_data.size = format!("{}2Ti", "1".repeat(38));
    assert!(
        matches!(
            validate_app(&app),
            Err(ValidationError::InvalidStorageSize { field, .. }) if field == "storage.app_data.size"
        ),
        "overflowing Ti quantity must be rejected"
    );
    app.storage.app_data.size = "10Gi".to_string();
    assert!(validate_app(&app).is_ok());
}

/// Round-16 self-check P3: the overflow gate must run on the API's
/// `ScaledDecimal` NORMALIZED coefficient, not the raw digit string. The API
/// (entitlements.rs `normalized()`) strips trailing fractional zeros before
/// `checked_mul`, so a long zero-fraction quantity it accepts must pass the
/// engine gate too — and trailing zeros must not MASK a real overflow.
#[test]
fn validate_matches_api_trailing_zero_normalization() {
    let mut app = sample_app();
    // 38 digits with a 24-zero fraction: the raw coefficient is 10^37 and
    // the Ti multiply overflows u128, but the API normalizes to 10^13 first
    // (10^13 * 2^20 fits comfortably).
    app.storage.app_data.size = format!("10000000000000.{}Ti", "0".repeat(24));
    assert!(validate_app(&app).is_ok());
    // Normalization does not mask overflows: 38 ones has no trailing zeros
    // to strip and 1.1e37 * 2^20 still overflows u128.
    app.storage.app_data.size = format!("{}Ti", "1".repeat(38));
    assert!(
        matches!(
            validate_app(&app),
            Err(ValidationError::InvalidStorageSize { field, .. })
                if field == "storage.app_data.size"
        ),
        "unnormalizable overflow must still be rejected"
    );
}

/// Round 3 review (Codex P2): tee_domain flows into the attestation
/// container's TEE_DOMAIN env and the TEE TLSRoute hostname, so a malformed
/// value must fail deploy validation like the other domains.
#[test]
fn validate_rejects_invalid_tee_domain() {
    let mut app = sample_app();
    app.domain.tee_domain = "not_a_domain".to_string();
    assert!(
        matches!(
            validate_app(&app),
            Err(ValidationError::InvalidDomain { field, .. }) if field == "domain.tee_domain"
        ),
        "malformed tee_domain must be rejected"
    );
    app.domain.tee_domain = "tee.enclava.dev".to_string();
    assert!(validate_app(&app).is_ok());
}
