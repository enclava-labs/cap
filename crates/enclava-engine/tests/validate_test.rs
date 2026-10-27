use enclava_engine::testutil::sample_app;
use enclava_engine::validate::ValidationError;
use enclava_engine::validate::validate_app;
use enclava_engine::validate::validate_persistent_volume_size_for_fresh_provisioning;
use sha2::{Digest, Sha256};

#[test]
fn valid_password_app_passes() {
    let app = sample_app();
    validate_app(&app).expect("password app should be valid");
}

#[test]
fn rejects_auto_unlock_workload() {
    // Runtime backstop: no caller may apply an auto-unlock workload.
    let mut app = sample_app();
    app.unlock_mode = enclava_common::types::UnlockMode::Auto;
    let err = validate_app(&app).unwrap_err();
    assert!(
        err.to_string().starts_with("auto_unlock_disabled"),
        "rejection must carry the stable code: {err}"
    );
}

#[test]
fn rejects_empty_name() {
    let mut app = sample_app();
    app.name = "".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("name"));
}

#[test]
fn rejects_no_containers() {
    let mut app = sample_app();
    app.containers.clear();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("container"));
}

#[test]
fn rejects_no_primary_container() {
    let mut app = sample_app();
    app.containers[0].is_primary = false;
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("primary"));
}

#[test]
fn rejects_tag_only_image() {
    let mut app = sample_app();
    app.containers[0].image =
        enclava_common::image::ImageRef::parse("ghcr.io/test/app:latest").unwrap();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("digest"));
}

#[test]
fn rejects_empty_pubkey_hash() {
    let mut app = sample_app();
    app.bootstrap_owner_pubkey_hash = "".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("bootstrap_owner_pubkey_hash"));
}

#[test]
fn rejects_empty_identity_hash() {
    let mut app = sample_app();
    app.tenant_instance_identity_hash = "".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("tenant_instance_identity_hash"));
}

#[test]
fn rejects_wrong_length_identity_hash() {
    let mut app = sample_app();
    app.tenant_instance_identity_hash = "deadbeef".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("64"));
}

#[test]
fn rejects_non_hex_identity_hash() {
    let mut app = sample_app();
    app.tenant_instance_identity_hash =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("hex"));
}

#[test]
fn name_must_be_dns_safe() {
    let mut app = sample_app();
    app.name = "My App!".to_string();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("name"));
}

#[test]
fn rejects_attestation_proxy_without_digest() {
    let mut app = sample_app();
    app.attestation.proxy_image =
        enclava_common::image::ImageRef::parse("ghcr.io/enclava-labs/proxy:latest").unwrap();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("attestation-proxy"));
}

#[test]
fn rejects_caddy_without_digest() {
    let mut app = sample_app();
    app.attestation.caddy_image =
        enclava_common::image::ImageRef::parse("ghcr.io/enclava-labs/caddy:v1").unwrap();
    let err = validate_app(&app).unwrap_err();
    assert!(err.to_string().contains("caddy"));
}

#[test]
fn fresh_provisioning_floor_rejects_sub_luks2_minimum_sizes() {
    // 16 MiB is the bricking size: luksFormat succeeds but activation has no
    // data area left, so anything below the 32 MiB floor (header + payload)
    // must be refused when the size governs a FRESH volume. See
    // MIN_VOLUME_SIZE_MIB. (Empirically re-verified with cryptsetup 2.7.0:
    // 17–31 MiB volumes DO activate, so the floor is a policy bound for
    // fresh provisioning, not a statement that those sizes cannot work.)
    for size in ["0.5Mi", "1Mi", "16Mi", "31Mi", "31.999Mi"] {
        let err =
            validate_persistent_volume_size_for_fresh_provisioning("storage.app_data.size", size)
                .unwrap_err();
        assert!(err.contains("at least 32Mi"), "{size}: {err}");
    }
    let err =
        validate_persistent_volume_size_for_fresh_provisioning("storage.tls_data.size", "16Mi")
            .unwrap_err();
    assert!(err.contains("tls_data"), "{err}");
    assert!(err.contains("at least 32Mi"), "{err}");
    for size in ["32Mi", "33Mi", "1Gi"] {
        validate_persistent_volume_size_for_fresh_provisioning("storage.app_data.size", size)
            .unwrap_or_else(|e| panic!("{size} should be accepted: {e}"));
    }
}

#[test]
fn validate_app_accepts_pre_floor_sizes_for_grandfathered_apps() {
    // validate_app runs on every apply path, including reapplies of apps
    // whose volumes were provisioned before the 32 MiB floor existed (the
    // ConfidentialApp spec carries no provisioning state, and sub-floor
    // LUKS2 volumes DO activate — e.g. a 24 MiB volume has an 8 MiB data
    // area). The floor is therefore NOT enforced there; only the
    // binary-quantity grammar is. If this test starts failing, every
    // reapply/redeploy of a grandfathered sub-floor app is broken, including
    // the domain-only reapply_tenant_ingress path.
    for size in ["16Mi", "24Mi", "31Mi", "32Mi", "1Gi"] {
        let mut app = sample_app();
        app.storage.app_data.size = size.to_string();
        validate_app(&app).unwrap_or_else(|e| panic!("{size} should pass validate_app: {e}"));
    }
}

#[test]
fn v2_spool_layout_rejects_tenant_path_mapping_onto_reserved_enclava_subdir() {
    // cap#290 review: the v2 log spool lives at <state-root>/.enclava/
    // log-spool; a tenant storage_path whose state subdir collapses onto
    // .enclava would share the directory with the spool.
    let err = validate_app(&v2_app_with_logs(vec!["/.enclava".to_string()])).unwrap_err();
    assert!(
        matches!(&err, ValidationError::InvalidStoragePath { .. }),
        "expected InvalidStoragePath, got: {err:?}"
    );

    // The same v2+encrypted app without the reserved path must not produce
    // InvalidStoragePath (the bind subdir transform leaves "/app/data" as
    // "app-data").
    let app = v2_app_with_logs(vec!["/app/data".to_string()]);
    assert!(
        !matches!(
            &validate_app(&app),
            Err(ValidationError::InvalidStoragePath { .. })
        ),
        "a non-colliding storage path must not be rejected"
    );
}

/// v2 signed layout with encrypted logging; the fixture sha256 matches
/// `public_key_sha256("".as_bytes())`-style canonical test material shared
/// with the manifest tests (AAAA… → sha256:Zmh6…).
fn v2_app_with_logs(storage_paths: Vec<String>) -> enclava_engine::types::ConfidentialApp {
    let mut app = sample_app();
    let policy_text = "# enclava-cap-volume-layout: guest-memory-v2\npackage agent_policy\n";
    app.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
        policy_text: policy_text.to_string(),
        policy_sha256: Sha256::digest(policy_text.as_bytes()).into(),
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
    });
    app.log_encryption = Some(enclava_engine::types::LogEncryptionConfig {
        algorithm: "x25519-hpke-v1".to_string(),
        key_id: "logs-prod".to_string(),
        public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
    });
    // The spool capacity floor (128Mi) is part of this gate; give the
    // fixture enough state so storage-path tests exercise only the path
    // checks.
    app.storage.app_data.size = "256Mi".to_string();
    app.containers[0].storage_paths = storage_paths;
    app
}

#[test]
fn v2_spool_layout_rejects_state_volume_too_small_for_the_spool() {
    // cap#290 round-2 review: the bind moves the 32 MiB-rotation spool onto
    // the state PVC; a sub-floor volume wedges the workload on ENOSPC. The
    // compare is exact (no ceil): 127.5Mi must NOT sneak past as 128Mi.
    for size in ["64Mi", "127.5Mi"] {
        let mut app = v2_app_with_logs(Vec::new());
        app.storage.app_data.size = size.to_string();
        let err = validate_app(&app).unwrap_err();
        assert!(
            matches!(
                &err,
                ValidationError::InvalidStorageSize { field, .. } if *field == "storage.app_data.size"
            ),
            "{size}: expected InvalidStorageSize for storage.app_data.size, got: {err:?}"
        );
    }

    // 128Mi exactly and its fractional-Gi spelling both satisfy the floor.
    for size in ["128Mi", "0.125Gi"] {
        let mut app = v2_app_with_logs(Vec::new());
        app.storage.app_data.size = size.to_string();
        assert!(
            !matches!(
                &validate_app(&app),
                Err(ValidationError::InvalidStorageSize { field, .. })
                    if *field == "storage.app_data.size"
            ),
            "{size} must satisfy the spool capacity gate"
        );
    }
}

#[test]
fn v2_spool_layout_rejects_storage_paths_covering_the_spool_target() {
    // cap#290 round-2 review: a tenant storage_path that covers the
    // /run/enclava-logs bind target (equal, ancestor, or descendant)
    // collides the app mount with the platform bind.
    for path in [
        "/run/enclava-logs",
        "/run",
        "/",
        "/run/enclava-logs/sub",
        "/./run/enclava-logs",
        "/run/enclava-logs/../x",
    ] {
        let err = validate_app(&v2_app_with_logs(vec![path.to_string()])).unwrap_err();
        assert!(
            matches!(&err, ValidationError::InvalidStoragePath { .. }),
            "{path}: expected InvalidStoragePath, got: {err:?}"
        );
    }

    // Sibling names and unrelated trees do not cover the target.
    for path in [
        "/run/enclava-logs-other",
        "/data",
        "/run/enclava",
        "/state/app",
    ] {
        let app = v2_app_with_logs(vec![path.to_string()]);
        assert!(
            !matches!(
                &validate_app(&app),
                Err(ValidationError::InvalidStoragePath { .. })
            ),
            "{path}: must not be rejected"
        );
    }
}
