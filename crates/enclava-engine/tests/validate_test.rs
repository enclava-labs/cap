use enclava_engine::testutil::{sample_app, sample_password_app};
use enclava_engine::validate::validate_app;
use enclava_engine::validate::validate_persistent_volume_size_for_fresh_provisioning;

#[test]
fn valid_auto_app_passes() {
    let app = sample_app();
    validate_app(&app).expect("sample auto app should be valid");
}

#[test]
fn valid_password_app_passes() {
    let app = sample_password_app();
    validate_app(&app).expect("password app should be valid");
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
