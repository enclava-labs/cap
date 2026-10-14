use enclava_engine::testutil::{sample_app, sample_password_app};
use enclava_engine::validate::validate_app;

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
fn rejects_persistent_volume_sizes_below_luks2_floor() {
    // 16 MiB is the bricking size: luksFormat succeeds but activation has no
    // data area left, so anything below the 32 MiB floor (header + payload)
    // must be refused at manifest validation. See MIN_VOLUME_SIZE_MIB.
    for size in ["0.5Mi", "1Mi", "16Mi", "31Mi", "31.999Mi"] {
        let mut app = sample_app();
        app.storage.app_data.size = size.to_string();
        let err = validate_app(&app).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("app_data"), "{size}: {message}");
        assert!(message.contains("at least 32Mi"), "{size}: {message}");
    }

    let mut app = sample_app();
    app.storage.tls_data.size = "16Mi".to_string();
    let err = validate_app(&app).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("tls_data"), "{message}");
    assert!(message.contains("at least 32Mi"), "{message}");
}

#[test]
fn accepts_persistent_volume_sizes_at_luks2_floor() {
    for size in ["32Mi", "33Mi", "1Gi"] {
        let mut app = sample_app();
        app.storage.app_data.size = size.to_string();
        validate_app(&app).unwrap_or_else(|e| panic!("{size} should be accepted: {e}"));
    }
}
