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
