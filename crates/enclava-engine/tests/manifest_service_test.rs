use enclava_engine::manifest::service::generate_service;
use enclava_engine::testutil::sample_app;
use enclava_engine::types::CaddyTlsMode;

#[test]
fn service_name_and_namespace() {
    let app = sample_app();
    let svc = generate_service(&app);
    assert_eq!(svc.metadata.name.as_deref(), Some("test-app"));
    assert_eq!(
        svc.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn service_has_https_port() {
    let app = sample_app();
    let svc = generate_service(&app);
    let ports = svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
    let https = ports
        .iter()
        .find(|p| p.name.as_deref() == Some("https"))
        .unwrap();
    assert_eq!(https.port, 443);
    assert_eq!(
        https.target_port.as_ref().unwrap(),
        &k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(443)
    );
}

#[test]
fn service_internal_tls_maps_https_to_caddy_high_port() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Internal;
    let svc = generate_service(&app);
    let ports = svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
    let https = ports
        .iter()
        .find(|p| p.name.as_deref() == Some("https"))
        .unwrap();
    assert_eq!(https.port, 443);
    assert_eq!(
        https.target_port.as_ref().unwrap(),
        &k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(10443)
    );
}

#[test]
fn service_has_attestation_port() {
    let app = sample_app();
    let svc = generate_service(&app);
    let ports = svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
    let att = ports
        .iter()
        .find(|p| p.name.as_deref() == Some("attestation"))
        .unwrap();
    assert_eq!(att.port, 8081);
    assert_eq!(
        att.target_port.as_ref().unwrap(),
        &k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443)
    );
}

#[test]
fn service_selector_matches_app() {
    let app = sample_app();
    let svc = generate_service(&app);
    let selector = svc.spec.as_ref().unwrap().selector.as_ref().unwrap();
    assert_eq!(selector.get("app"), Some(&"test-app".to_string()));
}

#[test]
fn service_serializes_to_yaml() {
    let app = sample_app();
    let svc = generate_service(&app);
    let yaml = serde_yaml::to_string(&svc).unwrap();
    assert!(yaml.contains("443"));
    assert!(yaml.contains("8081"));
    assert!(yaml.contains("test-app"));
}
