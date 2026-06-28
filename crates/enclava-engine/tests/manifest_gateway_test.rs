use enclava_engine::manifest::gateway::{
    generate_envoy_proxy, generate_gateway, generate_sni_route_configmap, generate_tee_tls_route,
    generate_tls_route,
};
use enclava_engine::testutil::sample_app;

#[test]
fn gateway_resources_are_instance_scoped() {
    let app = sample_app();

    let envoy_proxy = generate_envoy_proxy(&app);
    let gateway = generate_gateway(&app);
    let tls_route = generate_tls_route(&app);
    let tee_tls_route = generate_tee_tls_route(&app);

    assert_eq!(
        envoy_proxy["metadata"]["name"],
        "tenant-gateway-proxy-test-app"
    );
    assert_eq!(gateway["metadata"]["name"], "tenant-gateway-test-app");
    assert_eq!(tls_route["metadata"]["name"], "tenant-passthrough-test-app");
    assert_eq!(
        tee_tls_route["metadata"]["name"],
        "tenant-tee-passthrough-test-app"
    );
}

#[test]
fn sni_route_configmap_matches_haproxy_discovery_contract() {
    let app = sample_app();
    let cm = generate_sni_route_configmap(&app);
    let labels = cm.metadata.labels.as_ref().unwrap();
    let data = cm.data.as_ref().unwrap();

    assert_eq!(cm.metadata.name.as_deref(), Some("test-app-sni-route"));
    assert_eq!(
        labels.get("caddy-sni-route").map(String::as_str),
        Some("true")
    );
    assert!(!labels.contains_key("kustomize.toolkit.fluxcd.io/name"));
    assert!(!labels.contains_key("kustomize.toolkit.fluxcd.io/namespace"));
    assert_eq!(
        data.get("host").map(String::as_str),
        Some("test-app.abcd1234.enclava.dev")
    );
    assert_eq!(
        data.get("backend_tls").map(String::as_str),
        Some("test-app.cap-test-org-test-app.svc.cluster.local:443")
    );
}

#[test]
fn gateway_uses_tls_passthrough() {
    let app = sample_app();
    let gateway = generate_gateway(&app);

    assert_eq!(gateway["spec"]["gatewayClassName"], "envoy-gateway-tenant");
    assert_eq!(gateway["spec"]["listeners"][0]["protocol"], "TLS");
    assert_eq!(
        gateway["spec"]["listeners"][0]["tls"]["mode"],
        "Passthrough"
    );
}

#[test]
fn tls_route_routes_domain_to_tenant_service() {
    let app = sample_app();
    let route = generate_tls_route(&app);

    assert_eq!(route["apiVersion"], "gateway.networking.k8s.io/v1alpha3");
    assert_eq!(
        route["spec"]["hostnames"][0],
        "test-app.abcd1234.enclava.dev"
    );
    assert_eq!(
        route["spec"]["parentRefs"][0]["name"],
        "tenant-gateway-test-app"
    );
    assert_eq!(
        route["spec"]["rules"][0]["backendRefs"][0]["name"],
        "test-app"
    );
    assert_eq!(route["spec"]["rules"][0]["backendRefs"][0]["port"], 443);
}

#[test]
fn tee_tls_route_routes_tee_domain_to_attestation_service_port() {
    let app = sample_app();
    let route = generate_tee_tls_route(&app);

    assert_eq!(route["apiVersion"], "gateway.networking.k8s.io/v1alpha3");
    assert_eq!(
        route["spec"]["hostnames"][0],
        "test-app.abcd1234.tee.enclava.dev"
    );
    assert_eq!(
        route["spec"]["parentRefs"][0]["name"],
        "tenant-gateway-test-app"
    );
    assert_eq!(
        route["spec"]["rules"][0]["backendRefs"][0]["name"],
        "test-app"
    );
    assert_eq!(route["spec"]["rules"][0]["backendRefs"][0]["port"], 8081);
}

#[test]
fn custom_domain_routes_custom_hostname() {
    let mut app = sample_app();
    app.domain.custom_domain = Some("app.example.com".to_string());

    let route = generate_tls_route(&app);

    assert_eq!(route["spec"]["hostnames"][0], "app.example.com");
}
