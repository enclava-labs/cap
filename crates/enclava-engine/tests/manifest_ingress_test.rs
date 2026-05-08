use enclava_engine::manifest::ingress::generate_ingress_configmap;
use enclava_engine::testutil::sample_app;

#[test]
fn ingress_configmap_name() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    assert_eq!(cm.metadata.name.as_deref(), Some("test-app-tenant-ingress"));
}

#[test]
fn ingress_configmap_namespace() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    assert_eq!(
        cm.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn caddyfile_contains_domain() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev"));
}

#[test]
fn caddyfile_contains_app_port() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("127.0.0.1:3000"));
}

#[test]
fn caddyfile_uses_rootfs_tls_storage_path() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("storage file_system /tmp/enclava-tls-state/caddy"));
}

#[test]
fn caddyfile_has_attestation_proxy_route() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("/v1/attestation"));
    assert!(caddyfile.contains("127.0.0.1:8081"));
}

#[test]
fn caddyfile_has_well_known_confidential_routes() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("/.well-known/confidential/*"));
}

#[test]
fn caddyfile_has_unlock_route() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("/unlock"));
}

#[test]
fn caddyfile_drops_dns01_cloudflare_path() {
    // Phase 0/5: DNS-01 / Cloudflare path is gone in favour of TLS-ALPN-01.
    // The Caddyfile must not reference Cloudflare or the env-supplied token.
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(!caddyfile.contains("dns cloudflare"));
    assert!(!caddyfile.contains("CF_API_TOKEN"));
}

#[test]
fn caddyfile_defaults_to_letsencrypt_production() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("acme_ca https://acme-v02.api.letsencrypt.org/directory"));
}

#[test]
fn caddyfile_uses_configured_acme_ca() {
    let mut app = sample_app();
    app.attestation.acme_ca_url =
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("acme_ca https://acme-staging-v02.api.letsencrypt.org/directory"));
}

#[test]
fn caddyfile_has_health_route() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("/health"));
}

#[test]
fn custom_domain_app_uses_custom_domain() {
    let mut app = sample_app();
    app.domain.custom_domain = Some("app.example.com".to_string());
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("app.example.com"));
}

#[test]
fn custom_domain_keeps_platform_domain_in_site_block() {
    // Regression for security review finding 3: when a custom domain is
    // verified post-deploy, the regenerated Caddyfile must still serve the
    // platform hostname so existing CLI/API clients keep working AND the new
    // custom hostname so HAProxy SNI routing has somewhere to terminate.
    let mut app = sample_app();
    app.domain.custom_domain = Some("app.example.com".to_string());
    let cm = generate_ingress_configmap(&app);
    let caddyfile = cm.data.as_ref().unwrap().get("Caddyfile").unwrap();
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev"));
    assert!(caddyfile.contains("app.example.com"));
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev, app.example.com"));
}
