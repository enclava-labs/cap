use enclava_engine::manifest::ingress::generate_ingress_configmap;
use enclava_engine::testutil::sample_app;
use enclava_engine::types::CaddyTlsMode;

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
    assert!(caddyfile.contains("storage file_system /run/enclava/caddy-runtime"));
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
fn caddyfile_handles_confidential_cors_preflight() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();

    assert!(caddyfile.contains("@confidential_preflight"));
    assert!(caddyfile.contains("method OPTIONS"));
    assert!(caddyfile.contains("Access-Control-Allow-Origin \"*\""));
    assert!(
        caddyfile.contains("Access-Control-Allow-Headers \"Authorization, Content-Type, Accept\"")
    );
    assert!(caddyfile.contains("respond \"\" 204"));
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
    assert!(caddyfile.contains("dir https://acme-v02.api.letsencrypt.org/directory"));
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev:10443"));
}

#[test]
fn caddyfile_acme_mode_disables_extra_caddy_runtime_surfaces() {
    let app = sample_app();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("admin off"));
    assert!(caddyfile.contains("persist_config off"));
    assert!(caddyfile.contains("auto_https disable_redirects"));
}

#[test]
fn caddyfile_uses_configured_acme_ca() {
    let mut app = sample_app();
    app.attestation.acme_ca_url =
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("dir https://acme-staging-v02.api.letsencrypt.org/directory"));
    assert!(caddyfile.contains(
        "issuer acme {\n      dir https://acme-staging-v02.api.letsencrypt.org/directory"
    ));
}

#[test]
fn caddyfile_dns01_broker_mode_uses_static_enclave_owned_certificate() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Dns01Broker;

    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();

    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev:10443"));
    assert!(caddyfile.contains(
        "tls /run/enclava/caddy-runtime/certificates/tls.crt /run/enclava/caddy-runtime/certificates/tls.key"
    ));
    assert!(!caddyfile.contains("issuer acme"));
    assert!(!caddyfile.contains("dns cloudflare"));
    assert!(!caddyfile.contains("CF_API_TOKEN"));
}

#[test]
fn caddyfile_internal_tls_mode_skips_acme() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Internal;
    let cm = generate_ingress_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    let caddyfile = data.get("Caddyfile").unwrap();
    assert!(caddyfile.contains("admin off"));
    assert!(caddyfile.contains("persist_config off"));
    assert!(caddyfile.contains("auto_https disable_redirects"));
    assert!(caddyfile.contains("storage file_system /run/enclava/caddy-runtime"));
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev:10443"));
    assert!(caddyfile.contains("tls internal"));
    assert!(!caddyfile.contains(" ca https://"));
    assert!(!caddyfile.contains("issuer acme"));
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
fn caddyfile_health_route_rewrites_to_configured_app_health_path() {
    let mut app = sample_app();
    app.health.path = "/v1/info".to_string();

    let cm = generate_ingress_configmap(&app);
    let caddyfile = cm.data.as_ref().unwrap().get("Caddyfile").unwrap();

    assert!(caddyfile.contains(
        "  handle /health {\n    rewrite * /v1/info\n    reverse_proxy 127.0.0.1:3000\n  }"
    ));
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
    assert!(caddyfile.contains("test-app.abcd1234.enclava.dev:10443, app.example.com:10443"));
}
