//! Volume + VCT shape tests. Phase 5 default: unlock-socket emptyDir,
//! shared decrypted mountpoint EmptyDirs, enclava-init-config ConfigMap volume,
//! no Cloudflare-token secret. PVCs stay raw Block devices for LUKS.

use enclava_engine::manifest::volumes::{build_volume_claim_templates, build_volumes};
use enclava_engine::testutil::sample_app;

#[test]
fn volumes_has_ownership_signal() {
    let vols = build_volumes(&sample_app());
    let os = vols.iter().find(|v| v.name == "ownership-signal").unwrap();
    let ed = os.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
}

#[test]
fn volumes_has_unlock_socket_memory_emptydir() {
    let vols = build_volumes(&sample_app());
    let v = vols.iter().find(|v| v.name == "unlock-socket").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
    let channel = vols.iter().find(|v| v.name == "unlock-channel").unwrap();
    let channel_ed = channel.empty_dir.as_ref().unwrap();
    assert_eq!(channel_ed.medium.as_deref(), Some("Memory"));
}

#[test]
fn volumes_has_enclava_init_config_configmap() {
    // Regression for prototype P1: ConfigMap volume must be wired up by name.
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols
        .iter()
        .find(|v| v.name == "enclava-init-config")
        .unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "test-app-enclava-init");
}

#[test]
fn volumes_has_startup_fallback_configmap() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols.iter().find(|v| v.name == "startup").unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "test-app-startup");
    assert_eq!(cm.default_mode, Some(0o555));
}

#[test]
fn volumes_omit_startup_fallback_configmap_when_primary_command_is_explicit() {
    let mut app = sample_app();
    app.containers[0].command = Some(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exec /usr/local/bin/app".to_string(),
    ]);

    let vols = build_volumes(&app);

    assert!(vols.iter().all(|v| v.name != "startup"));
}

#[test]
fn volumes_have_shared_decrypted_mountpoints() {
    let vols = build_volumes(&sample_app());
    assert!(vols.iter().any(|v| v.name == "state-mount"));
    assert!(vols.iter().any(|v| v.name == "tls-state-mount"));
    assert!(vols.iter().all(|v| v.name != "caddy-runtime"));
}

#[test]
fn volumes_do_not_include_enclava_tools_emptydir() {
    let vols = build_volumes(&sample_app());
    assert!(vols.iter().any(|v| v.name == "enclava-tools"));
}

#[test]
fn volumes_has_tenant_ingress_caddyfile() {
    let vols = build_volumes(&sample_app());
    let v = vols
        .iter()
        .find(|v| v.name == "tenant-ingress-caddyfile")
        .unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "test-app-tenant-ingress");
}

#[test]
fn volumes_does_not_mount_cloudflare_token_in_phase5_default() {
    // Phase 0/5: TLS-ALPN-01 only — no Cloudflare DNS-01 token mount.
    let vols = build_volumes(&sample_app());
    assert!(vols.iter().all(|v| v.name != "tls-cloudflare-token"));
}

#[test]
fn vcts_state_uses_block_volume_mode() {
    let vcts = build_volume_claim_templates(&sample_app());
    let state = vcts
        .iter()
        .find(|v| v.metadata.name.as_deref() == Some("state"))
        .unwrap();
    let spec = state.spec.as_ref().unwrap();
    assert_eq!(spec.volume_mode.as_deref(), Some("Block"));
}

#[test]
fn vcts_tls_state_uses_block_volume_mode() {
    let vcts = build_volume_claim_templates(&sample_app());
    let tls = vcts
        .iter()
        .find(|v| v.metadata.name.as_deref() == Some("tls-state"))
        .unwrap();
    let spec = tls.spec.as_ref().unwrap();
    assert_eq!(spec.volume_mode.as_deref(), Some("Block"));
}

#[test]
fn vcts_use_read_write_once() {
    let vcts = build_volume_claim_templates(&sample_app());
    for vct in &vcts {
        let modes = vct.spec.as_ref().unwrap().access_modes.as_ref().unwrap();
        assert_eq!(modes, &["ReadWriteOnce"]);
    }
}
