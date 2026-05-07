//! Container shape tests. Phase 5 default (no `LEGACY_BOOTSTRAP_SCRIPT`):
//! app and caddy start under an argv-preserving static wait/exec helper, then
//! enclava-init opens LUKS as a long-running mounter sidecar. App/caddy are
//! unprivileged and consume decrypted mountpoint volumes, not raw block PVCs.

use enclava_engine::manifest::containers::{
    ENCLAVA_WAIT_EXEC_PATH, build_app_container, build_attestation_proxy_container,
    build_caddy_container, build_enclava_init_container,
};
use enclava_engine::testutil::sample_app;

// === App container (Phase 5 default) ===

#[test]
fn app_container_name() {
    let c = build_app_container(&sample_app());
    assert_eq!(c.name, "web");
}

#[test]
fn app_container_is_not_privileged() {
    let c = build_app_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    assert_eq!(sc.allow_privilege_escalation, Some(false));
    assert_eq!(sc.run_as_non_root, Some(true));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert!(caps.add.as_deref().map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn app_container_does_not_use_sh_c() {
    let c = build_app_container(&sample_app());
    if let Some(cmd) = c.command.as_ref() {
        assert!(!cmd.iter().any(|s| s == "-c"));
        assert!(!cmd.iter().any(|s| s.contains("bootstrap.sh")));
    }
}

#[test]
fn app_container_starts_under_wait_wrapper() {
    let c = build_app_container(&sample_app());
    assert_eq!(
        c.command.as_ref().unwrap(),
        &vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]
    );
    assert_eq!(ENCLAVA_WAIT_EXEC_PATH, "/usr/local/bin/enclava-wait-exec");
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_CONTAINER_NAME")
            .unwrap()
            .value
            .as_deref(),
        Some("web")
    );
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "startup"));
    assert!(vm.iter().all(|m| m.name != "enclava-tools"));
    assert!(vm.iter().any(|m| m.name == "unlock-socket"));
}

#[test]
fn app_container_reads_seed_from_state_app() {
    let c = build_app_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "APP_SEED_PATH").unwrap();
    assert_eq!(found.value.as_deref(), Some("/state/app/seed"));
}

#[test]
fn app_container_mounts_state_filesystem() {
    let c = build_app_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "state-mount").unwrap();
    assert_eq!(m.mount_path, "/state");
    assert_eq!(m.mount_propagation.as_deref(), None);
    assert!(c.volume_devices.is_none());
}

#[test]
fn app_container_preserves_declared_storage_paths_as_subpaths() {
    let c = build_app_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm
        .iter()
        .find(|m| m.name == "state-mount" && m.mount_path == "/app/data")
        .unwrap();
    assert_eq!(m.sub_path.as_deref(), Some("app-data"));
    assert_eq!(m.mount_propagation.as_deref(), None);
    assert_eq!(
        c.env
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.name == "VOLUME_MOUNT_POINT")
            .unwrap()
            .value
            .as_deref(),
        Some("/state")
    );
}

// === Attestation proxy ===

#[test]
fn proxy_container_name_and_port() {
    let c = build_attestation_proxy_container(&sample_app());
    assert_eq!(c.name, "attestation-proxy");
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 8081));
    assert!(ports.iter().any(|p| p.container_port == 8443));
    assert!(
        ports
            .iter()
            .any(|p| { p.container_port == 8081 && p.name.as_deref() == Some("attest-http") })
    );
    assert!(
        ports
            .iter()
            .any(|p| { p.container_port == 8443 && p.name.as_deref() == Some("attestation") })
    );
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ATTESTATION_TLS_PORT")
            .unwrap()
            .value
            .as_deref(),
        Some("8443")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "TEE_DOMAIN")
            .unwrap()
            .value
            .as_deref(),
        Some("test-app.abcd1234.tee.enclava.dev")
    );
}

#[test]
fn proxy_container_is_non_root() {
    let c = build_attestation_proxy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.run_as_non_root, Some(true));
    assert_eq!(sc.run_as_user, Some(65532));
    assert_eq!(sc.read_only_root_filesystem, Some(true));
}

#[test]
fn proxy_container_mounts_unlock_socket() {
    let c = build_attestation_proxy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "unlock-socket").unwrap();
    assert_eq!(m.mount_path, "/run/enclava");
}

// === Caddy ===

#[test]
fn caddy_container_name_and_port() {
    let c = build_caddy_container(&sample_app());
    assert_eq!(c.name, "tenant-ingress");
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 443));
}

#[test]
fn caddy_container_is_unprivileged_with_only_net_bind() {
    let c = build_caddy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(
        caps.add.as_deref(),
        Some(&["NET_BIND_SERVICE".to_string()][..])
    );
}

#[test]
fn caddy_container_command_is_argv_not_shell() {
    let c = build_caddy_container(&sample_app());
    let cmd = c.command.as_ref().unwrap();
    assert_eq!(cmd, &vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]);
    let args = c.args.as_ref().unwrap();
    assert_eq!(
        args,
        &vec![
            "caddy".to_string(),
            "run".to_string(),
            "--config".to_string(),
            "/etc/caddy/Caddyfile".to_string(),
        ]
    );
}

#[test]
fn caddy_container_uses_in_image_static_wait_exec_helper() {
    let c = build_caddy_container(&sample_app());
    assert_eq!(
        c.command.as_ref().unwrap(),
        &vec!["/usr/local/bin/enclava-wait-exec".to_string()]
    );
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.name != "enclava-tools"));
}

#[test]
fn caddy_container_has_no_cf_api_token_env() {
    // DNS-01 / Cloudflare path is gone; CF_API_TOKEN must not be set anywhere.
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    assert!(env.iter().all(|e| e.name != "CF_API_TOKEN"));
    if let Some(cmd) = c.command.as_ref() {
        for s in cmd {
            assert!(!s.contains("CF_API_TOKEN"));
        }
    }
}

#[test]
fn caddy_container_does_not_mount_cloudflare_token() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.name != "tls-cloudflare-token"));
}

#[test]
fn caddy_container_mounts_tls_state_filesystem() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "tls-state-mount").unwrap();
    assert_eq!(m.mount_path, "/state/tls-state");
    assert_eq!(m.mount_propagation.as_deref(), None);
    assert!(c.volume_devices.is_none());
}

#[test]
fn caddy_container_reads_seed_from_state_caddy() {
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "CADDY_SEED_PATH").unwrap();
    assert_eq!(found.value.as_deref(), Some("/state/caddy/seed"));
}

// === enclava-init mounter sidecar ===

#[test]
fn enclava_init_container_is_mounter_sidecar_and_keeps_only_sys_admin() {
    let c = build_enclava_init_container(&sample_app());
    assert_eq!(c.name, "enclava-init");
    assert!(c.restart_policy.is_none());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(true));
    assert_eq!(sc.allow_privilege_escalation, Some(true));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(caps.add.as_deref(), Some(&["SYS_ADMIN".to_string()][..]));
}

#[test]
fn enclava_init_container_waits_for_workloads_and_marks_ready_file() {
    let c = build_enclava_init_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_STAY_ALIVE")
            .unwrap()
            .value
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_READY_FILE")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/init-ready")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_WAIT_FOR_CONTAINERS")
            .unwrap()
            .value
            .as_deref(),
        Some("web,tenant-ingress")
    );
    assert!(c.startup_probe.is_none());
    let probe = c.readiness_probe.as_ref().unwrap();
    let command = probe.exec.as_ref().unwrap().command.as_ref().unwrap();
    assert_eq!(
        command,
        &vec![
            "/usr/local/bin/enclava-init".to_string(),
            "--probe-ready".to_string()
        ]
    );
}

#[test]
fn enclava_init_container_mounts_both_luks_devices_and_unlock_socket() {
    let c = build_enclava_init_container(&sample_app());
    let vd = c.volume_devices.as_ref().unwrap();
    assert!(vd.iter().any(|d| d.name == "state"));
    assert!(vd.iter().any(|d| d.name == "tls-state"));
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "unlock-socket"));
    assert!(vm.iter().any(|m| m.name == "enclava-init-config"));
    let state_mount = vm.iter().find(|m| m.name == "state-mount").unwrap();
    let tls_mount = vm.iter().find(|m| m.name == "tls-state-mount").unwrap();
    assert_eq!(state_mount.mount_propagation.as_deref(), None);
    assert_eq!(tls_mount.mount_propagation.as_deref(), None);
}
