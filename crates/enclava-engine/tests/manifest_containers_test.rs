//! Container shape tests. Phase 5 default (no `LEGACY_BOOTSTRAP_SCRIPT`):
//! app and caddy start under an argv-preserving static wait/exec helper, then
//! enclava-init opens LUKS as a long-running mounter sidecar. App/caddy are
//! unprivileged and consume decrypted mountpoint volumes, not raw block PVCs.

use enclava_engine::manifest::containers::{
    ENCLAVA_WAIT_EXEC_PATH, build_app_container, build_attestation_proxy_container,
    build_caddy_container, build_enclava_init_container, build_enclava_tools_init_container,
};
use enclava_engine::testutil::sample_app;
use enclava_engine::types::CaddyTlsMode;

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
    assert_eq!(ENCLAVA_WAIT_EXEC_PATH, "/enclava-tools/enclava-wait-exec");
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
    assert!(vm.iter().any(|m| m.name == "enclava-tools"));
    assert!(vm.iter().any(|m| m.name == "unlock-socket"));
}

#[test]
fn app_container_with_explicit_command_omits_startup_fallback_mount() {
    let mut app = sample_app();
    app.containers[0].command = Some(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exec /usr/local/bin/app".to_string(),
    ]);

    let c = build_app_container(&app);

    assert_eq!(
        c.command.as_ref().unwrap(),
        &vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]
    );
    assert_eq!(
        c.args.as_ref().unwrap(),
        &vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exec /usr/local/bin/app".to_string()
        ]
    );
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.name != "startup"));
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
    assert_eq!(m.mount_propagation.as_deref(), Some("HostToContainer"));
    assert!(c.volume_devices.is_none());
}

#[test]
fn app_container_leaves_declared_storage_paths_for_enclava_init_bind_mounts() {
    let c = build_app_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(
        vm.iter()
            .any(|m| m.name == "state-mount" && m.mount_path == "/state")
    );
    assert!(
        vm.iter()
            .all(|m| !(m.name == "state-mount" && m.mount_path == "/app/data"))
    );
    assert!(vm.iter().all(|m| m.sub_path.is_none()));
    assert_eq!(
        vm.iter()
            .find(|m| m.name == "state-mount" && m.mount_path == "/state")
            .unwrap()
            .mount_propagation
            .as_deref(),
        Some("HostToContainer")
    );
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

#[test]
fn app_container_has_no_kubernetes_subpath_mounts() {
    let c = build_app_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.sub_path.is_none()));
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

#[test]
fn app_container_uses_http_health_probes_with_liveness() {
    let app = sample_app();
    let expected_timeout = app.health.timeout_seconds as i32;
    let c = build_app_container(&app);

    let startup = c.startup_probe.as_ref().unwrap();
    let startup_http = startup.http_get.as_ref().unwrap();
    assert_eq!(startup_http.path.as_deref(), Some("/health"));
    assert_eq!(
        startup_http.port,
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(3000)
    );
    assert_eq!(startup_http.scheme.as_deref(), Some("HTTP"));
    assert!(startup.tcp_socket.is_none());
    assert_eq!(startup.period_seconds, Some(10));
    assert_eq!(startup.failure_threshold, Some(180));

    let readiness = c.readiness_probe.as_ref().unwrap();
    let readiness_http = readiness.http_get.as_ref().unwrap();
    assert_eq!(readiness_http.path.as_deref(), Some("/health"));
    assert_eq!(
        readiness_http.port,
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(3000)
    );
    assert_eq!(readiness_http.scheme.as_deref(), Some("HTTP"));
    assert!(readiness.tcp_socket.is_none());

    let liveness = c.liveness_probe.as_ref().unwrap();
    let liveness_http = liveness.http_get.as_ref().unwrap();
    assert_eq!(liveness_http.path.as_deref(), Some("/health"));
    assert_eq!(
        liveness_http.port,
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(3000)
    );
    assert_eq!(liveness_http.scheme.as_deref(), Some("HTTP"));
    assert!(liveness.tcp_socket.is_none());
    assert_eq!(liveness.period_seconds, Some(30));
    assert_eq!(liveness.timeout_seconds, Some(expected_timeout));
    assert_eq!(liveness.failure_threshold, Some(3));
}

#[test]
fn app_container_uses_configured_health_path() {
    let mut app = sample_app();
    app.health.path = "/v1/info".to_string();

    let c = build_app_container(&app);

    assert_eq!(
        c.startup_probe
            .as_ref()
            .unwrap()
            .http_get
            .as_ref()
            .unwrap()
            .path
            .as_deref(),
        Some("/v1/info")
    );
    assert_eq!(
        c.readiness_probe
            .as_ref()
            .unwrap()
            .http_get
            .as_ref()
            .unwrap()
            .path
            .as_deref(),
        Some("/v1/info")
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
            .find(|e| e.name == "ATTESTATION_BIND")
            .unwrap()
            .value
            .as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ATTESTATION_TLS_BIND")
            .unwrap()
            .value
            .as_deref(),
        Some("0.0.0.0")
    );
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
    assert_eq!(
        env.iter()
            .find(|e| e.name == "CAP_API_SIGNING_PUBKEY")
            .unwrap()
            .value
            .as_deref(),
        Some("test-pubkey-placeholder")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "KBS_RESOURCE_URL")
            .unwrap()
            .value
            .as_deref(),
        Some("http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource")
    );
    let readiness = c.readiness_probe.as_ref().unwrap();
    let http_get = readiness.http_get.as_ref().unwrap();
    assert_eq!(
        http_get.port,
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443)
    );
    assert_eq!(http_get.scheme.as_deref(), Some("HTTPS"));
}

#[test]
fn proxy_container_can_create_sev_guest_device_for_auto_unlock() {
    let c = build_attestation_proxy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.run_as_non_root, Some(false));
    assert_eq!(sc.run_as_user, Some(0));
    assert_eq!(sc.run_as_group, Some(0));
    assert_eq!(sc.read_only_root_filesystem, Some(true));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(
        caps.add.as_deref(),
        Some(
            &[
                "CHOWN".to_string(),
                "MKNOD".to_string(),
                "SYS_PTRACE".to_string()
            ][..]
        )
    );
}

#[test]
fn proxy_container_mounts_unlock_socket() {
    let c = build_attestation_proxy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "unlock-channel").unwrap();
    assert_eq!(m.mount_path, "/run/enclava-unlock");
    let ready_m = vm
        .iter()
        .find(|m| m.name == "unlock-socket" && m.mount_path == "/run/enclava")
        .unwrap();
    assert_ne!(
        ready_m.read_only,
        Some(true),
        "proxy must write its startup sentinel before init-ready"
    );
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_UNLOCK_SOCKET")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava-unlock/unlock.sock")
    );
}

#[test]
fn proxy_container_registers_startup_sentinel_without_waiting_for_init_ready() {
    let c = build_attestation_proxy_container(&sample_app());
    let env = c.env.as_ref().unwrap();

    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_CONTAINER_NAME")
            .unwrap()
            .value
            .as_deref(),
        Some("attestation-proxy")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_STARTED_DIR")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/containers")
    );
    assert!(
        env.iter().all(|e| e.name != "ENCLAVA_INIT_READY_FILE"),
        "proxy must not wait for init-ready before serving unlock"
    );

    assert_eq!(
        c.command.as_ref().unwrap(),
        &vec!["/attestation-proxy".to_string()]
    );
    assert!(c.args.as_ref().is_none_or(|args| args.is_empty()));
}

#[test]
fn proxy_container_uses_luks_state_root_for_config_storage() {
    let c = build_attestation_proxy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let legacy_m = vm
        .iter()
        .find(|m| m.name == "state-mount" && m.mount_path == "/data")
        .unwrap();
    assert_eq!(
        legacy_m.mount_propagation.as_deref(),
        Some("HostToContainer")
    );
    assert!(legacy_m.sub_path.is_none());

    let app_visible_m = vm
        .iter()
        .find(|m| m.name == "state-mount" && m.mount_path == "/state")
        .unwrap();
    assert_eq!(
        app_visible_m.mount_propagation.as_deref(),
        Some("HostToContainer")
    );
    assert!(app_visible_m.sub_path.is_none());

    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "CAP_CONFIG_DIR")
            .unwrap()
            .value
            .as_deref(),
        Some("/state/app-data/.enclava/config")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "CAP_CONFIG_READY_MARKER")
            .unwrap()
            .value
            .as_deref(),
        Some("/state/app-data/.enclava/luks-ready")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "CAP_CONFIG_FILE_GID")
            .unwrap()
            .value
            .as_deref(),
        Some("10001")
    );
}

// === Caddy ===

#[test]
fn caddy_container_name_and_port() {
    let c = build_caddy_container(&sample_app());
    assert_eq!(c.name, "tenant-ingress");
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 10443));
}

#[test]
fn caddy_container_internal_tls_uses_high_port() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Internal;
    let c = build_caddy_container(&app);
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 10443));
    let probe = c.readiness_probe.as_ref().unwrap();
    assert!(
        probe.http_get.is_none(),
        "kubelet HTTPS probes do not set TLS SNI for the tenant domain"
    );
    let tcp_socket = probe.tcp_socket.as_ref().unwrap();
    assert_eq!(
        tcp_socket.port,
        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(10443)
    );
}

#[test]
fn caddy_container_is_unprivileged_without_bind_capabilities() {
    let c = build_caddy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    assert_eq!(sc.allow_privilege_escalation, Some(false));
    assert_eq!(sc.run_as_user, Some(10002));
    assert_eq!(sc.run_as_group, Some(10002));
    assert_eq!(sc.run_as_non_root, Some(true));
    assert_eq!(sc.read_only_root_filesystem, Some(false));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert!(caps.add.as_deref().unwrap_or_default().is_empty());
}

#[test]
fn caddy_container_waits_for_init_ready_before_starting_caddy() {
    let c = build_caddy_container(&sample_app());
    assert_eq!(
        c.command.as_ref().unwrap(),
        &vec!["/enclava-tools/enclava-wait-exec".to_string()]
    );
    let args = c.args.as_ref().unwrap();
    assert_eq!(args[0], "/bin/sh");
    assert_eq!(args[1], "-ec");
    assert!(args[2].contains("/usr/bin/caddy run --config /etc/caddy/Caddyfile"));
}

#[test]
fn caddy_container_supervises_caddy_inside_existing_kata_container() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Dns01Broker;
    let c = build_caddy_container(&app);
    let args = c.args.as_ref().unwrap();

    assert_eq!(args[0], "/bin/sh");
    assert_eq!(args[1], "-ec");
    assert!(
        args[2].contains("/run/enclava/caddy-runtime/certificates/tls.crt"),
        "broker TLS mode must wait for the runtime certificate handoff"
    );
    assert!(
        args[2].contains("/run/enclava/caddy-runtime/certificates/tls.key"),
        "broker TLS mode must wait for the runtime private key handoff"
    );
    assert!(
        args[2].contains("/usr/bin/caddy validate --config /etc/caddy/Caddyfile"),
        "ingress must validate before serving so failures are visible"
    );
    assert!(
        args[2].contains("tenant-ingress caddy exited"),
        "ingress must retry inside the existing Kata container instead of relying on container restarts"
    );
}

#[test]
fn caddy_container_does_not_mount_extra_tools() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "enclava-tools"));
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
fn caddy_container_mounts_runtime_handoff_for_persistence() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.name != "state-mount"));
    assert!(vm.iter().all(|m| m.name != "tls-state-mount"));
    assert!(vm.iter().all(|m| m.name != "caddy-runtime"));
    let shared_mount = vm.iter().find(|m| m.name == "unlock-socket").unwrap();
    assert_eq!(shared_mount.mount_path, "/run/enclava");
    assert!(shared_mount.mount_propagation.is_none());
    assert!(shared_mount.sub_path.is_none());
    assert!(c.volume_devices.is_none());
}

#[test]
fn caddy_container_reads_seed_from_state_caddy() {
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "CADDY_SEED_PATH").unwrap();
    assert_eq!(found.value.as_deref(), Some("/state/caddy/seed"));
}

#[test]
fn caddy_container_uses_writable_caddy_runtime_dirs() {
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "XDG_DATA_HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "XDG_CONFIG_HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime/config")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime")
    );
}

#[test]
fn caddy_container_internal_tls_uses_tmp_runtime_dirs() {
    let mut app = sample_app();
    app.attestation.caddy_tls_mode = CaddyTlsMode::Internal;
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    assert_eq!(
        env.iter()
            .find(|e| e.name == "XDG_DATA_HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "XDG_CONFIG_HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime/config")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "HOME")
            .unwrap()
            .value
            .as_deref(),
        Some("/run/enclava/caddy-runtime")
    );
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
        Some("web,tenant-ingress,attestation-proxy")
    );
    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_UNLOCK_SOCKET_GID")
            .unwrap()
            .value
            .as_deref(),
        Some("10001")
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
fn enclava_init_container_waits_for_tenant_ingress_sentinel() {
    let mut app = sample_app();
    app.containers[0].storage_paths.clear();

    let c = build_enclava_init_container(&app);
    let env = c.env.as_ref().unwrap();

    assert_eq!(
        env.iter()
            .find(|e| e.name == "ENCLAVA_INIT_WAIT_FOR_CONTAINERS")
            .unwrap()
            .value
            .as_deref(),
        Some("web,tenant-ingress,attestation-proxy")
    );
}

#[test]
fn enclava_init_container_has_memory_for_unlock_verification_and_certificate_provisioning() {
    let c = build_enclava_init_container(&sample_app());
    let resources = c.resources.as_ref().unwrap();
    let requests = resources.requests.as_ref().unwrap();
    let limits = resources.limits.as_ref().unwrap();

    assert_eq!(requests.get("memory").unwrap().0, "64Mi");
    assert_eq!(limits.get("memory").unwrap().0, "512Mi");
}

#[test]
fn enclava_tools_init_container_has_resources_for_tenant_quota() {
    let c = build_enclava_tools_init_container();
    let resources = c.resources.as_ref().unwrap();
    let requests = resources.requests.as_ref().unwrap();
    let limits = resources.limits.as_ref().unwrap();

    assert_eq!(requests.get("cpu").unwrap().0, "10m");
    assert_eq!(requests.get("memory").unwrap().0, "16Mi");
    assert_eq!(limits.get("cpu").unwrap().0, "50m");
    assert_eq!(limits.get("memory").unwrap().0, "64Mi");
}

#[test]
fn enclava_tools_init_container_prepares_group_restricted_wait_handoff() {
    let c = build_enclava_tools_init_container();
    let command = c.command.as_ref().unwrap().join(" ");
    assert!(command.contains("install -d -m 02770 -o 0 -g 10001 /run/enclava/containers"));
    let mounts = c.volume_mounts.as_ref().unwrap();
    assert!(
        mounts
            .iter()
            .any(|m| m.name == "unlock-socket" && m.mount_path == "/run/enclava")
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
    assert!(vm.iter().any(|m| m.name == "unlock-channel"));
    assert!(vm.iter().any(|m| m.name == "enclava-init-config"));
    assert!(vm.iter().all(|m| m.name != "caddy-runtime"));
    let state_mount = vm.iter().find(|m| m.name == "state-mount").unwrap();
    let tls_mount = vm.iter().find(|m| m.name == "tls-state-mount").unwrap();
    assert_eq!(
        state_mount.mount_propagation.as_deref(),
        Some("Bidirectional")
    );
    assert_eq!(
        tls_mount.mount_propagation.as_deref(),
        Some("Bidirectional")
    );
}
