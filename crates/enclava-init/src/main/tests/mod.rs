use super::*;
use tempfile::tempdir;

#[test]
fn ready_probe_reflects_ready_file_state() {
    let dir = tempdir().unwrap();
    let ready = dir.path().join("run/enclava/init-ready");

    assert!(!ready_file_exists(&ready));
    mark_ready_file(&ready).unwrap();
    assert!(ready_file_exists(&ready));
    clear_ready_file(&ready).unwrap();
    assert!(!ready_file_exists(&ready));
}

#[test]
fn failure_file_includes_last_recorded_stage() {
    let dir = tempdir().unwrap();
    let error = dir.path().join("init-error");
    let termination = dir.path().join("termination-log");
    let stage = dir.path().join("init-stage");
    unsafe {
        std::env::set_var("ENCLAVA_INIT_ERROR_FILE", &error);
        std::env::set_var("ENCLAVA_INIT_TERMINATION_LOG", &termination);
        std::env::set_var("ENCLAVA_INIT_STAGE_FILE", &stage);
    }

    record_stage("opening luks volumes").unwrap();
    record_failure_file("mount failed\n");

    let body = std::fs::read_to_string(&error).unwrap();
    assert!(body.contains("last_stage=opening luks volumes"));
    assert!(body.contains("mount failed"));
    assert_eq!(std::fs::read_to_string(&termination).unwrap(), body);

    unsafe {
        std::env::remove_var("ENCLAVA_INIT_ERROR_FILE");
        std::env::remove_var("ENCLAVA_INIT_TERMINATION_LOG");
        std::env::remove_var("ENCLAVA_INIT_STAGE_FILE");
    }
}

#[test]
fn container_sentinel_names_are_single_path_components() {
    assert_eq!(validate_sentinel_name("web").unwrap(), "web");
    assert!(validate_sentinel_name("../web").is_err());
    assert!(validate_sentinel_name("web/sidecar").is_err());
}

#[test]
fn same_object_check_detects_identical_and_distinct_dirs() {
    let dir = tempdir().unwrap();
    let one = dir.path().join("one");
    let two = dir.path().join("two");
    std::fs::create_dir_all(&one).unwrap();
    std::fs::create_dir_all(&two).unwrap();

    assert!(paths_resolve_to_same_object(&one, &one).unwrap());
    assert!(!paths_resolve_to_same_object(&one, &two).unwrap());
}

#[test]
fn namespace_bind_chroots_to_workload_proc_root() {
    let root = workload_proc_root_path(42);

    assert_eq!(root, PathBuf::from("/proc/42/root"));
}

#[test]
fn namespace_bind_chroot_source_strips_init_proc_root() {
    let source = Path::new("/proc/10/root/state/data");

    let stripped = mount_source_path_after_workload_chroot(source);

    assert_eq!(stripped, PathBuf::from("/state/data"));
}

#[test]
fn caddy_tls_bind_source_is_below_tls_state_root() {
    assert_eq!(
        caddy_tls_bind_dir(Path::new("/state/tls-state")),
        PathBuf::from("/state/tls-state/tenant-ingress")
    );
}

#[test]
fn caddy_runtime_sync_copies_nested_files_and_skips_symlinks() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(src.join("caddy/certificates")).unwrap();
    std::fs::create_dir_all(src.join("locks")).unwrap();
    std::fs::write(src.join("caddy/certificates/site.crt"), b"cert").unwrap();
    std::fs::write(src.join("locks/issue_cert.lock"), b"lock").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", src.join("skip-link")).unwrap();

    sync_dir_contents(&src, &dst).unwrap();

    assert_eq!(
        std::fs::read(dst.join("caddy/certificates/site.crt")).unwrap(),
        b"cert"
    );
    assert!(!dst.join("skip-link").exists());
    assert!(!dst.join("locks").exists());
}

#[test]
fn caddy_runtime_handoff_reowns_copied_tree_for_caddy() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(src.join("certificates")).unwrap();
    std::fs::write(src.join("certificates/tls.key"), b"key").unwrap();
    let caddy_identity = numeric_identity(10002, 10002);

    let mut chowned = Vec::new();
    seed_caddy_runtime_handoff_at(&src, &dst, caddy_identity, |path, identity| {
        chowned.push((path.to_path_buf(), identity));
        Ok(())
    })
    .unwrap();

    assert_eq!(
        std::fs::read(dst.join("certificates/tls.key")).unwrap(),
        b"key"
    );
    assert_eq!(chowned, vec![(dst, caddy_identity)]);
}

#[test]
fn tenant_ingress_bind_plan_uses_shared_tls_mount_not_namespace_bind() {
    let dir = tempdir().unwrap();
    let cfg = config_with_signed_cc(dir.path(), "");
    let workload = WorkloadNamespace {
        name: "tenant-ingress".to_string(),
        pid: 1234,
    };

    let mounts = bind_mount_plan_for_workload(&cfg, 42, &workload).unwrap();

    assert!(mounts.is_empty());
}

#[test]
fn kbs_proxy_health_url_strips_cdh_resource_suffix() {
    assert_eq!(
        kbs_proxy_health_url("http://127.0.0.1:8081/cdh/resource"),
        "http://127.0.0.1:8081/health"
    );
    assert_eq!(
        kbs_proxy_health_url("http://127.0.0.1:8081/cdh/resource/"),
        "http://127.0.0.1:8081/health"
    );
    assert_eq!(
        kbs_proxy_health_url("http://127.0.0.1:8081/custom"),
        "http://127.0.0.1:8081/custom/health"
    );
}

#[test]
fn local_kbs_proxy_detection_matches_loopback_8081() {
    assert!(is_local_kbs_proxy_url("http://127.0.0.1:8081/cdh/resource"));
    assert!(is_local_kbs_proxy_url("http://localhost:8081/cdh/resource"));
    assert!(!is_local_kbs_proxy_url(
        "http://127.0.0.1:8080/cdh/resource"
    ));
    assert!(!is_local_kbs_proxy_url(
        "http://127.0.0.1:8006/cdh/resource"
    ));
    assert!(!is_local_kbs_proxy_url(
        "https://kbs.example.test/cdh/resource"
    ));
}

#[test]
fn kbs_proxy_health_accepts_ready_statuses() {
    assert!(kbs_proxy_health_status_is_ready(200));
    assert!(kbs_proxy_health_status_is_ready(423));
    assert!(!kbs_proxy_health_status_is_ready(503));
}

fn config_with_signed_cc(dir: &Path, cc_body: &str) -> Config {
    let cc_path = dir.join("cc-init-data.toml");
    std::fs::write(&cc_path, cc_body).unwrap();
    Config {
        mode: Mode::Autounlock,
        state: VolumeConfig {
            device: "/dev/csi0".to_string(),
            mapping_name: "cap-state".to_string(),
            mount_path: "/state".to_string(),
            hkdf_info: "state-luks-key".to_string(),
        },
        tls_state: VolumeConfig {
            device: "/dev/csi1".to_string(),
            mapping_name: "cap-tls-state".to_string(),
            mount_path: "/state/tls-state".to_string(),
            hkdf_info: "tls-state-luks-key".to_string(),
        },
        unlock_socket: "/run/enclava/unlock.sock".to_string(),
        state_root: "/state".to_string(),
        attempts_path: "/run/enclava/unlock-attempts".to_string(),
        app_uid: 10001,
        app_gid: 10001,
        caddy_uid: 10002,
        caddy_gid: 10002,
        app_bind_mounts: Vec::new(),
        kbs_url: Some("http://127.0.0.1:8006/cdh/resource".to_string()),
        kbs_resource_path: Some("default/app-owner/seed-encrypted".to_string()),
        argon2_salt_hex: Some("aa".repeat(32)),
        trustee_policy_read_available: true,
        workload_artifacts_url: Some("file:///artifacts.json".to_string()),
        tls_certificate_broker_url: None,
        tls_certificate_hostnames: Vec::new(),
        trustee_policy_url: Some("file:///policy.json".to_string()),
        kbs_attestation_token_url: "http://127.0.0.1:8006/aa/token?token_type=kbs".to_string(),
        cc_init_data_path: Some(cc_path.display().to_string()),
        platform_trustee_policy_pubkey_hex: None,
        signing_service_pubkey_hex: None,
    }
}

#[test]
fn signed_cc_init_data_claims_bind_configmap_critical_values() {
    let dir = tempdir().unwrap();
    let cc_body = format!(
        r#"
version = "0.1.0"
algorithm = "sha256"

[data]
argon2_salt_hex = "{}"
kbs_url = "http://127.0.0.1:8006/cdh/resource"
kbs_resource_path = "default/app-owner/seed-encrypted"
kbs_attestation_token_url = "http://127.0.0.1:8006/aa/token?token_type=kbs"
workload_artifacts_url = "file:///artifacts.json"
trustee_policy_url = "file:///policy.json"
"#,
        "aa".repeat(32)
    );
    let cfg = config_with_signed_cc(dir.path(), &cc_body);

    validate_configmap_transport_against_signed_cc_init_data(&cfg).unwrap();
}

#[test]
fn signed_cc_init_data_mismatch_rejects_configmap_transport() {
    let dir = tempdir().unwrap();
    let cc_body = format!(
        r#"
version = "0.1.0"
algorithm = "sha256"

[data]
argon2_salt_hex = "{}"
kbs_url = "http://127.0.0.1:8006/cdh/resource"
kbs_resource_path = "default/other-owner/seed-encrypted"
kbs_attestation_token_url = "http://127.0.0.1:8006/aa/token?token_type=kbs"
workload_artifacts_url = "file:///artifacts.json"
trustee_policy_url = "file:///policy.json"
"#,
        "aa".repeat(32)
    );
    let cfg = config_with_signed_cc(dir.path(), &cc_body);

    let err = validate_configmap_transport_against_signed_cc_init_data(&cfg).unwrap_err();
    assert!(err.to_string().contains("kbs-resource-path"));
}

#[test]
fn password_unlock_socket_is_reached_before_waiting_on_workload_namespaces() {
    let source = include_str!("../../main.rs");
    let owner_seed_stage = source
        .find("record_stage(\"waiting for owner seed\")")
        .expect("owner seed stage marker");
    let workload_wait_stage = source
        .find("record_stage(\"waiting for workload containers\")")
        .expect("workload wait stage marker");

    assert!(
        owner_seed_stage < workload_wait_stage,
        "enclava-init must accept claim/unlock before waiting on workload sentinels"
    );
}

#[test]
fn workload_pid_fallback_finds_wait_exec_process_by_container_name() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("123");
    std::fs::create_dir_all(proc_dir.join("ns")).unwrap();
    std::fs::write(
        proc_dir.join("environ"),
        b"PATH=/usr/bin\0ENCLAVA_CONTAINER_NAME=tenant-ingress\0",
    )
    .unwrap();
    std::fs::write(proc_dir.join("ns/mnt"), b"").unwrap();

    let pid = find_workload_pid_by_env(dir.path(), "tenant-ingress").unwrap();

    assert_eq!(pid, 123);
}

#[test]
fn workload_pid_fallback_rejects_missing_mount_namespace() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("456");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(proc_dir.join("environ"), b"ENCLAVA_CONTAINER_NAME=web\0").unwrap();

    let err = find_workload_pid_by_env(dir.path(), "web").unwrap_err();

    assert!(err.to_string().contains("mount namespace"));
}
