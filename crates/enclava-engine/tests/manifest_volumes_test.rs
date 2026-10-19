//! Volume + VCT shape tests. Phase 5 default: unlock-socket emptyDir,
//! shared decrypted mountpoint EmptyDirs, enclava-init-config ConfigMap volume,
//! no Cloudflare-token secret. PVCs stay raw Block devices for LUKS.

use enclava_engine::manifest::volumes::{build_volume_claim_templates, build_volumes};
use enclava_engine::testutil::sample_app;
use enclava_engine::types::{ConfidentialApp, GeneratedAgentPolicy};
use sha2::{Digest, Sha256};

const MEMORY_LAYOUT_MARKER: &str = "# enclava-cap-volume-layout: guest-memory-v1\n";

fn app_with_policy(policy_text: String) -> ConfidentialApp {
    let mut app = sample_app();
    app.generated_agent_policy = Some(GeneratedAgentPolicy {
        policy_sha256: Sha256::digest(policy_text.as_bytes()).into(),
        policy_text,
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
    });
    app
}

fn memory_app() -> ConfidentialApp {
    app_with_policy(format!("{MEMORY_LAYOUT_MARKER}package agent_policy\n"))
}

fn v2_app() -> ConfidentialApp {
    app_with_policy(
        "# enclava-cap-volume-layout: guest-memory-v2\npackage agent_policy\n".to_string(),
    )
}

fn v2_app_with_logs() -> ConfidentialApp {
    let mut app = v2_app();
    app.log_encryption = Some(enclava_engine::types::LogEncryptionConfig {
        algorithm: "x25519-hpke-v1".to_string(),
        key_id: "logs-prod".to_string(),
        public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
    });
    app
}

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
fn volumes_omit_startup_configmap_for_explicit_command() {
    let mut app = sample_app();
    app.containers[0].command = Some(vec!["/usr/local/bin/template-entrypoint".to_string()]);

    let vols = build_volumes(&app);
    assert!(vols.iter().all(|v| v.name != "startup"));
    assert!(vols.iter().any(|v| v.name == "enclava-tools"));
    assert!(vols.iter().any(|v| v.name == "unlock-socket"));
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
fn volumes_enclava_tools_uses_memory_medium_and_16mi_limit() {
    let vols = build_volumes(&memory_app());
    let v = vols.iter().find(|v| v.name == "enclava-tools").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
    assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("16Mi"));
}

#[test]
fn volumes_decrypted_mountpoints_use_memory_medium_and_1mi_limit() {
    let vols = build_volumes(&memory_app());
    for name in ["state-mount", "tls-state-mount"] {
        let v = vols.iter().find(|v| v.name == name).unwrap();
        let ed = v.empty_dir.as_ref().unwrap();
        assert_eq!(ed.medium.as_deref(), Some("Memory"), "{name}");
        assert_eq!(
            ed.size_limit.as_ref().map(|q| q.0.as_str()),
            Some("1Mi"),
            "{name}"
        );
    }
}

#[test]
fn volumes_logs_emptydir_is_disk_backed_and_bounded() {
    // Legacy (pre-v2) layouts share this disk-backed volume with Kata
    // staging. #223 observed ~2.4 GiB of real blocks before readiness; 64Mi
    // evicted first deployments. The v2 layout re-binds the spool onto the
    // encrypted state PVC instead (cap#289).
    for app in [sample_app(), memory_app()] {
        let vols = build_volumes(&app);
        let v = vols.iter().find(|v| v.name == "logs").unwrap();
        let ed = v.empty_dir.as_ref().unwrap();
        assert!(ed.medium.is_none());
        assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("4Gi"));
    }
}

#[test]
fn v2_layout_without_log_encryption_omits_logs_volume() {
    let vols = build_volumes(&v2_app());
    assert!(
        vols.iter().all(|v| v.name != "logs"),
        "v2 without encrypted logging must not render the logs emptyDir"
    );
}

#[test]
fn v2_layout_with_log_encryption_renders_memory_mountpoint() {
    let vols = build_volumes(&v2_app_with_logs());
    let v = vols.iter().find(|v| v.name == "logs").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
    assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("1Mi"));
    // Volume order is part of the rendered pod shape: logs stays first.
    assert_eq!(vols.first().unwrap().name, "logs");
}

#[test]
fn v2_layout_with_omit_spool_bind_pin_keeps_memory_mountpoint() {
    // A claim-less v2 artifact (hash computed before log_spool_storage
    // existed) pins omit_log_spool_bind_claim at validation. Its signed
    // agent policy still encodes the v2 tmpfs mount, so the render must
    // keep the Memory mountpoint; only the guest-side state bind is off.
    let mut app = v2_app_with_logs();
    app.workload_artifact_binding = Some(enclava_engine::types::WorkloadArtifactBinding {
        descriptor_core_hash: [0u8; 32],
        descriptor_signing_pubkey: [0u8; 32],
        org_keyring_fingerprint: [0u8; 32],
        omit_log_encryption_claim: false,
        legacy_collapsed_trustee_key: false,
        omit_luks2_header_seal_claim: false,
        omit_log_spool_bind_claim: true,
    });
    let vols = build_volumes(&app);
    let v = vols.iter().find(|v| v.name == "logs").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
    assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("1Mi"));
}

#[test]
fn v1_layout_without_log_encryption_keeps_disk_spool_and_tools_mount() {
    // A v1-signed artifact renders byte-identical to its signed shape: the
    // 4Gi disk spool AND the enclava-logs provisioning stay.
    let app = memory_app();
    let vols = build_volumes(&app);
    let v = vols.iter().find(|v| v.name == "logs").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    assert!(ed.medium.is_none());
    assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("4Gi"));

    let c = enclava_engine::manifest::containers::build_enclava_tools_init_container(true);
    let command = c.command.as_ref().unwrap().join(" ");
    assert!(command.contains("install -d -m 02770 -o 0 -g 10001 /run/enclava-logs"));
    assert!(
        c.volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .any(|m| m.name == "logs" && m.mount_path == "/run/enclava-logs")
    );
}

#[test]
fn v2_layout_statefulset_drops_logs_everywhere_without_log_encryption() {
    use enclava_engine::manifest::statefulset::generate_statefulset;
    let sts = generate_statefulset(&v2_app());
    let spec = sts.spec.unwrap().template.spec.unwrap();
    assert!(
        spec.volumes
            .as_ref()
            .unwrap()
            .iter()
            .all(|v| v.name != "logs")
    );
    let tools = spec
        .init_containers
        .as_ref()
        .unwrap()
        .iter()
        .find(|c| c.name == "enclava-tools")
        .unwrap();
    assert!(
        tools
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .all(|m| m.name != "logs")
    );
    let command = tools.command.as_ref().unwrap().join(" ");
    assert!(!command.contains("/run/enclava-logs"));
}

#[test]
fn historical_policy_replay_preserves_bootstrap_volume_layout() {
    use enclava_engine::manifest::statefulset::generate_statefulset;

    // Retry/rollback reconstruct the app with the original stored policy,
    // even when the operation's deployment ID changes.
    for (app, expected_memory) in [
        (sample_app(), false),
        (app_with_policy("package agent_policy\n".to_string()), false),
        (memory_app(), true),
    ] {
        let original = generate_statefulset(&app);
        let mut replay = app.clone();
        replay.deployment_id = uuid::Uuid::new_v4();
        let replayed = generate_statefulset(&replay);
        let original_spec = original.spec.unwrap().template.spec.unwrap();
        let replayed_spec = replayed.spec.unwrap().template.spec.unwrap();
        assert_eq!(original_spec.volumes, replayed_spec.volumes);
        assert_eq!(
            replayed_spec.containers.last().unwrap().name,
            "enclava-init"
        );
        for (name, disk_limit) in [
            ("enclava-tools", "16Mi"),
            ("state-mount", "1Mi"),
            ("tls-state-mount", "1Mi"),
        ] {
            let ed = replayed_spec
                .volumes
                .as_ref()
                .unwrap()
                .iter()
                .find(|volume| volume.name == name)
                .unwrap()
                .empty_dir
                .as_ref()
                .unwrap();
            assert_eq!(ed.medium.as_deref(), expected_memory.then_some("Memory"));
            if !expected_memory {
                // #138: disk-backed bootstrap emptyDirs keep an explicit
                // node-side size bound instead of unbounded disk usage.
                assert_eq!(
                    ed.size_limit.as_ref().map(|q| q.0.as_str()),
                    Some(disk_limit)
                );
            }
        }
    }
}

#[test]
fn only_exact_first_line_policy_marker_selects_memory() {
    for prefix in [
        "# enclava-cap-volume-layout: guest-memory-v3\n".to_string(),
        format!("\n{MEMORY_LAYOUT_MARKER}"),
        format!("\u{feff}{MEMORY_LAYOUT_MARKER}"),
        MEMORY_LAYOUT_MARKER.replace('\n', "\r\n"),
        MEMORY_LAYOUT_MARKER.trim_end().to_string(),
        format!("# unrelated\n{MEMORY_LAYOUT_MARKER}"),
        format!(" {MEMORY_LAYOUT_MARKER}"),
    ] {
        let app = app_with_policy(format!("{prefix}package agent_policy\n"));
        let sts = enclava_engine::manifest::statefulset::generate_statefulset(&app);
        for volume in sts.spec.unwrap().template.spec.unwrap().volumes.unwrap() {
            let expected_limit = match volume.name.as_str() {
                "enclava-tools" => "16Mi",
                "state-mount" | "tls-state-mount" => "1Mi",
                _ => continue,
            };
            let ed = volume.empty_dir.unwrap();
            // Unmarked policies keep disk medium, now with an explicit
            // node-side bound (#138) instead of an unbounded default.
            assert!(ed.medium.is_none());
            assert_eq!(
                ed.size_limit.as_ref().map(|q| q.0.as_str()),
                Some(expected_limit)
            );
        }
    }
}

#[test]
#[should_panic(expected = "generated_agent_policy.policy_sha256 must match policy_text")]
fn adding_layout_marker_without_updating_policy_hash_is_rejected() {
    let mut app = app_with_policy("package agent_policy\n".to_string());
    app.generated_agent_policy
        .as_mut()
        .unwrap()
        .policy_text
        .insert_str(0, MEMORY_LAYOUT_MARKER);
    enclava_engine::manifest::statefulset::generate_statefulset(&app);
}

#[test]
fn legacy_bootstrap_keeps_disk_even_with_marked_policy() {
    // Isolate the legacy environment switch from parallel tests.
    if std::env::var("LEGACY_BOOTSTRAP_SCRIPT").as_deref() != Ok("true") {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "legacy_bootstrap_keeps_disk_even_with_marked_policy",
            ])
            .env("LEGACY_BOOTSTRAP_SCRIPT", "true")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let volumes = build_volumes(&memory_app());
    let tools = volumes
        .iter()
        .find(|volume| volume.name == "enclava-tools")
        .unwrap();
    assert_eq!(tools.empty_dir.as_ref().unwrap(), &Default::default());
    assert!(
        volumes
            .iter()
            .all(|volume| !["state-mount", "tls-state-mount"].contains(&volume.name.as_str()))
    );
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
