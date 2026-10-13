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
    let vols = build_volumes(&memory_app());
    let v = vols.iter().find(|v| v.name == "logs").unwrap();
    let ed = v.empty_dir.as_ref().unwrap();
    // #138: disk medium with an explicit node-side bound (relay tails at most
    // 2 MiB per container). #223: the bound must survive the volume's second
    // writer — kata's dm-integrity staging container, ~6.5 MB/s of real
    // growth from pod start — not just the rotating log spool.
    assert!(ed.medium.is_none());
    assert_eq!(ed.size_limit.as_ref().map(|q| q.0.as_str()), Some("4Gi"));
}

/// Parse a Kubernetes binary quantity ("4Gi", "64Mi") into bytes.
fn quantity_bytes(value: &str) -> Option<u64> {
    let (number, suffix) = value.split_at(value.find(|c: char| c.is_ascii_alphabetic())?);
    let multiplier = match suffix {
        "Ki" => 1024u64,
        "Mi" => 1024u64.pow(2),
        "Gi" => 1024u64.pow(3),
        "Ti" => 1024u64.pow(4),
        _ => return None,
    };
    let n: u64 = number.trim().parse().ok()?;
    n.checked_mul(multiplier)
}

/// #223 repro: demonstrate the eviction trigger purely from the manifest
/// config — the code path this repo owns. On the host, kubelet evicts the pod
/// when the emptyDir's REAL usage crosses sizeLimit; the trigger inputs are
/// (a) the manifest's declared sizeLimit and (b) the volume's real usage. We
/// cannot run kata/SEV here, so we replay the exact arithmetic kubelet
/// performs on those two numbers for both writers observed in #223:
///
///   - the dm-integrity staging container: apparent ~98 GiB sparse file,
///     REAL usage growing ~6.5 MB/s from pod start (the usage kubelet sees);
///   - the encrypted log spool: rotating at 32 MiB, retaining 8 MiB.
///
/// The fence must hold deployment-window usage strictly below sizeLimit for
/// the full first-deploy convergence window (~3 min observed) with margin.
#[test]
fn logs_emptydir_fence_survives_dm_integrity_staging_growth() {
    const DISK_IMG_APPARENT_BYTES: u64 = 105_089_261_568; // stat, #223
    const DISK_IMG_GROWTH_BYTES_PER_SEC: u64 = 6_500_000; // blkid-sampled rate
    const DEPLOY_CONVERGENCE_WINDOW_SECS: u64 = 180; // ~2:43 healthy in #223
    const PRE_223_LIMIT_BYTES: u64 = 64 * 1024 * 1024; // PR #176 fence
    const SPOOL_ROTATE_BYTES: u64 = 32 * 1024 * 1024; // wait-exec inner fence
    const SPOOL_KEEP_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024; // relay tail bound

    let vols = build_volumes(&memory_app());
    let logs = vols.iter().find(|v| v.name == "logs").unwrap();
    let ed = logs.empty_dir.as_ref().unwrap();
    let limit = quantity_bytes(ed.size_limit.as_ref().map(|q| q.0.as_str()).unwrap())
        .expect("logs sizeLimit parses as a binary quantity");

    // Steady-state log-spool footprint: one live spool mid-rotation plus the
    // retained prefix of the previous generation plus the relay tail buffer.
    let spool_steady_state = SPOOL_ROTATE_BYTES + SPOOL_KEEP_BYTES + MAX_TAIL_BYTES;

    // Worst-case real usage at the end of the convergence window if the
    // dm-integrity container never settles (the "true runaway" case #223
    // could not rule out): spool steady state + full-window growth.
    let usage_at_window_end =
        spool_steady_state + DISK_IMG_GROWTH_BYTES_PER_SEC * DEPLOY_CONVERGENCE_WINDOW_SECS;

    // The fence must not evict during the window: usage stays under the cap.
    assert!(
        usage_at_window_end < limit,
        "fence {limit} B must hold worst-case convergence-window usage \
         {usage_at_window_end} B (spool {spool_steady_state} B + dm-integrity growth)"
    );

    // The fence must actually fence: a runaway writer must hit it eventually.
    // At the observed rate the cap is reached in ~10.5 min — bounded node
    // disk exhaustion (#138's goal) without killing a first deploy (#223).
    let secs_to_fence = limit / DISK_IMG_GROWTH_BYTES_PER_SEC;
    assert!(
        secs_to_fence > DEPLOY_CONVERGENCE_WINDOW_SECS,
        "fence {limit} B is reached in {secs_to_fence} s at the observed rate, \
         inside the {DEPLOY_CONVERGENCE_WINDOW_SECS} s convergence window"
    );

    // The pre-#223 fence demonstrably FAILED this arithmetic — this is the
    // eviction loop: the staging container alone crosses 64 MiB in <10 s,
    // long before any deploy can converge, and kubelet evicts every ~61 s.
    let pre_usage = spool_steady_state + DISK_IMG_GROWTH_BYTES_PER_SEC * 61;
    assert!(
        pre_usage > PRE_223_LIMIT_BYTES,
        "pre-#223 64Mi fence must be shown insufficient for the observed writers"
    );
    let staging_cross_time = PRE_223_LIMIT_BYTES / DISK_IMG_GROWTH_BYTES_PER_SEC;
    assert!(
        staging_cross_time <= 11,
        "staging writer alone crosses 64Mi in ~{staging_cross_time}s, before any deploy converges"
    );

    // The apparent (sparse) size dwarfs ANY fence — only real usage matters
    // to kubelet, which is why this cannot be fixed by sizing alone at the
    // manifest layer; the root sizing bug stays tracked in #223.
    assert!(DISK_IMG_APPARENT_BYTES > limit);
}

#[test]
fn logs_emptydir_fence_reproduces_observed_eviction_interval() {
    // Pin the fence arithmetic against #223's timeline: at the observed
    // growth rate, usage crosses the PRE-#223 fence at t≈10 s; kubelet's
    // eviction then fires on its next housekeeping pass, producing the
    // observed steady ~61 s eviction period. The current fence pushes the
    // crossing far past the convergence window, so a healthy deploy never
    // sees an eviction.
    const RATE: u64 = 6_500_000;
    const PRE_223_LIMIT: u64 = 64 * 1024 * 1024;
    let vols = build_volumes(&memory_app());
    let logs = vols.iter().find(|v| v.name == "logs").unwrap();
    let limit = quantity_bytes(
        logs.empty_dir
            .as_ref()
            .unwrap()
            .size_limit
            .as_ref()
            .map(|q| q.0.as_str())
            .unwrap(),
    )
    .unwrap();

    // Simulated usage samples: t=0..300 s (first-deploy window) at the rate
    // #223 measured, plus the spool steady state.
    let spool = (32 + 8 + 2) * 1024 * 1024u64;
    let crossing = (0..=300u64)
        .step_by(30)
        .find(|&t| spool + RATE * t > PRE_223_LIMIT);
    assert_eq!(
        crossing,
        Some(30),
        "pre-#223 fence is crossed ~30 s into the window: {crossing:?}"
    );
    let new_crossing = (0..=300u64).step_by(30).find(|&t| spool + RATE * t > limit);
    assert_eq!(
        new_crossing, None,
        "current fence is never crossed inside the 300 s first-deploy window"
    );
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
        "# enclava-cap-volume-layout: guest-memory-v2\n".to_string(),
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
