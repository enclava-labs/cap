//! Volume and VolumeClaimTemplate builders for the StatefulSet.
//!
//! Phase 5 default: raw Block PVCs are passed only to enclava-init. The
//! decrypted filesystems are mounted into shared EmptyDir mountpoint volumes
//! (`state-mount`, `tls-state-mount`) that app/caddy consume after enclava-init
//! bind-mounts decrypted paths inside the shared Kata guest. Workload images
//! carry the static wait/exec helper.

use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, EmptyDirVolumeSource, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    Volume, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::manifest::containers::legacy_bootstrap_enabled;
use crate::manifest::enclava_init_config;
use crate::types::ConfidentialApp;

const GUEST_MEMORY_LAYOUT_MARKER: &str = "# enclava-cap-volume-layout: guest-memory-v1\n";

/// Names of the StatefulSet volumeClaimTemplates CAP renders. PVCs created
/// from them are named `<vct>-<statefulset>-<ordinal>`; cleanup identifies
/// CAP-owned PVCs by these name shapes because VCT metadata is immutable in
/// Kubernetes (labels cannot be added to an existing StatefulSet's VCTs).
pub const CAP_VCT_NAMES: [&str; 2] = ["state", "tls-state"];

/// Name of the PVC Kubernetes creates for a CAP volumeClaimTemplate on a
/// replica-0 StatefulSet: `<vct>-<statefulset>-0`. CAP renders `replicas: 1`,
/// so ordinal 0 is the only claim any workload pod mounts.
pub fn provisioned_claim_name(vct: &str, statefulset: &str) -> String {
    format!("{vct}-{statefulset}-0")
}

/// Name of the pod Kubernetes creates for a CAP StatefulSet's ordinal-0
/// replica: `<statefulset>-0`. That pod is the only consumer of the claims
/// [`provisioned_claim_name`] produces.
pub fn provisioned_pod_name(statefulset: &str) -> String {
    format!("{statefulset}-0")
}

/// Disk-backed bound for the workload log spool emptyDir. The relay tails at
/// most MAX_TAIL_BYTES per container (2 MiB today) and enclava-wait-exec
/// rotates its spool at 32 MiB (retaining the newest 8 MiB), so the spool's
/// own steady-state footprint is ~40 MiB — the rotation is the inner fence
/// keeping a chatty workload from dying by ENOSPC/SIGPIPE.
///
/// The outer bound must additionally survive the volume's OTHER writer
/// (#223): kata's direct-assigned-volume staging places a sparse dm-integrity
/// `disk.img` on this volume (~98 GiB apparent; real blocks grow at a
/// phase-dependent ~6.5–70 MB/s, bursts ~100 MB/s, re-running from 0 on
/// every pod boot). Kubelet measures real usage against sizeLimit — loosely:
/// its poll lags, and under the pre-#223 64Mi cap pods were evicted at
/// ~2.3 GB real usage, in a ~61 s loop a pre-ready pod can never escape
/// (each eviction restarts the writer).
///
/// 4 GiB rests on the only hypothesis under which a moderate fence works
/// (#223, n=2, unproven): both sampled generations ended at an identical
/// ~2.3–2.4 GB real usage despite different growth rates (52 vs 70 MB/s),
/// consistent with the write phase completing there. If growth instead
/// never settles, 4 GiB is crossed in ~60–85 s at 52–70 MB/s (~43 s at a
/// 100 MB/s burst) — inside the ~3 min first-deploy window — and the fence
/// must rise past ~12 GiB or the kata-side root sizing fix must land; both
/// stay tracked in #223. No pod has survived past ~2.4 GB under the old
/// fence, so this raise is what makes the question answerable: a one-time
/// 15-minute first-deploy usage watch after rollout decides it (plateau at
/// or below the fence = settles). Either way the bound still fences a true
/// runaway per pod, loosely, where an unbounded volume would not (#138).
const LOGS_EMPTY_DIR_SIZE_LIMIT: &str = "4Gi";

pub fn build_volumes(app: &ConfidentialApp) -> Vec<Volume> {
    let legacy = legacy_bootstrap_enabled();
    // The signer binds this exact prefix into the policy hash/signature.
    // Retry and rollback retain their stored policy and therefore its layout.
    // Unmarked policies (including the local fallback) keep historical disks.
    let guest_memory = app
        .generated_agent_policy
        .as_ref()
        .is_some_and(|policy| policy.policy_text.starts_with(GUEST_MEMORY_LAYOUT_MARKER));
    let bootstrap_empty_dir = |size: &str| {
        if guest_memory {
            EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity(size.to_string())),
            }
        } else {
            // Disk-backed with an explicit node-side bound: the sizes below
            // are hard caps on node disk usage, not just guest hints.
            EmptyDirVolumeSource {
                medium: None,
                size_limit: Some(Quantity(size.to_string())),
            }
        }
    };
    let mut v = vec![
        Volume {
            name: "logs".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: None,
                size_limit: Some(Quantity(LOGS_EMPTY_DIR_SIZE_LIMIT.to_string())),
            }),
            ..Default::default()
        },
        Volume {
            name: "ownership-signal".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity("1Mi".to_string())),
            }),
            ..Default::default()
        },
        Volume {
            name: "tenant-ingress-caddyfile".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-tenant-ingress", app.name),
                default_mode: Some(0o444),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];
    if legacy {
        v.push(Volume {
            name: "secure-pv-bootstrap".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: "secure-pv-bootstrap-script".to_string(),
                default_mode: Some(0o555),
                ..Default::default()
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "enclava-tools".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        });
        v.push(Volume {
            name: "startup".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-startup", app.name),
                default_mode: Some(0o755),
                ..Default::default()
            }),
            ..Default::default()
        });
    } else {
        // These emptyDirs hold helper binaries and shared decrypted
        // mountpoints, not persistent payload. Kata may not enforce the
        // guest-side sizeLimit, so the declared sizes are not a security
        // bound.
        v.push(Volume {
            name: "enclava-tools".to_string(),
            empty_dir: Some(bootstrap_empty_dir("16Mi")),
            ..Default::default()
        });
        if app
            .primary_container()
            .is_some_and(|primary| primary.command.is_none())
        {
            v.push(Volume {
                name: "startup".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: format!("{}-startup", app.name),
                    default_mode: Some(0o555),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        v.push(Volume {
            name: "unlock-socket".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                // cap#242: /run/enclava also holds the detached LUKS2 header
                // copies (a full header region is 16MiB per volume, two
                // volumes) alongside init-ready, containers, caddy-runtime
                // and the ephemeral key files. 16Mi could not fit even one
                // header; give the RAM-backed volume enough headroom that
                // the sizeLimit never wedges boot where it is enforced.
                size_limit: Some(Quantity("64Mi".to_string())),
            }),
            ..Default::default()
        });
        // cap#244 review: plaintext LUKS material (detached header copies,
        // transient key files) must be isolated from the workload
        // container. /run/enclava is mounted writable into the primary
        // container, and rootful workload profiles share UID 0 with
        // enclava-init, so uid/mode checks there provide no isolation.
        // This RAM-backed volume is mounted into enclava-init ONLY
        // (mount-level isolation) at the path enclava-init's
        // PRIVATE_MATERIAL_DIR expects (/run/enclava-luks).
        if !legacy {
            v.push(Volume {
                name: "luks-material".to_string(),
                empty_dir: Some(EmptyDirVolumeSource {
                    medium: Some("Memory".to_string()),
                    // Two full header regions (state + tls-state, 16MiB
                    // each) plus transient key files and headroom.
                    size_limit: Some(Quantity("48Mi".to_string())),
                }),
                ..Default::default()
            });
        }
        v.push(Volume {
            name: "unlock-channel".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity("1Mi".to_string())),
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "state-mount".to_string(),
            empty_dir: Some(bootstrap_empty_dir("1Mi")),
            ..Default::default()
        });
        v.push(Volume {
            name: "tls-state-mount".to_string(),
            empty_dir: Some(bootstrap_empty_dir("1Mi")),
            ..Default::default()
        });
        v.push(Volume {
            name: "enclava-init-config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: enclava_init_config::configmap_name(&app.name),
                default_mode: Some(0o400),
                ..Default::default()
            }),
            ..Default::default()
        });
        if app.attestation.verification_material.is_some() {
            v.push(Volume {
                name: "verification-material".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: crate::manifest::verification_material::configmap_name(&app.name),
                    default_mode: Some(0o444),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
    }
    v
}

pub fn build_volume_claim_templates(app: &ConfidentialApp) -> Vec<PersistentVolumeClaim> {
    vec![
        build_vct("state", &app.storage.app_data.size),
        build_vct("tls-state", &app.storage.tls_data.size),
    ]
}

fn build_vct(name: &str, size: &str) -> PersistentVolumeClaim {
    let mut requests = BTreeMap::new();
    requests.insert("storage".to_string(), Quantity(size.to_string()));

    // NOTE: no labels here. spec.volumeClaimTemplates is immutable in
    // Kubernetes (KEP-4650 only makes it mutable-alpha in 1.35+): adding or
    // changing VCT metadata makes every redeploy of an existing StatefulSet
    // fail with 422. Cleanup therefore identifies CAP-owned PVCs by the VCT
    // name shape (CAP_VCT_NAMES) instead of labels.

    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            volume_mode: Some("Block".to_string()),
            storage_class_name: Some("longhorn-wait".to_string()),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
