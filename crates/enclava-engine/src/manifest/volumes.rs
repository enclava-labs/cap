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

/// Disk-backed bound for the workload log spool emptyDir. The relay tails at
/// most MAX_TAIL_BYTES per container (2 MiB today), so 64 MiB leaves generous
/// headroom while bounding node-disk exhaustion from a runaway writer.
/// enclava-wait-exec additionally rotates its spool at 32 MiB (retaining the
/// newest 8 MiB), so a chatty workload cannot hit the volume cap and die by
/// ENOSPC/SIGPIPE — the sizeLimit is the outer fence, rotation the inner one.
const LOGS_EMPTY_DIR_SIZE_LIMIT: &str = "64Mi";

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
                size_limit: Some(Quantity("16Mi".to_string())),
            }),
            ..Default::default()
        });
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
