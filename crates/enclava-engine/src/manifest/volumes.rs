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

pub fn build_volumes(app: &ConfidentialApp) -> Vec<Volume> {
    let legacy = legacy_bootstrap_enabled();
    let mut v = vec![
        Volume {
            name: "logs".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
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
        v.push(Volume {
            name: "enclava-tools".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        });
        v.push(Volume {
            name: "startup".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-startup", app.name),
                default_mode: Some(0o555),
                ..Default::default()
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "unlock-socket".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity("16Mi".to_string())),
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "state-mount".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        });
        v.push(Volume {
            name: "tls-state-mount".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
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
