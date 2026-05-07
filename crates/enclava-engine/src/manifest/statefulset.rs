//! StatefulSet assembly: combines containers, volumes, annotations, and VCTs.

use k8s_openapi::api::apps::v1::{
    StatefulSet, StatefulSetPersistentVolumeClaimRetentionPolicy, StatefulSetSpec,
};
use k8s_openapi::api::core::v1::{PodSecurityContext, PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use std::collections::BTreeMap;

use crate::manifest::cc_init_data;
use crate::manifest::containers::{
    build_app_container, build_attestation_proxy_container, build_caddy_container,
    build_enclava_init_container, legacy_bootstrap_enabled,
};
use crate::manifest::volumes::{build_volume_claim_templates, build_volumes};
use crate::types::ConfidentialApp;

const KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";

pub fn generate_statefulset(app: &ConfidentialApp) -> StatefulSet {
    let (cc_init_data_encoded, cc_init_data_hash) = cc_init_data::compute_cc_init_data(app);

    let mut pod_labels = BTreeMap::new();
    pod_labels.insert("app".to_string(), app.name.clone());

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "io.containerd.cri.runtime-handler".to_string(),
        "kata-qemu-snp".to_string(),
    );
    annotations.insert(
        "io.katacontainers.config.hypervisor.kernel_params".to_string(),
        format!("agent.aa_kbc_params=cc_kbc::{KBS_URL} agent.guest_components_rest_api=all"),
    );
    annotations.insert(
        "io.katacontainers.config.hypervisor.cc_init_data".to_string(),
        cc_init_data_encoded.clone(),
    );
    annotations.insert(
        "io.katacontainers.config.runtime.cc_init_data".to_string(),
        cc_init_data_encoded,
    );
    annotations.insert(
        "storage.enclava.dev/secure-pv-init-data-sha256".to_string(),
        cc_init_data_hash,
    );
    annotations.insert("tenant.flowforge.sh/instance".to_string(), app.name.clone());

    let legacy = legacy_bootstrap_enabled();

    let mut node_selector = BTreeMap::new();
    node_selector.insert(
        "katacontainers.io/kata-runtime".to_string(),
        "true".to_string(),
    );
    node_selector.insert("node.kubernetes.io/worker".to_string(), "true".to_string());

    let mut selector_labels = BTreeMap::new();
    selector_labels.insert("app".to_string(), app.name.clone());

    let mut sts_labels = BTreeMap::new();
    sts_labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    sts_labels.insert("app".to_string(), app.name.clone());

    // Stateful Kata SEV-SNP pods must not gate workload creation through
    // initContainers. Live validation showed the reliable contract is to start
    // all long-running containers together, let app/caddy wait under
    // `enclava-wait-exec`, then have enclava-init open LUKS and mark ready.
    // Customer workload images are therefore required to include
    // /usr/local/bin/enclava-wait-exec.
    let (init_containers, containers) = if legacy {
        (
            None,
            vec![
                build_app_container(app),
                build_attestation_proxy_container(app),
                build_caddy_container(app),
            ],
        )
    } else {
        (
            None,
            vec![
                build_app_container(app),
                build_attestation_proxy_container(app),
                build_caddy_container(app),
                build_enclava_init_container(app),
            ],
        )
    };

    let volumes = build_volumes(app);
    let volume_claim_templates = build_volume_claim_templates(app);

    StatefulSet {
        metadata: ObjectMeta {
            name: Some(app.name.clone()),
            namespace: Some(app.namespace.clone()),
            labels: Some(sts_labels),
            ..Default::default()
        },
        spec: Some(StatefulSetSpec {
            service_name: Some(app.name.clone()),
            replicas: Some(1),
            persistent_volume_claim_retention_policy: Some(
                StatefulSetPersistentVolumeClaimRetentionPolicy {
                    when_deleted: Some("Retain".to_string()),
                    when_scaled: Some("Retain".to_string()),
                },
            ),
            selector: LabelSelector {
                match_labels: Some(selector_labels),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    annotations: Some(annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    runtime_class_name: Some(
                        super::cc_init_data::DEFAULT_RUNTIME_CLASS.to_string(),
                    ),
                    service_account_name: Some(app.service_account.clone()),
                    automount_service_account_token: Some(false),
                    enable_service_links: Some(false),
                    node_selector: Some(node_selector),
                    security_context: Some(PodSecurityContext {
                        fs_group: Some(10001),
                        fs_group_change_policy: Some("OnRootMismatch".to_string()),
                        supplemental_groups: Some(vec![6]),
                        ..Default::default()
                    }),
                    init_containers,
                    containers,
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(volume_claim_templates),
            ..Default::default()
        }),
        ..Default::default()
    }
}
