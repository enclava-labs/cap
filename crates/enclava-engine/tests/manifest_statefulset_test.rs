use enclava_engine::manifest::statefulset::generate_statefulset;
use enclava_engine::testutil::sample_app;

#[test]
fn statefulset_name() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    assert_eq!(sts.metadata.name.as_deref(), Some("test-app"));
}

#[test]
fn statefulset_namespace() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    assert_eq!(
        sts.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn statefulset_replicas() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    assert_eq!(sts.spec.as_ref().unwrap().replicas, Some(1));
}

#[test]
fn statefulset_service_name() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    assert_eq!(
        sts.spec.as_ref().unwrap().service_name.as_deref(),
        Some("test-app")
    );
}

#[test]
fn statefulset_runtime_class() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
    assert_eq!(
        pod_spec.runtime_class_name.as_deref(),
        Some("kata-qemu-snp")
    );
}

#[test]
fn statefulset_service_account() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
    assert_eq!(
        pod_spec.service_account_name.as_deref(),
        Some("cap-test-app-sa")
    );
}

#[test]
fn statefulset_pod_spec_disables_automount() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
    assert_eq!(pod_spec.automount_service_account_token, Some(false));
}

#[test]
fn statefulset_pod_spec_disables_service_links() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
    assert_eq!(pod_spec.enable_service_links, Some(false));
}

#[test]
fn statefulset_shares_process_namespace_for_in_guest_bind_mounts() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
    assert_eq!(pod_spec.share_process_namespace, Some(true));
}

#[test]
fn statefulset_has_kata_runtime_annotation() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    assert_eq!(
        annotations.get("io.containerd.cri.runtime-handler"),
        Some(&"kata-qemu-snp".to_string())
    );
}

#[test]
fn statefulset_has_cc_init_data_annotation() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    let cc = annotations
        .get("io.katacontainers.config.hypervisor.cc_init_data")
        .unwrap();
    assert!(!cc.is_empty());
    let cc_runtime = annotations
        .get("io.katacontainers.config.runtime.cc_init_data")
        .unwrap();
    assert_eq!(cc, cc_runtime);
}

#[test]
fn statefulset_has_init_data_sha256_annotation() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    let hash = annotations
        .get("storage.enclava.dev/secure-pv-init-data-sha256")
        .unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn statefulset_has_policy_instance_annotation() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    assert_eq!(
        annotations.get("tenant.flowforge.sh/instance"),
        Some(&"test-app".to_string())
    );
}

#[test]
fn statefulset_has_kernel_params_annotation() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    let kp = annotations
        .get("io.katacontainers.config.hypervisor.kernel_params")
        .unwrap();
    assert!(kp.contains("agent.aa_kbc_params=cc_kbc::"));
    assert!(kp.contains("kbs-service.trustee-operator-system"));
}

#[test]
fn statefulset_phase5_uses_only_steady_state_containers() {
    // Stateful Kata SEV-SNP pods use normal containers only: app/caddy start
    // under their in-image wait helper, attestation-proxy is a normal sidecar,
    // and enclava-init is the long-running mounter sidecar.
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let pod = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();

    assert_eq!(pod.init_containers.as_ref().map(|v| v.len()), Some(1));

    let names: Vec<&str> = pod.containers.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"web"));
    assert!(names.contains(&"attestation-proxy"));
    assert!(names.contains(&"tenant-ingress"));
    assert!(names.contains(&"enclava-init"));
    assert_eq!(names.len(), 4);

    let proxy = pod
        .containers
        .iter()
        .find(|c| c.name == "attestation-proxy")
        .unwrap();
    assert!(proxy.restart_policy.is_none());
}

#[test]
fn statefulset_does_not_request_guest_kernel_modules() {
    // The production Kata guest has dm_mod/dm_crypt built in. Asking kata-agent
    // to modprobe built-in-only features makes sandbox startup fail with ENOENT.
    let sts = generate_statefulset(&sample_app());
    let annotations = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .annotations
        .as_ref()
        .unwrap();
    assert!(!annotations.contains_key("io.katacontainers.config.agent.kernel_modules"));
}

#[test]
fn statefulset_has_two_volume_claim_templates() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let vcts = sts
        .spec
        .as_ref()
        .unwrap()
        .volume_claim_templates
        .as_ref()
        .unwrap();
    assert_eq!(vcts.len(), 2);
    let names: Vec<Option<&str>> = vcts.iter().map(|v| v.metadata.name.as_deref()).collect();
    assert!(names.contains(&Some("state")));
    assert!(names.contains(&Some("tls-state")));
}

#[test]
fn statefulset_has_volumes() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let volumes = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap()
        .volumes
        .as_ref()
        .unwrap();
    assert!(volumes.iter().any(|v| v.name == "ownership-signal"));
    assert!(volumes.iter().any(|v| v.name == "unlock-socket"));
    assert!(volumes.iter().any(|v| v.name == "unlock-channel"));
    assert!(volumes.iter().any(|v| v.name == "enclava-tools"));
    assert!(volumes.iter().any(|v| v.name == "enclava-init-config"));
    // Phase 5 default does not mount Cloudflare DNS-01 token nor the legacy bootstrap script.
    assert!(volumes.iter().all(|v| v.name != "tls-cloudflare-token"));
    assert!(volumes.iter().all(|v| v.name != "secure-pv-bootstrap"));
}

#[test]
fn statefulset_node_selector() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let ns = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap()
        .node_selector
        .as_ref()
        .unwrap();
    assert_eq!(
        ns.get("katacontainers.io/kata-runtime"),
        Some(&"true".to_string())
    );
    assert_eq!(
        ns.get("node.kubernetes.io/worker"),
        Some(&"true".to_string())
    );
}

#[test]
fn statefulset_retain_policy() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let policy = sts
        .spec
        .as_ref()
        .unwrap()
        .persistent_volume_claim_retention_policy
        .as_ref()
        .unwrap();
    assert_eq!(policy.when_deleted.as_deref(), Some("Retain"));
    assert_eq!(policy.when_scaled.as_deref(), Some("Retain"));
}

#[test]
fn statefulset_selector_matches_labels() {
    let app = sample_app();
    let sts = generate_statefulset(&app);
    let selector = sts
        .spec
        .as_ref()
        .unwrap()
        .selector
        .match_labels
        .as_ref()
        .unwrap();
    let labels = sts
        .spec
        .as_ref()
        .unwrap()
        .template
        .metadata
        .as_ref()
        .unwrap()
        .labels
        .as_ref()
        .unwrap();
    assert_eq!(selector.get("app"), labels.get("app"));
}
