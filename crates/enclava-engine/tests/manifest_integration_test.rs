use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::manifest::kbs_policy::generate_kbs_policy_rego;
use enclava_engine::testutil::sample_app;

#[test]
fn generate_all_manifests_returns_all_resources() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    // Namespace
    assert_eq!(
        m.namespace.metadata.name.as_deref(),
        Some("cap-test-org-test-app")
    );

    // ServiceAccount
    assert_eq!(
        m.service_account.metadata.name.as_deref(),
        Some("cap-test-app-sa")
    );

    // NetworkPolicy (CiliumNetworkPolicy CRD)
    assert_eq!(m.network_policy["kind"], "CiliumNetworkPolicy");
    assert_eq!(
        m.network_policy["metadata"]["namespace"],
        "cap-test-org-test-app"
    );

    // ResourceQuota
    assert_eq!(
        m.resource_quota.metadata.name.as_deref(),
        Some("tenant-quota")
    );

    // Service
    assert_eq!(m.service.metadata.name.as_deref(), Some("test-app"));
    assert_eq!(
        m.service
            .spec
            .as_ref()
            .and_then(|spec| spec.publish_not_ready_addresses),
        Some(true)
    );

    // Public TLS passthrough routing
    assert_eq!(
        m.sni_route_configmap.metadata.name.as_deref(),
        Some("test-app-sni-route")
    );
    let sni_data = m.sni_route_configmap.data.as_ref().unwrap();
    assert_eq!(
        sni_data.get("host").map(|s| s.as_str()),
        Some("test-app.abcd1234.enclava.dev")
    );
    assert_eq!(
        sni_data.get("backend_tls").map(|s| s.as_str()),
        Some("test-app.cap-test-org-test-app.svc.cluster.local:443")
    );
    assert_eq!(m.envoy_proxy["kind"], "EnvoyProxy");
    assert_eq!(
        m.envoy_proxy["metadata"]["name"],
        "tenant-gateway-proxy-test-app"
    );
    assert_eq!(m.gateway["kind"], "Gateway");
    assert_eq!(m.gateway["metadata"]["name"], "tenant-gateway-test-app");
    assert_eq!(m.tls_route["kind"], "TLSRoute");
    assert_eq!(
        m.tls_route["metadata"]["name"],
        "tenant-passthrough-test-app"
    );
    assert_eq!(
        m.tls_route["spec"]["hostnames"][0],
        "test-app.abcd1234.enclava.dev"
    );
    assert_eq!(
        m.tls_route["spec"]["rules"][0]["backendRefs"][0]["name"],
        "test-app"
    );

    // Bootstrap ConfigMap
    assert_eq!(
        m.bootstrap_configmap.metadata.name.as_deref(),
        Some("secure-pv-bootstrap-script")
    );

    // Startup ConfigMap
    assert_eq!(
        m.startup_configmap.metadata.name.as_deref(),
        Some("test-app-startup")
    );

    // Ingress ConfigMap
    assert_eq!(
        m.ingress_configmap.metadata.name.as_deref(),
        Some("test-app-tenant-ingress")
    );

    // StatefulSet
    assert_eq!(m.statefulset.metadata.name.as_deref(), Some("test-app"));
    // Phase 5: stateful Kata SEV-SNP uses normal steady-state containers only.
    // App/caddy carry the wait helper in their images; attestation-proxy and
    // enclava-init run as regular sidecars.
    let pod = m
        .statefulset
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap();
    assert_eq!(pod.containers.len(), 4);
    assert_eq!(pod.init_containers.as_ref().map(|v| v.len()), Some(1));
    let names: Vec<&str> = pod.containers.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"web"));
    assert!(names.contains(&"attestation-proxy"));
    assert!(names.contains(&"tenant-ingress"));
    assert!(names.contains(&"enclava-init"));

    // enclava-init ConfigMap is generated.
    assert_eq!(
        m.enclava_init_configmap.metadata.name.as_deref(),
        Some("test-app-enclava-init")
    );

    // KBS owner binding
    let (key, value) = &m.kbs_owner_binding;
    assert!(key.ends_with("-owner"));
    assert!(value.get("allowed_identity_hashes").is_some());
}

#[test]
fn all_namespaced_resources_share_namespace() {
    let app = sample_app();
    let m = generate_all_manifests(&app);
    let ns = "cap-test-org-test-app";

    assert_eq!(m.namespace.metadata.name.as_deref(), Some(ns));
    assert_eq!(m.service_account.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.resource_quota.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.service.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(
        m.bootstrap_configmap.metadata.namespace.as_deref(),
        Some(ns)
    );
    assert_eq!(m.startup_configmap.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.ingress_configmap.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.statefulset.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.network_policy["metadata"]["namespace"].as_str(), Some(ns));
    assert_eq!(
        m.sni_route_configmap.metadata.namespace.as_deref(),
        Some(ns)
    );
    assert_eq!(m.envoy_proxy["metadata"]["namespace"].as_str(), Some(ns));
    assert_eq!(m.gateway["metadata"]["namespace"].as_str(), Some(ns));
    assert_eq!(m.tls_route["metadata"]["namespace"].as_str(), Some(ns));
}

#[test]
fn all_managed_resources_have_managed_by_label() {
    let app = sample_app();
    let m = generate_all_manifests(&app);
    let managed_by = "enclava-platform";

    // Namespace
    let ns_labels = m.namespace.metadata.labels.as_ref().unwrap();
    assert_eq!(
        ns_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // ServiceAccount
    let sa_labels = m.service_account.metadata.labels.as_ref().unwrap();
    assert_eq!(
        sa_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // ResourceQuota
    let rq_labels = m.resource_quota.metadata.labels.as_ref().unwrap();
    assert_eq!(
        rq_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // Service
    let svc_labels = m.service.metadata.labels.as_ref().unwrap();
    assert_eq!(
        svc_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // StatefulSet
    let sts_labels = m.statefulset.metadata.labels.as_ref().unwrap();
    assert_eq!(
        sts_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    let startup_labels = m.startup_configmap.metadata.labels.as_ref().unwrap();
    assert_eq!(
        startup_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // CiliumNetworkPolicy
    assert_eq!(
        m.network_policy["metadata"]["labels"]["app.kubernetes.io/managed-by"].as_str(),
        Some(managed_by)
    );

    let sni_labels = m.sni_route_configmap.metadata.labels.as_ref().unwrap();
    assert_eq!(
        sni_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );
    assert_eq!(
        m.envoy_proxy["metadata"]["labels"]["app.kubernetes.io/managed-by"].as_str(),
        Some(managed_by)
    );
    assert_eq!(
        m.gateway["metadata"]["labels"]["app.kubernetes.io/managed-by"].as_str(),
        Some(managed_by)
    );
    assert_eq!(
        m.tls_route["metadata"]["labels"]["app.kubernetes.io/managed-by"].as_str(),
        Some(managed_by)
    );
}

#[test]
fn kbs_policy_rego_integrates_with_owner_binding() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    let rego = generate_kbs_policy_rego(&[&app], "");
    let (key, _) = &m.kbs_owner_binding;
    assert!(rego.contains("owner_resource_bindings"));
    assert!(rego.contains(key));
}

#[test]
fn manifests_serialize_to_yaml() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    // Each k8s-openapi type must round-trip through serde_yaml
    let ns_yaml = serde_yaml::to_string(&m.namespace).unwrap();
    assert!(ns_yaml.contains("cap-test-org-test-app"));

    let sa_yaml = serde_yaml::to_string(&m.service_account).unwrap();
    assert!(sa_yaml.contains("cap-test-app-sa"));

    let rq_yaml = serde_yaml::to_string(&m.resource_quota).unwrap();
    assert!(rq_yaml.contains("tenant-quota"));

    let svc_yaml = serde_yaml::to_string(&m.service).unwrap();
    assert!(svc_yaml.contains("test-app"));

    let sts_yaml = serde_yaml::to_string(&m.statefulset).unwrap();
    assert!(sts_yaml.contains("kata-qemu-snp"));

    let cm_yaml = serde_yaml::to_string(&m.bootstrap_configmap).unwrap();
    assert!(cm_yaml.contains("secure-pv-bootstrap-script"));

    let ingress_yaml = serde_yaml::to_string(&m.ingress_configmap).unwrap();
    assert!(ingress_yaml.contains("test-app-tenant-ingress"));

    let sni_yaml = serde_yaml::to_string(&m.sni_route_configmap).unwrap();
    assert!(sni_yaml.contains("test-app-sni-route"));

    let gateway_yaml = serde_yaml::to_string(&m.gateway).unwrap();
    assert!(gateway_yaml.contains("tenant-gateway-test-app"));

    let tls_route_yaml = serde_yaml::to_string(&m.tls_route).unwrap();
    assert!(tls_route_yaml.contains("tenant-passthrough-test-app"));

    // CiliumNetworkPolicy is Value, uses serde_json for serialization
    let np_yaml = serde_yaml::to_string(&m.network_policy).unwrap();
    assert!(np_yaml.contains("CiliumNetworkPolicy"));
}
