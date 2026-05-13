use enclava_engine::manifest::resource_quota::generate_resource_quota;
use enclava_engine::testutil::sample_app;

#[test]
fn resource_quota_name_and_namespace() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    assert_eq!(rq.metadata.name.as_deref(), Some("tenant-quota"));
    assert_eq!(
        rq.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn resource_quota_has_cpu_limits() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let hard = rq.spec.as_ref().unwrap().hard.as_ref().unwrap();
    assert_eq!(hard.get("requests.cpu").unwrap().0, "1500m");
    assert_eq!(hard.get("limits.cpu").unwrap().0, "3250m");
}

#[test]
fn resource_quota_has_memory_limits() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let hard = rq.spec.as_ref().unwrap().hard.as_ref().unwrap();
    assert_eq!(hard.get("requests.memory").unwrap().0, "4928Mi");
    assert_eq!(hard.get("limits.memory").unwrap().0, "6Gi");
}

#[test]
fn resource_quota_has_storage() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let hard = rq.spec.as_ref().unwrap().hard.as_ref().unwrap();
    assert_eq!(hard.get("requests.storage").unwrap().0, "12Gi");
    assert!(hard.contains_key("persistentvolumeclaims"));
}

#[test]
fn resource_quota_blocks_loadbalancers_and_nodeports() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let hard = rq.spec.as_ref().unwrap().hard.as_ref().unwrap();
    let lb = hard.get("services.loadbalancers").unwrap();
    let np = hard.get("services.nodeports").unwrap();
    assert_eq!(lb.0, "0");
    assert_eq!(np.0, "0");
}

#[test]
fn resource_quota_has_pods_services_secrets_configmaps() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let hard = rq.spec.as_ref().unwrap().hard.as_ref().unwrap();
    assert!(hard.contains_key("pods"));
    assert!(hard.contains_key("services"));
    assert!(hard.contains_key("secrets"));
    assert!(hard.contains_key("configmaps"));
}

#[test]
fn resource_quota_serializes_to_yaml() {
    let app = sample_app();
    let rq = generate_resource_quota(&app);
    let yaml = serde_yaml::to_string(&rq).unwrap();
    assert!(yaml.contains("tenant-quota"));
    assert!(yaml.contains("services.loadbalancers"));
}
