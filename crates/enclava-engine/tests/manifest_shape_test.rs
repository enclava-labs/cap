//! Focused coverage for shape-aware manifest rendering: a sub-512Mi
//! application memory limit selects the small workload shape, and every
//! artifact (pod, cc_init_data, quota, gateway) must agree.

use enclava_engine::manifest::cc_init_data::{self, verify_runtime_class_binding};
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::manifest::shape;
use enclava_engine::testutil::sample_app;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Container;

fn small_app() -> enclava_engine::types::ConfidentialApp {
    let mut app = sample_app();
    app.resources.memory = "128Mi".to_string();
    app
}

fn pod_spec(sts: &StatefulSet) -> &k8s_openapi::api::core::v1::PodSpec {
    sts.spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .expect("statefulset must have a pod spec")
}

fn container<'a>(spec: &'a k8s_openapi::api::core::v1::PodSpec, name: &str) -> &'a Container {
    spec.containers
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("missing container {name}"))
}

fn memory_of(container: &Container) -> (String, String) {
    let resources = container.resources.as_ref().expect("container resources");
    let requests = resources.requests.as_ref().expect("requests");
    let limits = resources.limits.as_ref().expect("limits");
    (
        requests.get("memory").expect("memory request").0.clone(),
        limits.get("memory").expect("memory limit").0.clone(),
    )
}

fn decode_cc_init_data(sts: &StatefulSet) -> String {
    use base64::Engine;
    use std::io::Read;
    let annotations = sts
        .spec
        .as_ref()
        .and_then(|s| s.template.metadata.as_ref())
        .and_then(|m| m.annotations.as_ref())
        .expect("pod annotations");
    let encoded = annotations
        .get("io.katacontainers.config.hypervisor.cc_init_data")
        .expect("cc_init_data annotation");
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("cc_init_data is base64");
    let mut out = String::new();
    flate2::read::GzDecoder::new(&compressed[..])
        .read_to_string(&mut out)
        .expect("cc_init_data is gzip");
    out
}

#[test]
fn small_app_renders_small_pod_shape() {
    let app = small_app();
    let manifests = generate_all_manifests(&app);
    let spec = pod_spec(&manifests.statefulset);

    assert_eq!(
        spec.runtime_class_name.as_deref(),
        Some(shape::SMALL_RUNTIME_CLASS)
    );

    let annotations = manifests
        .statefulset
        .spec
        .as_ref()
        .and_then(|s| s.template.metadata.as_ref())
        .and_then(|m| m.annotations.as_ref())
        .expect("pod annotations");
    assert_eq!(
        annotations
            .get("io.katacontainers.config.hypervisor.default_memory")
            .map(String::as_str),
        Some("1536")
    );
    assert_eq!(
        annotations
            .get("io.containerd.cri.runtime-handler")
            .map(String::as_str),
        Some(shape::SMALL_RUNTIME_CLASS)
    );

    // App request lowered to the limit; limit unchanged.
    assert_eq!(
        memory_of(container(spec, "web")),
        ("128Mi".into(), "128Mi".into())
    );
    // Sidecars keep the standard budget: their claim-path working set is
    // fixed platform overhead that does not shrink with the app.
    assert_eq!(
        memory_of(container(spec, "attestation-proxy")),
        ("128Mi".into(), "256Mi".into())
    );
    assert_eq!(
        memory_of(container(spec, "tenant-ingress")),
        ("128Mi".into(), "256Mi".into())
    );
    // enclava-init keeps the 512Mi ceiling (Argon2 cost is not weakened);
    // it is a regular container alongside the app, not an init container.
    let init = container(spec, "enclava-init");
    let init_resources = init.resources.as_ref().unwrap();
    assert_eq!(
        init_resources
            .limits
            .as_ref()
            .unwrap()
            .get("memory")
            .unwrap()
            .0,
        "512Mi"
    );
    assert_eq!(
        init_resources
            .limits
            .as_ref()
            .unwrap()
            .get("cpu")
            .unwrap()
            .0,
        "250m"
    );
}

#[test]
fn small_app_cross_artifact_agreement() {
    let app = small_app();
    let manifests = generate_all_manifests(&app);

    // Pod runtimeClassName == cc_init_data bound class == resolved class.
    let spec = pod_spec(&manifests.statefulset);
    let pod_class = spec.runtime_class_name.clone().unwrap();
    let resolved = shape::resolved_runtime_class(&app);
    assert_eq!(pod_class, resolved);

    let toml = decode_cc_init_data(&manifests.statefulset);
    assert!(
        toml.contains(&format!("runtime_class = \"{resolved}\"")),
        "cc_init_data must bind the resolved class, got:\n{toml}"
    );

    verify_runtime_class_binding(&manifests.statefulset, &app)
        .expect("small app must bind runtime class");

    // ResourceQuota agrees with the small shape: app request 128 + sidecars
    // 128+128 + init 64 + RuntimeClass overhead 1536 = 1984Mi requested;
    // limits 128+256+256+512+1536 = 2688Mi.
    let hard = manifests
        .resource_quota
        .spec
        .as_ref()
        .and_then(|s| s.hard.as_ref())
        .expect("quota hard limits");
    assert_eq!(hard.get("requests.memory").unwrap().0, "1984Mi");
    assert_eq!(hard.get("limits.memory").unwrap().0, "2688Mi");
    // CPU: 250+100+100+50+500m = 1000m; limits 1 + 500+500+250+500m = 2750m.
    assert_eq!(hard.get("requests.cpu").unwrap().0, "1");
    assert_eq!(hard.get("limits.cpu").unwrap().0, "2750m");
}

#[test]
fn small_app_gateway_requests_and_placement() {
    let app = small_app();
    let manifests = generate_all_manifests(&app);
    let kubernetes = &manifests.envoy_proxy["spec"]["provider"]["kubernetes"];
    let deployment = &kubernetes["envoyDeployment"];
    assert_eq!(
        deployment["pod"]["nodeSelector"]["node.kubernetes.io/worker"].as_str(),
        Some("true")
    );
    // The CRD's singular `container` field carries the envoy request; the
    // shutdown-manager request rides the strategic-merge `patch` field.
    assert_eq!(
        deployment["container"]["resources"]["requests"]["memory"],
        "96Mi"
    );
    assert_eq!(
        deployment["container"]["resources"]["requests"]["cpu"],
        "100m"
    );
    assert!(deployment["container"]["resources"].get("limits").is_none());
    let patch_containers = deployment["patch"]["value"]["spec"]["template"]["spec"]["containers"]
        .as_array()
        .expect("shutdown-manager patch");
    let shutdown = patch_containers
        .iter()
        .find(|c| c["name"] == "shutdown-manager")
        .expect("shutdown-manager request patch");
    assert_eq!(shutdown["resources"]["requests"]["memory"], "32Mi");
    assert_eq!(shutdown["resources"]["requests"]["cpu"], "10m");
    assert!(shutdown["resources"].get("limits").is_none());
    assert_eq!(deployment["patch"]["type"], "StrategicMerge");
}

#[test]
fn fractional_small_limit_quota_rounds_up() {
    let mut app = small_app();
    app.resources.memory = "128.5Mi".to_string();
    let manifests = generate_all_manifests(&app);

    // The pod keeps the exact request; the quota rounds the summed total up
    // so it never admits less than the pod requests.
    let spec = pod_spec(&manifests.statefulset);
    assert_eq!(
        memory_of(container(spec, "web")),
        ("128.5Mi".into(), "128.5Mi".into())
    );
    let hard = manifests
        .resource_quota
        .spec
        .as_ref()
        .and_then(|s| s.hard.as_ref())
        .expect("quota hard limits");
    // 128.5 + 128 + 128 + 64 + 1536 = 1984.5Mi -> 1985Mi.
    assert_eq!(hard.get("requests.memory").unwrap().0, "1985Mi");
}

#[test]
fn mixed_unit_storage_quota_covers_both_claims() {
    // "512Mi" TLS storage + "10Gi" app storage must not collapse to 10Gi:
    // the quota has to admit both PVCs or the second claim is rejected.
    let mut app = small_app();
    app.storage.tls_data.size = "512Mi".to_string();
    let manifests = generate_all_manifests(&app);
    let hard = manifests
        .resource_quota
        .spec
        .as_ref()
        .and_then(|s| s.hard.as_ref())
        .expect("quota hard limits");
    assert_eq!(hard.get("requests.storage").unwrap().0, "10752Mi");
}

#[test]
fn standard_app_output_is_unchanged() {
    let app = sample_app();
    let manifests = generate_all_manifests(&app);
    let spec = pod_spec(&manifests.statefulset);

    // Deployment default class, no VM baseline annotation.
    assert_eq!(
        spec.runtime_class_name.as_deref(),
        Some(cc_init_data::runtime_class().as_str())
    );
    let annotations = manifests
        .statefulset
        .spec
        .as_ref()
        .and_then(|s| s.template.metadata.as_ref())
        .and_then(|m| m.annotations.as_ref())
        .expect("pod annotations");
    assert!(!annotations.contains_key("io.katacontainers.config.hypervisor.default_memory"));

    // Fixed 512Mi request and standard sidecar budgets.
    assert_eq!(
        memory_of(container(spec, "web")),
        ("512Mi".into(), app.resources.memory.clone())
    );
    assert_eq!(
        memory_of(container(spec, "attestation-proxy")),
        ("128Mi".into(), "256Mi".into())
    );
    assert_eq!(
        memory_of(container(spec, "tenant-ingress")),
        ("128Mi".into(), "256Mi".into())
    );

    // Standard quota totals: requests 512+128+128+64+4096=4928Mi; limits
    // 1024+256+256+512+4096=6144Mi=6Gi; cpu 1500m/3250m.
    let hard = manifests
        .resource_quota
        .spec
        .as_ref()
        .and_then(|s| s.hard.as_ref())
        .expect("quota hard limits");
    assert_eq!(hard.get("requests.memory").unwrap().0, "4928Mi");
    assert_eq!(hard.get("limits.memory").unwrap().0, "6Gi");
    assert_eq!(hard.get("requests.cpu").unwrap().0, "1500m");
    assert_eq!(hard.get("limits.cpu").unwrap().0, "3250m");

    // Standard apps do not patch the gateway deployment.
    assert!(
        manifests.envoy_proxy["spec"]["provider"]["kubernetes"]
            .get("envoyDeployment")
            .is_none()
    );

    let toml = decode_cc_init_data(&manifests.statefulset);
    assert!(toml.contains("runtime_class = \"kata-qemu-snp\""));
    verify_runtime_class_binding(&manifests.statefulset, &app)
        .expect("standard app must bind runtime class");
}
