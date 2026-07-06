use enclava_engine::manifest::network_policy::generate_network_policy;
use enclava_engine::testutil::sample_app;

#[test]
fn network_policy_api_version() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    assert_eq!(val["apiVersion"], "cilium.io/v2");
    assert_eq!(val["kind"], "CiliumNetworkPolicy");
}

#[test]
fn network_policy_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    assert_eq!(val["metadata"]["namespace"], "cap-test-org-test-app");
}

#[test]
fn network_policy_ingress_allows_same_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let ingress = &val["spec"]["ingress"];
    let from = &ingress[0]["fromEndpoints"];
    assert_eq!(
        from[0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "cap-test-org-test-app"
    );
}

#[test]
fn network_policy_ingress_allows_envoy_gateway() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let from = &val["spec"]["ingress"][1]["fromEndpoints"];
    assert_eq!(
        from[0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "tenant-envoy"
    );
    assert_eq!(from[0]["matchLabels"]["app.kubernetes.io/name"], "envoy");
}

#[test]
fn network_policy_ingress_allows_cap_api_to_tee_control_port() {
    let mut app = sample_app();
    app.attestation.tls_certificate_broker_url = Some(
        "http://cap-api.cap-test01.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
            .to_string(),
    );

    let val = generate_network_policy(&app);
    let ingress = &val["spec"]["ingress"][2];
    let from = &ingress["fromEndpoints"];
    assert_eq!(
        from[0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "cap-test01"
    );
    assert_eq!(from[0]["matchLabels"]["app.kubernetes.io/name"], "cap-api");
    assert_eq!(ingress["toPorts"][0]["ports"][0]["port"], "8081");
    assert_eq!(ingress["toPorts"][0]["ports"][0]["protocol"], "TCP");
}

#[test]
fn network_policy_ingress_allows_platform_edge_host_path_on_public_ports() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let ingress = &val["spec"]["ingress"][2];
    let entities = ingress["fromEntities"].as_array().unwrap();
    let entities = entities
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(entities, vec!["host", "remote-node"]);
    let ports = ingress["toPorts"][0]["ports"].as_array().unwrap();
    let ports = ports
        .iter()
        .map(|port| {
            (
                port["port"].as_str().unwrap(),
                port["protocol"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ports, vec![("10443", "TCP"), ("8443", "TCP")]);
}

#[test]
fn network_policy_egress_has_dns() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    let dns_endpoints = &egress[0]["toEndpoints"][0]["matchLabels"];
    assert_eq!(dns_endpoints["io.kubernetes.pod.namespace"], "kube-system");
    assert_eq!(dns_endpoints["k8s-app"], "kube-dns");
    let dns_ports = &egress[0]["toPorts"][0]["ports"];
    assert_eq!(dns_ports[0]["port"], "53");
    assert_eq!(dns_ports[0]["protocol"], "UDP");
    assert_eq!(dns_ports[1]["port"], "53");
    assert_eq!(dns_ports[1]["protocol"], "TCP");
    assert_eq!(
        egress[0]["toPorts"][0]["rules"]["dns"][0]["matchPattern"],
        "*"
    );
}

#[test]
fn network_policy_egress_has_same_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[1]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "cap-test-org-test-app"
    );
}

#[test]
fn network_policy_egress_has_kbs() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[2]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "trustee-operator-system"
    );
    assert_eq!(egress[2]["toPorts"][0]["ports"][0]["port"], "8080");
}

#[test]
fn network_policy_egress_has_kbs_service() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[3]["toServices"][0]["k8sService"]["namespace"],
        "trustee-operator-system"
    );
    assert_eq!(
        egress[3]["toServices"][0]["k8sService"]["serviceName"],
        "kbs-service"
    );
}

#[test]
fn default_app_has_no_world_egress() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    for rule in egress {
        assert!(
            rule.get("toEntities").is_none(),
            "no rule may use toEntities (world): {rule}"
        );
    }
}

#[test]
fn world_is_never_in_default_egress() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let serialized = serde_json::to_string(&val).unwrap();
    assert!(
        !serialized.contains("\"world\""),
        "platform default egress must never include world: {serialized}"
    );
    assert!(
        !serialized.contains("toEntities"),
        "platform default egress must never use toEntities: {serialized}"
    );
}

#[test]
fn public_internet_egress_uses_cidr_exclusions_not_world_entity() {
    use enclava_engine::types::EgressMode;

    let mut app = sample_app();
    app.egress_mode = EgressMode::PublicInternet;
    app.public_internet_egress_excluded_cidrs = vec!["95.217.56.192/26".to_string()];

    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    let public_rule = egress
        .iter()
        .find(|rule| rule["toCIDRSet"][0]["cidr"].as_str() == Some("0.0.0.0/0"))
        .expect("public internet CIDR rule");
    let except = public_rule["toCIDRSet"][0]["except"]
        .as_array()
        .expect("public egress exclusions");
    let except = except
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();

    assert!(except.contains(&"10.0.0.0/8"));
    assert!(except.contains(&"169.254.0.0/16"));
    assert!(except.contains(&"172.16.0.0/12"));
    assert!(except.contains(&"192.168.0.0/16"));
    assert!(except.contains(&"95.217.56.192/26"));
    assert!(
        !serde_json::to_string(&val).unwrap().contains("toEntities"),
        "public internet mode must not use broad Cilium entities"
    );
}

#[test]
fn restricted_egress_mode_does_not_emit_public_cidr() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    assert!(
        egress
            .iter()
            .all(|rule| rule["toCIDRSet"][0]["cidr"].as_str() != Some("0.0.0.0/0"))
    );
}

#[test]
fn default_egress_includes_acme_endpoints() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    let fqdns: Vec<&str> = egress
        .iter()
        .filter_map(|r| r["toFQDNs"][0]["matchName"].as_str())
        .collect();
    assert!(
        fqdns.contains(&"acme-v02.api.letsencrypt.org"),
        "missing ACME prod endpoint in {fqdns:?}"
    );
    assert!(
        fqdns.contains(&"acme-staging-v02.api.letsencrypt.org"),
        "missing ACME staging endpoint in {fqdns:?}"
    );
    for rule in egress {
        if rule["toFQDNs"][0]["matchName"]
            .as_str()
            .map(|s| s.contains("letsencrypt.org"))
            .unwrap_or(false)
        {
            assert_eq!(rule["toPorts"][0]["ports"][0]["port"], "443");
            assert_eq!(rule["toPorts"][0]["ports"][0]["protocol"], "TCP");
        }
    }
}

#[test]
fn dns01_broker_url_is_allowed_for_static_certificate_provisioning() {
    let mut app = sample_app();
    app.attestation.tls_certificate_broker_url = Some(
        "https://cap-test01-enclava.enclava.dev/api/v1/workload/tls/dns01-certificate".to_string(),
    );

    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    let broker_rule = egress
        .iter()
        .find(|rule| {
            rule["toFQDNs"][0]["matchName"].as_str() == Some("cap-test01-enclava.enclava.dev")
        })
        .expect("broker FQDN egress rule");

    assert_eq!(broker_rule["toPorts"][0]["ports"][0]["port"], "443");
    assert_eq!(broker_rule["toPorts"][0]["ports"][0]["protocol"], "TCP");
}

#[test]
fn dns01_broker_kubernetes_service_url_is_allowed_for_static_certificate_provisioning() {
    let mut app = sample_app();
    app.attestation.tls_certificate_broker_url = Some(
        "http://cap-api.cap-test01.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
            .to_string(),
    );

    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    let broker_rule = egress
        .iter()
        .find(|rule| {
            rule["toServices"][0]["k8sService"]["namespace"].as_str() == Some("cap-test01")
                && rule["toServices"][0]["k8sService"]["serviceName"].as_str() == Some("cap-api")
        })
        .expect("broker Kubernetes service egress rule");

    assert_eq!(broker_rule["toPorts"][0]["ports"][0]["port"], "80");
    assert_eq!(broker_rule["toPorts"][0]["ports"][0]["protocol"], "TCP");

    let cap_api_endpoint_rule = egress
        .iter()
        .find(|rule| {
            rule["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"].as_str()
                == Some("cap-test01")
                && rule["toEndpoints"][0]["matchLabels"]["app.kubernetes.io/name"].as_str()
                    == Some("cap-api")
        })
        .expect("broker CAP API endpoint egress rule");
    assert_eq!(
        cap_api_endpoint_rule["toPorts"][0]["ports"][0]["port"],
        "3000"
    );
    assert_eq!(
        cap_api_endpoint_rule["toPorts"][0]["ports"][0]["protocol"],
        "TCP"
    );
}

#[test]
fn empty_egress_allowlist_renders_zero_extra_rules() {
    let mut app = sample_app();
    app.egress_allowlist = Vec::new();
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    assert_eq!(egress.len(), 6, "DNS + same-ns + KBS x2 + ACME x2");
}

#[test]
fn per_app_egress_extends_platform_default() {
    use enclava_engine::types::EgressRule;
    let mut app = sample_app();
    app.egress_allowlist = vec![EgressRule {
        host: "api.stripe.com".to_string(),
        ports: vec![443],
    }];
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    let fqdns: Vec<&str> = egress
        .iter()
        .filter_map(|r| r["toFQDNs"][0]["matchName"].as_str())
        .collect();
    assert!(fqdns.contains(&"acme-v02.api.letsencrypt.org"));
    assert!(fqdns.contains(&"acme-staging-v02.api.letsencrypt.org"));
    assert!(fqdns.contains(&"api.stripe.com"));
}

#[test]
fn egress_allowlist_renders_one_rule_per_entry() {
    use enclava_engine::types::EgressRule;
    let mut app = sample_app();
    app.egress_allowlist = vec![
        EgressRule {
            host: "api.stripe.com".to_string(),
            ports: vec![443],
        },
        EgressRule {
            host: "hooks.slack.com".to_string(),
            ports: vec![443],
        },
    ];
    let val = generate_network_policy(&app);
    let egress = val["spec"]["egress"].as_array().unwrap();
    assert_eq!(egress.len(), 8, "4 cluster + 2 ACME + 2 user");
    assert_eq!(egress[6]["toFQDNs"][0]["matchName"], "api.stripe.com");
    assert_eq!(egress[6]["toPorts"][0]["ports"][0]["port"], "443");
    assert_eq!(egress[7]["toFQDNs"][0]["matchName"], "hooks.slack.com");
}
