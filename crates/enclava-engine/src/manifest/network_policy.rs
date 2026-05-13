use serde_json::{Value, json};

use crate::types::{ConfidentialApp, EgressRule};

/// Platform-default FQDN egress allowlist.
///
/// Hardcoded so the operator cannot quietly drop these. Caddy needs ACME
/// reachability to issue and renew TLS certs for tenant ingress.
const PLATFORM_DEFAULT_FQDNS: &[&str] = &[
    "acme-v02.api.letsencrypt.org",
    "acme-staging-v02.api.letsencrypt.org",
];

/// Generate a CiliumNetworkPolicy (cilium.io/v2 CRD).
///
/// Default: no egress to `world`. The previous policy allowed unrestricted
/// HTTP/HTTPS egress to the internet, which let a compromised workload
/// exfiltrate plaintext to any host. Phase 11: per-app FQDN allowlist instead.
///
/// Each `EgressRule` becomes a Cilium `toFQDNs` rule scoped to the listed ports.
/// The platform-default allowlist (DNS, KBS, ACME) is always present; per-app
/// `egress_allowlist` adds on top.
pub fn generate_network_policy(app: &ConfidentialApp) -> Value {
    let mut egress = vec![
        // Rule: DNS to kube-dns
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "kube-system",
                        "k8s-app": "kube-dns"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "53", "protocol": "UDP" },
                        { "port": "53", "protocol": "TCP" }
                    ]
                }
            ]
        }),
        // Rule: same namespace
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": &app.namespace
                    }
                }
            ]
        }),
        // Rule: KBS endpoint (direct pod access)
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "trustee-operator-system"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "8080", "protocol": "TCP" }
                    ]
                }
            ]
        }),
        // Rule: KBS service (service routing)
        json!({
            "toServices": [
                {
                    "k8sService": {
                        "namespace": "trustee-operator-system",
                        "serviceName": "kbs-service"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "8080", "protocol": "TCP" }
                    ]
                }
            ]
        }),
    ];

    for fqdn in PLATFORM_DEFAULT_FQDNS {
        egress.push(json!({
            "toFQDNs": [{ "matchName": fqdn }],
            "toPorts": [{ "ports": [{ "port": "443", "protocol": "TCP" }] }],
        }));
    }

    for rule in tls_certificate_broker_egress_rules(app) {
        egress.push(rule);
    }

    for rule in &app.egress_allowlist {
        egress.push(egress_rule_value(rule));
    }

    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "tenant-isolation",
            "namespace": app.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "enclava-platform"
            }
        },
        "spec": {
            "description": "Strict network isolation for confidential workload",
            "endpointSelector": {},
            "ingress": [
                {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": &app.namespace
                            }
                        },
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": "tenant-envoy",
                                "app.kubernetes.io/name": "envoy"
                            }
                        }
                    ]
                }
            ],
            "egress": egress,
        }
    })
}

fn egress_rule_value(rule: &EgressRule) -> Value {
    let ports: Vec<Value> = rule
        .ports
        .iter()
        .map(|p| json!({ "port": p.to_string(), "protocol": "TCP" }))
        .collect();
    json!({
        "toFQDNs": [{ "matchName": rule.host }],
        "toPorts": [{ "ports": ports }],
    })
}

fn tls_certificate_broker_egress_rules(app: &ConfidentialApp) -> Vec<Value> {
    let Some(url) = app.attestation.tls_certificate_broker_url.as_deref() else {
        return Vec::new();
    };
    let Some((scheme, rest)) = url.trim().split_once("://") else {
        return Vec::new();
    };
    let Some(authority) = rest.split('/').next().map(str::trim) else {
        return Vec::new();
    };
    if authority.is_empty() {
        return Vec::new();
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| authority.split(':').next().unwrap_or(authority))
        .trim();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let port = explicit_url_port(authority).unwrap_or(match scheme {
        "http" => 80,
        "https" => 443,
        _ => return Vec::new(),
    });

    if let Some((service_name, namespace)) = kubernetes_service_name(host) {
        let mut rules = vec![json!({
            "toServices": [
                {
                    "k8sService": {
                        "namespace": namespace,
                        "serviceName": service_name
                    }
                }
            ],
            "toPorts": [{ "ports": [{ "port": port.to_string(), "protocol": "TCP" }] }],
        })];
        if service_name == "cap-api" {
            rules.push(json!({
                "toEndpoints": [
                    {
                        "matchLabels": {
                            "io.kubernetes.pod.namespace": namespace,
                            "app.kubernetes.io/name": service_name
                        }
                    }
                ],
                "toPorts": [{ "ports": [{ "port": "3000", "protocol": "TCP" }] }],
            }));
        }
        return rules;
    }

    vec![json!({
        "toFQDNs": [{ "matchName": host }],
        "toPorts": [{ "ports": [{ "port": port.to_string(), "protocol": "TCP" }] }],
    })]
}

fn explicit_url_port(authority: &str) -> Option<u16> {
    if authority.starts_with('[') {
        return authority
            .split_once("]:")
            .and_then(|(_, port)| port.parse().ok());
    }
    let mut parts = authority.split(':');
    let _host = parts.next()?;
    let port = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    port.parse().ok()
}

fn kubernetes_service_name(host: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = host.split('.').collect();
    match parts.as_slice() {
        [service, namespace, "svc"] | [service, namespace, "svc", "cluster", "local"] => {
            Some((*service, *namespace))
        }
        _ => None,
    }
}
