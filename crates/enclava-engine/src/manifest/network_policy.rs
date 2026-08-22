use serde_json::{Value, json};

use crate::types::{AttestationConfig, ConfidentialApp, EgressMode, EgressRule};

/// Platform-default FQDN egress allowlist.
///
/// Hardcoded so the operator cannot quietly drop these. Caddy needs ACME
/// reachability to issue and renew TLS certs. AMD KDS traffic uses the internal
/// relay below because Kata guests cannot use Cilium's DNS proxy.
const PLATFORM_DEFAULT_FQDNS: &[&str] = &[
    "acme-v02.api.letsencrypt.org",
    "acme-staging-v02.api.letsencrypt.org",
];

const PUBLIC_INTERNET_CIDR: &str = "0.0.0.0/0";
const PUBLIC_INTERNET_DEFAULT_EXCLUDED_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
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
    let mut ingress = vec![
        json!({
            "fromEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": &app.namespace
                    }
                }
            ]
        }),
        json!({
            "fromEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "tenant-envoy",
                        "app.kubernetes.io/name": "envoy"
                    }
                }
            ]
        }),
    ];

    if let Some(rule) = cap_api_tee_ingress_rule(app) {
        ingress.push(rule);
    }

    ingress.push(json!({
        "fromEntities": ["host", "remote-node"],
        "toPorts": [
            {
                "ports": [
                    { "port": "10443", "protocol": "TCP" },
                    { "port": "8443", "protocol": "TCP" }
                ]
            }
        ]
    }));

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

    egress.extend(amd_kds_relay_egress_rules(app));

    for rule in tls_certificate_broker_egress_rules(app) {
        egress.push(rule);
    }

    if app.egress_mode == EgressMode::PublicInternet {
        egress.push(public_internet_egress_rule(app));
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
            "ingress": ingress,
            "egress": egress,
            // Name-layer denylists (internal/metadata hostnames) are
            // bypassable by a tenant-controlled domain whose A/AAAA record
            // points at internal space: `toFQDNs` authorizes whatever the
            // DNS layer resolves. Deny rules outrank allow rules in Cilium,
            // so metadata and link-local space is unreachable through ANY
            // allow rule — no legitimate tenant egress ever touches it.
            // (169.254.0.0/16 covers 169.254.169.254 metadata endpoints;
            // fc00::/7 covers AWS IMDS IPv6 fd00:ec2::254.)
            "egressDeny": [
                { "toCIDR": ["169.254.0.0/16", "fc00::/7"] }
            ],
        }
    })
}

fn amd_kds_relay_egress_rules(app: &ConfidentialApp) -> Vec<Value> {
    let Some(url) = app.attestation.amd_kds_base_url.as_deref() else {
        return Vec::new();
    };
    let Some(authority) = parse_url_authority(url) else {
        return Vec::new();
    };
    let Some((service_name, namespace)) = kubernetes_service_name(authority.host) else {
        return vec![json!({
            "toFQDNs": [{ "matchName": authority.host }],
            "toPorts": [{ "ports": [{
                "port": authority.port.to_string(),
                "protocol": "TCP"
            }] }],
        })];
    };
    vec![
        json!({
            "toServices": [{
                "k8sService": {
                    "namespace": namespace,
                    "serviceName": service_name
                }
            }],
            "toPorts": [{ "ports": [{
                "port": authority.port.to_string(),
                "protocol": "TCP"
            }] }]
        }),
        json!({
            "toEndpoints": [{
                "matchLabels": {
                    "io.kubernetes.pod.namespace": namespace,
                    "app.kubernetes.io/name": service_name
                }
            }],
            "toPorts": [{ "ports": [{
                "port": authority.port.to_string(),
                "protocol": "TCP"
            }] }]
        }),
    ]
}

fn public_internet_egress_rule(app: &ConfidentialApp) -> Value {
    let mut excluded = PUBLIC_INTERNET_DEFAULT_EXCLUDED_CIDRS
        .iter()
        .map(|cidr| (*cidr).to_string())
        .collect::<Vec<_>>();
    excluded.extend(app.public_internet_egress_excluded_cidrs.iter().cloned());
    excluded.sort();
    excluded.dedup();

    json!({
        "toCIDRSet": [
            {
                "cidr": PUBLIC_INTERNET_CIDR,
                "except": excluded
            }
        ]
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
    let Some(authority) = parse_url_authority(url) else {
        return Vec::new();
    };

    if let Some((service_name, namespace)) = kubernetes_service_name(authority.host) {
        // The broker may be any explicitly configured internal Service (for
        // example a standalone CAP candidate), not only one literally named
        // `cap-api`. The URL remains platform-supplied, never tenant input.
        let mut rules = vec![json!({
            "toServices": [
                {
                    "k8sService": {
                        "namespace": namespace,
                        "serviceName": service_name
                    }
                }
            ],
            "toPorts": [{ "ports": [{ "port": authority.port.to_string(), "protocol": "TCP" }] }],
        })];
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
        return rules;
    }

    vec![json!({
        "toFQDNs": [{ "matchName": authority.host }],
        "toPorts": [{ "ports": [{ "port": authority.port.to_string(), "protocol": "TCP" }] }],
    })]
}

fn cap_api_tee_ingress_rule(app: &ConfidentialApp) -> Option<Value> {
    let (service_name, namespace) =
        cap_api_service_for_attestation(&app.attestation, &app.api_url)?;
    Some(json!({
        "fromEndpoints": [
            {
                "matchLabels": {
                    "io.kubernetes.pod.namespace": namespace,
                    "app.kubernetes.io/name": service_name
                }
            }
        ],
        "toPorts": [
            {
                "ports": [
                    { "port": "10443", "protocol": "TCP" },
                    { "port": "8443", "protocol": "TCP" }
                ]
            }
        ]
    }))
}

/// Return the CAP namespace only when workload configuration explicitly uses
/// an internal CAP Service. Tenant policy generation and CAP status observation
/// share this predicate so the direct TEE path is selected only when its
/// ingress rule is present.
pub fn cap_api_namespace_for_attestation<'a>(
    attestation: &'a AttestationConfig,
    api_url: &'a str,
) -> Option<&'a str> {
    cap_api_service_for_attestation(attestation, api_url).map(|(_, namespace)| namespace)
}

fn cap_api_service_for_attestation<'a>(
    attestation: &'a AttestationConfig,
    api_url: &'a str,
) -> Option<(&'a str, &'a str)> {
    // `trustee_policy_url` is intentionally absent: independent-verification
    // deployments hand the policy to init as a local file URI. It is not a
    // CAP network dependency and must not select CAP ingress policy.
    [
        attestation.tls_certificate_broker_url.as_deref(),
        attestation.workload_artifacts_url.as_deref(),
        Some(api_url),
    ]
    .into_iter()
    .flatten()
    .find_map(|url| {
        let authority = parse_url_authority(url)?;
        kubernetes_service_name(authority.host)
    })
}

struct ParsedUrlAuthority<'a> {
    host: &'a str,
    port: u16,
}

fn parse_url_authority(url: &str) -> Option<ParsedUrlAuthority<'_>> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority = rest.split('/').next().map(str::trim)?;
    if authority.is_empty() {
        return None;
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| authority.split(':').next().unwrap_or(authority))
        .trim();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let port = explicit_url_port(authority).unwrap_or(match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    });

    Some(ParsedUrlAuthority { host, port })
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
