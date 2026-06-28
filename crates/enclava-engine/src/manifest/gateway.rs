//! Gateway API resources for public TLS passthrough to a CAP tenant.
//!
//! TLS is terminated by the tenant-ingress sidecar inside the confidential pod.
//! The Gateway/TLSRoute layer only routes by SNI to the tenant Service.

use serde_json::{Value, json};

use crate::types::ConfidentialApp;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

fn labels(app: &ConfidentialApp) -> Value {
    json!({
        "app.kubernetes.io/managed-by": "enclava-platform",
        "app.kubernetes.io/instance": app.tenant_id,
        "app.kubernetes.io/name": app.name,
        "tenant": app.tenant_id,
        "client": app.tenant_id,
    })
}

pub fn envoy_proxy_name(app: &ConfidentialApp) -> String {
    format!("tenant-gateway-proxy-{}", app.name)
}

pub fn gateway_name(app: &ConfidentialApp) -> String {
    format!("tenant-gateway-{}", app.name)
}

pub fn tls_route_name(app: &ConfidentialApp) -> String {
    format!("tenant-passthrough-{}", app.name)
}

pub fn tee_tls_route_name(app: &ConfidentialApp) -> String {
    format!("tenant-tee-passthrough-{}", app.name)
}

pub fn sni_route_name(app: &ConfidentialApp) -> String {
    format!("{}-sni-route", app.name)
}

/// Generate the SNI route ConfigMap consumed by the tenant HAProxy renderer.
///
/// The edge HAProxy discovers tenant routes from `caddy-sni-route=true`
/// ConfigMaps. CAP emits that contract directly; tenant resources must not
/// impersonate Flux-managed objects.
pub fn generate_sni_route_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app.kubernetes.io/name".to_string(), app.name.clone());
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        "sni-route".to_string(),
    );
    labels.insert("caddy-sni-route".to_string(), "true".to_string());

    let mut data = BTreeMap::new();
    data.insert("host".to_string(), app.primary_domain().to_string());
    data.insert(
        "backend_tls".to_string(),
        format!("{}.{}.svc.cluster.local:443", app.name, app.namespace),
    );
    data.insert("tenant".to_string(), app.tenant_id.clone());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(sni_route_name(app)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Generate an EnvoyProxy parameters resource for the tenant Gateway.
pub fn generate_envoy_proxy(app: &ConfidentialApp) -> Value {
    json!({
        "apiVersion": "gateway.envoyproxy.io/v1alpha1",
        "kind": "EnvoyProxy",
        "metadata": {
            "name": envoy_proxy_name(app),
            "namespace": app.namespace,
            "labels": labels(app),
        },
        "spec": {
            "logging": {
                "level": {
                    "default": "warn"
                }
            },
            "provider": {
                "type": "Kubernetes",
                "kubernetes": {
                    "envoyService": {
                        "type": "ClusterIP",
                        "externalTrafficPolicy": "Local"
                    }
                }
            }
        }
    })
}

/// Generate an instance-scoped TLS passthrough Gateway.
pub fn generate_gateway(app: &ConfidentialApp) -> Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": gateway_name(app),
            "namespace": app.namespace,
            "labels": labels(app),
        },
        "spec": {
            "gatewayClassName": "envoy-gateway-tenant",
            "infrastructure": {
                "parametersRef": {
                    "group": "gateway.envoyproxy.io",
                    "kind": "EnvoyProxy",
                    "name": envoy_proxy_name(app)
                }
            },
            "listeners": [
                {
                    "name": "tls-passthrough",
                    "port": 443,
                    "protocol": "TLS",
                    "tls": {
                        "mode": "Passthrough"
                    },
                    "allowedRoutes": {
                        "namespaces": {
                            "from": "Same"
                        }
                    }
                }
            ]
        }
    })
}

/// Generate a TLSRoute from the tenant Gateway to the tenant ingress Service port.
pub fn generate_tls_route(app: &ConfidentialApp) -> Value {
    generate_tls_route_to_service_port(app, &tls_route_name(app), app.primary_domain(), 443)
}

/// Generate a TLSRoute from the tenant Gateway to the attestation proxy Service port.
///
/// The TEE API must be reachable before the workload and tenant-ingress sidecars
/// are ready, so it cannot share the app-domain route that targets Caddy on
/// Service port 443.
pub fn generate_tee_tls_route(app: &ConfidentialApp) -> Value {
    generate_tls_route_to_service_port(app, &tee_tls_route_name(app), &app.domain.tee_domain, 8081)
}

fn generate_tls_route_to_service_port(
    app: &ConfidentialApp,
    name: &str,
    hostname: &str,
    port: u16,
) -> Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1alpha3",
        "kind": "TLSRoute",
        "metadata": {
            "name": name,
            "namespace": app.namespace,
            "labels": labels(app),
        },
        "spec": {
            "hostnames": [
                hostname
            ],
            "parentRefs": [
                {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": gateway_name(app),
                    "sectionName": "tls-passthrough"
                }
            ],
            "rules": [
                {
                    "backendRefs": [
                        {
                            "group": "",
                            "kind": "Service",
                            "name": app.name,
                            "port": port,
                            "weight": 1
                        }
                    ]
                }
            ]
        }
    })
}
