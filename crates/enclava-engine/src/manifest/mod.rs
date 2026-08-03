//! Manifest generation for confidential workloads.
//!
//! Each sub-module generates one Kubernetes resource. The top-level
//! `generate_all_manifests` assembles every resource needed to deploy
//! a single confidential application.

pub mod bootstrap;
pub mod cc_init_data;
pub mod containers;
pub mod enclava_init_config;
pub mod gateway;
pub mod ingress;
pub mod kbs_policy;
pub mod namespace;
pub mod network_policy;
pub mod resource_quota;
pub mod service;
pub mod service_account;
pub mod startup;
pub mod statefulset;
pub mod verification_material;
pub mod volumes;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, ResourceQuota, Service, ServiceAccount};
use serde_json::Value;

use crate::types::ConfidentialApp;

/// All Kubernetes resources needed to deploy a confidential application.
///
/// Produced by `generate_all_manifests`. The caller (API server or CLI)
/// serialises each field into YAML and applies via server-side apply.
pub struct GeneratedManifests {
    pub namespace: Namespace,
    pub service_account: ServiceAccount,
    pub network_policy: Value,
    pub resource_quota: ResourceQuota,
    pub service: Service,
    pub sni_route_configmap: ConfigMap,
    pub envoy_proxy: Value,
    pub gateway: Value,
    pub tls_route: Value,
    pub tee_tls_route: Value,
    pub bootstrap_configmap: ConfigMap,
    pub startup_configmap: ConfigMap,
    pub ingress_configmap: ConfigMap,
    pub enclava_init_configmap: ConfigMap,
    pub verification_material_configmap: Option<ConfigMap>,
    pub statefulset: StatefulSet,
    /// KBS owner_resource_bindings entry: (key, value) for the policy Rego.
    pub kbs_owner_binding: (String, Value),
}

/// Generate every Kubernetes resource for a single confidential app.
///
/// Does NOT include the KBS policy Rego itself — that aggregates across
/// all apps and is generated separately via `kbs_policy::generate_kbs_policy_rego`.
pub fn generate_all_manifests(app: &ConfidentialApp) -> GeneratedManifests {
    GeneratedManifests {
        namespace: namespace::generate_namespace(app),
        service_account: service_account::generate_service_account(app),
        network_policy: network_policy::generate_network_policy(app),
        resource_quota: resource_quota::generate_resource_quota(app),
        service: service::generate_service(app),
        sni_route_configmap: gateway::generate_sni_route_configmap(app),
        envoy_proxy: gateway::generate_envoy_proxy(app),
        gateway: gateway::generate_gateway(app),
        tls_route: gateway::generate_tls_route(app),
        tee_tls_route: gateway::generate_tee_tls_route(app),
        bootstrap_configmap: bootstrap::generate_bootstrap_configmap(app),
        startup_configmap: startup::generate_startup_configmap(app),
        ingress_configmap: ingress::generate_ingress_configmap(app),
        enclava_init_configmap: enclava_init_config::generate_enclava_init_configmap(app),
        verification_material_configmap: verification_material::generate(app),
        statefulset: statefulset::generate_statefulset(app),
        kbs_owner_binding: kbs_policy::generate_owner_binding_entry(app),
    }
}
