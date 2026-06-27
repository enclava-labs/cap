use k8s_openapi::api::core::v1::{LocalObjectReference, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate a ServiceAccount for the app.
pub fn generate_service_account(app: &ConfidentialApp) -> ServiceAccount {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(app.service_account.clone()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        image_pull_secrets: app
            .image_pull_secret_name
            .as_ref()
            .map(|name| vec![LocalObjectReference { name: name.clone() }]),
        // Phase 0 item E: confidential workloads must never automount the
        // default token; nothing inside the TEE talks to the K8s API.
        automount_service_account_token: Some(false),
        ..Default::default()
    }
}
