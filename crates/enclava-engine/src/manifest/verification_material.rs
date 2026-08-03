use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::types::ConfidentialApp;

pub const MAX_BYTES: usize = 716_800;
pub const FILE_NAME: &str = "verification-material.ce";

pub fn configmap_name(app_name: &str) -> String {
    format!("{app_name}-verification")
}

pub fn generate(app: &ConfidentialApp) -> Option<ConfigMap> {
    let material = app.attestation.verification_material.as_ref()?;
    assert!(
        material.len() <= MAX_BYTES,
        "verification material exceeds 700 KiB"
    );
    Some(ConfigMap {
        metadata: ObjectMeta {
            name: Some(configmap_name(&app.name)),
            namespace: Some(app.namespace.clone()),
            ..Default::default()
        },
        binary_data: Some(BTreeMap::from([(
            FILE_NAME.to_string(),
            ByteString(material.clone()),
        )])),
        ..Default::default()
    })
}
