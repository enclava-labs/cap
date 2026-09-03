//! KBS owner_resource_bindings Rego generation.
//!
//! CAP generates `owner_resource_bindings` for owner state and generic
//! `resource_bindings` for tenant TLS seeds. Legacy `resource_bindings` are
//! imported as frozen entries per OID-5.

use serde_json::{Value, json};

use crate::types::ConfidentialApp;

use super::cc_init_data::compute_cc_init_data;

/// Generate the owner_resource_bindings map entry for a single app.
/// Returns (key, value) where key is "{namespace}-{name}-owner".
pub fn generate_owner_binding_entry(app: &ConfidentialApp) -> (String, Value) {
    let key = app.owner_resource_type();
    let value = json!({
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": [&app.namespace],
        "allowed_service_accounts": [&app.service_account],
        "allowed_identity_hashes": [&app.tenant_instance_identity_hash]
    });
    (key, value)
}

/// Generate the generic resource_bindings map entry for a single app's TLS seed.
/// Returns (key, value) where key is "{namespace}-{name}-tls".
pub fn generate_tls_binding_entry(app: &ConfidentialApp) -> (String, Value) {
    let key = app.tls_resource_type();
    let primary = app
        .primary_container()
        .expect("app must have a primary container");
    let (_encoded, init_data_hash) = compute_cc_init_data(app);
    let value = json!({
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": [primary.image.digest_ref()],
        "allowed_image_tag_prefixes": [],
        "allowed_init_data_hashes": [init_data_hash],
        "allowed_signer_identity_subjects": app.signer_identity_subject.as_ref().map(|s| vec![s]).unwrap_or_default(),
        "allowed_signer_identity_issuers": app.signer_identity_issuer.as_ref().map(|s| vec![s]).unwrap_or_default(),
        "allowed_namespaces": [&app.namespace],
        "allowed_service_accounts": [&app.service_account],
        "allowed_identity_hashes": [&app.tenant_instance_identity_hash]
    });
    (key, value)
}

/// Generate the complete KBS resource-policy.rego.
///
/// - `apps`: all CAP-managed apps that need owner_resource_bindings
/// - `legacy_resource_bindings_body`: the inner body of the frozen legacy resource_bindings
///   map (the content between the outer braces). Pass empty string if no legacy bindings.
///
/// The output includes the full Rego file: package, imports, resource_bindings (frozen legacy),
/// owner_resource_bindings (CAP-generated), and all the evaluation rules from the live policy.
pub fn generate_kbs_policy_rego(
    apps: &[&ConfidentialApp],
    legacy_resource_bindings_body: &str,
) -> String {
    let mut rego = String::new();

    rego.push_str("package policy\n\nimport rego.v1\n\ndefault allow := false\n\n");

    // Legacy resource_bindings (frozen per OID-5) plus CAP TLS seed bindings.
    if legacy_resource_bindings_body.trim().is_empty() {
        rego.push_str("resource_bindings := {\n");
    } else {
        rego.push_str("resource_bindings := {\n");
        rego.push_str(legacy_resource_bindings_body);
    }
    let tls_entries: Vec<String> = apps
        .iter()
        .map(|app| {
            let (key, _val) = generate_tls_binding_entry(app);
            let primary = app
                .primary_container()
                .expect("app must have a primary container");
            let (_encoded, init_data_hash) = compute_cc_init_data(app);
            // Every interpolated value is a Rego string literal: Rego string
            // syntax is JSON-compatible, so serialize through serde_json to
            // guarantee escaping (prevents crafted namespaces/identities from
            // injecting policy source).
            format!(
                "  {key}: {{\n\
                 {indent}\"repository\": \"default\",\n\
                 {indent}\"tag\": \"workload-secret-seed\",\n\
                 {indent}\"allowed_images\": [{image_digest}],\n\
                 {indent}\"allowed_image_tag_prefixes\": [],\n\
                 {indent}\"allowed_init_data_hashes\": [{init_data_hash}],\n\
                 {indent}\"allowed_signer_identity_subjects\": {signer_subjects},\n\
                 {indent}\"allowed_signer_identity_issuers\": {signer_issuers},\n\
                 {indent}\"allowed_namespaces\": [{namespace}],\n\
                 {indent}\"allowed_service_accounts\": [{sa}],\n\
                 {indent}\"allowed_identity_hashes\": [{hash}]\n\
                 {indent2}}}",
                key = rego_quoted_string(&key),
                indent = "    ",
                indent2 = "  ",
                image_digest = rego_quoted_string(&primary.image.digest_ref()),
                init_data_hash = rego_quoted_string(&init_data_hash),
                signer_subjects = optional_string_array(app.signer_identity_subject.as_deref()),
                signer_issuers = optional_string_array(app.signer_identity_issuer.as_deref()),
                namespace = rego_quoted_string(&app.namespace),
                sa = rego_quoted_string(&app.service_account),
                hash = rego_quoted_string(&app.tenant_instance_identity_hash),
            )
        })
        .collect();
    if !legacy_resource_bindings_body.trim().is_empty() && !tls_entries.is_empty() {
        rego.push_str(",\n");
    }
    rego.push_str(&tls_entries.join(",\n"));
    rego.push_str("\n}\n\n");

    // CAP owner_resource_bindings
    rego.push_str("owner_resource_bindings := {\n");
    let entries: Vec<String> = apps
        .iter()
        .map(|app| {
            let (key, _val) = generate_owner_binding_entry(app);
            format!(
                "  {key}: {{\n\
                 {indent}\"repository\": \"default\",\n\
                 {indent}\"allowed_tags\": [\"seed-encrypted\", \"seed-sealed\"],\n\
                 {indent}\"allowed_namespaces\": [{namespace}],\n\
                 {indent}\"allowed_service_accounts\": [{sa}],\n\
                 {indent}\"allowed_identity_hashes\": [{hash}]\n\
                 {indent2}}}",
                key = rego_quoted_string(&key),
                indent = "    ",
                indent2 = "  ",
                namespace = rego_quoted_string(&app.namespace),
                sa = rego_quoted_string(&app.service_account),
                hash = rego_quoted_string(&app.tenant_instance_identity_hash),
            )
        })
        .collect();
    rego.push_str(&entries.join(",\n"));
    rego.push_str("\n}\n");

    rego
}

fn optional_string_array(value: Option<&str>) -> String {
    value
        .filter(|v| !v.trim().is_empty())
        .map(|v| serde_json::to_string(&[v]).expect("string array serialization is infallible"))
        .unwrap_or_else(|| "[]".to_string())
}

/// A Rego string literal for an arbitrary value. Rego string syntax is
/// JSON-compatible, so JSON serialization provides correct escaping; this
/// keeps crafted identities or namespaces from injecting policy source.
fn rego_quoted_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}
