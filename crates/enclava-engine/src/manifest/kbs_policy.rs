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
            let (key, val) = generate_tls_binding_entry(app);
            render_binding_entry(&key, &val)
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
            let (key, val) = generate_owner_binding_entry(app);
            render_binding_entry(&key, &val)
        })
        .collect();
    rego.push_str(&entries.join(",\n"));
    rego.push_str("\n}\n");

    rego
}

/// Render a single `"key": {...}` map entry as Rego/JSON text, one field per
/// line. Key and every field value are serialized with serde_json so that
/// quotes, newlines and other metacharacters in tenant-influenced fields are
/// escaped and can never terminate a string literal.
fn render_binding_entry(key: &str, value: &Value) -> String {
    let to_json = |v: &Value| serde_json::to_string(v).expect("json serialization is infallible");
    let fields = value
        .as_object()
        .expect("binding entry must be a JSON object")
        .iter()
        .map(|(k, v)| format!("    {}: {}", to_json(&Value::String(k.clone())), to_json(v)))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "  {}: {{\n{fields}\n  }}",
        to_json(&Value::String(key.to_string()))
    )
}
