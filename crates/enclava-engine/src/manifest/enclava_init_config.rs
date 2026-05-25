//! ConfigMap that backs `/etc/enclava-init/config.toml` for the enclava-init
//! initContainer (Phase 5). Generated alongside the StatefulSet so the init
//! container has all the per-app knobs it needs (LUKS device paths, mapping
//! names, mount points, KBS resource path, in-TEE verification toggles).

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::manifest::cc_init_data;
use crate::types::ConfidentialApp;
use enclava_common::canonical::ce_v1_hash;
use enclava_common::types::UnlockMode;

pub(crate) const LOCAL_OWNER_SEED_RESOURCE_URL: &str = "http://127.0.0.1:8006/internal/owner-seed";
pub(crate) const LOCAL_KBS_ATTESTATION_TOKEN_URL: &str =
    "http://127.0.0.1:8006/aa/token?token_type=kbs";
const LOCAL_WORKLOAD_ARTIFACTS_PATH: &str = "/etc/enclava-init/workload-artifacts.json";
const LOCAL_TRUSTEE_POLICY_PATH: &str = "/etc/enclava-init/trustee-policy.json";
const APP_UID: u32 = 10001;
const APP_GID: u32 = 10001;
const CADDY_UID: u32 = 10002;
const CADDY_GID: u32 = 10002;

pub fn configmap_name(app_name: &str) -> String {
    format!("{app_name}-enclava-init")
}

pub fn generate_enclava_init_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    let mut data = BTreeMap::new();
    data.insert("config.toml".to_string(), render_config_toml(app));
    if app.attestation.trustee_policy_read_available {
        data.insert(
            "cc-init-data.toml".to_string(),
            cc_init_data::build_toml(app),
        );
        if let Some(json) = app.attestation.local_workload_artifacts_json.as_ref() {
            data.insert("workload-artifacts.json".to_string(), json.clone());
        }
        if let Some(json) = app.attestation.local_trustee_policy_json.as_ref() {
            data.insert("trustee-policy.json".to_string(), json.clone());
        }
    }

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(configmap_name(&app.name)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

fn render_config_toml(app: &ConfidentialApp) -> String {
    let mode = match app.unlock_mode {
        UnlockMode::Auto => "autounlock",
        UnlockMode::Password => "password",
    };
    let mut out = String::new();
    out.push_str(&format!("mode = \"{mode}\"\n"));
    out.push_str("state-root = \"/state\"\n");
    out.push_str("unlock-socket = \"/run/enclava-unlock/unlock.sock\"\n");
    out.push_str("attempts-path = \"/run/enclava-unlock/unlock-attempts\"\n");
    out.push_str(&format!("app-uid = {APP_UID}\n"));
    out.push_str(&format!("app-gid = {APP_GID}\n"));
    out.push_str(&format!("caddy-uid = {CADDY_UID}\n"));
    out.push_str(&format!("caddy-gid = {CADDY_GID}\n"));
    out.push_str(&format!("argon2-salt-hex = \"{}\"\n", argon2_salt_hex(app)));

    if app.unlock_mode == UnlockMode::Auto {
        out.push_str(&format!("kbs-url = \"{LOCAL_OWNER_SEED_RESOURCE_URL}\"\n"));
        out.push_str(&format!(
            "kbs-resource-path = \"{}\"\n",
            app.owner_resource_path()
        ));
    }

    if app.attestation.trustee_policy_read_available {
        out.push_str("trustee-policy-read-available = true\n");
        out.push_str("cc-init-data-path = \"/etc/enclava-init/cc-init-data.toml\"\n");
        push_required_option(
            &mut out,
            "workload-artifacts-url",
            app.attestation
                .local_workload_artifacts_json
                .as_ref()
                .map(|_| format!("file://{LOCAL_WORKLOAD_ARTIFACTS_PATH}"))
                .as_deref()
                .or(app.attestation.workload_artifacts_url.as_deref()),
        );
        if let Some(url) = app.attestation.tls_certificate_broker_url.as_deref() {
            push_optional_option(&mut out, "tls-certificate-broker-url", Some(url));
            push_string_array(
                &mut out,
                "tls-certificate-hostnames",
                &tls_certificate_hostnames(app),
            );
        }
        push_required_option(
            &mut out,
            "trustee-policy-url",
            app.attestation
                .local_trustee_policy_json
                .as_ref()
                .map(|_| format!("file://{LOCAL_TRUSTEE_POLICY_PATH}"))
                .as_deref()
                .or(app.attestation.trustee_policy_url.as_deref()),
        );
        out.push_str(&format!(
            "kbs-attestation-token-url = \"{LOCAL_KBS_ATTESTATION_TOKEN_URL}\"\n",
        ));
        push_optional_option(
            &mut out,
            "platform-trustee-policy-pubkey-hex",
            app.attestation
                .platform_trustee_policy_pubkey_hex
                .as_deref(),
        );
        push_optional_option(
            &mut out,
            "signing-service-pubkey-hex",
            app.attestation.signing_service_pubkey_hex.as_deref(),
        );
    } else {
        out.push_str("\n# Phase 3 Trustee patches not yet deployed; in-TEE verification\n");
        out.push_str("# stays SKIPPED with a loud error log until this flips true.\n");
        out.push_str("trustee-policy-read-available = false\n");
    }

    out.push_str("\n[state]\n");
    out.push_str(&format!(
        "device = \"{}\"\n",
        app.storage.app_data.device_path
    ));
    out.push_str("mapping-name = \"cap-state\"\n");
    out.push_str("mount-path = \"/state\"\n");
    out.push_str("hkdf-info = \"state-luks-key\"\n");
    out.push_str("\n[tls-state]\n");
    out.push_str(&format!(
        "device = \"{}\"\n",
        app.storage.tls_data.device_path
    ));
    out.push_str("mapping-name = \"cap-tls-state\"\n");
    out.push_str("mount-path = \"/state/tls-state\"\n");
    out.push_str("hkdf-info = \"tls-state-luks-key\"\n");

    if let Some(primary) = app.primary_container() {
        for path in &primary.storage_paths {
            out.push_str("\n[[app-bind-mounts]]\n");
            out.push_str(&format!(
                "subdir = {}\n",
                toml_string(&storage_subdir(path))
            ));
            out.push_str(&format!("mount-path = {}\n", toml_string(path)));
        }
    }

    out
}

pub(crate) fn argon2_salt_hex(app: &ConfidentialApp) -> String {
    hex::encode(ce_v1_hash(&[
        ("purpose", b"enclava-init-argon2-salt-v1"),
        ("app_id", app.app_id.as_bytes().as_slice()),
        ("namespace", app.namespace.as_bytes()),
        (
            "identity_hash",
            app.tenant_instance_identity_hash.as_bytes(),
        ),
    ]))
}

fn storage_subdir(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
}

fn toml_string(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization is infallible")
}

fn tls_certificate_hostnames(app: &ConfidentialApp) -> Vec<String> {
    let mut hosts = vec![app.domain.platform_domain.clone()];
    if let Some(custom) = app.domain.custom_domain.as_ref()
        && !custom.is_empty()
        && !hosts.iter().any(|host| host == custom)
    {
        hosts.push(custom.clone());
    }
    hosts
}

fn push_required_option(out: &mut String, key: &str, value: Option<&str>) {
    let value = value.unwrap_or_else(|| panic!("missing required enclava-init config key {key}"));
    out.push_str(&format!("{key} = {}\n", toml_string(value)));
}

fn push_optional_option(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.push_str(&format!("{key} = {}\n", toml_string(value)));
    }
}

fn push_string_array(out: &mut String, key: &str, values: &[String]) {
    let encoded = values
        .iter()
        .map(|value| toml_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("{key} = [{encoded}]\n"));
}
