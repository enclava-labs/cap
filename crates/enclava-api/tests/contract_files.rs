use std::{fs, path::PathBuf};

#[test]
fn paas_internal_logs_contract() {
    let contract = fs::read_to_string(
        workspace_root().join("deploy/api/cap-paas-internal-logs.contract.yaml"),
    )
    .expect("read CAP/PaaS internal logs contract");

    for required in [
        "contract: cap-paas-internal-logs",
        "path: /internal/paas/orgs/{paas_org_id}/apps/{app_name}/logs",
        "actor_header: x-enclava-paas-user-id",
        "scope_not_allowed",
        "invalid_log_query",
        "encrypted_logs_required",
        "cache_control: no-store",
        "plaintext_kubernetes_logs: forbidden",
        "cap_or_paas_plaintext_access: forbidden",
        "audit_log_bodies: forbidden",
        "Error:",
    ] {
        assert!(
            contract.contains(required),
            "internal logs contract is missing `{required}`"
        );
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
