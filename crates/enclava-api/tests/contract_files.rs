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
        "application/x-ndjson",
        "encrypted-jsonl; version=enclava-log-frame-v1",
        "ciphertext_brokerage_only: true",
        "encrypted_logs_required",
        "logs_not_ready",
        "encrypted_log_stream_unavailable",
        "cache_control: no-store",
        "plaintext_kubernetes_logs: forbidden",
        "cap_or_paas_plaintext_access: forbidden",
        "tenant_client_decrypts: required",
        "audit_log_bodies: forbidden",
        "EncryptedLogFrame:",
        "org_id",
        "app_name",
        "deployment_id",
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

#[test]
fn kbs_policy_storage_observability_contract() {
    let root = workspace_root();
    let alerts = fs::read_to_string(root.join("deploy/kbs-policy-storage-alerts.prometheus.yml"))
        .expect("read KBS policy storage alerts");
    let dashboard = fs::read_to_string(root.join("deploy/kbs-policy-storage-dashboard.json"))
        .expect("read KBS policy storage dashboard");
    let runbook = fs::read_to_string(root.join("runbooks/kbs-policy-storage.md"))
        .expect("read KBS policy storage runbook");

    for required in [
        "EnclavaLegacyKBSPolicyObserved",
        "EnclavaKBSStaticPolicyCardinalityDrift",
        "EnclavaKBSAuthorizationPublicationSLOBreach",
        "EnclavaKBSAuthorizationReadbackMismatch",
        "EnclavaKBSAuthorizationReconciliationDrift",
        "EnclavaKBSAuthorizationReconciliationInconclusive",
        "EnclavaKBSPublisherUnauthorized",
        "EnclavaKBSAttestationClaimConflict",
        "EnclavaArtifactBundleDigestMismatch",
        "kbs_authorization_outbox_pending",
        "kbs_authorization_reconciliation_total",
        "kbs_deployment_authorization_publisher_request_total",
    ] {
        assert!(alerts.contains(required), "alerts missing `{required}`");
    }

    let dashboard: serde_json::Value =
        serde_json::from_str(&dashboard).expect("dashboard is valid JSON");
    assert_eq!(dashboard["uid"], "enclava-kbs-policy-storage");
    assert!(
        dashboard["panels"]
            .as_array()
            .is_some_and(|panels| panels.len() >= 9)
    );

    for required in [
        "Never recover availability by enabling the legacy",
        "publisher_readback_mismatch",
        "an outage is not evidence of drift",
        "Receipt verification never falls back",
        "permanent CAP tombstone ledger",
        "remote monitoring backend",
    ] {
        assert!(runbook.contains(required), "runbook missing `{required}`");
    }
}
