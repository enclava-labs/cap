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

#[test]
fn ci_serializes_tests_that_share_postgres_authority() {
    let workflow = fs::read_to_string(workspace_root().join(".github/workflows/ci.yml"))
        .expect("read CI workflow");

    assert!(
        workflow.contains("cargo test --workspace -- --test-threads=1"),
        "CI must serialize tests that share global PostgreSQL-backed provider fences"
    );
}

#[test]
fn dockerfiles_pin_base_images_by_digest() {
    // Mutable tags can be repointed by the registry at any time; every FROM
    // must carry the immutable digest that was reviewed (issue #140).
    let mut checked = 0;
    for entry in fs::read_dir(workspace_root().join("crates"))
        .expect("list crates")
        .filter_map(|e| e.ok())
    {
        let dockerfile = entry.path().join("Dockerfile");
        let Ok(content) = fs::read_to_string(&dockerfile) else {
            continue;
        };
        for line in content.lines() {
            let Some(rest) = line.strip_prefix("FROM ") else {
                continue;
            };
            let image = rest.split_whitespace().next().unwrap_or("");
            assert_is_digest_pinned(&dockerfile, image);
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "expected to check at least one Dockerfile FROM line"
    );
}

#[test]
fn ci_and_compose_service_images_are_digest_pinned() {
    // Dev/CI service images are not production artifacts, but they are part
    // of the reproducible-build story: pin them the same way (issue #140).
    for (path, needle) in [
        (
            ".github/workflows/ci.yml",
            "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
        ),
        (
            "docker-compose.yml",
            "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
        ),
    ] {
        let content = fs::read_to_string(workspace_root().join(path))
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            content.contains(needle),
            "{path} must pin the postgres service image by the reviewed digest"
        );
        assert!(
            !content.contains("postgres:16-alpine\n"),
            "{path} must not reference the mutable postgres:16-alpine tag"
        );
    }
}

fn assert_is_digest_pinned(dockerfile: &std::path::Path, image: &str) {
    // scratch has no bytes to pin; anything else needs a well-formed
    // sha256 digest: exactly 64 lowercase hex characters.
    if image == "scratch" {
        return;
    }
    let digest = image
        .rsplit_once("@sha256:")
        .map(|(_, hex)| hex)
        .unwrap_or_default();
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    assert!(
        valid,
        "{}: FROM `{image}` must be pinned by a sha256 digest (64 lowercase hex chars)",
        dockerfile.display()
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
