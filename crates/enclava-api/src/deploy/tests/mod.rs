mod creation_ledger_regressions {
    use super::*;
    include!("creation_ledger_regressions.rs");
}
use super::*;
use chrono::TimeZone;
use enclava_common::descriptor::{
    Capabilities, DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources,
    SecurityContext, Sidecars, SignerIdentity,
};
use std::sync::{Arc, Mutex};

fn test_attestation_config() -> AttestationConfig {
    AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
            trustee_policy_read_available: true,
            workload_artifacts_url: None,
            tls_certificate_broker_url: None,
            amd_kds_base_url: None,
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
            verification_material: None,
        }
}

fn queued_apply_app() -> App {
    let now = chrono::Utc::now();
    App {
        id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        org_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        name: "queued-app".to_string(),
        namespace: "cap-queued-app".to_string(),
        instance_id: "queued-app-instance".to_string(),
        tenant_id: "8f346820".to_string(),
        service_account: "cap-queued-app-sa".to_string(),
        bootstrap_owner_pubkey_hash: "11".repeat(32),
        tenant_instance_identity_hash: "22".repeat(32),
        unlock_mode: crate::models::UnlockMode::Password,
        domain: "queued-app.8f346820.enclava.dev".to_string(),
        tee_domain: Some("queued-app.8f346820.tee.enclava.dev".to_string()),
        custom_domain: None,
        status: AppStatus::Creating,
        signer_identity_subject: Some("https://github.com/acme/app".to_string()),
        signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        signer_identity_set_at: Some(now),
        signer_rotation_generation: 1,
        source_provider: Some("github".to_string()),
        source_repository: Some("acme/app".to_string()),
        egress_allowlist: sqlx::types::Json(Vec::new()),
        egress_mode: "restricted".to_string(),
        created_at: now,
        updated_at: now,
    }
}

fn queued_apply_snapshot(digest_byte: char) -> DeploymentApplySnapshot {
    let app = queued_apply_app();
    let digest = format!("sha256:{}", digest_byte.to_string().repeat(64));
    DeploymentApplySnapshot::new(
        vec![AppContainer {
            id: uuid::Uuid::new_v4(),
            app_id: app.id,
            name: "web".to_string(),
            image_ref: "ghcr.io/acme/app:latest".to_string(),
            image_digest: Some(digest),
            port: Some(8080),
            command: None,
            storage_paths: Some(vec!["/data".to_string()]),
            workload_security_profile: Some("restricted".to_string()),
            is_primary: true,
        }],
        AppResources {
            app_id: app.id,
            cpu_limit: "1".to_string(),
            memory_limit: "1Gi".to_string(),
            app_data_size: "5Gi".to_string(),
            tls_data_size: "2Gi".to_string(),
        },
    )
}

#[test]
fn stored_auto_unlock_app_cannot_build_a_workload() {
    // The shared apply authority must refuse every deployment lineage
    // (deploy, redeploy, rollback, transition reapply) for a stored-auto
    // app: no auto-unlock workload may ever be rendered again.
    let mut app = queued_apply_app();
    app.unlock_mode = crate::models::UnlockMode::Auto;
    let snapshot = queued_apply_snapshot('a');
    let error = build_confidential_app_from_rows(
        &app,
        uuid::Uuid::new_v4(),
        &test_attestation_config(),
        "api-signing-key",
        "https://api.enclava.dev",
        &snapshot.containers,
        &snapshot.resources,
    )
    .expect_err("stored-auto app must not build a workload");
    match error {
        DeployError::Validation(message) => {
            assert!(
                message.starts_with("auto_unlock_disabled"),
                "rejection must carry the stable code: {message}"
            );
        }
        other => panic!("expected validation rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn queued_apply_renders_its_captured_rows_after_later_state_changes() {
    let app = queued_apply_app();
    let first_snapshot = queued_apply_snapshot('a');
    let later_snapshot = queued_apply_snapshot('b');
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let queued_gate = gate.clone();
    let queued_app = app.clone();
    let queued = tokio::spawn(async move {
        let _permit = queued_gate.acquire().await.expect("queue remains open");
        build_confidential_app_from_rows(
            &queued_app,
            uuid::Uuid::new_v4(),
            &test_attestation_config(),
            "api-signing-key",
            "https://api.enclava.dev",
            &first_snapshot.containers,
            &first_snapshot.resources,
        )
        .expect("captured apply snapshot")
    });

    tokio::task::yield_now().await;
    let later = build_confidential_app_from_rows(
        &app,
        uuid::Uuid::new_v4(),
        &test_attestation_config(),
        "api-signing-key",
        "https://api.enclava.dev",
        &later_snapshot.containers,
        &later_snapshot.resources,
    )
    .expect("later apply snapshot");
    gate.add_permits(1);
    let first = queued.await.expect("queued renderer");

    assert_eq!(
        first.containers[0].image.digest(),
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        later.containers[0].image.digest(),
        format!("sha256:{}", "b".repeat(64))
    );
}

#[test]
fn tagged_rows_render_the_digest_pinned_name() {
    let app = queued_apply_app();
    let snapshot = queued_apply_snapshot('c');
    let rendered = build_confidential_app_from_rows(
        &app,
        uuid::Uuid::new_v4(),
        &test_attestation_config(),
        "api-signing-key",
        "https://api.enclava.dev",
        &snapshot.containers,
        &snapshot.resources,
    )
    .expect("render");
    // A stored tag must not leak into the rendered name: the signed
    // descriptor binds registry/repository@digest (#210 review).
    assert_eq!(
        rendered.containers[0].image.digest_ref(),
        format!("ghcr.io/acme/app@sha256:{}", "c".repeat(64))
    );
}

#[test]
fn password_redeploy_timeout_stays_healthy_for_manual_unlock() {
    let outcome = classify_rollout_result(
        Ok(EngineDeployStatus::timed_out(
            "rollout did not complete within 600s",
        )),
        AppStatus::Running,
        crate::models::UnlockMode::Password,
    );

    assert_eq!(
        outcome,
        DeploymentOutcome {
            deploy_status: "healthy",
            app_status: "running",
            error_message: None,
            terminal: true,
        }
    );
}

#[test]
fn deployment_error_persistence_discards_plaintext() {
    const SENSITIVE_ERROR: &str =
        "kubernetes response included customer-secret-name and private-config";

    let persisted = persisted_deployment_error(Some(SENSITIVE_ERROR));
    assert_eq!(persisted, Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE));
    assert!(!persisted.unwrap().contains("customer-secret-name"));
    assert_eq!(persisted_deployment_error(None), None);

    let error = DeployError::Apply(enclava_engine::apply::engine::ApplyError::RolloutFailed(
        SENSITIVE_ERROR.to_string(),
    ));
    assert_eq!(error.public_code(), "rollout_failed");
    assert!(!error.public_code().contains("customer-secret-name"));

    let mutation_error = DeployError::Mutation(crate::mutation_leases::MutationLeaseError::Busy);
    assert_eq!(mutation_error.public_code(), "mutation_fence_error");
    assert_eq!(
        crate::deployment_jobs::DeploymentJobError::from(mutation_error).code(),
        "mutation_fence_error"
    );
}

#[test]
fn password_create_timeout_stays_watchable_for_initial_claim() {
    let outcome = classify_rollout_result(
        Ok(EngineDeployStatus::timed_out(
            "rollout did not complete within 600s",
        )),
        AppStatus::Creating,
        crate::models::UnlockMode::Password,
    );

    assert_eq!(
        outcome,
        DeploymentOutcome {
            deploy_status: "watching",
            app_status: "creating",
            error_message: None,
            terminal: false,
        }
    );
}

#[test]
fn tenant_image_pull_secret_uses_dockerconfigjson_shape() {
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_fake".to_string(),
        allowed_repositories: Vec::new(),
    };

    let secret = generate_tenant_image_pull_secret("tenant-ns", &config);
    let string_data = secret.string_data.as_ref().unwrap();
    let docker_config: serde_json::Value =
        serde_json::from_str(string_data.get(".dockerconfigjson").unwrap()).unwrap();

    assert_eq!(
        secret.metadata.name.as_deref(),
        Some("enclava-registry-auth")
    );
    assert_eq!(secret.metadata.namespace.as_deref(), Some("tenant-ns"));
    assert_eq!(
        secret
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
            .map(String::as_str),
        Some("enclava-platform")
    );
    assert_eq!(
        secret.type_.as_deref(),
        Some("kubernetes.io/dockerconfigjson")
    );
    assert_eq!(
        docker_config["auths"]["ghcr.io"]["username"].as_str(),
        Some("cap-bot")
    );
    assert_eq!(
        docker_config["auths"]["ghcr.io"]["password"].as_str(),
        Some("ghp_fake")
    );
    assert_eq!(
        docker_config["auths"]["ghcr.io"]["auth"].as_str(),
        Some("Y2FwLWJvdDpnaHBfZmFrZQ==")
    );
}

fn pull_secret_config(
    allowed_repositories: Vec<ImagePullRepositoryScope>,
) -> TenantImagePullSecretConfig {
    TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_fake".to_string(),
        allowed_repositories,
    }
}

fn test_container(image_ref: &str) -> Container {
    Container {
        name: "web".to_string(),
        image: ImageRef::parse(image_ref).unwrap(),
        port: Some(8080),
        command: None,
        env: std::collections::HashMap::new(),
        storage_paths: Vec::new(),
        workload_security_profile: WorkloadSecurityProfile::Restricted,
        is_primary: true,
    }
}

#[test]
fn tenant_image_pull_scope_parses_exact_and_prefix_repositories() {
    assert_eq!(
        parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template").unwrap(),
        ImagePullRepositoryScope {
            registry: "ghcr.io".to_string(),
            repository: "enclava-ai/private-template".to_string(),
            include_subrepositories: false,
        }
    );
    assert_eq!(
        parse_image_pull_repository_scope(" ghcr.io/enclava-ai/templates/* ").unwrap(),
        ImagePullRepositoryScope {
            registry: "ghcr.io".to_string(),
            repository: "enclava-ai/templates".to_string(),
            include_subrepositories: true,
        }
    );
    assert!(parse_image_pull_repository_scope("ghcr.io").is_err());
}

/// Codex review on #276, P2: `GHCR.IO` is the same registry as `ghcr.io`.
/// An uppercase scope must parse to the canonical host, and a workload
/// image that preserves `GHCR.IO` must match that scope. Repository path
/// case stays exact.
#[test]
fn ghcr_scope_canonicalizes_registry_case() {
    let scope = parse_image_pull_repository_scope("GHCR.IO/org/private").unwrap();
    assert_eq!(
        scope,
        ImagePullRepositoryScope {
            registry: "ghcr.io".to_string(),
            repository: "org/private".to_string(),
            include_subrepositories: false,
        }
    );
    let digest = "a".repeat(64);
    let uppercase = ImageRef::parse(&format!("GHCR.IO/org/private@sha256:{digest}")).unwrap();
    let lowercase = ImageRef::parse(&format!("ghcr.io/org/private@sha256:{digest}")).unwrap();
    assert_ne!(uppercase.registry(), lowercase.registry());
    assert!(image_matches_repository_scope(&uppercase, &scope));
    assert!(image_matches_repository_scope(&lowercase, &scope));
    let wildcard = parse_image_pull_repository_scope("Ghcr.Io/org/private/*").unwrap();
    let child = ImageRef::parse(&format!("GHCR.IO/org/private/child@sha256:{digest}")).unwrap();
    assert!(image_matches_repository_scope(&child, &wildcard));
    let other_repo = ImageRef::parse(&format!("ghcr.io/Org/private@sha256:{digest}")).unwrap();
    assert!(!image_matches_repository_scope(&other_repo, &scope));
    assert!(parse_image_pull_repository_scope("Example.COM/org/private").is_err());
}

/// Codex review on #276, P1 + cap#272: a sweep-created secret classifies
/// as a failed-generation leftover only with platform field-manager
/// ownership of the creation annotation AND a server-recorded creation
/// row. The same annotations without that ownership stay foreign; with
/// ownership but no ledger row they stay unresolved (fail closed).
#[test]
fn sweep_created_pull_secret_lineage_is_a_generation_leftover() {
    use enclava_engine::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{FieldsV1, ManagedFieldsEntry};

    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "token".to_string(),
        allowed_repositories: Vec::new(),
    };
    let mut secret = generate_tenant_image_pull_secret("tenant-ns", &config);
    stamp_sweep_created_pull_secret_lineage(&mut secret);
    secret.metadata.uid = Some("uid-sweep-created".to_string());
    secret.metadata.creation_timestamp =
        Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            "2026-10-18T00:00:00Z".parse().expect("fixture timestamp"),
        ));
    let strict_ledger = enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new();
    assert!(matches!(
        crate::deployment_failure_cleanup::classify_generation_leftover(&secret, 7, &strict_ledger),
        crate::deployment_failure_cleanup::GenerationLeftover::Foreign
    ));
    secret.metadata.managed_fields = Some(vec![ManagedFieldsEntry {
        manager: Some("enclava-platform".to_string()),
        fields_v1: Some(FieldsV1(serde_json::json!({
            "f:metadata": {
                "f:annotations": {
                    format!("f:{RESOURCE_CREATED_BY_ANNOTATION}"): {}
                }
            }
        }))),
        ..Default::default()
    }]);
    assert_eq!(
        secret
            .metadata
            .annotations
            .as_ref()
            .unwrap()
            .get(MUTATION_GENERATION_ANNOTATION)
            .map(String::as_str),
        Some("1")
    );
    assert!(matches!(
        crate::deployment_failure_cleanup::classify_generation_leftover(&secret, 1, &strict_ledger),
        crate::deployment_failure_cleanup::GenerationLeftover::ProvenanceUnproven
    ));
    let recorded_ledger = enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new();
    recorded_ledger.preload([(
        "Secret".to_string(),
        "enclava-registry-auth".to_string(),
        "uid-sweep-created".to_string(),
    )]);
    assert!(matches!(
        crate::deployment_failure_cleanup::classify_generation_leftover(
            &secret,
            1,
            &recorded_ledger
        ),
        crate::deployment_failure_cleanup::GenerationLeftover::Leftover
    ));
    assert!(matches!(
        crate::deployment_failure_cleanup::classify_generation_leftover(
            &secret,
            7,
            &recorded_ledger
        ),
        crate::deployment_failure_cleanup::GenerationLeftover::Leftover
    ));
}

#[test]
fn shared_pull_secret_predicate_covers_label_and_configured_name_only() {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        TENANT_PULL_SECRET_LABEL.to_string(),
        TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
    );
    assert!(secret_is_shared_tenant_pull_secret(
        "renamed-old-secret",
        Some(&labels)
    ));
    assert!(secret_is_shared_tenant_pull_secret(
        &default_tenant_image_pull_secret_name_for_cleanup(),
        None
    ));
    assert!(!secret_is_shared_tenant_pull_secret("tenant-owned", None));
}

/// #252: scopes with empty path segments — a trailing '/' (including the
/// `ghcr.io/company/private//*` typo that strips exactly one `/*` and
/// leaves a trailing slash), interior `//`, or a leading '/' — must be
/// validation errors, never silently normalized into a scope.
#[test]
fn tenant_image_pull_scope_rejects_trailing_slash_and_empty_segments() {
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private//*").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private/").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private//").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company//private").is_err());
    assert!(parse_image_pull_repository_scope("/ghcr.io/company/private").is_err());
}

/// A repeated wildcard suffix must be rejected, never stripped down into
/// the broader scope (P1 review): `registry/repository/*/*` would widen to
/// `registry/repository/*` if all `/*` repetitions were trimmed.
#[test]
fn tenant_image_pull_scope_rejects_repeated_wildcard_suffixes() {
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private/*/*").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private/**").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company*/private").is_err());
    assert!(parse_image_pull_repository_scope("*/company/private").is_err());
    assert!(parse_image_pull_repository_scope("ghcr.io/company/private/*x").is_err());

    // A single trailing "/*" keeps its subrepository semantics — the
    // rejection must not break the documented grammar.
    assert_eq!(
        parse_image_pull_repository_scope("ghcr.io/company/private/*").unwrap(),
        ImagePullRepositoryScope {
            registry: "ghcr.io".to_string(),
            repository: "company/private".to_string(),
            include_subrepositories: true,
        }
    );
}

/// Issue #225: an unscoped config must never attach the platform pull
/// secret to tenant workloads — this was the previous "global fallback"
/// that materialized the platform GHCR PAT into every tenant namespace.
#[test]
fn tenant_image_pull_secret_without_scope_fails_closed() {
    let config = pull_secret_config(Vec::new());
    let containers = vec![test_container(
        "ghcr.io/tenant/private-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )];

    assert!(!tenant_image_pull_secret_applies_to_containers(
        &containers,
        &config
    ));
}

/// Issue #225: a scope list with invalid entries must not silently
/// degrade into a different (or missing) scope.
#[test]
fn tenant_image_pull_scope_parser_rejects_invalid_entries() {
    assert!(parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*,bogus").is_err());
    assert!(parse_image_pull_scopes_strict("ghcr.io").is_err());
    assert_eq!(
        parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*").unwrap(),
        vec![parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap()]
    );
}

/// A list with one valid and one malformed scope must name the malformed
/// entry in the error instead of claiming no valid entries exist (review
/// finding): operators need the exact offending entry to fix the typo.
#[test]
fn tenant_image_pull_scope_errors_name_malformed_entries() {
    let error = parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*,bogus,ghcr.io/a/b")
        .unwrap_err();
    assert!(error.contains("bogus"), "error should name entry: {error}");
    assert!(error.contains("#2"), "error should give position: {error}");
    assert!(
        !error.contains("ghcr.io/a/b"),
        "valid entries must not be reported: {error}"
    );

    let empty_entry = parse_image_pull_scopes_strict("ghcr.io/a/b,").unwrap_err();
    assert!(
        empty_entry.contains("#2"),
        "error should give position: {empty_entry}"
    );
}

#[test]
fn managed_tenant_image_pull_secret_detection_matches_label_and_legacy_shape() {
    use k8s_openapi::ByteString;

    let matching = Some(("cap-bot", "x"));
    let mut labeled = generate_tenant_image_pull_secret(
        "tenant-ns",
        &pull_secret_config(vec![
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
        ]),
    );
    // The managed-by label is the ownership proof for generated secrets:
    // detection passes on the label alone, without reading any data.
    assert!(is_managed_tenant_image_pull_secret(&labeled, matching));
    // Labeled secrets are proven ours by the label alone.
    assert!(is_managed_tenant_image_pull_secret(&labeled, None));

    // Legacy pre-label secret: dockerconfigjson with exactly one ghcr.io
    // auth entry carrying the configured GHCR pair, as the old global
    // fallback generated it.
    let legacy_json =
        serde_json::json!({"auths": {"ghcr.io": {"username": "cap-bot", "password": "x"}}})
            .to_string();
    let mut legacy = Secret {
        metadata: ObjectMeta {
            name: Some("enclava-registry-auth".to_string()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        ..Default::default()
    };
    legacy.data = Some(std::collections::BTreeMap::from([(
        ".dockerconfigjson".to_string(),
        ByteString(legacy_json.into_bytes()),
    )]));
    assert!(is_managed_tenant_image_pull_secret(&legacy, matching));
    // An unlabeled secret with a tenant's own GHCR credentials under the
    // managed name is NOT CAP-generated: never delete it (review finding).
    assert!(!is_managed_tenant_image_pull_secret(
        &legacy,
        Some(("tenant-user", "tenant-token"))
    ));
    assert!(!is_managed_tenant_image_pull_secret(&legacy, None));

    // A tenant's own multi-registry secret is never CAP-managed.
    let tenant_json = serde_json::json!({
        "auths": {
            "ghcr.io": {"username": "cap-bot", "password": "x"},
            "registry.example": {"username": "tenant"}
        }
    })
    .to_string();
    let mut tenant = legacy.clone();
    tenant.data = Some(std::collections::BTreeMap::from([(
        ".dockerconfigjson".to_string(),
        ByteString(tenant_json.into_bytes()),
    )]));
    assert!(!is_managed_tenant_image_pull_secret(&tenant, matching));

    // Wrong type / missing payload is never CAP-managed.
    let opaque = Secret {
        metadata: ObjectMeta {
            name: Some("enclava-registry-auth".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!is_managed_tenant_image_pull_secret(&opaque, matching));

    // A stray managed-by label on an unparseable secret is still ours.
    labeled.data = None;
    labeled.string_data = None;
    assert!(is_managed_tenant_image_pull_secret(&labeled, matching));
}

#[test]
fn namespace_keeps_pull_secret_only_while_an_app_is_in_scope() {
    let config = pull_secret_config(vec![
        parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
    ]);
    let in_scope = Some(vec![test_container(
            "ghcr.io/enclava-ai/templates/ssh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .image
        .clone()]);
    let out_of_scope = Some(vec![test_container(
            "ghcr.io/tenant/private-app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .image
        .clone()]);

    assert!(namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        std::slice::from_ref(&in_scope)
    ));
    assert!(namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        &[out_of_scope.clone(), in_scope.clone()]
    ));
    assert!(!namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        &[out_of_scope]
    ));
    // Unparsable stored images never keep the secret by themselves …
    assert!(!namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        &[None]
    ));
    // … but they never evict it from a namespace with a valid in-scope app.
    assert!(namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        &[None, in_scope.clone()]
    ));
    assert!(namespace_keeps_tenant_image_pull_secret(
        Some(&config),
        &[Some(vec![]), in_scope]
    ));
    // No scoped config at all: nothing keeps the secret.
    assert!(!namespace_keeps_tenant_image_pull_secret(None, &[]));
}

#[test]
fn tenant_image_pull_secret_scope_requires_every_container_to_match() {
    let config = pull_secret_config(vec![
        parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template").unwrap(),
        parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
    ]);
    let allowed = vec![
        test_container(
            "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        test_container(
            "ghcr.io/enclava-ai/templates/ssh@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ];
    let mixed = vec![
        test_container(
            "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        test_container(
            "ghcr.io/tenant/private-app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
    ];

    assert!(tenant_image_pull_secret_applies_to_containers(
        &allowed, &config
    ));
    assert!(!tenant_image_pull_secret_applies_to_containers(
        &mixed, &config
    ));
}

#[test]
fn signed_deploy_with_local_artifacts_still_reconciles_global_kbs_policy() {
    let mut attestation = test_attestation_config();
    assert!(should_reconcile_global_signed_policy_artifacts(
        true,
        &attestation
    ));

    attestation.local_workload_artifacts_json = Some("{\"bundle\":true}".to_string());
    assert!(should_reconcile_global_signed_policy_artifacts(
        true,
        &attestation
    ));

    attestation.local_trustee_policy_json = Some("{\"policy\":true}".to_string());
    assert!(should_reconcile_global_signed_policy_artifacts(
        true,
        &attestation
    ));
    assert!(!should_reconcile_global_signed_policy_artifacts(
        false,
        &attestation
    ));
}

fn customer_app_descriptor() -> DeploymentDescriptor {
    DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "8f346820".to_string(),
            app_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "customer-app".to_string(),
            deploy_id: uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap(),
            nonce: [1; 32],
            app_domain: "customer-app.8f346820.enclava.dev".to_string(),
            tee_domain: "customer-app.8f346820.tee.enclava.dev".to_string(),
            custom_domains: Vec::new(),
            namespace: "cap-demo-org-customer-app".to_string(),
            service_account: "cap-customer-app-sa".to_string(),
            identity_hash: [2; 32],
            image_ref:
                "ghcr.io/acme/customer-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject:
                    "https://github.com/acme/customer-app/.github/workflows/docker.yaml@refs/heads/main"
                        .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/usr/local/bin/enclava-wait-exec".to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![EnvVar {
                    name: "APP_SEED_PATH".to_string(),
                    value: "/run/enclava/seeds/app/seed".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3338,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![
                    Mount {
                        source: "state-mount".to_string(),
                        destination: "/state".to_string(),
                        mount_type: "kubernetes-volume".to_string(),
                        options: vec!["rw".to_string()],
                    },
                    Mount {
                        source: "state-mount:data".to_string(),
                        destination: "/data".to_string(),
                        mount_type: "kubernetes-volume-subpath".to_string(),
                        options: vec!["rw".to_string()],
                    },
                ],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                caddy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            independent_verification: true,
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-demo-org-customer-app-customer-app-owner/seed-encrypted"
                .to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "test".to_string(),
            expected_agent_policy_hash: [5; 32],
            expected_cc_init_data_hash: [6; 32],
            expected_kbs_policy_hash: [7; 32],
        }
}

#[test]
fn signed_descriptor_runtime_fields_match_descriptor_expectations() {
    let descriptor = customer_app_descriptor();

    assert_eq!(
        serialize_workload_command(&descriptor.oci_runtime_spec.args).unwrap(),
        Some("[\"/usr/local/bin/app\"]".to_string())
    );
    assert_eq!(descriptor_primary_port(&descriptor), Some(3338));
    assert_eq!(
        descriptor_storage_paths(&descriptor),
        vec!["/data".to_string()]
    );
}

#[test]
fn descriptor_runtime_overrides_stale_primary_container_fields() {
    let descriptor = customer_app_descriptor();
    let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: Vec::new(),
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: None,
                tls_certificate_broker_url: None,
                amd_kds_base_url: None,
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
                verification_material: None,
            },
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

    set_primary_descriptor_runtime(&mut app, &descriptor);

    let primary = app.primary_container().unwrap();
    assert_eq!(
        primary.command,
        Some(vec!["/usr/local/bin/app".to_string()])
    );
    assert_eq!(primary.port, Some(3338));
    assert_eq!(primary.storage_paths, vec!["/data".to_string()]);
}

#[test]
fn signed_descriptor_without_subpath_mounts_clears_stale_storage_paths() {
    let mut descriptor = customer_app_descriptor();
    descriptor
        .oci_runtime_spec
        .mounts
        .retain(|mount| mount.destination == "/state");
    let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: vec!["/data".to_string()],
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: None,
                tls_certificate_broker_url: None,
                amd_kds_base_url: None,
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
                verification_material: None,
            },
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

    set_primary_descriptor_runtime(&mut app, &descriptor);

    assert!(descriptor_storage_paths(&descriptor).is_empty());
    assert!(app.primary_container().unwrap().storage_paths.is_empty());
}

/// A Kubernetes API double with configurable readiness and an empty pod list.
fn rollout_client(ready: bool) -> kube::Client {
    rollout_client_with(1, 1, i32::from(ready))
}

fn rollout_client_with(
    generation: i64,
    observed_generation: i64,
    ready_replicas: i32,
) -> kube::Client {
    use axum::http::{Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use tower::service_fn;

    kube::Client::new(
        service_fn(move |request: Request<Body>| async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let path = request.uri().path().to_string();
            let _ = request.into_body().collect().await;
            let value = if path.ends_with("/pods") {
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "items": [],
                })
            } else {
                serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {
                        "name": "queued-app",
                        "namespace": "cap-queued-app",
                        "generation": generation,
                    },
                    "spec": { "replicas": 1 },
                    "status": {
                        "observedGeneration": observed_generation,
                        "replicas": ready_replicas,
                        "readyReplicas": ready_replicas,
                        "currentReplicas": ready_replicas,
                        "updatedReplicas": ready_replicas,
                    },
                })
            };
            Ok::<_, std::io::Error>(
                Response::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_vec(&value).unwrap()))
                    .unwrap(),
            )
        }),
        "default",
    )
}

fn rollout_test_engine() -> ApplyEngine {
    ApplyEngine::new(
        rollout_client(false),
        enclava_engine::apply::types::ApplyConfig {
            rollout_timeout: std::time::Duration::from_secs(600),
            poll_interval: std::time::Duration::from_millis(5),
            ..enclava_engine::apply::types::ApplyConfig::default()
        },
    )
}

fn expired_rollout_anchor(budget: std::time::Duration) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::from_std(budget).unwrap() - chrono::Duration::seconds(1)
}

/// The base budget an initialized redeploy would carry: no fresh claim
/// contributes the first-boot allowance.
fn initialized_redeploy_budget() -> std::time::Duration {
    rollout_test_engine()
        .config()
        .rollout_timeout_for_storage(
            "2Ti",
            "2Ti",
            enclava_engine::apply::orchestrator::FreshVolumeClaims::NONE,
        )
        .expect("fixture rollout budget")
}

/// The budget a first render that must freshly initialize both volumes
/// would record with its watching marker.
fn fresh_initialization_budget(app_data_size: &str, tls_data_size: &str) -> std::time::Duration {
    rollout_test_engine()
        .config()
        .rollout_timeout_for_storage(
            app_data_size,
            tls_data_size,
            enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
        )
        .expect("fixture rollout budget")
}

#[tokio::test]
async fn rollout_watch_slice_returns_nonterminal_while_budget_remains() {
    // An owner-waiting workload must release its worker slot between
    // observation slices instead of holding it for the full rollout
    // timeout.
    let outcome = DeploymentRollout::observe_only(
        queued_apply_app(),
        rollout_test_engine(),
        "slice-manifest".to_string(),
        chrono::Utc::now(),
        fresh_initialization_budget("32Mi", "32Mi"),
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "watching");
    assert_eq!(outcome.app_status, "creating");
    assert!(!outcome.terminal);
    assert_eq!(outcome.manifest_hash, "slice-manifest");
}

#[tokio::test]
async fn rollout_watch_respects_anchored_cumulative_deadline() {
    // A restarted observer anchors at `observing_since`: once the
    // cumulative rollout budget is spent, the slice ends immediately and
    // returns the engine timeout classification instead of restarting a
    // fresh initialization budget. A stopped redeploy does not classify
    // as an owner wait, so budget exhaustion stays terminal.
    let mut app = queued_apply_app();
    app.status = AppStatus::Stopped;
    let budget = fresh_initialization_budget("32Mi", "32Mi");
    let outcome = DeploymentRollout::observe_only(
        app,
        rollout_test_engine(),
        "deadline-manifest".to_string(),
        expired_rollout_anchor(budget),
        budget,
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "failed");
    assert_eq!(outcome.app_status, "failed");
    assert!(outcome.terminal);
    assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
}

#[tokio::test]
async fn initialized_redeploy_expires_at_base_budget() {
    // A redeploy whose volumes are already initialized carries only the
    // base rollout budget. A 2 Ti manifest must NOT inherit a
    // multi-hour first-boot allowance: once the recorded base budget is
    // spent, the cumulative deadline ends the rollout normally. A stopped
    // redeploy does not classify as an owner wait, so exhaustion stays
    // terminal.
    let mut app = queued_apply_app();
    app.status = AppStatus::Stopped;
    let outcome = DeploymentRollout::observe_only(
        app,
        rollout_test_engine(),
        "initialized-redeploy-manifest".to_string(),
        expired_rollout_anchor(initialized_redeploy_budget()),
        initialized_redeploy_budget(),
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "failed");
    assert_eq!(outcome.app_status, "failed");
    assert!(outcome.terminal);
    assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
}

#[tokio::test]
async fn resumed_observer_keeps_recorded_budget() {
    // The budget persisted with the watching marker is the deadline.
    // Simulating a restart where live pod/volume state has changed, the
    // resumed observer must reuse the recorded value: a record smaller
    // than any size-derived budget still expires, a record larger than
    // one still keeps observing. Neither recomputes.
    let mut expired_app = queued_apply_app();
    expired_app.status = AppStatus::Stopped;
    let recorded_small = std::time::Duration::from_secs(1);
    let expired = DeploymentRollout::observe_only(
        expired_app,
        rollout_test_engine(),
        "resumed-expired-manifest".to_string(),
        expired_rollout_anchor(recorded_small),
        recorded_small,
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(expired.deploy_status, "failed");
    assert!(expired.terminal);

    let waiting_app = queued_apply_app();
    let waiting = DeploymentRollout::observe_only(
        waiting_app,
        rollout_test_engine(),
        "resumed-waiting-manifest".to_string(),
        chrono::Utc::now() - chrono::Duration::minutes(30),
        fresh_initialization_budget("2Ti", "2Ti"),
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(waiting.deploy_status, "watching");
    assert!(!waiting.terminal);
    assert_eq!(waiting.error_code, None);
}

#[tokio::test]
async fn rollout_watch_observes_late_owner_unlock_after_deadline() {
    let engine = ApplyEngine::new(
        rollout_client(true),
        enclava_engine::apply::types::ApplyConfig::default(),
    );
    let budget = fresh_initialization_budget("32Mi", "32Mi");
    let outcome = DeploymentRollout::observe_only(
        queued_apply_app(),
        engine,
        "late-unlock-manifest".to_string(),
        expired_rollout_anchor(budget),
        budget,
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "healthy");
    assert_eq!(outcome.app_status, "running");
    assert!(outcome.terminal);
}

#[tokio::test]
async fn rollout_watch_password_timeout_stays_nonterminal_for_owner_wait() {
    // Password-mode creates classify an exhausted rollout budget as a
    // continuing owner wait, but the observation slice still returns
    // promptly so the worker slot is released between probes.
    let budget = fresh_initialization_budget("32Mi", "32Mi");
    let outcome = DeploymentRollout::observe_only(
        queued_apply_app(),
        rollout_test_engine(),
        "password-manifest".to_string(),
        expired_rollout_anchor(budget),
        budget,
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "watching");
    assert_eq!(outcome.app_status, "creating");
    assert!(!outcome.terminal);
}

#[tokio::test]
async fn rollout_watch_password_timeout_stays_nonterminal_for_failed_app_redeploy() {
    // The job payload freezes the app snapshot at accept time, so a
    // redeploy of a previously-failed app carries status "failed". The
    // apply already persisted "creating" for the new rollout; the stale
    // snapshot must not terminalize a legitimate owner wait.
    let mut app = queued_apply_app();
    app.status = AppStatus::Failed;
    let budget = fresh_initialization_budget("32Mi", "32Mi");
    let outcome = DeploymentRollout::observe_only(
        app,
        rollout_test_engine(),
        "password-redeploy-manifest".to_string(),
        expired_rollout_anchor(budget),
        budget,
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "watching");
    assert_eq!(outcome.app_status, "creating");
    assert!(!outcome.terminal);
}

#[test]
fn extended_owner_wait_probe_slice_spans_two_poll_intervals() {
    // Two poll intervals give a late unlock a fresh observation before the
    // probe ends; anything larger creeps the per-app apply-worker duty cycle
    // back toward the full slice's (#231).
    assert_eq!(
        EXTENDED_OWNER_WAIT_PROBE_SLICE,
        2 * enclava_engine::apply::types::ApplyConfig::default().poll_interval
    );
    assert!(EXTENDED_OWNER_WAIT_PROBE_SLICE < ROLLOUT_OBSERVATION_SLICE);
}

#[tokio::test(start_paused = true)]
async fn extended_owner_wait_releases_the_worker_after_the_probe_slice() {
    // With the production 90 s slice configured, an abandoned locked app
    // must end its observation after the 10 s probe instead of holding one
    // of the bounded apply-worker slots for the full slice, while the owner
    // wait itself stays nonterminal (#231).
    let budget = fresh_initialization_budget("32Mi", "32Mi");
    let started = tokio::time::Instant::now();
    let outcome = DeploymentRollout::observe_only(
        queued_apply_app(),
        rollout_test_engine(),
        "probe-slice-manifest".to_string(),
        expired_rollout_anchor(budget),
        budget,
    )
    .expect("valid rollout budget")
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "watching");
    assert_eq!(outcome.app_status, "creating");
    assert!(!outcome.terminal);
    assert!(
        started.elapsed() <= EXTENDED_OWNER_WAIT_PROBE_SLICE + std::time::Duration::from_secs(1),
        "extended owner wait must release its worker after the probe slice, held {:?}",
        started.elapsed()
    );
}

fn settled_statefulset(
    generation: i64,
    observed: i64,
    desired: i32,
    ready: i32,
    current: i32,
    updated: i32,
) -> k8s_openapi::api::apps::v1::StatefulSet {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "app", "namespace": "cap-app", "generation": generation},
        "spec": {"replicas": desired},
        "status": {
            "observedGeneration": observed,
            "readyReplicas": ready,
            "currentReplicas": current,
            "updatedReplicas": updated,
        },
    }))
    .expect("statefulset settling fixture")
}

#[test]
fn statefulset_rollout_settled_matches_the_rollout_completion_criterion() {
    // Fully converged: the controller has observed the current
    // generation and every replica matches the latest spec.
    assert!(statefulset_rollout_settled(&settled_statefulset(
        3, 3, 1, 1, 1, 1
    )));
    // The controller has not observed the newest applied generation:
    // a failed rollout's spec is still being reconciled and its
    // controller can still replace the TEE.
    assert!(!statefulset_rollout_settled(&settled_statefulset(
        3, 2, 1, 1, 1, 1
    )));
    // The replacement is not up yet: the workload is mid-swap even
    // though the controller caught up with the generation.
    assert!(!statefulset_rollout_settled(&settled_statefulset(
        3, 3, 1, 0, 1, 1
    )));
    assert!(!statefulset_rollout_settled(&settled_statefulset(
        3, 3, 1, 1, 1, 0
    )));
    // A scaled-down workload has no TEE that could be replaced.
    assert!(statefulset_rollout_settled(&settled_statefulset(
        3, 3, 0, 0, 0, 0
    )));
}

#[tokio::test]
async fn supersession_serializes_customer_config_delivery() {
    let pool = crate::test_support::database_test_pool().await;
    let (app, deployment_id, _, _) = crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
    sqlx::query(
        "UPDATE deployment_apply_jobs
                SET customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() + interval '1 hour',
                    next_attempt_at = 'infinity'
              WHERE deployment_id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("arm config delivery hold");

    for (scenario, blocked) in [
        ("active", true),
        ("expired", false),
        ("released", false),
        ("deleting", false),
    ] {
        let mut tx = pool.begin().await.expect("begin supersession scenario");
        lock_app_deployment_lane(&mut tx, app.id).await.unwrap();
        if scenario == "expired" {
            sqlx::query(
                "UPDATE deployment_apply_jobs
                        SET customer_config_hold_until = clock_timestamp() - interval '1 second'
                      WHERE deployment_id = $1",
            )
            .bind(deployment_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        if scenario == "released" {
            sqlx::query(
                "UPDATE deployment_apply_jobs
                        SET customer_config_released_at = clock_timestamp(),
                            next_attempt_at = clock_timestamp()
                      WHERE deployment_id = $1",
            )
            .bind(deployment_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        if scenario == "deleting" {
            sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
                .bind(app.id)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let result = supersede_incomplete_deployments(&mut tx, app.id).await;
        if blocked {
            assert!(matches!(result, Err(SupersedeDeploymentError::Busy)));
            let state: String = sqlx::query_scalar(
                "SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1",
            )
            .bind(deployment_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(state, "setup_pending");
        } else {
            assert_eq!(result.expect(scenario), 1);
        }
        tx.rollback().await.unwrap();
    }
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn workload_rollout_settled_reads_the_live_generation() {
    let converged = ApplyEngine::new(
        rollout_client(true),
        enclava_engine::apply::types::ApplyConfig::default(),
    );
    assert_eq!(
        workload_rollout_settled(&converged, "cap-queued-app", "queued-app")
            .await
            .expect("probe converged workload"),
        Some(true)
    );

    let converging = ApplyEngine::new(
        rollout_client(false),
        enclava_engine::apply::types::ApplyConfig::default(),
    );
    assert_eq!(
        workload_rollout_settled(&converging, "cap-queued-app", "queued-app")
            .await
            .expect("probe converging workload"),
        Some(false)
    );
}

#[tokio::test]
async fn workload_rollout_settled_rejects_an_unobserved_generation() {
    // observedGeneration behind metadata.generation: the controller has
    // not caught up to the newest applied spec yet, so the failed
    // rollout is still reconciling even though the replica counts look
    // ready. The probe must read both fields through the client.
    let lagging = ApplyEngine::new(
        rollout_client_with(3, 2, 1),
        enclava_engine::apply::types::ApplyConfig::default(),
    );
    assert_eq!(
        workload_rollout_settled(&lagging, "cap-queued-app", "queued-app")
            .await
            .expect("probe lagging workload"),
        Some(false)
    );
}

#[tokio::test]
async fn workload_rollout_settled_distinguishes_a_missing_workload() {
    use axum::http::{Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use tower::service_fn;

    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| async move {
            let _ = request.into_body().collect().await;
            let status = serde_json::json!({
                "apiVersion": "v1", "kind": "Status",
                "status": "Failure", "reason": "NotFound",
                "message": "absent", "code": 404,
            });
            Ok::<_, std::io::Error>(
                Response::builder()
                    .status(404)
                    .body(Body::from(serde_json::to_vec(&status).unwrap()))
                    .unwrap(),
            )
        }),
        "default",
    );
    let engine = ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default());
    assert_eq!(
        workload_rollout_settled(&engine, "cap-absent-app", "absent-app")
            .await
            .expect("probe missing workload"),
        None
    );
}

#[tokio::test]
async fn large_volume_initialization_keeps_observing_after_base_deadline() {
    // The recorded first-boot budget extends past the base deadline: 30
    // minutes into observation a fresh 2 Ti render is still watching.
    let app = queued_apply_app();
    let outcome = DeploymentRollout::observe_only(
        app,
        rollout_test_engine(),
        "initializing-manifest".to_string(),
        chrono::Utc::now() - chrono::Duration::minutes(30),
        fresh_initialization_budget("2Ti", "2Gi"),
    )
    .expect("valid rollout budget")
    .with_observation_slice(std::time::Duration::from_millis(50))
    .watch()
    .await;
    assert_eq!(outcome.deploy_status, "watching");
    assert_eq!(outcome.app_status, "creating");
    assert!(!outcome.terminal);
    assert_eq!(outcome.error_code, None);
}

/// Kubernetes API double for `ingress_restart_verdict`, including empty
/// pod lists and 404 responses for absent individual resources.
struct GateCluster {
    responses: std::collections::HashMap<String, (u16, serde_json::Value)>,
}

impl GateCluster {
    fn empty() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
        }
    }

    /// A live StatefulSet plus both claims created at a fixed timestamp.
    fn deployed(namespace: &str, workload: &str) -> Self {
        let mut cluster = Self::empty();
        cluster.put(
            format!("/apis/apps/v1/namespaces/{namespace}/statefulsets/{workload}"),
            200,
            serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {"name": workload, "namespace": namespace},
            }),
        );
        cluster.with_claims(namespace, workload, &["state", "tls-state"]);
        cluster.put(
            format!("/api/v1/namespaces/{namespace}/pods"),
            200,
            serde_json::json!({"apiVersion": "v1", "kind": "PodList", "items": []}),
        );
        cluster
    }

    fn with_claims(&mut self, namespace: &str, workload: &str, vcts: &[&str]) {
        for vct in vcts {
            let claim_name = format!("{vct}-{workload}-0");
            self.put(
                format!("/api/v1/namespaces/{namespace}/persistentvolumeclaims/{claim_name}"),
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": {
                        "name": claim_name,
                        "namespace": namespace,
                        "creationTimestamp": "2025-01-01T00:00:00Z",
                    },
                }),
            );
        }
    }

    /// Ordinal-0 pod created AFTER both claims (strict whole-second
    /// ordering satisfied), mounting both claims, with configurable
    /// readiness — a still-formatting initializer reports `ready=false`.
    fn with_pod(&mut self, namespace: &str, workload: &str, ready: bool) {
        let pod_name = format!("{workload}-0");
        let state_claim = format!("state-{workload}-0");
        let tls_claim = format!("tls-state-{workload}-0");
        let ready_status = if ready { "True" } else { "False" };
        let pod = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "namespace": namespace,
                    "creationTimestamp": "2025-01-01T00:01:00Z",
                },
                "spec": {
                    "containers": [],
                    "volumes": [
                        {"name": "state",
                         "persistentVolumeClaim": {"claimName": state_claim}},
                        {"name": "tls-state",
                         "persistentVolumeClaim": {"claimName": tls_claim}},
                    ],
                },
                "status": {
                    "conditions": [{
                        "type": "Ready",
                        "status": ready_status,
                    }],
                },
        });
        self.put(
            format!("/api/v1/namespaces/{namespace}/pods"),
            200,
            serde_json::json!({"apiVersion": "v1", "kind": "PodList", "items": [pod]}),
        );
    }

    fn put(&mut self, path: String, status: u16, body: serde_json::Value) {
        self.responses.insert(path, (status, body));
    }

    fn client(self) -> kube::Client {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let responses = self.responses.clone();
                async move {
                    let path = request.uri().path().to_string();
                    let _ = request.into_body().collect().await;
                    let (status, body) = responses.get(&path).cloned().unwrap_or_else(|| {
                        (
                            404,
                            serde_json::json!({
                                "apiVersion": "v1",
                                "kind": "Status",
                                "status": "Failure",
                                "reason": "NotFound",
                                "code": 404,
                                "message": format!("{path} not found"),
                            }),
                        )
                    });
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }
}

fn gate_engine(cluster: GateCluster) -> ApplyEngine {
    ApplyEngine::new(
        cluster.client(),
        enclava_engine::apply::types::ApplyConfig::default(),
    )
}

#[tokio::test]
async fn ingress_restart_not_deployed_without_statefulset() {
    // No StatefulSet: nothing to restart, so the predeploy verify keeps
    // its DNS-only path. The probe must not provision or wait.
    let engine = gate_engine(GateCluster::empty());
    let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
        .await
        .expect("404 StatefulSet lookup is a verdict, not an error");
    assert_eq!(verdict, IngressRestartVerdict::NotDeployed);
}

#[tokio::test]
async fn ingress_restart_ready_when_live_pod_proves_both_claims() {
    // Exact ordinal-0 Ready pod, created after both claims, mounting both:
    // the restart only re-opens initialized volumes under the base budget.
    let mut cluster = GateCluster::deployed("cap-app", "app");
    cluster.with_pod("cap-app", "app", true);
    let engine = gate_engine(cluster);
    let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
        .await
        .expect("live cluster proof must resolve");
    assert_eq!(verdict, IngressRestartVerdict::Ready);
}

#[tokio::test]
async fn ingress_restart_unproven_when_claim_missing() {
    // The tls-state claim is gone: a restart lands the replacement pod on
    // a never-formatted device under the base deadline — refuse, never
    // wait longer under the shared fences.
    let mut cluster = GateCluster::deployed("cap-app", "app");
    cluster.with_pod("cap-app", "app", true);
    cluster
        .responses
        .remove("/api/v1/namespaces/cap-app/persistentvolumeclaims/tls-state-app-0");
    let engine = gate_engine(cluster);
    let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
        .await
        .expect("live cluster proof must resolve");
    assert_eq!(verdict, IngressRestartVerdict::Unproven);
}

#[tokio::test]
async fn ingress_restart_unproven_while_initializer_not_ready() {
    // Live pod mounting both claims but not yet Ready: enclava-init may
    // still be scanning/formatting — a restart now could strand a
    // partially formatted volume.
    let mut cluster = GateCluster::deployed("cap-app", "app");
    cluster.with_pod("cap-app", "app", false);
    let engine = gate_engine(cluster);
    let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
        .await
        .expect("live cluster proof must resolve");
    assert_eq!(verdict, IngressRestartVerdict::Unproven);
}

#[tokio::test]
async fn ingress_restart_unproven_without_live_pod() {
    // Claims exist but the ordinal-0 pod is absent (evicted/scaled): no
    // live proof of completed initialization, fail closed.
    let cluster = GateCluster::deployed("cap-app", "app");
    let engine = gate_engine(cluster);
    let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
        .await
        .expect("live cluster proof must resolve");
    assert_eq!(verdict, IngressRestartVerdict::Unproven);
}

#[tokio::test]
async fn terminal_failed_deployment_cannot_admit_restart_of_live_unready_pod() {
    // A 'failed' deployment row is terminal — the DB guard passes it —
    // but the pod it left behind is still mid first-boot. The verdict
    // consults live cluster state only, so it must refuse regardless of
    // the recorded status.
    let pool = crate::test_support::database_test_pool().await;
    let (app, deployment_id, _, _) = crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
    sqlx::query("UPDATE deployments SET status = 'failed'::deploy_status_enum WHERE id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("record terminal deployment status");

    let mut cluster = GateCluster::deployed(&app.namespace, &app.name);
    cluster.with_pod(&app.namespace, &app.name, false);
    let engine = gate_engine(cluster);
    let verdict = ingress_restart_verdict(&engine, &app.namespace, &app.name)
        .await
        .expect("live cluster proof must resolve");
    assert_eq!(verdict, IngressRestartVerdict::Unproven);

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("clean up fixture");
}

/// Codex review on #243 (P2): a scope entry must use the workload-image
/// reference grammar. Tags, digests, URL schemes, and malformed path
/// components used to parse into scopes that can never equal the parsed
/// repository of a digest-pinned image, so startup succeeded but every
/// affected private workload silently lost its pull secret.
#[test]
fn tenant_image_pull_scope_rejects_image_reference_syntax_errors() {
    for invalid in [
        "ghcr.io/org/private:latest",
        "ghcr.io/org/private@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://ghcr.io/org/private",
        "ghcr.io/org//private",
        "ghcr.io//private",
        "ghcr.io/org/.",
        "ghcr.io/org/..",
        "org/private",
    ] {
        assert!(
            parse_image_pull_repository_scope(invalid).is_err(),
            "scope {invalid:?} must be rejected"
        );
    }
    // The generated pull secret only authenticates ghcr.io, so scopes at
    // any other registry are rejected instead of exposing the platform
    // token to workloads that cannot use it.
    for foreign in [
        "registry.example.com:5000/org/private",
        "registry.corp.example/team/private",
        "ghcr.io:443/org/private",
    ] {
        let error = parse_image_pull_repository_scope(foreign).unwrap_err();
        assert!(
            error.contains("ghcr.io"),
            "error should explain the ghcr.io binding: {error}"
        );
    }
    // Valid scopes — exact and wildcard — keep parsing unchanged.
    assert!(parse_image_pull_repository_scope("ghcr.io/org/private").is_ok());
    assert!(parse_image_pull_repository_scope("ghcr.io/org/private/*").is_ok());
}

/// Keep/remove decision gate (review findings on #243): a managed secret
/// stays only in an in-scope namespace, and only while it is the
/// configured name or still referenced by a generated ServiceAccount.
#[test]
fn keep_managed_pull_secret_gates_on_scope_name_and_references() {
    let mut referenced = BTreeSet::new();
    referenced.insert("old-name".to_string());

    // In scope: the configured name and still-referenced old names stay.
    assert!(keep_managed_pull_secret(
        true,
        "enclava-registry-auth",
        "enclava-registry-auth",
        &referenced
    ));
    assert!(keep_managed_pull_secret(
        true,
        "old-name",
        "enclava-registry-auth",
        &referenced
    ));
    // In scope: unreferenced residue (a renamed old secret) is removed.
    assert!(!keep_managed_pull_secret(
        true,
        "renamed-old",
        "enclava-registry-auth",
        &referenced
    ));
    // Out of scope: nothing managed stays, references or not.
    assert!(!keep_managed_pull_secret(
        false,
        "enclava-registry-auth",
        "enclava-registry-auth",
        &referenced
    ));
    assert!(!keep_managed_pull_secret(
        false,
        "old-name",
        "enclava-registry-auth",
        &referenced
    ));
}

/// In-memory Kubernetes API double for the pull-secret reconcile tests:
/// holds Secrets and ServiceAccounts and serves exactly the verbs the
/// reconcile path exercises (label-selected list, get, merge patch and
/// delete on Secrets; get and merge patch on ServiceAccounts).
/// `namespace_missing` models an app row whose namespace does not exist
/// yet (or is already gone) — every namespaced request 404s. The two
/// `replace_*` hooks model a tenant replacing the pull secret mid-cleanup
/// at the exact windows the review asked to be tested: as the
/// ServiceAccount patch lands, and as the delete lands.
///
/// A deploy that follows the sweep's generation check: after N named
/// Secret GETs, the next GET of `service_account` attaches `secret_name`
/// and stamps that secret with `generation`. The clear then reads this
/// latest ServiceAccount, so its own resourceVersion cannot tell the
/// scope decision is stale.
struct FreshReferenceAfterSecretGets {
    arm_after_named_secret_gets: u8,
    named_secret_gets: u8,
    armed: bool,
    service_account: String,
    secret_name: String,
    generation: i64,
}

#[derive(Default)]
struct FakeCluster {
    secrets: Vec<Secret>,
    service_accounts: Vec<ServiceAccount>,
    namespace_missing: bool,
    replace_on_sa_patch: Option<Secret>,
    replace_on_delete: Option<Secret>,
    /// Simulated same-object updates between the cleanup's ownership read
    /// and its pinned delete: each delete request first bumps the live
    /// secret's `resourceVersion` (same UID) this many times, forcing a
    /// 409 precondition conflict without replacing the object.
    rv_bumps_on_delete: u8,
    /// Fail ServiceAccount patches with a 500: the reference cleanup
    /// fails and the secret delete must be deferred (Codex review on
    /// #243, P2).
    sa_patch_fails: bool,
    /// Simulate a finalizer on the managed Secret: the accepted DELETE
    /// leaves the object present with a `deletionTimestamp` for this many
    /// subsequent GETs before it actually disappears (`u8::MAX` keeps it
    /// stuck forever). Acceptance is not removal (Codex review on #243,
    /// P2).
    delete_lingering_polls: u8,
    /// Scratch counter for `delete_lingering_polls` — GETs remaining
    /// before the finalizer releases the terminating Secret.
    lingering_polls_left: u8,
    /// Simulate a concurrent deploy rewriting the managed secret mid-
    /// cleanup: the first delete request annotates the live object (same
    /// UID) with a NEWER mutation generation — the self-check race on
    /// #243, where the rewrite that causes the 409 must not be deleted.
    annotate_generation_on_delete: Option<i64>,
    /// Stall every namespace GET far beyond the sweep's per-namespace
    /// budget: `namespace_absent` must fall through on its own timeout
    /// instead of hanging the sweep (review on #306).
    stall_namespace_gets: bool,
    /// Simulate a stalled API server (Codex review on #243, P1 follow-up):
    /// the label-selected Secret list hangs until the caller's per-
    /// namespace budget cancels it.
    stall_secrets_list: bool,
    /// Fail ServiceAccount patches that ADD an `imagePullSecrets` entry
    /// (reference restores) with a 500 this many times — the durable
    /// repair-intent path (Codex review on #243, P2): the clear succeeds,
    /// the delete finds a replacement, and the restore fails.
    fail_reference_restores: u8,
    /// Simulate perpetual resource-version contention on Secret writes
    /// (Codex review on #243, P2): every Secret PATCH and CREATE returns
    /// 409, driving the apply retry loop to exhaustion.
    secret_write_conflicts: bool,
    /// `fieldManager` query parameter of the most recent Secret POST, so
    /// tests can prove sweep-created secrets are attributed to the
    /// platform manager failure cleanup requires.
    last_secret_create_field_manager: Option<String>,
    /// Secret inserted when the next create POST arrives, which then
    /// returns 409. Models an older replica losing the create race to a
    /// newer scope rollout (Codex review on #276, P1).
    inject_secret_on_create: Option<Secret>,
    /// If set, every Secret GET returns this status instead of the object.
    secret_get_status: Option<u16>,
    /// Named Secret GETs return 404 this many times before the object
    /// becomes visible (Codex review on #280, P1 "Poll for the full
    /// late-commit window"): models a create still executing server-side
    /// past the client's first probes.
    secret_get_404s_left: u8,
    /// One-shot: the first N named Secret GETs of an ALREADY-STORED object
    /// fail with a 500 — models a transient apiserver error during
    /// ambiguity-recovery probing, without disturbing the apply's own
    /// pre-create read (Codex review on #280, round 3).
    fail_secret_gets_left: u8,
    /// Secret DELETEs hang without responding (Devin review on #280): the
    /// compensation path must fall out of the caller's recovery budget
    /// instead of holding the deploy's mutation guard and apply permit.
    stall_secret_deletes: bool,
    /// Secret DELETEs are accepted but remove nothing: the removal poll
    /// is the only notice the object survived (Codex review on #280, P1
    /// "Keep confirmed-create compensation armed until removal").
    noop_secret_deletes: bool,
    /// Count every Secret DELETE the fake routes (asserts that recovery
    /// re-attempted a compensation the apply itself never finished).
    secret_delete_attempts: u32,
    /// POST is accepted (object stored) and then the response FAILS with
    /// a transport error (Codex review on #280, P1 "Recover ambiguous
    /// POST transport failures before returning"): the create is as
    /// ambiguous as a timeout and must reach recovery.
    transport_error_after_accepting_secret_create: bool,
    /// Simulate a mutating admission webhook that strips
    /// RESOURCE_CREATED_BY_ANNOTATION from an ACCEPTED Secret create
    /// (Codex review on #243, round 2, P1): the stored/returned object
    /// carries every other annotation, so only the evidence verify
    /// path can catch it.
    strip_creation_evidence_on_create: bool,
    /// Webhook simulation (Codex review on #243, round 3, P1): the create
    /// is ACCEPTED but the field-manager attribution (`managedFields`)
    /// is dropped from the persisted object — the recreate path must
    /// detect an unattributable platform PAT and delete it.
    strip_field_manager_on_create: bool,
    /// Webhook simulation (Codex review on #278, P1): the create is
    /// ACCEPTED and the platform manager entry still exists, but the
    /// dedicated pull-secret LABEL is stripped (value and ownership) —
    /// the recreate path must detect an unmarked platform PAT and delete
    /// it instead of treating any manager entry as ownership.
    strip_pull_secret_label_on_create: bool,
    /// Override POST managedFields to model a webhook retaining the
    /// annotation value but moving its ownership to an untrusted entry.
    creation_managed_fields_override: Option<serde_json::Value>,
    /// Simulate a Kubernetes API that accepts a connection but stalls on
    /// NAMED Secret GETs (Codex review on #243, round 2, P1): the apply
    /// path's budget must defer instead of hanging the deploy's lease.
    stall_secret_gets: bool,
    /// POST is accepted (object stored) and then the response stalls until
    /// the caller's budget drops the future. Recovery must re-read the
    /// stored Secret rather than treating the timeout as "nothing landed".
    stall_after_accepting_secret_create: bool,
    /// Webhook strips the mutation-generation annotation from an accepted
    /// create or patch while leaving other fields intact.
    strip_mutation_generation_on_create: bool,
    strip_mutation_generation_on_patch: bool,
    /// After an accepted create, replace the mutation-generation value.
    /// Models another writer winning the name before our stalled POST is
    /// observed. Recovery must not compensate that object.
    replace_mutation_generation_on_create: Option<i64>,
    /// Deploy attaches a reference after the sweep's generation check.
    fresh_reference_after_secret_gets: Option<FreshReferenceAfterSecretGets>,
    /// One-shot: before answering a named Secret GET, raise the fleet
    /// rollout authority. Models a narrowing rollout that deleted the
    /// secret after this replica passed its pre-write check.
    raise_rollout_authority_on_secret_get: Option<(i64, i64)>,
    rollout_authority_pool: Option<PgPool>,
    /// When set, cluster-scoped Namespace GET/PATCH echo this mutation
    /// generation so deploy-path tests can pass `apply_namespace`.
    echo_namespace_generation: Option<i64>,
}

fn fake_managed_secret(name: &str, labeled: bool, username: &str, token: &str) -> Secret {
    use k8s_openapi::ByteString;
    let mut labels = std::collections::BTreeMap::new();
    if labeled {
        labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
        labels.insert(
            TENANT_PULL_SECRET_LABEL.to_string(),
            TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
        );
    }
    let docker_config = serde_json::json!({
        "auths": {
            "ghcr.io": { "username": username, "password": token }
        }
    });
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some("tenant-ns".to_string()),
            uid: Some(format!("uid-{name}")),
            resource_version: Some("1".to_string()),
            labels: if labels.is_empty() {
                None
            } else {
                Some(labels)
            },
            ..Default::default()
        },
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        data: Some(std::collections::BTreeMap::from([(
            ".dockerconfigjson".to_string(),
            ByteString(serde_json::to_vec(&docker_config).unwrap()),
        )])),
        ..Default::default()
    }
}

fn fake_service_account(name: &str, references: &[&str]) -> ServiceAccount {
    use k8s_openapi::api::core::v1::LocalObjectReference;
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some("tenant-ns".to_string()),
            uid: Some(format!("uid-{name}")),
            resource_version: Some("1".to_string()),
            ..Default::default()
        },
        image_pull_secrets: if references.is_empty() {
            None
        } else {
            Some(
                references
                    .iter()
                    .map(|name| LocalObjectReference {
                        name: (*name).to_string(),
                    })
                    .collect(),
            )
        },
        ..Default::default()
    }
}

fn reconcile_engine(cluster: Arc<Mutex<FakeCluster>>) -> ApplyEngine {
    use axum::http::{Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use tower::service_fn;

    let client = kube::Client::new(
        service_fn(move |request: Request<Body>| {
            let cluster = cluster.clone();
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let query = request.uri().query().map(str::to_string);
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let accept_then_stall = {
                    let state = cluster.lock().unwrap();
                    state.stall_after_accepting_secret_create
                        && method.as_str() == "POST"
                        && path.contains("/secrets")
                };
                if accept_then_stall {
                    let (status, value) = {
                        let mut state = cluster.lock().unwrap();
                        route_fake_cluster(
                            &mut state,
                            method.as_str(),
                            &path,
                            query.as_deref(),
                            &body,
                        )
                    };
                    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                    return Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(serde_json::to_vec(&value).unwrap()))
                            .unwrap(),
                    );
                }
                let accept_then_error = {
                    let state = cluster.lock().unwrap();
                    state.transport_error_after_accepting_secret_create
                        && method.as_str() == "POST"
                        && path.contains("/secrets")
                };
                if accept_then_error {
                    let _ = {
                        let mut state = cluster.lock().unwrap();
                        route_fake_cluster(
                            &mut state,
                            method.as_str(),
                            &path,
                            query.as_deref(),
                            &body,
                        )
                    };
                    return Err(std::io::Error::other(
                        "simulated transport failure after the create was accepted",
                    ));
                }
                // Stalled-API-server simulation (Codex review on #243, P1
                // follow-up): the label-selected Secret list hangs far
                // beyond the per-namespace reconcile budget, until the
                // caller's timeout cancels the request. The guard's scope
                // ends before the sleep so the future stays Send.
                let stall = {
                    let state = cluster.lock().unwrap();
                    let named_secret_get = method.as_str() == "GET"
                        && path.contains("/secrets/")
                        && !path.trim_end_matches('/').ends_with("/secrets");
                    let namespace_get = method.as_str() == "GET"
                        && path
                            .trim_start_matches('/')
                            .starts_with("api/v1/namespaces/")
                        && path
                            .trim_start_matches("/api/v1/namespaces/")
                            .trim_end_matches('/')
                            .find('/')
                            .is_none();
                    (state.stall_secrets_list
                            && method.as_str() == "GET"
                            && path.trim_end_matches('/').ends_with("/secrets"))
                            || (state.stall_secret_gets && named_secret_get)
                            || (state.stall_namespace_gets && namespace_get)
                            // A DELETE that never responds (Devin review on
                            // #280): only the caller's recovery budget can
                            // end this request.
                            || (state.stall_secret_deletes
                                && method.as_str() == "DELETE"
                                && path.contains("/secrets"))
                };
                if stall {
                    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                }
                let named_secret_get = method.as_str() == "GET"
                    && path.contains("/secrets/")
                    && !path.trim_end_matches('/').ends_with("/secrets");
                if named_secret_get {
                    let raise = {
                        let mut state = cluster.lock().unwrap();
                        state
                            .raise_rollout_authority_on_secret_get
                            .take()
                            .zip(state.rollout_authority_pool.clone())
                    };
                    if let Some(((scope_epoch, credential_epoch), pool)) = raise {
                        sqlx::query(
                            "UPDATE tenant_pull_secret_rollout_authority \
                                 SET max_scope_epoch = GREATEST(max_scope_epoch, $1), \
                                     max_credential_epoch = GREATEST(max_credential_epoch, $2)",
                        )
                        .bind(scope_epoch)
                        .bind(credential_epoch)
                        .execute(&pool)
                        .await
                        .expect("raise rollout authority from the fake");
                    }
                }
                let mut state = cluster.lock().unwrap();
                let (status, value) =
                    route_fake_cluster(&mut state, method.as_str(), &path, query.as_deref(), &body);
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(status)
                        .body(Body::from(serde_json::to_vec(&value).unwrap()))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default())
}

fn route_fake_cluster(
    state: &mut FakeCluster,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
) -> (u16, serde_json::Value) {
    fn not_found() -> (u16, serde_json::Value) {
        (
            404,
            serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404,
            }),
        )
    }
    fn conflict() -> (u16, serde_json::Value) {
        (
            409,
            serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "Conflict", "code": 409,
            }),
        )
    }
    if state.namespace_missing {
        // The namespace does not exist: every namespaced request is a 404
        // (Codex review on #243, P1).
        return not_found();
    }
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let (kind, name) = match segments.as_slice() {
        ["api", "v1", "namespaces", _, "secrets"] => ("secrets", None),
        ["api", "v1", "namespaces", _, "secrets", name] => ("secrets", Some(*name)),
        ["api", "v1", "namespaces", _, "serviceaccounts", name] => ("serviceaccounts", Some(*name)),
        ["api", "v1", "namespaces", name] => ("namespaces", Some(*name)),
        _ => return not_found(),
    };
    match (kind, method) {
        ("secrets", "GET") if name.is_none() => {
            // Label-selected list. `labelSelector=key=value` is compared
            // against each secret's labels.
            let selector = query
                .and_then(|query| {
                    query.split('&').find_map(|pair| {
                        let (key, value) = pair.split_once('=')?;
                        (key == "labelSelector").then(|| decode_query_component(value))
                    })
                })
                .unwrap_or_default();
            let items: Vec<serde_json::Value> = state
                .secrets
                .iter()
                .filter(|secret| {
                    selector.split(',').all(|requirement| {
                        let Some((key, value)) = requirement.split_once('=') else {
                            return false;
                        };
                        secret
                            .metadata
                            .labels
                            .as_ref()
                            .and_then(|labels| labels.get(key))
                            .map(String::as_str)
                            == Some(value)
                    })
                })
                .map(|secret| serde_json::to_value(secret).unwrap())
                .collect();
            (
                200,
                serde_json::json!({
                    "apiVersion": "v1", "kind": "SecretList",
                    "metadata": {}, "items": items,
                }),
            )
        }
        ("secrets", "GET") => {
            // Named-GET 404 countdown: the object is absent for the first
            // N named GETs — modeling a create still executing server-side
            // past the client's first probes (Codex review on #280).
            if state.secret_get_404s_left > 0 {
                state.secret_get_404s_left -= 1;
                return not_found();
            }
            if state.fail_secret_gets_left > 0 && !state.secrets.is_empty() {
                state.fail_secret_gets_left -= 1;
                return (
                    500,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "status": "Failure",
                        "reason": "InternalError", "code": 500,
                    }),
                );
            }
            if let Some(status) = state.secret_get_status {
                return (
                    status,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "status": "Failure",
                        "reason": "LookupFailed", "code": status,
                    }),
                );
            }
            if let Some(hook) = state.fresh_reference_after_secret_gets.as_mut() {
                hook.named_secret_gets = hook.named_secret_gets.saturating_add(1);
                if hook.named_secret_gets >= hook.arm_after_named_secret_gets {
                    hook.armed = true;
                }
            }
            let index = state
                .secrets
                .iter()
                .position(|secret| secret.metadata.name.as_deref() == name);
            let Some(index) = index else {
                return not_found();
            };
            // Finalizer simulation (Codex review on #243, P2): the
            // accepted delete left the object terminating; it stays
            // readable until the simulated finalizer releases it.
            if state.secrets[index].metadata.deletion_timestamp.is_some() {
                if state.lingering_polls_left > 0 {
                    state.lingering_polls_left -= 1;
                } else {
                    state.secrets.remove(index);
                    return not_found();
                }
            }
            (200, serde_json::to_value(&state.secrets[index]).unwrap())
        }
        ("secrets", "PATCH") => {
            if state.secret_write_conflicts {
                // Perpetual resource-version contention (Codex review on
                // #243, P2): every conditional write 409s.
                return conflict();
            }
            let patch: serde_json::Value = serde_json::from_slice(body).unwrap();
            let Some(secret) = state
                .secrets
                .iter_mut()
                .find(|secret| secret.metadata.name.as_deref() == name)
            else {
                return not_found();
            };
            if let Some(rv) = patch
                .pointer("/metadata/resourceVersion")
                .and_then(|rv| rv.as_str())
                && secret.metadata.resource_version.as_deref() != Some(rv)
            {
                return conflict();
            }
            if let Some(string_data) = patch.get("stringData").and_then(|value| value.as_object()) {
                let data = secret.data.get_or_insert_with(Default::default);
                for (key, value) in string_data {
                    data.insert(
                        key.clone(),
                        k8s_openapi::ByteString(value.as_str().unwrap().as_bytes().to_vec()),
                    );
                }
            }
            if let Some(labels) = patch
                .pointer("/metadata/labels")
                .and_then(|labels| labels.as_object())
            {
                let entry = secret.metadata.labels.get_or_insert_with(Default::default);
                for (key, value) in labels {
                    entry.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
                }
            }
            if let Some(annotations) = patch
                .pointer("/metadata/annotations")
                .and_then(|annotations| annotations.as_object())
            {
                let entry = secret
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default);
                for (key, value) in annotations {
                    entry.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
                }
            }
            // Credential-refresh writes (Codex review on #243, P1): the
            // data map carries base64-encoded `.dockerconfigjson`
            // payloads, exactly like the real API server.
            if let Some(data) = patch.pointer("/data").and_then(|data| data.as_object()) {
                use base64::Engine as _;
                let entry = secret.data.get_or_insert_with(Default::default);
                for (key, value) in data {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD
                        .decode(value.as_str().unwrap_or_default())
                    {
                        entry.insert(key.clone(), k8s_openapi::ByteString(bytes));
                    }
                }
            }
            if let Some(type_) = patch.get("type").and_then(|type_| type_.as_str()) {
                secret.type_ = Some(type_.to_string());
            }
            secret.metadata.resource_version = Some(format!(
                "{}-patch",
                secret.metadata.resource_version.as_deref().unwrap_or("1")
            ));
            if state.strip_mutation_generation_on_patch
                && let Some(annotations) = secret.metadata.annotations.as_mut()
            {
                annotations
                    .remove(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION);
            }
            (200, serde_json::to_value(secret).unwrap())
        }
        ("secrets", "POST") => {
            if state.secret_write_conflicts {
                return conflict();
            }
            if let Some(injected) = state.inject_secret_on_create.take() {
                if !state
                    .secrets
                    .iter()
                    .any(|secret| secret.metadata.name == injected.metadata.name)
                {
                    state.secrets.push(injected);
                }
                return conflict();
            }
            state.last_secret_create_field_manager = query.and_then(|query| {
                query.split('&').find_map(|pair| {
                    let (key, value) = pair.split_once('=')?;
                    (key == "fieldManager").then(|| decode_query_component(value))
                })
            });
            let mut created: Secret = serde_json::from_slice(body).unwrap();
            // A real API server records the request's fieldManager in
            // `managedFields` (Codex review on #243, round 3, P1): stamp
            // it so the recreate path's attribution verify can succeed —
            // and so the strip simulation below is the only way it fails.
            let field_manager = query.and_then(|query| {
                query.split('&').find_map(|pair| {
                    let (key, value) = pair.split_once('=')?;
                    (key == "fieldManager").then(|| decode_query_component(value))
                })
            });
            if let Some(manager) = field_manager
                && !state.strip_field_manager_on_create
            {
                created
                        .metadata
                        .managed_fields
                        .get_or_insert_with(Default::default)
                        .push(
                            k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry {
                                manager: Some(manager),
                                fields_type: Some("FieldsV1".to_string()),
                                fields_v1: Some(
                                    k8s_openapi::apimachinery::pkg::apis::meta::v1::FieldsV1(
                                        serde_json::json!({
                                            "f:metadata": {
                                                "f:annotations": created.metadata.annotations
                                                    .as_ref()
                                                    .into_iter()
                                                    .flat_map(|annotations| annotations.keys())
                                                    .map(|key| (format!("f:{key}"), serde_json::json!({})))
                                                    .collect::<serde_json::Map<_, _>>(),
                                                "f:labels": created.metadata.labels
                                                    .as_ref()
                                                    .into_iter()
                                                    .flat_map(|labels| labels.keys())
                                                    .map(|key| (format!("f:{key}"), serde_json::json!({})))
                                                    .collect::<serde_json::Map<_, _>>(),
                                            }
                                        }),
                                    ),
                                ),
                                ..Default::default()
                            },
                        );
            }
            if let Some(fields) = &state.creation_managed_fields_override {
                created.metadata.managed_fields =
                    Some(serde_json::from_value(fields.clone()).unwrap());
            }
            if state.strip_creation_evidence_on_create {
                // Webhook simulation (Codex review on #243, round 2, P1):
                // the create is ACCEPTED but the evidence annotation is
                // dropped from the persisted object.
                if let Some(annotations) = created.metadata.annotations.as_mut() {
                    annotations
                        .remove(enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION);
                }
            }
            if state.strip_pull_secret_label_on_create {
                // Webhook simulation (Codex review on #278, P1): the
                // create is ACCEPTED with the manager entry intact but
                // the dedicated label removed — from the object and from
                // the manager's owned paths.
                if let Some(labels) = created.metadata.labels.as_mut() {
                    labels.remove(TENANT_PULL_SECRET_LABEL);
                }
                for entry in created.metadata.managed_fields.iter_mut().flatten() {
                    if let Some(fields) = entry.fields_v1.as_mut()
                        && let Some(labels) = fields
                            .0
                            .pointer_mut("/f:metadata/f:labels")
                            .and_then(|labels| labels.as_object_mut())
                    {
                        labels.remove(&format!("f:{TENANT_PULL_SECRET_LABEL}"));
                    }
                }
            }
            if state
                .secrets
                .iter()
                .any(|secret| secret.metadata.name == created.metadata.name)
            {
                return conflict();
            }
            created.metadata.uid.get_or_insert_with(|| {
                format!("uid-{}", created.metadata.name.clone().unwrap_or_default())
            });
            created
                .metadata
                .resource_version
                .get_or_insert_with(|| "1".to_string());
            if state.strip_mutation_generation_on_create
                && let Some(annotations) = created.metadata.annotations.as_mut()
            {
                annotations
                    .remove(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION);
            }
            if let Some(generation) = state.replace_mutation_generation_on_create {
                created
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default)
                    .insert(
                        enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION
                            .to_string(),
                        generation.to_string(),
                    );
            }
            state.secrets.push(created);
            (
                201,
                serde_json::to_value(state.secrets.last().unwrap()).unwrap(),
            )
        }
        ("secrets", "DELETE") => {
            state.secret_delete_attempts += 1;
            if state.noop_secret_deletes {
                // Accepted, but nothing is removed: model a finalizer or
                // wedged API that keeps the object alive after DELETE
                // acceptance.
                return (
                    200,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200,
                    }),
                );
            }
            if let Some(replacement) = state.replace_on_delete.take() {
                // The tenant replaces the secret between the cleanup's
                // ownership check and its delete (review finding on #243).
                swap_secret(&mut state.secrets, replacement);
            }
            if let Some(generation) = state.annotate_generation_on_delete.take() {
                // A concurrent deploy rewrites the managed secret (same
                // UID) under a NEWER mutation generation mid-cleanup —
                // the self-check race on #243: the re-read after the 409
                // must keep it instead of deleting.
                if let Some(secret) = state
                    .secrets
                    .iter_mut()
                    .find(|secret| secret.metadata.name.as_deref() == name)
                {
                    secret
                        .metadata
                        .annotations
                        .get_or_insert_with(Default::default)
                        .insert(
                            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION
                                .to_string(),
                            generation.to_string(),
                        );
                    secret.metadata.resource_version = Some(format!("rv-rewritten-{generation}"));
                }
            }
            if state.rv_bumps_on_delete > 0 {
                // A concurrent writer updates the SAME managed secret
                // between the cleanup's ownership check and its delete:
                // only resourceVersion moves, and the pinned delete must
                // conflict without the object being replaced.
                state.rv_bumps_on_delete -= 1;
                if let Some(secret) = state
                    .secrets
                    .iter_mut()
                    .find(|secret| secret.metadata.name.as_deref() == name)
                {
                    secret.metadata.resource_version =
                        Some(format!("rv-bumped-{}", state.rv_bumps_on_delete));
                }
            }
            let index = state
                .secrets
                .iter()
                .position(|secret| secret.metadata.name.as_deref() == name);
            let Some(index) = index else {
                return not_found();
            };
            // Preconditions mirror the API server: a stale uid or
            // resourceVersion must conflict instead of deleting.
            let delete_options: serde_json::Value = serde_json::from_slice(body).unwrap();
            let preconditions = delete_options.pointer("/preconditions");
            let live = &state.secrets[index];
            if let Some(preconditions) = preconditions {
                let uid = preconditions.get("uid").and_then(|uid| uid.as_str());
                let resource_version = preconditions
                    .get("resourceVersion")
                    .and_then(|rv| rv.as_str());
                let uid_mismatch = uid.is_some_and(|uid| live.metadata.uid.as_deref() != Some(uid));
                let rv_mismatch = resource_version
                    .is_some_and(|rv| live.metadata.resource_version.as_deref() != Some(rv));
                if uid_mismatch || rv_mismatch {
                    return conflict();
                }
            }
            if state.lingering_polls_left == 0 && state.delete_lingering_polls == 0 {
                state.secrets.remove(index);
            } else {
                // Finalizer simulation: the delete is accepted but the
                // object lingers, terminating, until the poll budget in
                // the GET handler releases it.
                if state.lingering_polls_left == 0 {
                    state.lingering_polls_left = state.delete_lingering_polls;
                }
                state.secrets[index].metadata.deletion_timestamp =
                    Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    ));
            }
            (
                200,
                serde_json::json!({
                    "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200,
                }),
            )
        }
        ("serviceaccounts", "GET") => {
            if let Some(hook) = state.fresh_reference_after_secret_gets.as_ref()
                && hook.armed
                && name == Some(hook.service_account.as_str())
            {
                let secret_name = hook.secret_name.clone();
                let generation = hook.generation;
                let account_name = hook.service_account.clone();
                state.fresh_reference_after_secret_gets = None;
                if let Some(secret) = state
                    .secrets
                    .iter_mut()
                    .find(|secret| secret.metadata.name.as_deref() == Some(secret_name.as_str()))
                {
                    secret
                        .metadata
                        .annotations
                        .get_or_insert_with(Default::default)
                        .insert(
                            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION
                                .to_string(),
                            generation.to_string(),
                        );
                }
                if let Some(account) = state
                    .service_accounts
                    .iter_mut()
                    .find(|account| account.metadata.name.as_deref() == Some(account_name.as_str()))
                {
                    use k8s_openapi::api::core::v1::LocalObjectReference;
                    let references = account.image_pull_secrets.get_or_insert_with(Vec::new);
                    if !references
                        .iter()
                        .any(|reference| reference.name == secret_name)
                    {
                        references.push(LocalObjectReference { name: secret_name });
                    }
                    account.metadata.resource_version = Some("fresh-deploy".to_string());
                }
            }
            match state
                .service_accounts
                .iter()
                .find(|account| account.metadata.name.as_deref() == name)
            {
                Some(account) => (200, serde_json::to_value(account).unwrap()),
                None => not_found(),
            }
        }
        ("serviceaccounts", "PATCH") => {
            if state.sa_patch_fails {
                // Codex review on #243 (P2): the ServiceAccount patch
                // transiently fails, so the reference cleanup fails and
                // the secret delete must be deferred.
                return (
                    500,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "status": "Failure",
                        "reason": "InternalError", "code": 500,
                    }),
                );
            }
            if let Some(replacement) = state.replace_on_sa_patch.take() {
                // The tenant replaces the secret between the cleanup's
                // ownership read and its ServiceAccount patch — the exact
                // window the review asked to be tested (review finding on
                // #243).
                swap_secret(&mut state.secrets, replacement);
            }
            let patch: serde_json::Value = serde_json::from_slice(body).unwrap();
            let Some(account) = state
                .service_accounts
                .iter_mut()
                .find(|account| account.metadata.name.as_deref() == name)
            else {
                return not_found();
            };
            if let Some(references) = patch.get("imagePullSecrets") {
                use k8s_openapi::api::core::v1::LocalObjectReference;
                // A patch whose reference list is LONGER than the live one
                // is a restore (it adds an entry); a shorter/null one is a
                // clear. `fail_reference_restores` fails restores — the
                // durable repair-intent window (Codex review on #243, P2).
                let is_restore = references.as_array().is_some_and(|patched| {
                    patched.len()
                        > account
                            .image_pull_secrets
                            .as_ref()
                            .map_or(0, |live| live.len())
                });
                if is_restore && state.fail_reference_restores > 0 {
                    state.fail_reference_restores -= 1;
                    return (
                        500,
                        serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "reason": "InternalError", "code": 500,
                        }),
                    );
                }
                account.image_pull_secrets = references.as_array().map(|references| {
                    references
                        .iter()
                        .map(|reference| LocalObjectReference {
                            name: reference
                                .get("name")
                                .and_then(|name| name.as_str())
                                .unwrap_or_default()
                                .to_string(),
                        })
                        .collect()
                });
            }
            if let Some(annotations) = patch
                .pointer("/metadata/annotations")
                .and_then(|annotations| annotations.as_object())
            {
                let entry = account
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default);
                for (key, value) in annotations {
                    if value.is_null() {
                        entry.remove(key);
                    } else {
                        entry.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
                    }
                }
            }
            (200, serde_json::to_value(account).unwrap())
        }
        ("namespaces", "GET" | "PATCH") => {
            let Some(generation) = state.echo_namespace_generation else {
                return not_found();
            };
            let name = name.unwrap_or("namespace");
            (
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": name,
                        "uid": format!("uid-{name}"),
                        "resourceVersion": "1",
                        "annotations": {
                            "enclava.dev/cap-provider-mutation-generation": generation.to_string(),
                        }
                    }
                }),
            )
        }
        _ => not_found(),
    }
}

fn decode_query_component(raw: &str) -> String {
    raw.replace("%3D", "=")
        .replace("%2F", "/")
        .replace("%2C", ",")
}

/// Replace (or insert) a secret by name — models a tenant replacing the
/// pull secret between two of the cleanup's requests.
fn swap_secret(secrets: &mut Vec<Secret>, replacement: Secret) {
    let name = replacement.metadata.name.clone();
    secrets.retain(|secret| secret.metadata.name != name);
    secrets.push(replacement);
}

fn expected_dockerconfigjson(username: &str, token: &str) -> String {
    use base64::Engine as _;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
    serde_json::json!({
        "auths": {
            "ghcr.io": { "username": username, "password": token, "auth": auth }
        }
    })
    .to_string()
}

fn reconcile_settings() -> PullSecretSettings {
    let ghcr_credentials = Some(("cap-bot".to_string(), "ghp_platform".to_string()));
    let configured_secret_data = ghcr_credentials
        .as_ref()
        .map(|(username, token)| expected_dockerconfigjson(username, token));
    PullSecretSettings {
        configured_name: "enclava-registry-auth".to_string(),
        ghcr_credentials,
        configured_secret_data,
    }
}

/// Devin review on #243 (BUG_…​_0002): an unlabeled secret holding a
/// tenant's OWN GHCR credentials under the managed name is not
/// CAP-generated. The sweep keeps it, so it must also keep the
/// ServiceAccount reference to it — clearing the reference would strip
/// the tenant's pods of their private-registry credentials.
#[tokio::test]
async fn reconcile_keeps_tenant_owned_look_alike_and_its_reference() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![
            // The tenant's own pull secret under the configured name,
            // carrying the tenant's own credentials.
            fake_managed_secret(
                "enclava-registry-auth",
                false,
                "tenant-user",
                "tenant-token",
            ),
        ],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1, "tenant-owned secret must survive");
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "tenant-owned reference must survive"
    );
}

/// Codex review on #243 (P1, "sweep all previously managed pull-secret
/// names"): a secret created under an older TENANT_IMAGE_PULL_SECRET_NAME
/// is discovered by its managed label and removed — with its
/// ServiceAccount references — even though the current configuration
/// generates a different name. While a generated ServiceAccount still
/// references it, it is kept until the workload redeploys (the documented
/// convergence order).
#[tokio::test]
async fn reconcile_removes_renamed_managed_secrets_and_clears_references() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform"),
            // Created before TENANT_IMAGE_PULL_SECRET_NAME was renamed;
            // still labeled, no longer referenced by the workload.
            fake_managed_secret("pull-secret-old-name", true, "cap-bot", "ghp_old_token"),
        ],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth", "pull-secret-old-name"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());

    // In-scope with the old name still referenced: kept until redeploy.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            2,
            "referenced old secret stays in scope"
        );
    }

    // Post-redeploy: the workload now references only the new name. The
    // unreferenced old secret is removed by name-independent discovery.
    cluster.lock().unwrap().service_accounts[0].image_pull_secrets =
        Some(vec![k8s_openapi::api::core::v1::LocalObjectReference {
            name: "enclava-registry-auth".to_string(),
        }]);
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    {
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(
            state.secrets[0].metadata.name.as_deref(),
            Some("enclava-registry-auth")
        );
    }

    // Out of scope: the referenced old secret is removed together with
    // its reference, while the current name is removed too.
    cluster.lock().unwrap().secrets.push(fake_managed_secret(
        "pull-secret-old-name",
        true,
        "cap-bot",
        "ghp_old_token",
    ));
    cluster.lock().unwrap().service_accounts[0].image_pull_secrets = Some(vec![
        k8s_openapi::api::core::v1::LocalObjectReference {
            name: "enclava-registry-auth".to_string(),
        },
        k8s_openapi::api::core::v1::LocalObjectReference {
            name: "pull-secret-old-name".to_string(),
        },
    ]);
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    {
        let state = cluster.lock().unwrap();
        assert!(state.secrets.is_empty(), "out-of-scope secrets are removed");
        assert!(
            state.service_accounts[0].image_pull_secrets.is_none(),
            "managed references are cleared out of scope"
        );
    }
}

/// Codex review on #243 (P1, "adopt legacy secrets before skipping
/// in-scope namespaces"): in an in-scope namespace a pre-label secret is
/// adopted (labeled) while its credentials still prove the generated
/// shape — before any in-scope skip — so the documented upgrade-then-
/// rotate sequence cannot orphan it when the GHCR token is later rotated.
#[tokio::test]
async fn reconcile_adopts_kept_legacy_secrets_in_scope() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![
            // Pre-label (unlabeled) legacy secret whose shape matches the
            // configured GHCR pair.
            fake_managed_secret("enclava-registry-auth", false, "cap-bot", "ghp_platform"),
        ],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    let labels = state.secrets[0].metadata.labels.as_ref().unwrap();
    assert_eq!(
        labels.get(TENANT_PULL_SECRET_LABEL).map(String::as_str),
        Some(TENANT_PULL_SECRET_LABEL_VALUE),
        "kept legacy secret must carry the dedicated pull-secret label (discovery marker)"
    );
    assert_eq!(
        labels.get(MANAGED_BY_LABEL).map(String::as_str),
        Some(MANAGED_BY_VALUE),
        "kept legacy secret must carry the managed-by ownership label"
    );
}

/// A tenant's own replacement secret under the managed name: a distinct
/// object (own UID/resourceVersion) with the tenant's credentials.
fn fake_replacement_secret(name: &str) -> Secret {
    let mut secret = fake_managed_secret(name, false, "tenant-user", "tenant-token");
    secret.metadata.uid = Some(format!("uid-replacement-{name}"));
    secret.metadata.resource_version = Some("42".to_string());
    secret
}

/// Devin review on #243 (BUG_…​_0001): a tenant that replaces the managed
/// pull secret after the cleanup's ownership read must keep both the
/// replacement and its ServiceAccount reference. The replacement lands in
/// the exact reviewed window — between the first Secret GET and the
/// ServiceAccount patch — and the delete that later detects it must
/// reverse the reference clear so the replacement's pods keep registry
/// access.
#[tokio::test]
async fn reconcile_restores_reference_when_secret_replaced_mid_cleanup() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The tenant swaps in their own secret right as the reference
        // clear is written.
        replace_on_sa_patch: Some(fake_replacement_secret("enclava-registry-auth")),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].metadata.uid.as_deref(),
        Some("uid-replacement-enclava-registry-auth"),
        "the tenant replacement must survive"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the replacement keeps the ServiceAccount reference it inherits by name"
    );
}

/// Devin review on #243 (BUG_…​_0001), second window: a replacement that
/// lands between the delete's ownership read and the delete itself must
/// survive — the delete is pinned to the verified object's
/// UID/resourceVersion — and its ServiceAccount reference must survive
/// with it.
#[tokio::test]
async fn reconcile_never_deletes_a_replacement_that_lands_at_delete_time() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        replace_on_delete: Some(fake_replacement_secret("enclava-registry-auth")),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].metadata.uid.as_deref(),
        Some("uid-replacement-enclava-registry-auth"),
        "the pinned delete must conflict instead of deleting the replacement"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the cleared reference must be restored for the replacement"
    );
}

/// Codex review on #243 (P2, "require the pull-secret label before
/// treating secrets as owned"): the generic managed-by label is used
/// broadly across platform resources and must not make an arbitrary
/// Secret fair game for this cleanup. Ownership requires the dedicated
/// pull-secret label or the legacy credential-shape proof — a
/// generically-labeled secret with foreign contents at the managed name
/// is tenant/operator-owned and must keep itself and its reference.
#[tokio::test]
async fn reconcile_keeps_generic_managed_by_look_alike() {
    use std::sync::{Arc, Mutex};

    let mut secret = fake_managed_secret(
        "enclava-registry-auth",
        false,
        "tenant-user",
        "tenant-token",
    );
    secret.metadata.labels = Some(std::collections::BTreeMap::from([(
        MANAGED_BY_LABEL.to_string(),
        MANAGED_BY_VALUE.to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "a generic-managed-by look-alike is not CAP's pull secret"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the generic-managed-by look-alike keeps its ServiceAccount reference"
    );
}

/// Codex review on #243 (P1, "treat missing tenant namespaces as an
/// already-clean sweep"): an app row can exist before its namespace is
/// created, or outlive the namespace after deletion, and the namespaced
/// Secret list then 404s. The sweep must treat that as "no stale
/// secrets" — a failure here would keep workload admission closed and
/// the dispatcher unspawned while the very pending setup/cleanup work
/// that would create the namespace or remove the row can never run, and
/// the background retry would loop on the same 404 forever.
#[tokio::test]
async fn reconcile_treats_missing_namespace_as_clean() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        namespace_missing: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        converged,
        "a missing namespace is an already-clean sweep, not a failure"
    );
}

/// #305: the discovery 404 path above only covers out-of-scope
/// namespaces — an IN-scope app whose namespace is absent drives the
/// configured-secret ensure into the same 404 and wedges admission. The
/// sweep now skips absent namespaces before any reconcile (#305), and
/// `namespace_absent` is the gate: true only on an explicit NotFound,
/// false whenever the namespace answers (or the API server errors — that
/// falls through to the reconcile, preserving today's behavior).
#[tokio::test]
async fn namespace_absent_is_true_only_on_explicit_not_found() {
    use std::sync::{Arc, Mutex};

    let missing = Arc::new(Mutex::new(FakeCluster {
        namespace_missing: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(missing);
    assert!(
        namespace_absent(&engine, "gone-ns", PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT).await,
        "a namespace the API server answers NotFound for is absent"
    );

    let live = Arc::new(Mutex::new(FakeCluster {
        echo_namespace_generation: Some(7),
        ..Default::default()
    }));
    let engine = reconcile_engine(live);
    assert!(
        !namespace_absent(&engine, "live-ns", PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT).await,
        "a namespace that answers is not absent"
    );
}

/// Review on #306: a stalled API server must not hang the sweep on the
/// probe — the bounded GET falls through (treated as not-absent) and the
/// budgeted reconcile decides.
#[tokio::test(start_paused = true)]
async fn namespace_absent_falls_through_when_the_probe_stalls() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_namespace_gets: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster);
    assert!(
        !namespace_absent(&engine, "any-ns", PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT).await,
        "a stalled probe must fall through to the reconcile path instead of hanging"
    );
}

/// Codex review on #306 (P2): the probe and the reconciliation share ONE
/// per-namespace deadline — an exhausted budget must not buy a second
/// full window. With the namespace budget already spent, a stalled probe
/// and a stalled reconcile both fall through immediately (no fresh
/// 180 s window each), so a namespace can never cost more than one
/// budget per sweep pass.
#[tokio::test(start_paused = true)]
async fn exhausted_shared_budget_does_not_buy_a_second_window() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_namespace_gets: true,
        stall_secrets_list: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster);

    let started = tokio::time::Instant::now();
    assert!(
        !namespace_absent(&engine, "any-ns", std::time::Duration::ZERO).await,
        "an exhausted budget makes the probe fall through without a fresh window"
    );
    let converged = sweep_namespace_with_budget(
        &engine,
        "any-ns",
        &[],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
        std::time::Duration::ZERO,
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "an exhausted budget reports the namespace unconverged, not converged"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "both steps must fall through immediately: the shared budget is one window, not one per step"
    );
}

/// Self-check blocking finding on #243 ("a delete conflict is treated as
/// a clean removal"): Kubernetes 409s both for a replaced object and for
/// the SAME managed secret merely updated between the ownership read and
/// the pinned delete. A same-object conflict must be retried — the secret
/// is still CAP's — and the sweep must still converge and remove the
/// token once the concurrent writer settles.
#[tokio::test(start_paused = true)]
async fn delete_retries_same_object_conflicts_until_the_writer_settles() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // A concurrent writer updates the SAME managed secret before each
        // of the first two delete attempts; the third attempt settles.
        rv_bumps_on_delete: 2,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
    )
    .await
    .unwrap();
    assert!(
        converged,
        "a same-object resourceVersion conflict is retried, not reported as a replacement"
    );

    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "the managed secret must be removed once the writer settles"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len())
            .unwrap_or(0),
        0,
        "a converged removal keeps the ServiceAccount reference cleared"
    );
}

/// The complement of the retry case: when the same managed secret keeps
/// changing under the delete and the bounded retries never settle, the
/// sweep must NOT report a clean removal (that is what let admission open
/// while the platform PAT stayed out), the error path must restore the
/// cleared references, and the live object must survive untouched.
#[tokio::test(start_paused = true)]
async fn persistent_same_object_conflicts_stay_closed_and_restore_references() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The writer never settles: every one of the bounded retry
        // budget's attempts conflicts (u8::MAX outlasts the budget).
        rv_bumps_on_delete: u8::MAX,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a sweep that cannot delete the managed secret must not report success"
    );

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "the managed secret must survive the conflicting deletes"
    );
    assert_eq!(
        state.secrets[0].metadata.uid.as_deref(),
        Some("uid-enclava-registry-auth"),
        "no attempt may have deleted or replaced the object"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        None,
        "ambiguous delete leaves the reference cleared until the next sweep"
    );
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[0]).len(),
        1
    );
}

/// Codex review on #243 (P2, "defer secret deletion when reference
/// cleanup fails"): a failed ServiceAccount patch must defer the Secret
/// delete — deleting it anyway would strand a dangling
/// `imagePullSecrets` reference the next sweep can no longer discover.
/// The pass reports non-convergence, the secret survives, and its
/// reference stays attached.
#[tokio::test]
async fn reconcile_defers_delete_when_reference_cleanup_fails() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        sa_patch_fails: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a failed reference cleanup must keep the pass unconverged"
    );

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "the secret must survive so the reference cleanup can be retried"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "no dangling reference: the failed patch left the reference in place"
    );
}

/// Codex review on #243 (P1, Devin SEC — "fence background cleanup
/// against concurrent deploys"): a sweep whose app-inventory snapshot
/// predates a deploy must not delete the pull secret that deploy applied.
/// The secret carries a mutation-generation annotation newer than the
/// generation the sweep snapshotted before its inventory read; the
/// reconcile pass skips it together with its ServiceAccount references.
#[tokio::test]
async fn sweep_skips_secrets_from_newer_mutation_generations() {
    use std::sync::{Arc, Mutex};

    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret.metadata.annotations = Some(std::collections::BTreeMap::from([(
        enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
        "7".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    // The sweep snapshotted generation 5; the live secret carries 7 — a
    // deploy the sweep's inventory never saw. Out-of-scope inventory, but
    // the newer generation wins.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(!converged, "a deferred secret must keep admission closed");

    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "a secret applied by a newer mutation generation must survive the stale sweep"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "its ServiceAccount reference must survive with it"
        );
    }

    // A sweep whose snapshot INCLUDES that generation (snapshot >= 7)
    // proceeds with the removal — the fence only protects secrets newer
    // than the snapshot.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 7,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "once the snapshot includes the generation, the stale secret is removed"
    );
}

/// Self-check on #243: a deploy rewrites the managed secret under a NEWER
/// mutation generation AFTER the reconcile-time skip check — the rewrite
/// that causes the delete's 409. The delete-loop re-read must keep the
/// rewritten secret and restore the already-cleared ServiceAccount
/// reference instead of deleting it.
#[tokio::test(start_paused = true)]
async fn delete_keeps_secret_rewritten_under_newer_generation_mid_cleanup() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The rewrite lands on the FIRST delete attempt: the pinned
        // delete conflicts, and the retry's re-read sees generation 9 —
        // newer than the sweep's snapshot of 5.
        annotate_generation_on_delete: Some(9),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "keeping a concurrently rewritten secret must defer convergence"
    );

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "a secret rewritten under a newer mutation generation mid-cleanup must survive"
    );
    assert_eq!(
        state.secrets[0]
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| {
                annotations.get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
            })
            .map(String::as_str),
        Some("9"),
        "the surviving object is the deploy's rewrite, not the original"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the cleared ServiceAccount reference must be restored for the rewrite"
    );
}

// Equal active generations must also survive a write after the precheck.
#[tokio::test(start_paused = true)]
async fn delete_keeps_secret_rewritten_under_equal_active_generation_mid_cleanup() {
    use std::sync::{Arc, Mutex};

    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    // The precheck now fail-closes on a missing marker while the lease is
    // held, so this race starts from an older parsable generation that the
    // precheck allows through. The deploy rewrite to the equal active
    // generation lands on the delete itself.
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "4".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The rewrite lands on the FIRST delete attempt: the pinned
        // delete conflicts, and the retry's re-read sees generation 5 —
        // equal to the active sweep snapshot of 5.
        annotate_generation_on_delete: Some(5),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: true,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "keeping a concurrently rewritten secret must defer convergence"
    );

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "a secret rewritten under an equal active mutation generation mid-cleanup must survive"
    );
    assert_eq!(
        state.secrets[0]
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| {
                annotations.get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
            })
            .map(String::as_str),
        Some("5"),
        "the surviving object is the deploy's rewrite, not the original"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the cleared ServiceAccount reference must be restored for the rewrite"
    );
}

/// Codex review on #243 (P2, "wait for Secret deletion to converge"): an
/// accepted DELETE with a finalizer keeps the Secret readable with a
/// deletionTimestamp. The removal must wait for the actual 404 (bounded),
/// and only then report Deleted — the ServiceAccount references stay
/// cleared because the token is provably gone.
#[tokio::test(start_paused = true)]
async fn delete_waits_for_finalizer_to_release_the_secret() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The finalizer holds the terminating secret for two polls, then
        // releases it.
        delete_lingering_polls: 2,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        converged,
        "a finalizer that releases within the poll budget converges"
    );

    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "Deleted may only be reported once the secret is actually gone"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len())
            .unwrap_or(0),
        0,
        "references stay cleared once removal provably converged"
    );
}

/// Codex review on #243 (P2), stuck-finalizer complement: when the
/// terminating Secret never disappears within the bounded poll deadline,
/// the removal must report failure (not Deleted), the pass stays
/// unconverged, and the cleared ServiceAccount references are restored so
/// the still-readable secret stays attached while the sweep retries.
#[tokio::test(start_paused = true)]
async fn stuck_finalizer_keeps_the_sweep_unconverged_and_restores_references() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The finalizer never releases the terminating secret.
        delete_lingering_polls: u8::MAX,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a stuck finalizer must keep the sweep unconverged (PAT still readable)"
    );

    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "the terminating-but-present secret is still in the fake cluster"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        None,
        "ambiguous finalizer delay leaves the reference cleared with repair intent"
    );
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[0]).len(),
        1
    );
}

#[tokio::test]
async fn scoped_deploy_updates_existing_secret_with_version_fence() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_old",
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_new".to_string(),
        allowed_repositories: Vec::new(),
    };
    apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(2).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0]
            .data
            .as_ref()
            .unwrap()
            .get(".dockerconfigjson")
            .unwrap()
            .0,
        expected_dockerconfigjson("cap-bot", "ghp_new").into_bytes()
    );
    assert_eq!(secret_mutation_generation(&state.secrets[0]), Some(2));
}

/// Codex review on #243, P1: the raw create POST must stamp
/// `RESOURCE_CREATED_BY_ANNOTATION` exactly like the engine's
/// applied-resource path, or the adopted-namespace compensating sweep
/// (`classify_generation_leftover`) classifies the new Secret as foreign,
/// skips deletion, and the periodic sweep keeps refreshing the platform
/// PAT in the tenant namespace forever.
#[tokio::test]
async fn scoped_deploy_created_secret_carries_creation_evidence() {
    use enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION;
    let cluster = Arc::new(Mutex::new(FakeCluster::default()));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_new".to_string(),
        allowed_repositories: Vec::new(),
    };
    apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(4).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.secrets[0]
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION)),
        Some(&"4".to_string()),
        "the create POST must stamp creation evidence"
    );
    assert!(
        enclava_engine::apply::generation::annotation_owned_by_manager(
            &state.secrets[0],
            RESOURCE_CREATED_BY_ANNOTATION,
            &engine.config().field_manager,
        ),
        "cleanup must be able to attribute the creation marker to CAP"
    );
}

/// Codex review on #243, P2: resource-version contention between each GET
/// and conditional patch is transient — an exhausted retry budget must
/// defer (requeueable) instead of terminally failing the deployment.
#[tokio::test]
async fn scoped_deploy_apply_conflict_exhaustion_defers_instead_of_failing() {
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_old",
        )],
        secret_write_conflicts: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_new".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(2).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "exhausted apply conflicts must defer, got {error:?}"
    );
}

#[tokio::test]
async fn old_replica_deploy_cannot_overwrite_newer_credential_epoch() {
    use std::sync::{Arc, Mutex};
    let mut live = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_new");
    live.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION.to_string(),
            u64::MAX.to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![live],
        ..Default::default()
    }));
    let before = cluster.lock().unwrap().secrets[0].data.clone();
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_old".to_string(),
        allowed_repositories: Vec::new(),
    };
    assert!(
        apply_scoped_pull_secret(
            &engine,
            "tenant-ns",
            &config,
            MutationGeneration::new(2).unwrap(),
            &[],
            None,
        )
        .await
        .is_err()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets[0].data, before);
}

#[test]
fn newer_rotation_generation_fences_stale_replica_refresh() {
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "new-token");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION.to_string(),
            "18446744073709551615".to_string(),
        );
    assert!(newer_pull_secret_credentials(&secret));
}

/// Codex review on #243 (P1, "refresh kept pull secrets after credential
/// rotation"): a labeled configured-name secret in an in-scope namespace
/// still carrying the PRE-rotation platform PAT is reconciled to the
/// current GHCR pair — no redeploy needed — and a secret already carrying
/// the current pair is left byte-identical (idempotence).
#[tokio::test]
async fn reconcile_refreshes_rotated_credentials_of_kept_configured_secret() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_stale_pre_rotation_token",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);

    let assert_live_token = |token: &str| {
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1, "the kept secret survives");
        let payload = &state.secrets[0]
            .data
            .as_ref()
            .unwrap()
            .get(".dockerconfigjson")
            .unwrap()
            .0;
        let config: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(
            config
                .pointer("/auths/ghcr.io/password")
                .and_then(|v| v.as_str()),
            Some(token),
            "the live secret must carry the expected credential"
        );
        assert_eq!(
            config
                .pointer("/auths/ghcr.io/username")
                .and_then(|v| v.as_str()),
            Some("cap-bot")
        );
    };

    // The rotation reached the namespace without a redeploy.
    assert_live_token("ghp_platform");

    // Idempotence: a second pass finds the current pair and rewrites
    // nothing (still converged, still the current pair).
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    assert_live_token("ghp_platform");
}

/// Codex review on #243 (P1, follow-up "let oversized cleanup sweeps make
/// forward progress"): one namespace's stalled reconciliation consumes its
/// own per-namespace budget and is reported unconverged — a bounded
/// failure, not a cancelled sweep — and once the API server recovers the
/// next attempt reconciles the same namespace to convergence. Every
/// namespace is visited on every attempt, so the tail can no longer be
/// starved by a slow head.
#[tokio::test(start_paused = true)]
async fn stalled_namespace_is_bounded_and_the_next_attempt_recovers() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        stall_secrets_list: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());

    // The stalled list hangs far beyond the per-namespace budget: the
    // budget converts the hang into "this namespace not converged".
    let converged = sweep_namespace_with_budget(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a stalled namespace is reported unconverged, not left hanging"
    );

    // Recovery: the API server answers again and the same namespace
    // reconciles — the sweep retries per namespace instead of restarting
    // a doomed whole pass forever.
    cluster.lock().unwrap().stall_secrets_list = false;
    let converged = sweep_namespace_with_budget(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
    )
    .await
    .unwrap();
    assert!(converged);
    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "the recovered attempt completes the removal"
    );
}

/// Codex review on #243 (P2, "persist failed pull-secret reference
/// restorations"): the reference clear writes durable repair intent onto
/// the ServiceAccount; when the delete then discovers a tenant
/// replacement AND the restoration fails transiently, the pass is
/// unconverged — and the NEXT pass still knows about the cleared
/// reference, restores it onto the surviving replacement, and discharges
/// the intent. Convergence is only reported once the ServiceAccount is
/// re-attached (the exact detachment the finding described).
#[tokio::test]
async fn failed_reference_restore_is_repaired_by_the_next_pass() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // The tenant swaps in their own secret as the delete lands…
        replace_on_delete: Some(fake_replacement_secret("enclava-registry-auth")),
        // …and the first restoration attempt fails transiently.
        fail_reference_restores: 1,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());

    // Pass 1: clear ok (+ intent recorded), delete sees the replacement,
    // restore 500s — unconverged, but the intent is on the SA.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(!converged, "the failed restore keeps the pass unconverged");
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets[0].metadata.uid.as_deref(),
            Some("uid-replacement-enclava-registry-auth"),
            "the tenant replacement survived the delete"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            0,
            "the reference is still cleared after the failed restore"
        );
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]),
            vec![PendingReferenceRepair {
                secret_name: "enclava-registry-auth".to_string(),
                cleared_uid: Some("uid-enclava-registry-auth".to_string()),
            }],
            "the durable repair intent (with the cleared object's UID) survived the failed \
                 restore"
        );
    }

    // Pass 2: the repair pass restores the reference onto the surviving
    // replacement (unmanaged — invisible to the removal loop) and
    // discharges the intent; only then is the namespace converged.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the replacement keeps the ServiceAccount reference it inherits by name"
        );
        assert!(
            pending_reference_repairs(&state.service_accounts[0]).is_empty(),
            "the repair intent is discharged once the reference is restored"
        );
    }
}

/// Complement of the repair-intent test (Codex review on #243, P2): when
/// a removal completes (`Deleted`), the cleared references are final and
/// their repair intent must be discharged in the same pass — a completed
/// cleanup leaves no pending-repair annotations behind.
#[tokio::test]
async fn completed_removals_discharge_their_repair_intent() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);

    let state = cluster.lock().unwrap();
    assert!(state.secrets.is_empty(), "the managed secret is removed");
    assert!(
        state.service_accounts[0].image_pull_secrets.is_none(),
        "the reference stays cleared after a completed removal"
    );
    assert!(
        pending_reference_repairs(&state.service_accounts[0]).is_empty(),
        "a completed removal discharges its durable repair intent"
    );
}

/// Reviewer follow-up on #243 (Critical): the repair pass must complete an
/// UNFINISHED verified removal instead of re-attaching the reference.
/// After a GHCR rotation the unlabeled old-PAT secret no longer matches
/// the legacy credential shape, so discovery cannot recognize it — only
/// the UID recorded with the repair intent proves which object was being
/// removed. The pass must delete that exact object (UID-pinned, never
/// re-attached) and only then converge.
#[tokio::test(start_paused = true)]
async fn repair_intent_completes_an_unfinished_removal_after_credential_rotation() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        // UNLABELED pre-label secret whose shape matches the pass-1
        // credentials — discoverable as managed only while they match.
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            false,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        // Every delete attempt of the bounded budget conflicts, so the
        // removal errors out…
        rv_bumps_on_delete: 64,
        // …and the reverse restore fails once, leaving the intent on the
        // ServiceAccount with the reference cleared.
        fail_reference_restores: 1,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());

    // Pass 1 (out of scope, credentials still prove the legacy shape):
    // clear ok, delete never converges, restore fails — unconverged with
    // durable intent recorded against the verified object's UID.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(!converged);
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            0,
            "the reference is cleared"
        );
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]),
            vec![PendingReferenceRepair {
                secret_name: "enclava-registry-auth".to_string(),
                cleared_uid: Some("uid-enclava-registry-auth".to_string()),
            }],
            "the intent records the cleared object's UID"
        );
    }

    // Pass 2 after the GHCR rotation: the legacy shape no longer matches,
    // the secret is invisible to discovery, and the writer settled. Only
    // the recorded UID proves the pending verified removal — the repair
    // pass must COMPLETE it, never re-attach the old platform PAT.
    let rotated = PullSecretSettings {
        configured_name: "enclava-registry-auth".to_string(),
        ghcr_credentials: Some(("cap-bot".to_string(), "ghp_rotated".to_string())),
        configured_secret_data: Some(expected_dockerconfigjson("cap-bot", "ghp_rotated")),
    };
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &rotated,
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        converged,
        "completing the UID-proven removal converges the namespace"
    );
    {
        let state = cluster.lock().unwrap();
        assert!(
            state.secrets.is_empty(),
            "the old-PAT secret must be deleted by its recorded UID, not kept"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            0,
            "the reference stays cleared — the old PAT is never re-attached"
        );
        assert!(
            pending_reference_repairs(&state.service_accounts[0]).is_empty(),
            "the completed removal discharges its intent"
        );
    }
}

#[tokio::test]
async fn expanded_scope_cancels_pending_same_uid_removal() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-enclava-registry-auth".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "enclava-registry-auth"
    );
    assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
}

#[tokio::test]
async fn expanded_scope_refreshes_uid_proven_unlabeled_old_credential_before_reattaching() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-enclava-registry-auth".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            false,
            "cap-bot",
            "ghp_old",
        )],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let settings = reconcile_settings();
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &settings,
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert!(is_labeled_managed_pull_secret(&state.secrets[0]));
    assert_eq!(
        state.secrets[0]
            .data
            .as_ref()
            .unwrap()
            .get(".dockerconfigjson")
            .unwrap()
            .0,
        settings.configured_secret_data.unwrap().into_bytes(),
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "enclava-registry-auth"
    );
    assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
    assert!(converged);
}

/// Codex review on #243, P2 "restore pending old-name secrets after
/// scope expansion": after a `TENANT_IMAGE_PULL_SECRET_NAME` change plus a
/// narrowing-then-expansion, a pending repair intent can name the OLD
/// secret whose UID-proven object still lives. The workload has not
/// redeployed and still needs that recorded reference — the repair pass
/// must refresh/adopt/restore it, not fall through to the removal path
/// and delete valid credentials (which converged and left pod restarts
/// unable to pull until another deployment occurred).
#[test]
fn startup_rejects_incomplete_ghcr_credentials() {
    const CHILD: &str = "CAP_GHCR_STARTUP_CASE";
    if let Ok(case) = std::env::var(CHILD) {
        let error = tenant_image_pull_secret_startup_error();
        if case == "valid" {
            assert!(error.is_none(), "{error:?}");
        } else {
            assert!(
                error
                    .unwrap()
                    .contains("must both be nonempty or both absent")
            );
        }
        return;
    }
    for (username, token, case) in [
        ("", "", "valid"),
        ("bot", "token", "valid"),
        ("bot", "", "incomplete"),
        ("", "token", "incomplete"),
        ("bot", "   ", "incomplete"),
        ("   ", "token", "incomplete"),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "deploy::tests::startup_rejects_incomplete_ghcr_credentials",
                "--nocapture",
            ])
            .env(CHILD, case)
            .env("GHCR_USERNAME", username)
            .env("GHCR_TOKEN", token)
            .env("TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES", "ghcr.io/team/*")
            .env_remove("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION")
            .env_remove("TENANT_IMAGE_PULL_SCOPE_GENERATION")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Devin review on #276: token-only GHCR authentication is valid for
/// cosign verification but must still refuse API startup. The tenant
/// pull secret is a dockerconfigjson Basic credential needing BOTH the
/// username and the token, and a process that booted token-only would
/// run the startup cleanup with no config — computing every namespace
/// out-of-scope and deleting every managed pull secret over an
/// incomplete credential rotation. This pins the documented
/// asymmetry with cosign's token-only verification auth: refusing
/// startup is the load-bearing half, because no legitimate capability
/// is lost (setting the username alongside the token is always
/// possible and cosign uses it verbatim).
#[test]
fn token_only_ghcr_refuses_startup_because_the_sweep_would_remove_every_secret() {
    const CHILD: &str = "CAP_GHCR_TOKEN_ONLY_CASE";
    if std::env::var(CHILD).is_ok() {
        assert!(
            tenant_image_pull_secret_startup_error()
                .as_deref()
                .is_some_and(|error| error.contains("must both be nonempty")),
            "token-only must refuse startup before the cleanup sweep runs"
        );
        assert!(
            tenant_image_pull_secret_config_from_env().is_none(),
            "token-only cannot materialize a pull secret"
        );
        let image = ImageRef::parse("ghcr.io/team/app:latest").unwrap();
        assert!(
            !namespace_keeps_tenant_image_pull_secret(None, &[Some(vec![image])]),
            "a booted token-only process would compute every namespace out-of-scope \
                 and the sweep would delete every managed pull secret"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "deploy::tests::token_only_ghcr_refuses_startup_because_the_sweep_would_remove_every_secret",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("GHCR_USERNAME")
            .env("GHCR_TOKEN", "ghp_token_only")
            .env("TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES", "ghcr.io/team/*")
            .env_remove("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION")
            .env_remove("TENANT_IMAGE_PULL_SCOPE_GENERATION")
            .env_remove("TENANT_IMAGE_PULL_SECRET_NAME")
            .output()
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn labeled_old_name_repairs_survive_cleanup_in_either_account_order() {
    use std::sync::{Arc, Mutex};
    for reverse in [false, true] {
        let mut accounts = vec![
            fake_service_account("cap-out", &[]),
            fake_service_account("cap-in", &[]),
        ];
        for account in &mut accounts {
            account.metadata.annotations = Some(std::collections::BTreeMap::from([(
                PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
                "old-pull-secret=uid-old-pull-secret".to_string(),
            )]));
        }
        if reverse {
            accounts.reverse();
        }
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "old-pull-secret",
                true,
                "cap-bot",
                "ghp_old",
            )],
            service_accounts: accounts,
            ..Default::default()
        }));
        let scope = PullSecretAccountScope {
            namespace_in_scope: true,
            in_scope_accounts: ["cap-in".to_string()].into_iter().collect(),
        };
        let engine = reconcile_engine(cluster.clone());
        assert!(
            reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &["cap-out".into(), "cap-in".into()],
                &reconcile_settings(),
                &scope,
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: 0,
                    lease_held: false,
                },
            )
            .await
            .unwrap()
        );
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        let desired = state
            .service_accounts
            .iter()
            .find(|a| a.metadata.name.as_deref() == Some("cap-in"))
            .unwrap();
        assert_eq!(
            desired.image_pull_secrets.as_ref().unwrap()[0].name,
            "old-pull-secret"
        );
        assert!(pending_reference_repairs(desired).is_empty());
        let excluded = state
            .service_accounts
            .iter()
            .find(|a| a.metadata.name.as_deref() == Some("cap-out"))
            .unwrap();
        assert!(
            excluded
                .image_pull_secrets
                .as_ref()
                .is_none_or(|r| r.is_empty())
        );
    }
}

#[tokio::test]
async fn expanded_scope_restores_pending_old_name_reference() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-old-pull-secret".to_string(),
    )]));
    // Unlabeled with the PRE-rotation credential: invisible to discovery,
    // proven only through the intent's recorded UID — exactly the object
    // the old code deleted after a re-expansion.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "old-pull-secret",
            false,
            "cap-bot",
            "ghp_old",
        )],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let settings = reconcile_settings();
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &settings,
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert!(converged);
    assert_eq!(
        state.secrets.len(),
        1,
        "the UID-proven old-name secret must survive the re-expansion"
    );
    assert!(
        is_labeled_managed_pull_secret(&state.secrets[0]),
        "adopted while the intent's UID proof holds"
    );
    assert_eq!(
        state.secrets[0]
            .data
            .as_ref()
            .unwrap()
            .get(".dockerconfigjson")
            .unwrap()
            .0,
        settings.configured_secret_data.unwrap().into_bytes(),
        "refreshed to the current credential before reattaching"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "old-pull-secret",
        "the recorded old-name reference is restored"
    );
    assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
}

/// Codex review on #243, P1 "reconcile pull-secret references per app in
/// shared namespaces": a shared namespace holds one app that still
/// matches the repository scope and one that no longer does. The
/// configured Secret stays for the matching app while the nonmatching
/// app's `imagePullSecrets` reference is cleared — with durable intent,
/// so a later broadening re-attaches it without waiting for a redeploy.
#[tokio::test]
async fn mixed_namespace_clears_reference_only_from_out_of_scope_apps() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![
            fake_service_account("cap-app-in-scope", &["enclava-registry-auth"]),
            fake_service_account("cap-app-out-of-scope", &["enclava-registry-auth"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let service_accounts = vec![
        "cap-app-in-scope".to_string(),
        "cap-app-out-of-scope".to_string(),
    ];
    let narrowed = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-app-in-scope".to_string()].into_iter().collect(),
    };
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &service_accounts,
            &reconcile_settings(),
            &narrowed,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "the secret stays for the in-scope app"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()
                .len(),
            1,
            "the in-scope app's reference is intact"
        );
        assert!(
            state.service_accounts[1]
                .image_pull_secrets
                .as_ref()
                .is_none_or(|references| references.is_empty()),
            "the out-of-scope app's reference is cleared"
        );
        assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[1]).len(),
            1,
            "durable intent records the per-app cleared reference"
        );
    }

    // Broadening: both apps back in scope — the durable intent refreshes
    // and re-attaches the reference without waiting for a redeploy.
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &service_accounts,
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.service_accounts[1]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "enclava-registry-auth",
        "broadening re-attached the narrowed app's reference"
    );
    assert!(pending_reference_repairs(&state.service_accounts[1]).is_empty());
}

/// Codex review on #243, P1 per-app scoping: an old-name secret
/// referenced ONLY by an out-of-scope app is residue under the narrowed
/// scope — the out-of-scope app's reference does not keep it, so it is
/// removed together with that reference.
#[tokio::test]
async fn out_of_scope_app_reference_does_not_keep_old_name_secret() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "old-pull-secret",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![
            fake_service_account("cap-app-in-scope", &[]),
            fake_service_account("cap-app-out-of-scope", &["old-pull-secret"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-app-in-scope".to_string()].into_iter().collect(),
    };
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &[
                "cap-app-in-scope".to_string(),
                "cap-app-out-of-scope".to_string(),
            ],
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.secrets[0].metadata.name.as_deref(),
        Some("enclava-registry-auth")
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "enclava-registry-auth"
    );
    assert!(
        state.service_accounts[1]
            .image_pull_secrets
            .as_ref()
            .is_none_or(|references| references.is_empty()),
        "the out-of-scope app's reference is cleared with the removal"
    );
    assert!(
        !pending_reference_repairs(&state.service_accounts[1])
            .iter()
            .any(|repair| repair.secret_name == "old-pull-secret"),
        "the completed old-name removal discharged its intent"
    );
}

/// Codex review on #243, P1 per-app guard: a pending UID-proven removal
/// on an out-of-scope account must NOT be completed when an in-scope
/// app's ServiceAccount still references that same old-name secret —
/// completing it would delete the in-scope app's credential.
#[tokio::test]
async fn pending_removal_of_secret_still_referenced_in_scope_is_kept() {
    use std::sync::{Arc, Mutex};
    let mut out_of_scope_account = fake_service_account("cap-app-out-of-scope", &[]);
    out_of_scope_account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-old-pull-secret".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "old-pull-secret",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        service_accounts: vec![
            fake_service_account("cap-app-in-scope", &["old-pull-secret"]),
            out_of_scope_account,
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-app-in-scope".to_string()].into_iter().collect(),
    };
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &[
                "cap-app-in-scope".to_string(),
                "cap-app-out-of-scope".to_string(),
            ],
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "the in-scope app's reference keeps the secret"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "old-pull-secret",
        "the in-scope app's reference is intact"
    );
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[1]).len(),
        1,
        "the out-of-scope account's intent survives (its reference stays \
             cleared; a broadening re-attaches)"
    );
}

/// Codex review on #243, P1 "fence secret-name rollouts before deleting
/// new secrets": a deploy that acquired the namespace lease BEFORE the
/// sweep snapshot writes its new-name Secret at a mutation generation
/// EQUAL to the snapshot's. While that lease is still HELD the Secret is
/// unreferenced only because the deploy's ServiceAccount apply has not
/// landed — the sweep must skip it. Once the lease is released, the same
/// still-unreferenced Secret is completed residue and is removed.
#[tokio::test]
async fn sweep_keeps_active_lease_generation_secret_until_lease_release() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("pull-secret-new-name", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "7".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![fake_service_account("cap-tenant-app", &[])],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        !reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 7,
                lease_held: true,
            },
        )
        .await
        .unwrap(),
        "held-lease pass must remain unconverged without touching the in-flight secret"
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "an ACTIVE lease generation is concurrent — its Secret is skipped"
        );
    }
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 7,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "once the lease is released, the unreferenced same-generation \
             Secret is completed residue and is removed"
    );
}

/// Codex review on #278, P1: quarantine retains `owner_token` through
/// `reclaim_after` after `locked_until` expires, because an accepted
/// Kubernetes request may still complete. The sweep snapshot must keep
/// that lease marked held so the equal-generation Secret is not deleted.
#[tokio::test]
async fn sweep_keeps_quarantined_lease_equal_generation_secret() {
    use std::sync::{Arc, Mutex};

    let pool = crate::test_support::database_test_pool().await;
    let namespace = format!("quar{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let owner = uuid::Uuid::new_v4();
    let operation_id = uuid::Uuid::new_v4();
    struct DeleteQuarantineLease {
        namespace: String,
    }
    impl Drop for DeleteQuarantineLease {
        fn drop(&mut self) {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
            let _ = std::process::Command::new("psql")
                .env("PGPASSWORD", "test")
                .arg(&url)
                .arg("-v")
                .arg("ON_ERROR_STOP=1")
                .arg("-c")
                .arg(format!(
                    "DELETE FROM external_resource_mutation_leases \
                         WHERE resource_scope = 'kubernetes_namespace' \
                           AND resource_key = '{}'",
                    self.namespace
                ))
                .output();
        }
    }
    let _cleanup = DeleteQuarantineLease {
        namespace: namespace.clone(),
    };
    sqlx::query(
        "INSERT INTO external_resource_mutation_leases(\
                resource_scope, resource_key, generation, owner_token, \
                operation_kind, operation_id, locked_until, reclaim_after) \
             VALUES (\
                'kubernetes_namespace', $1, 7, $2, 'deployment_apply', $3, \
                clock_timestamp() - interval '30 seconds', \
                clock_timestamp() + interval '300 seconds')",
    )
    .bind(&namespace)
    .bind(owner)
    .bind(operation_id)
    .execute(&pool)
    .await
    .expect("insert quarantined namespace lease");

    let snapshot = crate::mutation_leases::snapshot_namespace_mutation_leases(&pool)
        .await
        .expect("snapshot namespace leases");
    let (generation, lease_held) = snapshot
        .iter()
        .find(|(key, _, _)| key == &namespace)
        .map(|(_, generation, held)| (*generation, *held))
        .expect("quarantined namespace is in the sweep snapshot");
    assert_eq!(generation, 7);

    let mut secret = fake_managed_secret("pull-secret-new-name", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            generation.to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![fake_service_account("cap-tenant-app", &[])],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: generation,
            lease_held,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        cluster.lock().unwrap().secrets.len(),
        1,
        "sweep deleted the quarantined lease's equal-generation Secret \
             (lease_held={lease_held}; locked_until expired, reclaim_after still future)"
    );
    assert!(
        !converged,
        "a quarantined equal generation must stay unconverged; lease_held={lease_held}"
    );

    sqlx::query(
        "UPDATE external_resource_mutation_leases \
                SET reclaim_after = clock_timestamp() - interval '1 second' \
              WHERE resource_scope = 'kubernetes_namespace' AND resource_key = $1",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("expire reclaim quarantine");
    let snapshot = crate::mutation_leases::snapshot_namespace_mutation_leases(&pool)
        .await
        .expect("snapshot after quarantine");
    let lease_held = snapshot
        .iter()
        .find(|(key, _, _)| key == &namespace)
        .map(|(_, _, held)| *held)
        .expect("row remains until reclaimed");
    assert!(
        !lease_held,
        "expired reclaim_after releases the sweep fence"
    );
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: generation,
                lease_held,
            },
        )
        .await
        .unwrap(),
        "after quarantine the equal-generation Secret is completed residue"
    );
    assert!(cluster.lock().unwrap().secrets.is_empty());
}

/// Both rollout dimensions must fit PostgreSQL's signed BIGINT domain.
#[test]
fn pull_secret_epoch_startup_enforces_bigint_range() {
    const CHILD: &str = "CAP_PULL_SECRET_EPOCH_STARTUP_CASE";
    if let Ok(expected) = std::env::var(CHILD) {
        let error = tenant_image_pull_secret_startup_error();
        if expected == "valid" {
            assert!(error.is_none(), "{error:?}");
        } else {
            let error = error.expect("invalid epochs must refuse startup");
            assert!(error.contains(&expected), "{error}");
            assert!(error.contains(&i64::MAX.to_string()), "{error}");
        }
        return;
    }
    for name in [
        "TENANT_IMAGE_PULL_SCOPE_GENERATION",
        "TENANT_IMAGE_PULL_CREDENTIAL_GENERATION",
    ] {
        for (value, valid) in [
            (None, true),
            (Some("0".to_string()), true),
            (Some(i64::MAX.to_string()), true),
            (Some((i64::MAX as u64 + 1).to_string()), false),
            (Some(u64::MAX.to_string()), false),
            (Some("18446744073709551616".to_string()), false),
            (Some("-1".to_string()), false),
            (Some("invalid".to_string()), false),
        ] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "deploy::tests::pull_secret_epoch_startup_enforces_bigint_range",
                    "--nocapture",
                ])
                .env(CHILD, if valid { "valid" } else { name })
                .env_remove("GHCR_USERNAME")
                .env_remove("GHCR_TOKEN")
                .env_remove("TENANT_IMAGE_PULL_SCOPE_GENERATION")
                .env_remove("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION");
            if let Some(value) = &value {
                command.env(name, value);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{name}={value:?}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn pull_secret_epoch_db_conversion_preserves_boundaries() {
    for epoch in [0, 1, i64::MAX as u64] {
        assert_eq!(
            pull_secret_epoch_for_db(epoch, "test epoch").unwrap(),
            epoch as i64
        );
    }
    for epoch in [i64::MAX as u64 + 1, u64::MAX] {
        let error = pull_secret_epoch_for_db(epoch, "test epoch").unwrap_err();
        assert!(matches!(error, sqlx::Error::Protocol(_)));
        assert!(error.to_string().contains("test epoch"));
    }
}

#[tokio::test]
async fn pull_secret_epoch_db_writes_reject_overflow_before_querying() {
    // A closed lazy pool proves that rejection happens before any DB access.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    pool.close().await;
    for epoch in [i64::MAX as u64 + 1, u64::MAX] {
        for (scope, credential, name) in [
            (epoch, 0, "TENANT_IMAGE_PULL_SCOPE_GENERATION"),
            (0, epoch, "TENANT_IMAGE_PULL_CREDENTIAL_GENERATION"),
        ] {
            let error = raise_tenant_pull_secret_rollout_authority(&pool, scope, credential)
                .await
                .unwrap_err();
            assert!(matches!(error, sqlx::Error::Protocol(_)));
            assert!(error.to_string().contains(name));
        }
        let error = record_tenant_pull_secret_scope_fence(&pool, "unused", epoch)
            .await
            .unwrap_err();
        assert!(matches!(error, sqlx::Error::Protocol(_)));
        assert!(
            error
                .to_string()
                .contains("TENANT_IMAGE_PULL_SCOPE_GENERATION")
        );
    }
}

/// The durable scope fence defers only replicas whose configured epoch is
/// older than the recorded epoch (tests run with the default epoch 0).
#[test]
fn pull_secret_scope_fence_defers_only_older_replicas() {
    assert!(
        !pull_secret_scope_fence_defers(0),
        "an equal (or absent) fence belongs to the current policy"
    );
    assert!(pull_secret_scope_fence_defers(1));
    assert!(pull_secret_scope_fence_defers(i64::MAX));
}

/// Codex review on #243, P1 per-app scoping: the scope decision struct
/// keeps the pre-per-app behavior when no explicit account set is given,
/// and decides per account when one is.
#[test]
fn pull_secret_account_scope_decides_per_app_only_when_partitioned() {
    let all = PullSecretAccountScope::uniform(true);
    assert!(all.account_in_scope("cap-any-app"));
    let none = PullSecretAccountScope::uniform(false);
    assert!(!none.account_in_scope("cap-any-app"));
    let mixed = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-app-in-scope".to_string()].into_iter().collect(),
    };
    assert!(mixed.account_in_scope("cap-app-in-scope"));
    assert!(!mixed.account_in_scope("cap-app-out-of-scope"));
}

/// Codex review on #243, round 2, P1 "refuse to overwrite an unowned
/// configured-name Secret": a tenant-owned secret under the configured
/// name must never be merge-patched into a platform-PAT secret — the
/// deploy fails closed with an actionable error and the object is left
/// untouched.
#[tokio::test]
async fn scoped_deploy_refuses_to_overwrite_unowned_secret() {
    use std::sync::{Arc, Mutex};
    let original = fake_managed_secret(
        "enclava-registry-auth",
        false,
        "tenant-user",
        "tenant-token",
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![original.clone()],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(2).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::Validation(ref message) if message.contains("not CAP-managed")),
        "unowned configured-name secret must fail closed, got {error:?}"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].data, original.data,
        "the tenant-owned secret must be untouched"
    );
    assert!(
        state.secrets[0]
            .metadata
            .labels
            .as_ref()
            .is_none_or(|labels| !labels.contains_key(TENANT_PULL_SECRET_LABEL)),
        "no CAP ownership label may be stamped onto the tenant's object"
    );
}

/// Codex review on #243, round 2, P1 "verify creation evidence returned
/// by the Secret POST": a mutating admission webhook that strips
/// RESOURCE_CREATED_BY_ANNOTATION from the accepted create must not
/// report success — the just-created object is deleted (pinned to the
/// response identity) and the deploy fails closed.
#[tokio::test]
async fn scoped_deploy_create_evidence_strip_deletes_secret_and_fails() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        strip_creation_evidence_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::Validation(ref message) if message.contains("creation evidence")),
        "stripped creation evidence must fail closed, got {error:?}"
    );
    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "the unattributable created secret must be deleted again"
    );
}

/// A matching annotation string is insufficient: cleanup also requires
/// ownership of its exact path by CAP in a non-status managed-fields entry.
#[tokio::test]
async fn scoped_deploy_create_untrusted_marker_ownership_compensates() {
    use enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION;
    let marker_fields = serde_json::json!({
        "f:metadata": {"f:annotations": {
            format!("f:{RESOURCE_CREATED_BY_ANNOTATION}"): {}
        }}
    });
    let cases = [
        ("absent managedFields", serde_json::json!([])),
        (
            "manager without marker path",
            serde_json::json!([{"manager": "enclava-platform", "fieldsV1": {
                "f:metadata": {"f:annotations": {"f:other": {}}}
            }}]),
        ),
        (
            "foreign owner",
            serde_json::json!([{"manager": "admission-webhook", "fieldsV1": marker_fields}]),
        ),
        (
            "status-only owner",
            serde_json::json!([{"manager": "enclava-platform", "subresource": "status",
                    "fieldsV1": marker_fields}]),
        ),
    ];
    for (case, fields) in cases {
        let cluster = Arc::new(Mutex::new(FakeCluster {
            creation_managed_fields_override: Some(fields),
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let config = TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_platform".to_string(),
            allowed_repositories: Vec::new(),
        };
        let error = apply_scoped_pull_secret(
            &engine,
            "tenant-ns",
            &config,
            MutationGeneration::new(3).unwrap(),
            &[],
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, DeployError::Validation(ref message) if message.contains("creation evidence")),
            "{case}: untrusted ownership must fail closed, got {error:?}"
        );
        assert!(
            cluster.lock().unwrap().secrets.is_empty(),
            "{case}: the unattributable PAT must be removed"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn scoped_deploy_create_compensation_waits_for_finalizer() {
    let cluster = Arc::new(Mutex::new(FakeCluster {
        strip_creation_evidence_on_create: true,
        delete_lingering_polls: 2,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, DeployError::Validation(_)));
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "terminal failure requires observing actual removal, not DELETE acceptance"
    );
}

#[tokio::test(start_paused = true)]
async fn scoped_deploy_create_compensation_stuck_finalizer_keeps_retrying() {
    let cluster = Arc::new(Mutex::new(FakeCluster {
        strip_creation_evidence_on_create: true,
        delete_lingering_polls: u8::MAX,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    for generation in [3, 4] {
        let error = apply_scoped_pull_secret(
            &engine,
            "tenant-ns",
            &config,
            MutationGeneration::new(generation).unwrap(),
            &[],
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, DeployError::PullSecretReconcileDeferred(_)),
            "the durable deployment job must retry while the PAT remains readable: {error:?}"
        );
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert!(state.secrets[0].metadata.deletion_timestamp.is_some());
        assert_eq!(
            secret_mutation_generation(&state.secrets[0]),
            Some(3),
            "a retry must not refresh or adopt the terminating PAT"
        );
    }
    // Once the finalizer releases, a fresh attempt can create an
    // attributable Secret rather than patching the old terminating one.
    {
        let mut state = cluster.lock().unwrap();
        state.lingering_polls_left = 0;
        state.delete_lingering_polls = 0;
        state.strip_creation_evidence_on_create = false;
    }
    apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(5).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert!(state.secrets[0].metadata.deletion_timestamp.is_none());
    assert_eq!(secret_mutation_generation(&state.secrets[0]), Some(5));
}

/// Codex review on #243, round 2, P1 "bound the custom pull-secret apply
/// path": a Kubernetes API that accepts a connection but never responds
/// must defer (requeueable) once the per-namespace budget elapses,
/// instead of holding the deploy's namespace lease and apply permit
/// indefinitely.
#[tokio::test(start_paused = true)]
async fn scoped_deploy_apply_stall_defers_within_budget() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_secret_gets: true,
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_old",
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster);
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_new".to_string(),
        allowed_repositories: Vec::new(),
    };
    assert!(matches!(
        apply_scoped_pull_secret(
            &engine,
            "tenant-ns",
            &config,
            MutationGeneration::new(2).unwrap(),
            &[],
            None,
        )
        .await,
        Err(DeployError::PullSecretReconcileDeferred(_))
    ));
}

/// Codex review on #243, round 2, P2 "advance the credential epoch even
/// when secret bytes match": matching payload bytes alone must not skip
/// the refresh — after a credential rollback/reuse the OLD
/// credential-generation annotation would survive, and an intermediate
/// old replica could overwrite the bytes with its stale token. The
/// idempotence predicate requires BOTH rollout epochs to be current.
#[tokio::test]
async fn refresh_persists_credential_epoch_when_bytes_match() {
    use std::sync::{Arc, Mutex};
    let expected = expected_dockerconfigjson("cap-bot", "ghp_platform");
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "x");
    secret.data = Some(std::collections::BTreeMap::from([(
        ".dockerconfigjson".to_string(),
        k8s_openapi::ByteString(expected.clone().into_bytes()),
    )]));
    // Scope epoch is current; the credential-generation annotation is
    // ABSENT (an older epoch) — the refresh must persist it.
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
            "0".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    // Bind the snapshot: a temporary MutexGuard in the call arguments
    // would live across the await and deadlock the fake's handler.
    let snapshot = cluster.lock().unwrap().secrets[0].clone();
    let rewritten =
        refresh_managed_pull_secret_credentials(&engine, "tenant-ns", &snapshot, &expected)
            .await
            .unwrap();
    assert!(rewritten, "a missing credential epoch must force a write");
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0]
            .metadata
            .annotations
            .as_ref()
            .unwrap()
            .get(PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION)
            .map(String::as_str),
        Some(pull_secret_credential_generation().to_string().as_str()),
        "the current credential epoch is persisted with the matching bytes"
    );
}

/// Codex review on #243, round 2, P1 "fence per-app reference clears
/// against concurrent deploys": the per-app scope comes from the sweep's
/// inventory snapshot; a concurrent deploy that re-scoped the app back in
/// rewrote the Secret under an active/ newer mutation generation and
/// attached the reference. The kept-secret per-app clear must be fenced
/// by that generation until the next sweep re-decides.
#[tokio::test]
async fn per_app_clear_skipped_while_concurrent_deploy_owns_secret() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "7".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![
            fake_service_account("cap-app-in-scope", &[]),
            fake_service_account("cap-app-out-of-scope", &["enclava-registry-auth"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-app-in-scope".to_string()].into_iter().collect(),
    };
    let service_accounts = vec![
        "cap-app-in-scope".to_string(),
        "cap-app-out-of-scope".to_string(),
    ];
    // Concurrent deploy holds the ACTIVE lease generation 7 (equal to the
    // sweep snapshot): the per-app clear is skipped, not converged.
    assert!(
        !reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &service_accounts,
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 7,
                lease_held: true,
            },
        )
        .await
        .unwrap()
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.service_accounts[1]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            1,
            "the concurrently attached reference survives the fenced sweep"
        );
        assert!(pending_reference_repairs(&state.service_accounts[1]).is_empty());
    }
    // Lease released: the strict fence resumes and the stale per-app
    // reference is cleared on the next pass.
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &service_accounts,
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 7,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert!(
        state.service_accounts[1]
            .image_pull_secrets
            .as_ref()
            .is_none_or(|references| references.is_empty()),
        "after the deploy completes, the out-of-scope app's reference is cleared"
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_secret_list_defers_deployment_instead_of_holding_permit_forever() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_secrets_list: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster);
    assert!(matches!(
        reconcile_managed_pull_secrets_for_deploy(
            &engine,
            "tenant-ns",
            &[],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        )
        .await,
        Err(DeployError::PullSecretReconcileDeferred(_))
    ));
}

#[tokio::test]
async fn pending_reference_replacement_is_restored_without_platform_credentials() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-previous-object".to_string(),
    )]));
    let replacement = fake_replacement_secret("enclava-registry-auth");
    let original = replacement.clone();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        !reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets[0].data, original.data);
    assert_eq!(state.secrets[0].metadata.labels, original.metadata.labels);
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "enclava-registry-auth"
    );
}

/// Devin review on #276 (security): a pending repair intent seeds the
/// OLD secret name into the sweep's keep decision — but the object
/// living under that name may be a tenant replacement carrying the
/// managed label it inherited from a wholesale copy. The repair pass
/// restores the replacement's reference by name and refuses to
/// overwrite it; the keep loop must not undo that by refreshing the
/// name with the platform PAT. On the pre-fix code the seeded name
/// reached credential refresh and the platform credential was written
/// into the tenant's replacement despite the intent's recorded UID
/// proving the object is not the one that was cleared.
#[tokio::test]
async fn pending_repair_replacement_never_receives_platform_credentials() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        // The UID of the object that was cleared — NOT the replacement's.
        "old-pull-secret=uid-cleared-object".to_string(),
    )]));
    // A labeled replacement under the old name with the tenant's own
    // credentials: discovery sees it through the label alone, so only
    // the intent's recorded UID can disprove ownership.
    let replacement = fake_managed_secret("old-pull-secret", true, "tenant-user", "tenant-token");
    let original_data = replacement.data.clone();
    let original_annotations = replacement.metadata.annotations.clone();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets[0].data, original_data,
            "the tenant replacement's credentials must never be overwritten with the platform PAT"
        );
        assert_eq!(
            state.secrets[0].metadata.annotations, original_annotations,
            "no credential or scope epoch may be stamped onto the replacement"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()[0]
                .name,
            "old-pull-secret",
            "the repair pass still restores the reference the name inherits"
        );
        assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
        assert_eq!(
            state.service_accounts[0]
                .metadata
                .annotations
                .as_ref()
                .unwrap()
                .get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION)
                .map(String::as_str),
            Some("old-pull-secret=uid-old-pull-secret"),
            "the mismatched UID is recorded before the pending intent is discharged"
        );
    }
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: i64::MAX,
                lease_held: false,
            },
        )
        .await
        .unwrap(),
        "the next sweep still converges"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].data, original_data,
        "the next sweep must not refresh the replacement after the pending intent is gone"
    );
}

/// Codex review on #276, P1: a labeled replacement at the configured name
/// is kept by name alone. The mismatched UID must still block adoption and
/// credential refresh, including on the sweep after the repair intent is
/// discharged.
#[tokio::test]
async fn configured_name_replacement_never_receives_platform_credentials() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-cleared-object".to_string(),
    )]));
    let replacement =
        fake_managed_secret("enclava-registry-auth", true, "tenant-user", "tenant-token");
    let original_data = replacement.data.clone();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    for _ in 0..2 {
        assert!(
            !reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &["cap-tenant-app".to_string()],
                &reconcile_settings(),
                &PullSecretAccountScope::uniform(true),
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: i64::MAX,
                    lease_held: false,
                },
            )
            .await
            .unwrap()
        );
    }
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets[0].data, original_data);
    assert_eq!(
        state.service_accounts[0]
            .metadata
            .annotations
            .as_ref()
            .unwrap()
            .get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION)
            .map(String::as_str),
        Some("enclava-registry-auth=uid-enclava-registry-auth")
    );
    assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
}

/// Codex review on #276, P1: a replacement already referenced by another
/// in-scope account used to fall through the pending-only predicate and
/// receive the platform PAT on the first sweep.
#[tokio::test]
async fn referenced_replacement_never_receives_platform_credentials() {
    use std::sync::{Arc, Mutex};
    let mut repair_account = fake_service_account("cap-repair-app", &[]);
    repair_account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-cleared-object".to_string(),
    )]));
    let replacement = fake_managed_secret("old-pull-secret", true, "tenant-user", "tenant-token");
    let original_data = replacement.data.clone();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![
            fake_service_account("cap-tenant-app", &["old-pull-secret"]),
            repair_account,
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string(), "cap-repair-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: i64::MAX,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets[0].data, original_data);
    assert!(
        state.service_accounts.iter().any(|account| {
            account
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| {
                    annotations.get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION)
                })
                .is_some_and(|value| value.contains("uid-old-pull-secret"))
        }),
        "the mismatched UID is recorded on the account that observed it"
    );
}

#[test]
fn shared_namespace_out_of_scope_deploy_uses_namespace_inventory() {
    let deploying = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: vec![
            parse_image_pull_repository_scope("ghcr.io/company/private").unwrap(),
        ],
    };
    let in_scope = ImageRef::parse("ghcr.io/company/private:latest").unwrap();
    let out_of_scope = ImageRef::parse("ghcr.io/other/public:latest").unwrap();
    let stored_in_scope = [
        NamespacePullSecretApp {
            app_id: deploying,
            service_account: "deploying".to_string(),
            images: Some(vec![in_scope.clone()]),
        },
        NamespacePullSecretApp {
            app_id: other,
            service_account: "other".to_string(),
            images: Some(vec![out_of_scope.clone()]),
        },
    ];
    let last_qualifying =
        scope_for_shared_namespace_out_of_scope_deploy(Some(&config), deploying, &stored_in_scope);
    assert!(
        !last_qualifying.namespace_in_scope,
        "stored in-scope images on the deploying app must not keep the secret"
    );
    let still_shared = scope_for_shared_namespace_out_of_scope_deploy(
        Some(&config),
        deploying,
        &[
            NamespacePullSecretApp {
                app_id: deploying,
                service_account: "deploying".to_string(),
                images: Some(vec![out_of_scope]),
            },
            NamespacePullSecretApp {
                app_id: other,
                service_account: "other".to_string(),
                images: Some(vec![in_scope]),
            },
        ],
    );
    assert!(still_shared.namespace_in_scope);
    assert!(!still_shared.account_in_scope("deploying"));
    assert!(still_shared.account_in_scope("other"));
    assert!(
        !scope_for_shared_namespace_out_of_scope_deploy(None, deploying, &stored_in_scope)
            .namespace_in_scope
    );
}

#[test]
fn shared_namespace_in_scope_deploy_forces_deploying_account_in_scope() {
    let deploying = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: vec![
            parse_image_pull_repository_scope("ghcr.io/company/private").unwrap(),
        ],
    };
    let out_of_scope = ImageRef::parse("ghcr.io/other/public:latest").unwrap();
    let in_scope = ImageRef::parse("ghcr.io/company/private:latest").unwrap();
    let scope = scope_for_shared_namespace_deploy(
        Some(&config),
        deploying,
        true,
        &[
            NamespacePullSecretApp {
                app_id: deploying,
                service_account: "stale-stored".to_string(),
                images: Some(vec![out_of_scope]),
            },
            NamespacePullSecretApp {
                app_id: other,
                service_account: "other".to_string(),
                images: Some(vec![in_scope]),
            },
        ],
        &["deploying".to_string()],
    );
    assert!(scope.namespace_in_scope);
    assert!(scope.account_in_scope("deploying"));
    assert!(scope.account_in_scope("other"));
    assert!(
        !scope.account_in_scope("stale-stored"),
        "stored out-of-scope images must not keep the deploying app's old account in scope"
    );
}

#[tokio::test]
async fn foreign_replacement_reference_survives_service_account_apply() {
    let mut old = fake_managed_secret("old-secret", false, "tenant", "token");
    old.metadata.uid = Some("uid-tenant".to_string());
    let mut configured = fake_managed_secret("enclava-registry-auth", false, "tenant", "token");
    configured.metadata.uid = Some("uid-other".to_string());
    let mut existing = fake_service_account("deploying", &["old-secret"]);
    existing.metadata.annotations = Some(BTreeMap::from([(
        FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
        "old-secret=uid-tenant,enclava-registry-auth=uid-other".to_string(),
    )]));
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
        secrets: vec![old, configured],
        service_accounts: vec![existing],
        ..Default::default()
    })));
    let desired = service_account_preserving_pull_secret_records(
        &engine,
        "tenant-ns",
        &fake_service_account("deploying", &["enclava-registry-auth"]),
    )
    .await
    .unwrap();
    let names: Vec<_> = desired
        .image_pull_secrets
        .unwrap()
        .into_iter()
        .map(|reference| reference.name)
        .collect();
    assert_eq!(names, vec!["enclava-registry-auth", "old-secret"]);
    assert_eq!(
        desired.metadata.annotations.unwrap()[FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION],
        "old-secret=uid-tenant,enclava-registry-auth=uid-other"
    );
}

#[tokio::test]
async fn foreign_replacement_merge_discards_stale_records_before_out_of_scope_apply() {
    // The annotation remembers tenant uid-A. Neither a managed uid-B at
    // that configured name, a missing object, nor an object without a UID
    // may cause an out-of-scope desired account to regain the reference.
    for live_uid in [Some("uid-A"), Some("uid-B"), None, Some("missing")] {
        let mut configured =
            fake_managed_secret("enclava-registry-auth", true, "platform", "token");
        configured.metadata.uid = live_uid.map(str::to_string);
        let mut tenant = fake_managed_secret("tenant-secret", false, "tenant", "token");
        tenant.metadata.uid = Some("uid-tenant".to_string());
        let mut existing =
            fake_service_account("deploying", &["enclava-registry-auth", "tenant-secret"]);
        existing.metadata.annotations = Some(BTreeMap::from([
                (
                    FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
                    "enclava-registry-auth=uid-A,tenant-secret=uid-tenant,missing-secret=uid-gone,invalid,=uid,empty=".to_string(),
                ),
                (
                    PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
                    "pending-secret=uid-pending".to_string(),
                ),
            ]));
        let mut secrets = vec![tenant];
        if live_uid != Some("missing") {
            secrets.push(configured);
        }
        let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
            secrets,
            service_accounts: vec![existing],
            ..Default::default()
        })));
        let desired = service_account_preserving_pull_secret_records(
            &engine,
            "tenant-ns",
            &fake_service_account("deploying", &[]),
        )
        .await
        .unwrap();
        let names: Vec<_> = desired
            .image_pull_secrets
            .unwrap()
            .into_iter()
            .map(|reference| reference.name)
            .collect();
        let annotations = desired.metadata.annotations.unwrap();
        if live_uid == Some("uid-A") {
            assert_eq!(names, vec!["enclava-registry-auth", "tenant-secret"]);
            assert_eq!(
                annotations[FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION],
                "enclava-registry-auth=uid-A,tenant-secret=uid-tenant"
            );
        } else {
            assert_eq!(names, vec!["tenant-secret"], "live UID: {live_uid:?}");
            assert_eq!(
                annotations[FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION],
                "tenant-secret=uid-tenant"
            );
        }
        assert_eq!(
            annotations[PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION],
            "pending-secret=uid-pending"
        );
    }
}

#[tokio::test]
async fn foreign_replacement_merge_removes_annotation_when_all_records_are_stale() {
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster::default())));
    let secrets = Api::<Secret>::namespaced(engine.client().clone(), "tenant-ns");
    let mut desired = fake_service_account("deploying", &["explicit-desired-secret"]);
    desired.metadata.annotations = Some(BTreeMap::from([(
        FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
        "missing-secret=uid-gone".to_string(),
    )]));
    merge_foreign_pull_secret_references(
        &secrets,
        &mut desired,
        "missing-secret=uid-gone,invalid,=uid,empty=",
    )
    .await
    .unwrap();
    assert!(
        !desired
            .metadata
            .annotations
            .unwrap()
            .contains_key(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION)
    );
    assert_eq!(
        desired.image_pull_secrets.unwrap()[0].name,
        "explicit-desired-secret",
        "stale foreign proof must not override explicit desired references"
    );
}

#[tokio::test]
async fn foreign_replacement_merge_fails_closed_on_secret_lookup_errors() {
    use axum::http::{Request, Response};
    use kube::client::Body;
    use tower::service_fn;

    for status in [403, 500] {
        let mut existing = fake_service_account("deploying", &[]);
        existing.metadata.annotations = Some(BTreeMap::from([(
            FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
            "tenant-secret=uid-tenant-secret".to_string(),
        )]));
        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let existing = existing.clone();
                async move {
                    let (code, value) = if request.uri().path().contains("/serviceaccounts/") {
                        (200, serde_json::to_value(existing).unwrap())
                    } else {
                        (
                            status,
                            serde_json::json!({
                                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                                "reason": "LookupFailed", "code": status,
                            }),
                        )
                    };
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(code)
                            .body(Body::from(serde_json::to_vec(&value).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let engine = ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default());
        assert!(
            service_account_preserving_pull_secret_records(
                &engine,
                "tenant-ns",
                &fake_service_account("deploying", &[]),
            )
            .await
            .is_err(),
            "Secret GET {status} must prevent service-account apply"
        );
        let secrets = Api::<Secret>::namespaced(engine.client().clone(), "tenant-ns");
        let mut desired = fake_service_account("deploying", &["explicit-desired-secret"]);
        let before = desired.clone();
        assert!(
            merge_foreign_pull_secret_references(
                &secrets,
                &mut desired,
                "tenant-secret=uid-tenant-secret",
            )
            .await
            .is_err()
        );
        assert_eq!(desired, before, "failed validation must not mutate desired");
    }
}

/// Codex review on #276, P1: after a narrowing deleted the configured
/// secret and discharged its pending repair, a later expansion has no
/// managed object and no intent. Reconciliation must recreate the secret
/// and attach it to qualifying accounts instead of reporting convergence.
#[tokio::test]
async fn in_scope_reconcile_recreates_configured_secret_without_pending_intent() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![],
        service_accounts: vec![
            fake_service_account("in-scope", &[]),
            fake_service_account("out-of-scope", &[]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["in-scope".to_string()].into(),
    };
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["in-scope".to_string(), "out-of-scope".to_string()],
        &reconcile_settings(),
        &scope,
        PullSecretDeleteMode::Unfenced {
            namespace_generation: i64::MAX,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(converged);
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.secrets[0].metadata.name.as_deref(),
        Some("enclava-registry-auth")
    );
    assert!(is_labeled_managed_pull_secret(&state.secrets[0]));
    let annotations = state.secrets[0].metadata.annotations.as_ref().unwrap();
    assert_eq!(
        annotations
            .get(enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION)
            .map(String::as_str),
        Some("1"),
        "sweep-created secrets must carry failure-cleanup creation evidence"
    );
    assert_eq!(
        annotations
            .get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
            .map(String::as_str),
        Some("1"),
    );
    assert_eq!(
        state.last_secret_create_field_manager.as_deref(),
        Some("enclava-platform"),
        "creation evidence is foreign unless the platform field manager owns it"
    );
    let in_scope = state
        .service_accounts
        .iter()
        .find(|account| account.metadata.name.as_deref() == Some("in-scope"))
        .unwrap();
    assert_eq!(
        in_scope.image_pull_secrets.as_ref().unwrap()[0].name,
        "enclava-registry-auth"
    );
    let out_of_scope = state
        .service_accounts
        .iter()
        .find(|account| account.metadata.name.as_deref() == Some("out-of-scope"))
        .unwrap();
    assert!(
        out_of_scope
            .image_pull_secrets
            .as_ref()
            .is_none_or(|references| references.is_empty()),
        "an out-of-scope account must not gain the recreated platform secret"
    );
}

#[tokio::test]
async fn in_scope_reconcile_uses_post_cleanup_inventory() {
    use std::sync::{Arc, Mutex};
    for pending in [false, true] {
        let mut account = fake_service_account("in-scope", &[]);
        if pending {
            account.metadata.annotations = Some(BTreeMap::from([(
                PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
                "already-deleted=uid-already-deleted".to_string(),
            )]));
        }
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: if pending {
                vec![]
            } else {
                vec![fake_managed_secret(
                    "stale-old-name",
                    true,
                    "cap-bot",
                    "ghp_old",
                )]
            },
            service_accounts: vec![account],
            ..Default::default()
        }));
        assert!(
            reconcile_managed_pull_secrets(
                &reconcile_engine(cluster.clone()),
                "tenant-ns",
                &["in-scope".into()],
                &reconcile_settings(),
                &PullSecretAccountScope::uniform(true),
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: 0,
                    lease_held: false,
                },
            )
            .await
            .unwrap()
        );
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(
            state.secrets[0].metadata.name.as_deref(),
            Some("enclava-registry-auth")
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()[0]
                .name,
            "enclava-registry-auth"
        );
        assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
    }
}

#[tokio::test]
async fn deploy_then_sweep_preserves_pending_replacement_uid_proof() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("qualifying", &[]);
    account.metadata.annotations = Some(BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-deleted-platform-object".to_string(),
    )]));
    let replacement = fake_managed_secret("enclava-registry-auth", true, "tenant", "tenant-token");
    let original_data = replacement.data.clone();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![account, fake_service_account("excluded", &[])],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["qualifying".to_string()].into(),
    };
    for delete_mode in [
        PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    ] {
        let repair_runs = runs_durable_pull_secret_repair(delete_mode);
        assert!(
            !reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &["qualifying".into(), "excluded".into()],
                &reconcile_settings(),
                &scope,
                delete_mode,
            )
            .await
            .unwrap()
        );
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets[0].data, original_data);
        if !repair_runs {
            assert!(!pending_reference_repairs(&state.service_accounts[0]).is_empty());
        } else {
            assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
            assert!(
                state.service_accounts[0]
                    .metadata
                    .annotations
                    .as_ref()
                    .unwrap()
                    .contains_key(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION)
            );
        }
    }
}

#[tokio::test]
async fn kept_secret_attaches_newly_in_scope_account_without_repair() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_old",
        )],
        service_accounts: vec![
            fake_service_account("existing", &["enclava-registry-auth"]),
            fake_service_account("newly-qualified", &[]),
            fake_service_account("excluded", &[]),
        ],
        ..Default::default()
    }));
    assert!(
        reconcile_managed_pull_secrets(
            &reconcile_engine(cluster.clone()),
            "tenant-ns",
            &[
                "existing".into(),
                "newly-qualified".into(),
                "excluded".into()
            ],
            &reconcile_settings(),
            &PullSecretAccountScope {
                namespace_in_scope: true,
                in_scope_accounts: ["existing".into(), "newly-qualified".into()].into(),
            },
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    for account in &state.service_accounts[..2] {
        assert_eq!(
            account.image_pull_secrets.as_ref().unwrap()[0].name,
            "enclava-registry-auth"
        );
    }
    assert!(
        state.service_accounts[2]
            .image_pull_secrets
            .as_ref()
            .is_none_or(Vec::is_empty)
    );
}

#[tokio::test]
async fn in_scope_reconcile_does_not_overwrite_tenant_owned_configured_name() {
    use std::sync::{Arc, Mutex};

    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            false,
            "tenant-user",
            "tenant-token",
        )],
        service_accounts: vec![fake_service_account("in-scope", &[])],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["in-scope".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: i64::MAX,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a tenant-owned object at the configured name must keep admission closed"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert!(!is_labeled_managed_pull_secret(&state.secrets[0]));
    let dockerconfig = state.secrets[0]
        .data
        .as_ref()
        .unwrap()
        .get(".dockerconfigjson")
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&dockerconfig.0).unwrap();
    assert_eq!(
        parsed["auths"]["ghcr.io"]["password"].as_str(),
        Some("tenant-token")
    );
}

/// Devin review on #276, positive half: when the live object's UID still
/// matches the UID the pending repair recorded, the object IS ours — a
/// labeled old-name secret with pre-rotation credentials must still be
/// refreshed to the current pair, so the UID gate narrows the fix to
/// proven replacements only.
#[tokio::test]
async fn pending_repair_uid_proven_old_name_still_receives_rotated_credentials() {
    use std::sync::{Arc, Mutex};
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-old-pull-secret".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "old-pull-secret",
            true,
            "cap-bot",
            "ghp_old",
        )],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let settings = reconcile_settings();
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &settings,
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.secrets[0]
            .data
            .as_ref()
            .unwrap()
            .get(".dockerconfigjson")
            .unwrap()
            .0,
        settings.configured_secret_data.unwrap().into_bytes(),
        "the UID-proven old-name secret is refreshed to the current credential"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()[0]
            .name,
        "old-pull-secret",
        "the recorded old-name reference is restored"
    );
}

#[tokio::test]
async fn deferred_uid_proven_unlabeled_removal_retains_discovery_intent() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("old-pull-secret", false, "cap-bot", "ghp_revoked");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "5".to_string(),
        );
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-old-pull-secret".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    for lease_held in [true, false] {
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 5,
                lease_held,
            },
        )
        .await
        .unwrap();
        assert_eq!(converged, !lease_held);
        let state = cluster.lock().unwrap();
        assert!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .is_none_or(|refs| refs.is_empty())
        );
        assert_eq!(state.secrets.len(), usize::from(lease_held));
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]).len(),
            usize::from(lease_held)
        );
    }
}

#[tokio::test]
async fn mixed_scope_concurrent_clear_defers_but_uniform_deploy_converges() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "5".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![
            fake_service_account("cap-in", &["enclava-registry-auth"]),
            fake_service_account("cap-out", &["enclava-registry-auth"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let accounts = ["cap-in".to_string(), "cap-out".to_string()];
    let mixed = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-in".to_string()].into_iter().collect(),
    };
    for (scope, expected) in [
        (&mixed, false),
        (&PullSecretAccountScope::uniform(true), true),
    ] {
        assert_eq!(
            reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &accounts,
                &reconcile_settings(),
                scope,
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: 5,
                    lease_held: true
                },
            )
            .await
            .unwrap(),
            expected
        );
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.service_accounts[1]
                .image_pull_secrets
                .as_ref()
                .unwrap()
                .len(),
            1
        );
    }
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &reconcile_settings(),
            &mixed,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 5,
                lease_held: false
            },
        )
        .await
        .unwrap()
    );
    assert!(
        cluster.lock().unwrap().service_accounts[1]
            .image_pull_secrets
            .as_ref()
            .is_none_or(|refs| refs.is_empty())
    );
}

#[test]
fn missing_lease_row_uses_sweep_generation_only_after_publish() {
    assert!(matches!(
        unfenced_pull_secret_delete_mode(None, true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: SWEEP_CREATED_PULL_SECRET_GENERATION,
            lease_held: false,
        }
    ));
    assert!(matches!(
        unfenced_pull_secret_delete_mode(None, false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        }
    ));
    assert!(matches!(
        unfenced_pull_secret_delete_mode(Some((7, true)), true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 7,
            lease_held: true,
        }
    ));
}

/// Codex review on #278, P1: with no lease row the sweep stamps generation
/// 1, then `(0, false)` classifies that stamp as a concurrent deploy and
/// never clears mixed-scope references. After the missing row is published,
/// the same object is this sweep's lineage and must converge. A strictly
/// newer marker is still someone else's.
#[tokio::test]
async fn published_missing_lease_row_does_not_treat_sweep_generation_as_concurrent() {
    use std::sync::{Arc, Mutex};

    fn stamped(generation: i64) -> Secret {
        let mut secret =
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
        secret
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
                generation.to_string(),
            );
        secret
    }
    let accounts = ["cap-in".to_string(), "cap-out".to_string()];
    let mixed = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-in".to_string()].into_iter().collect(),
    };
    let run = |secret: Secret, mode: PullSecretDeleteMode| {
        let accounts = accounts.clone();
        let mixed = mixed.clone();
        async move {
            let cluster = Arc::new(Mutex::new(FakeCluster {
                secrets: vec![secret],
                service_accounts: vec![
                    fake_service_account("cap-in", &["enclava-registry-auth"]),
                    fake_service_account("cap-out", &["enclava-registry-auth"]),
                ],
                ..Default::default()
            }));
            let engine = reconcile_engine(cluster.clone());
            let converged = reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &accounts,
                &reconcile_settings(),
                &mixed,
                mode,
            )
            .await
            .unwrap();
            let out_refs = cluster.lock().unwrap().service_accounts[1]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len())
                .unwrap_or(0);
            (converged, out_refs)
        }
    };

    let (converged, out_refs) = run(
        stamped(SWEEP_CREATED_PULL_SECRET_GENERATION),
        unfenced_pull_secret_delete_mode(None, false),
    )
    .await;
    assert!(
        !converged && out_refs == 1,
        "generation 0 with no row must still protect a positive marker, got converged={converged} refs={out_refs}"
    );

    let (converged, out_refs) = run(
        stamped(SWEEP_CREATED_PULL_SECRET_GENERATION),
        unfenced_pull_secret_delete_mode(None, true),
    )
    .await;
    assert!(
        converged && out_refs == 0,
        "a published missing row must let the sweep clear its own generation-1 secret, got converged={converged} refs={out_refs}"
    );

    let (converged, out_refs) = run(
        stamped(SWEEP_CREATED_PULL_SECRET_GENERATION + 1),
        unfenced_pull_secret_delete_mode(None, true),
    )
    .await;
    assert!(
        !converged && out_refs == 1,
        "a deploy that claimed after publish and wrote generation 2 must still be deferred"
    );
}

/// Codex review on #278, P1: a missing or unparsable mutation-generation
/// marker must not be treated as safe to remove while the snapshot lease
/// is held. After the lease is released, an unannotated legacy secret is
/// removable again.
#[tokio::test]
async fn held_lease_defers_unmarked_pull_secret_removal() {
    use std::sync::{Arc, Mutex};

    async fn reconcile_unmarked(marker: Option<&str>, lease_held: bool) -> (bool, usize) {
        let mut secret =
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
        if let Some(marker) = marker {
            secret
                .metadata
                .annotations
                .get_or_insert_with(Default::default)
                .insert(
                    enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
                    marker.to_string(),
                );
        }
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![secret],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 5,
                lease_held,
            },
        )
        .await
        .unwrap();
        let remaining = cluster.lock().unwrap().secrets.len();
        (converged, remaining)
    }

    let (converged, remaining) = reconcile_unmarked(None, true).await;
    assert!(
        !converged && remaining == 1,
        "missing marker while the lease is held"
    );
    let (converged, remaining) = reconcile_unmarked(Some("not-a-generation"), true).await;
    assert!(
        !converged && remaining == 1,
        "unparsable marker while the lease is held"
    );
    let (converged, remaining) = reconcile_unmarked(None, false).await;
    assert!(
        converged && remaining == 0,
        "an unmarked secret is legacy residue once the lease is released"
    );
}

#[tokio::test]
async fn scoped_deploy_patch_missing_generation_marker_defers() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "enclava-registry-auth",
            true,
            "cap-bot",
            "ghp_platform",
        )],
        strip_mutation_generation_on_patch: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(4).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "a stripped patch marker must not be treated as a successful write: {error:?}"
    );
    assert_eq!(
        cluster.lock().unwrap().secrets.len(),
        1,
        "a pre-existing secret is not deleted when its patch response is unmarked"
    );
}

#[tokio::test]
async fn scoped_deploy_create_missing_generation_marker_compensates() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        strip_mutation_generation_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::Validation(_)),
        "a create response without the mutation-generation marker must fail closed: {error:?}"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "the unmarked created PAT must be compensated"
    );
}

/// Codex review on #278, P1: the API can accept the Secret POST and stall
/// the response until the apply budget drops the future. Re-read the
/// accepted object and record its UID so the caller's ledger gate persists
/// it. A stripped marker on that same object is compensated instead.
#[tokio::test(start_paused = true)]
async fn scoped_deploy_create_timeout_records_accepted_secret() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_after_accepting_secret_create: true,
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(Arc::clone(&ledger));
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .expect("accepted create whose response stalled must be recovered");
    let pending = ledger.drain_pending();
    assert_eq!(pending.len(), 1, "the recovered UID must be ledgered");
    assert_eq!(pending[0].kind, "Secret");
    assert_eq!(pending[0].mutation_generation, 3);
    assert_eq!(cluster.lock().unwrap().secrets.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn scoped_deploy_create_timeout_compensates_stripped_marker() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_after_accepting_secret_create: true,
        strip_mutation_generation_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "an accepted but unmarked create must not be reported as success: {error:?}"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "the unmarked accepted PAT must be compensated before the deferred error"
    );
}

#[test]
fn nonpositive_generation_markers_are_invalid_not_ownership() {
    // Codex review on #280, P1: a webhook rewriting the annotation to 0 or
    // a negative must fall into the missing-marker branch — real
    // generations are positive — instead of comparing as "older than" an
    // active lease and escaping its protection.
    let held = PullSecretDeleteMode::Unfenced {
        namespace_generation: 5,
        lease_held: true,
    };
    let released = PullSecretDeleteMode::Unfenced {
        namespace_generation: 5,
        lease_held: false,
    };
    for mode in [held, released] {
        let missing = observed_generation_blocks_removal(mode, None);
        let missing_owns = observed_concurrent_deploy_owns(mode, None);
        for invalid in [Some(0), Some(-3), Some(i64::MIN)] {
            assert_eq!(
                observed_generation_blocks_removal(mode, invalid),
                missing,
                "nonpositive markers must behave exactly like missing ones"
            );
            assert_eq!(
                observed_concurrent_deploy_owns(mode, invalid),
                missing_owns,
                "nonpositive markers must behave exactly like missing ones"
            );
        }
    }
    // Positive markers keep their real ownership semantics: a generation
    // strictly below the snapshot never blocks removal.
    assert!(!observed_generation_blocks_removal(
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: true,
        },
        Some(4)
    ));
}

#[tokio::test(start_paused = true)]
async fn armed_transport_error_routes_through_ambiguity_recovery() {
    use std::sync::{Arc, Mutex};
    // Codex review on #280, P1 "Recover ambiguous POST transport failures
    // before returning": the create is ACCEPTED (stored) and the response
    // fails at the transport — as ambiguous as a timeout. The armed
    // failure must reach recovery, which dispositions the stored object
    // (here: evidence-untrusted via a stripped creation annotation, so the
    // nonce-proven compensation removes it) instead of leaving an
    // untracked platform PAT behind.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        transport_error_after_accepting_secret_create: true,
        strip_creation_evidence_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "an armed transport failure must resolve its ambiguity before returning: {error:?}"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "the stored create must be dispositioned by recovery, not left untracked"
    );
}

#[tokio::test(start_paused = true)]
async fn failed_compensation_stays_armed_for_recovery() {
    use std::sync::{Arc, Mutex};
    // Codex review on #280, P1 "Keep confirmed-create compensation armed
    // until removal": the create comes back without trusted evidence and
    // the compensating DELETE never removes anything. The candidate must
    // stay armed, so the outer timeout's recovery re-attempts the
    // compensation (delete attempts: the apply's own + recovery's).
    let cluster = Arc::new(Mutex::new(FakeCluster {
        strip_creation_evidence_on_create: true,
        noop_secret_deletes: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "an unremoved platform PAT must surface as deferred, not success: {error:?}"
    );
    assert!(
        cluster.lock().unwrap().secret_delete_attempts >= 2,
        "the owed compensation must stay armed: recovery re-attempts the delete"
    );
}

#[tokio::test(start_paused = true)]
async fn recovery_tolerates_transient_probe_errors() {
    use std::sync::{Arc, Mutex};
    // Codex review on #280, round 3: a transient recovery-read failure
    // (timeout, 5xx) must not abandon the late-commit loop — the create
    // may still commit under the normal apiserver timeout and its UID
    // would never be recorded. One 500 on the first probe, then the
    // stored object: recovery keeps probing and records it.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        transport_error_after_accepting_secret_create: true,
        fail_secret_gets_left: 1,
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(ledger.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::Apply(_)),
        "the transport error is the real outcome once recovery resolved the ambiguity: {error:?}"
    );
    let pending = ledger.drain_pending();
    assert_eq!(
        pending.len(),
        1,
        "a transient probe error must not abandon recording the committed create"
    );
}

#[tokio::test(start_paused = true)]
async fn recovery_compensates_label_stripped_nonce_proven_create() {
    use std::sync::{Arc, Mutex};
    // Codex review on #280, round 3: a webhook stripping the dedicated
    // label (but not the nonce) from an ambiguously accepted create must
    // not strand the platform PAT — neither recorded nor deleted. The
    // nonce is the request-specific proof; compensation runs.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        transport_error_after_accepting_secret_create: true,
        strip_pull_secret_label_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "a compensated create defers the deploy for a clean retry: {error:?}"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "a nonce-proven create must not be stranded by label stripping"
    );
}

#[tokio::test]
async fn armed_transport_recovery_persists_before_step_error() {
    // Codex review on #280, round 3: when the armed transport error is
    // recovered by RECORDING the created Secret, the durable creation
    // ledger must be persisted even though the apply step itself fails —
    // previously the `?` exited apply_all before any persistence gate,
    // leaving the UID memory-only (failure cleanup could not prove
    // provenance).
    let _reset = ResetStaleRolloutAuthority;
    let pool = crate::test_support::database_test_pool().await;
    sqlx::query(
            "UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0",
        )
        .execute(&pool)
        .await
        .unwrap();
    let org_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let suffix = app_id.simple().to_string();
    let namespace = format!("codex-persist-{}", &suffix[..12]);
    sqlx::query("DELETE FROM tenant_pull_secret_scope_fences WHERE namespace = $1")
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    unsafe {
        std::env::set_var("TENANT_IMAGE_PULL_SCOPE_GENERATION", "1");
        std::env::set_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION", "1");
    }
    sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(format!("codex-persist-{org_id}"))
        .bind(&suffix[..8])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                 status, egress_allowlist, egress_mode, created_at, updated_at
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, 'auto',
                 $10, $11, 'creating', '[]'::jsonb, 'restricted',
                 clock_timestamp(), clock_timestamp()
             )",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(format!("codex-persist-{}", &suffix[..12]))
    .bind(&namespace)
    .bind(&suffix[..8])
    .bind(format!("codex-persist-{suffix}"))
    .bind(format!("codex-persist-{}-sa", &suffix[..12]))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("codex-persist-{}.example.test", &suffix[..12]))
    .bind(format!("codex-persist-{}.tee.example.test", &suffix[..12]))
    .execute(&pool)
    .await
    .unwrap();
    let cluster = Arc::new(Mutex::new(FakeCluster {
        transport_error_after_accepting_secret_create: true,
        echo_namespace_generation: Some(2),
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(ledger.clone());
    let manifests = stale_rollout_manifests(&namespace);
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let (_lost_tx, lost_rx) = tokio::sync::watch::channel(false);
    let mutation =
        crate::mutation_leases::tests::test_app_mutation_lease_for_pool(pool.clone(), lost_rx);
    let error = apply_all_with_tenant_image_pull_secret(
        &engine,
        &pool,
        app_id,
        Uuid::nil(),
        &manifests,
        "hash",
        Some(&config),
        MutationGeneration::new(2).unwrap(),
        &mutation,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, DeployError::Apply(_)),
        "the transport error is the real outcome once recovery recorded the create: {error:?}"
    );
    // The gate drains the ledger as it persists, so the proof is the
    // durable row itself — keyed by the app, written before the step's
    // error propagated out of apply_all.
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM resource_creation_ledger WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        persisted, 1,
        "the gate must persist the recovered creation record BEFORE the step error propagates"
    );
    pool.close().await;
}

#[tokio::test(start_paused = true)]
async fn scoped_deploy_create_timeout_keeps_other_writers_secret() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        stall_after_accepting_secret_create: true,
        replace_mutation_generation_on_create: Some(9),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_platform".to_string(),
        allowed_repositories: Vec::new(),
    };
    let error = apply_scoped_pull_secret(
        &engine,
        "tenant-ns",
        &config,
        MutationGeneration::new(3).unwrap(),
        &[],
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, DeployError::PullSecretReconcileDeferred(_)));
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(secret_mutation_generation(&state.secrets[0]), Some(9));
}

#[tokio::test]
async fn publish_missing_namespace_lease_does_not_clobber_a_claim() {
    let pool = crate::test_support::database_test_pool().await;
    let fresh = format!("pub{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let held = format!("hld{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let owner = uuid::Uuid::new_v4();
    let operation_id = uuid::Uuid::new_v4();
    let cleanup = async {
        sqlx::query(
            "DELETE FROM external_resource_mutation_leases \
                 WHERE resource_scope = 'kubernetes_namespace' \
                   AND resource_key IN ($1, $2)",
        )
        .bind(&fresh)
        .bind(&held)
        .execute(&pool)
        .await
        .ok();
    };
    let inserted = publish_missing_namespace_pull_secret_lease(&pool, &fresh)
        .await
        .expect("publish missing lease");
    assert!(inserted, "first publish inserts the released row");
    let again = publish_missing_namespace_pull_secret_lease(&pool, &fresh)
        .await
        .expect("second publish");
    assert!(!again, "a second publish must not bump or replace the row");
    let (generation, owner_token): (i64, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT generation, owner_token FROM external_resource_mutation_leases \
             WHERE resource_scope = 'kubernetes_namespace' AND resource_key = $1",
    )
    .bind(&fresh)
    .fetch_one(&pool)
    .await
    .expect("load published lease");
    assert_eq!(generation, SWEEP_CREATED_PULL_SECRET_GENERATION);
    assert!(owner_token.is_none(), "the published row is released");

    sqlx::query(
        "INSERT INTO external_resource_mutation_leases(\
                resource_scope, resource_key, generation, owner_token, \
                operation_kind, operation_id, locked_until, reclaim_after) \
             VALUES (\
                'kubernetes_namespace', $1, 5, $2, 'deployment_apply', $3, \
                clock_timestamp() + interval '30 seconds', \
                clock_timestamp() + interval '90 seconds')",
    )
    .bind(&held)
    .bind(owner)
    .bind(operation_id)
    .execute(&pool)
    .await
    .expect("insert held lease");
    let raced = publish_missing_namespace_pull_secret_lease(&pool, &held)
        .await
        .expect("publish against a claim");
    assert!(!raced, "a held claim wins the insert race");
    let held_generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM external_resource_mutation_leases \
             WHERE resource_scope = 'kubernetes_namespace' AND resource_key = $1",
    )
    .bind(&held)
    .fetch_one(&pool)
    .await
    .expect("load held lease");
    assert_eq!(held_generation, 5);
    cleanup.await;
}

/// Codex review on #278, P1: the deploy that just wrote the configured
/// Secret at this generation must not treat that marker as a concurrent
/// deploy. In a mixed-scope namespace the out-of-scope account's reference
/// has to be cleared, or `repaired` becomes a terminal validation error
/// and every retry repeats it.
#[tokio::test]
async fn deploy_owned_generation_clears_mixed_scope_out_of_scope_reference() {
    use std::sync::{Arc, Mutex};

    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "5".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![
            fake_service_account("cap-in", &["enclava-registry-auth"]),
            fake_service_account("cap-out", &["enclava-registry-auth"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let accounts = ["cap-in".to_string(), "cap-out".to_string()];
    let mixed = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-in".to_string()].into_iter().collect(),
    };
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &reconcile_settings(),
            &mixed,
            PullSecretDeleteMode::DeployOwned { generation: 5 },
        )
        .await
        .unwrap(),
        "the deploy's own generation must not defer mixed-scope cleanup"
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1, "the configured secret stays");
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the in-scope account keeps its reference"
        );
        assert!(
            state.service_accounts[1]
                .image_pull_secrets
                .as_ref()
                .is_none_or(|references| references.is_empty()),
            "the out-of-scope account's reference is cleared"
        );
    }

    // A strictly newer marker is still someone else, even on the deploy's
    // own pass.
    let mut newer = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    newer
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "9".to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![newer],
        service_accounts: vec![
            fake_service_account("cap-in", &["enclava-registry-auth"]),
            fake_service_account("cap-out", &["enclava-registry-auth"]),
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(
        !reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &reconcile_settings(),
            &mixed,
            PullSecretDeleteMode::DeployOwned { generation: 5 },
        )
        .await
        .unwrap(),
        "a newer generation is still a concurrent deploy"
    );
    assert_eq!(
        cluster.lock().unwrap().service_accounts[1]
            .image_pull_secrets
            .as_ref()
            .map(|references| references.len()),
        Some(1),
        "the newer generation's out-of-scope reference is left for the next sweep"
    );
}

/// Devin review on #278 (SEC, "Out-of-scope app regains platform credential",
/// review 5560886851 on 00b72ae0). A concurrent deploy rewrites the
/// UID-proven pending-repair Secret, so the delete returns `Superseded`.
/// The object is still platform-managed. Restoring the out-of-scope
/// account's reference would hand it the platform credential despite the
/// narrowed scope. 7dd5cb32 stopped that restore; this pins it.
#[tokio::test(start_paused = true)]
async fn superseded_pending_repair_does_not_restore_out_of_scope_platform_credential() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "1".to_string(),
        );
    let mut account = fake_service_account("cap-out", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-enclava-registry-auth".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![account],
        annotate_generation_on_delete: Some(9),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-out".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a superseded pending removal must stay open for the next sweep"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets.len(),
        1,
        "the rewritten object is still the platform-managed secret"
    );
    assert!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .is_none_or(|refs| refs.is_empty()),
        "Superseded must not restore the out-of-scope account's reference"
    );
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[0]).len(),
        1,
        "the durable discovery proof must be retained"
    );
}

/// Devin review on #278 (bug, "Fresh deployment reference cleared mid-sweep").
/// The generation check passes, then a deploy attaches the reference. The
/// clear reads that latest ServiceAccount, so its resourceVersion cannot
/// detect the stale scope decision.
#[tokio::test]
async fn fresh_deploy_reference_attached_after_generation_check_is_not_cleared() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret.metadata.annotations = Some(std::collections::BTreeMap::from([(
        enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
        "1".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![
            fake_service_account("cap-in", &["enclava-registry-auth"]),
            fake_service_account("cap-out", &[]),
        ],
        fresh_reference_after_secret_gets: Some(FreshReferenceAfterSecretGets {
            arm_after_named_secret_gets: 1,
            named_secret_gets: 0,
            armed: false,
            service_account: "cap-out".to_string(),
            secret_name: "enclava-registry-auth".to_string(),
            generation: 9,
        }),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["cap-in".to_string()].into_iter().collect(),
    };
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-in".to_string(), "cap-out".to_string()],
        &reconcile_settings(),
        &scope,
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 5,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "clearing a reference attached after the generation check must defer"
    );
    let state = cluster.lock().unwrap();
    let out = state
        .service_accounts
        .iter()
        .find(|account| account.metadata.name.as_deref() == Some("cap-out"))
        .unwrap();
    assert!(
        out.image_pull_secrets.as_ref().is_some_and(|refs| {
            refs.iter()
                .any(|reference| reference.name == "enclava-registry-auth")
        }),
        "a reference attached after the generation check must survive the sweep"
    );
}

#[tokio::test]
async fn generation_rewrite_during_reference_patch_restores_and_defers() {
    use std::sync::{Arc, Mutex};
    for (actual, lease_held) in [(9, false), (5, true)] {
        let mut secret =
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
        let mut rewritten = secret.clone();
        let key = enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION;
        secret
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(key.to_string(), "1".to_string());
        rewritten
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(key.to_string(), actual.to_string());
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![secret],
            service_accounts: vec![fake_service_account("cap-out", &["enclava-registry-auth"])],
            // Same UID, no ServiceAccount resourceVersion change: deploy's
            // reference apply was a no-op while its Secret write landed.
            replace_on_sa_patch: Some(rewritten),
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        assert!(matches!(
            clear_pull_secret_reference_from_service_account(
                &engine,
                "tenant-ns",
                "cap-out",
                "enclava-registry-auth",
                Some("uid-enclava-registry-auth"),
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: 5,
                    lease_held
                },
            )
            .await,
            Err(DeployError::PullSecretReconcileDeferred(_))
        ));
        let state = cluster.lock().unwrap();
        assert!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()
                .iter()
                .any(|reference| reference.name == "enclava-registry-auth")
        );
        assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
    }
}

#[tokio::test]
async fn pending_repair_from_newer_scope_keeps_uid_proof_and_reference_cleared() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
            u64::MAX.to_string(),
        );
    let mut account = fake_service_account("cap-tenant-app", &[]);
    account.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-enclava-registry-auth".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![account],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(matches!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: i64::MAX,
                lease_held: false,
            },
        )
        .await,
        Err(DeployError::PullSecretReconcileDeferred(_))
    ));
    let state = cluster.lock().unwrap();
    assert!(state.service_accounts[0].image_pull_secrets.is_none());
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[0]).len(),
        1
    );
    assert_eq!(state.secrets.len(), 1);
}

#[tokio::test]
async fn referenced_old_name_is_refreshed_after_rotation() {
    use std::sync::{Arc, Mutex};
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "old-pull-secret",
            true,
            "cap-bot",
            "ghp_old",
        )],
        service_accounts: vec![fake_service_account("cap-tenant-app", &["old-pull-secret"])],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let settings = reconcile_settings();
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &settings,
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].data.as_ref().unwrap()[".dockerconfigjson"].0,
        settings.configured_secret_data.unwrap().into_bytes()
    );
}

#[tokio::test]
async fn older_scope_replica_cannot_clear_or_delete_newer_scope_secret() {
    use std::sync::{Arc, Mutex};
    let mut live = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    live.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
            u64::MAX.to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![live],
        service_accounts: vec![fake_service_account(
            "cap-tenant-app",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    assert!(matches!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(false),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: i64::MAX,
                lease_held: false,
            },
        )
        .await,
        Err(DeployError::PullSecretReconcileDeferred(_))
    ));
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn empty_namespace_rejects_unmarked_created_pull_secret() {
    use std::sync::{Arc, Mutex};

    for (strip_label, strip_manager, lingering_polls) in
        [(true, false, 0), (false, true, 0), (true, false, 2)]
    {
        let cluster = Arc::new(Mutex::new(FakeCluster {
            service_accounts: vec![fake_service_account("cap-tenant-app", &[])],
            strip_pull_secret_label_on_create: strip_label,
            strip_field_manager_on_create: strip_manager,
            delete_lingering_polls: lingering_polls,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster);
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: i64::MAX,
                lease_held: false,
            },
        )
        .await
        .unwrap();
        assert!(!converged);
        let secrets: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
        assert!(
            secrets
                .get_opt("enclava-registry-auth")
                .await
                .unwrap()
                .is_none()
        );
        let accounts: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), "tenant-ns");
        let account = accounts.get("cap-tenant-app").await.unwrap();
        assert!(
            account
                .image_pull_secrets
                .as_ref()
                .is_none_or(Vec::is_empty)
        );
    }
}
/// Codex review on #243, round 3, P1 "Attribute created Secrets to the
/// platform field manager": the sweep's 404-recreate POST must stamp the
/// engine field manager (not `PostParams::default()`), and a create that
/// comes back WITHOUT that attribution (mutating webhook) must be
/// deleted (pinned) and keep the pass unconverged — an unattributable
/// platform PAT must not land in a tenant namespace.

#[tokio::test]
async fn sweep_recreate_attributes_and_verifies_field_manager_ownership() {
    use std::sync::{Arc, Mutex};
    let pending_intent = |uid: &str| {
        let mut account = fake_service_account("cap-tenant-app", &[]);
        account.metadata.annotations = Some(std::collections::BTreeMap::from([(
            PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
            format!("enclava-registry-auth={uid}"),
        )]));
        account
    };

    // (a) Attributed create: the fake API server records the request's
    // fieldManager; the secret is kept and the reference restored.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![],
        service_accounts: vec![pending_intent("uid-previous-object")],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let expected_manager = engine.config().field_manager.clone();
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            &PullSecretAccountScope::uniform(true),
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "attributed recreate keeps the secret"
        );
        let managers: Vec<String> = state.secrets[0]
            .metadata
            .managed_fields
            .as_ref()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.manager.clone())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            managers.contains(&expected_manager),
            "recreated secret must be attributed to the platform field manager \
                 {expected_manager}, got {managers:?}"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()[0]
                .name,
            "enclava-registry-auth"
        );
    }

    // (b) Stripped attribution: the recreated secret is deleted and the
    // pass stays unconverged.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![],
        service_accounts: vec![pending_intent("uid-previous-object")],
        strip_field_manager_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "an unattributable platform PAT must keep the sweep unconverged"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "the unattributed recreated secret must be deleted"
    );

    // Admission can strip the dedicated label while leaving the manager entry.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![],
        service_accounts: vec![pending_intent("uid-previous-object")],
        strip_pull_secret_label_on_create: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a recreated PAT missing the dedicated pull-secret label must keep \
             the sweep unconverged even when the platform manager entry survives"
    );
    assert!(
        cluster.lock().unwrap().secrets.is_empty(),
        "the unlabeled recreated secret must be deleted"
    );

    // DELETE acceptance does not prove absence while a finalizer holds the Secret.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![],
        service_accounts: vec![pending_intent("uid-previous-object")],
        strip_pull_secret_label_on_create: true,
        delete_lingering_polls: 2,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(true),
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "an unlabeled recreated secret is still deleted; the pass is \
             unconverged because the namespace never gained the credential"
    );
    let state = cluster.lock().unwrap();
    assert!(
        state.secrets.is_empty(),
        "the compensation must wait out the finalizer to a real 404"
    );
}

#[tokio::test]
async fn empty_fleet_publishes_rollout_authority_before_inventory() {
    let pool = crate::test_support::database_test_pool().await;
    sqlx::query(
            "UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0",
        )
        .execute(&pool)
        .await
        .unwrap();
    unsafe {
        std::env::set_var("TENANT_IMAGE_PULL_SCOPE_GENERATION", "8");
        std::env::set_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION", "4");
    }
    // The authority is published before any inventory or Kubernetes work.
    let client = kube::Client::try_from(kube::Config::new(
        "http://127.0.0.1:9".parse().expect("static test url"),
    ))
    .expect("test kube client");
    let _ = cleanup_stale_tenant_image_pull_secrets(&pool, &client).await;
    unsafe {
        std::env::remove_var("TENANT_IMAGE_PULL_SCOPE_GENERATION");
        std::env::remove_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION");
    }
    let maxima = raise_tenant_pull_secret_rollout_authority(&pool, 0, 0)
        .await
        .unwrap();
    assert_eq!(maxima, (8, 4));
    sqlx::query(
            "UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0",
        )
        .execute(&pool)
        .await
        .unwrap();
}

/// Codex review on #243, round 3, P1 "Stop stale-scope replicas from
/// dispatching new namespaces" + P1 "Fence pull-secret creation against
/// credential rollouts": the rollout-wide authority is monotonic (a
/// stale replica can never rewind it) and defers a replica that is older
/// on EITHER epoch — the new-namespace hole (no per-namespace fence row
/// yet) and the absent-Secret credential hole (no annotation epoch to
/// compare against) both collapse into this check.
#[tokio::test]
async fn rollout_authority_defers_stale_replicas_and_never_rewinds() {
    let pool = crate::test_support::database_test_pool().await;
    let (scope, credential) = raise_tenant_pull_secret_rollout_authority(&pool, 0, 0)
        .await
        .unwrap();
    assert_eq!(
        (scope, credential),
        (0, 0),
        "a fresh authority starts at zero and never defers an epoch-0 replica"
    );
    let (scope, credential) = raise_tenant_pull_secret_rollout_authority(&pool, 5, 2)
        .await
        .unwrap();
    assert_eq!((scope, credential), (5, 2));
    let (scope, credential) = raise_tenant_pull_secret_rollout_authority(&pool, 3, 1)
        .await
        .unwrap();
    assert_eq!(
        (scope, credential),
        (5, 2),
        "a stale replica's stamp must never rewind the fleet-wide maxima"
    );

    unsafe {
        std::env::set_var("TENANT_IMAGE_PULL_SCOPE_GENERATION", "3");
        std::env::set_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION", "1");
    }
    assert!(
        pull_secret_rollout_authority_defers(5, 2),
        "older on both epochs"
    );
    assert!(
        pull_secret_rollout_authority_defers(5, 0),
        "a newer scope epoch alone defers — the new-namespace hole (no fence row)"
    );
    assert!(
        pull_secret_rollout_authority_defers(0, 2),
        "a newer credential epoch alone defers — the absent-Secret hole (no annotation)"
    );
    assert!(
        !pull_secret_rollout_authority_defers(3, 1),
        "the current replica proceeds"
    );
    assert!(
        !pull_secret_rollout_authority_defers(2, 0),
        "an older recorded authority never blocks a newer replica"
    );
    unsafe {
        std::env::remove_var("TENANT_IMAGE_PULL_SCOPE_GENERATION");
        std::env::remove_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION");
    }
}

fn stale_rollout_manifests(namespace: &str) -> enclava_engine::manifest::GeneratedManifests {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::{ConfigMap, ResourceQuota, Service};
    enclava_engine::manifest::GeneratedManifests {
        namespace: k8s_openapi::api::core::v1::Namespace {
            metadata: ObjectMeta {
                name: Some(namespace.to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
        service_account: ServiceAccount {
            metadata: ObjectMeta {
                name: Some("cap-tenant-app".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
        network_policy: serde_json::Value::Null,
        resource_quota: ResourceQuota::default(),
        service: Service::default(),
        sni_route_configmap: ConfigMap::default(),
        envoy_proxy: serde_json::Value::Null,
        gateway: serde_json::Value::Null,
        tls_route: serde_json::Value::Null,
        tee_tls_route: serde_json::Value::Null,
        bootstrap_configmap: ConfigMap::default(),
        startup_configmap: ConfigMap::default(),
        ingress_configmap: ConfigMap::default(),
        enclava_init_configmap: ConfigMap::default(),
        verification_material_configmap: None,
        statefulset: StatefulSet::default(),
        kbs_owner_binding: (String::new(), serde_json::Value::Null),
    }
}

fn reset_stale_rollout_authority_blocking() {
    unsafe {
        std::env::remove_var("TENANT_IMAGE_PULL_SCOPE_GENERATION");
        std::env::remove_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION");
    }
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let _ = std::process::Command::new("psql")
        .env("PGPASSWORD", "test")
        .arg(&url)
        .arg("-v")
        .arg("ON_ERROR_STOP=1")
        .arg("-c")
        .arg(
            "UPDATE tenant_pull_secret_rollout_authority \
                 SET max_scope_epoch = 0, max_credential_epoch = 0; \
                 DELETE FROM tenant_pull_secret_scope_fences \
                 WHERE namespace = 'devin-stale-rollout-ns'",
        )
        .output();
}

struct ResetStaleRolloutAuthority;
impl Drop for ResetStaleRolloutAuthority {
    fn drop(&mut self) {
        reset_stale_rollout_authority_blocking();
    }
}

/// Devin review on #278 (SEC, "Stale rollout resurrects narrowed credentials").
/// An older replica passes `raise_tenant_pull_secret_rollout_authority`,
/// then a narrowing rollout deletes the secret and raises the epoch. The
/// later create-on-404 must re-check that epoch and must not recreate the
/// platform secret.
#[tokio::test]
async fn rollout_transition_waits_for_deploy_and_sweep_mutation_guards() {
    let _reset = ResetStaleRolloutAuthority;
    let pool = crate::test_support::database_test_pool().await;
    sqlx::query("UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0")
            .execute(&pool).await.unwrap();
    // Deploy and sweep both hold this guard across Secret writes and
    // reference repairs, including the sweep's create-on-404 path.
    let deploy = pull_secret_mutation_guard(&pool).await.unwrap();
    let sweep = pull_secret_mutation_guard(&pool).await.unwrap();
    let other_pool = pool.clone();
    let mut transition =
        tokio::spawn(
            async move { raise_tenant_pull_secret_rollout_authority(&other_pool, 9, 9).await },
        );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut transition)
            .await
            .is_err()
    );
    deploy.rollback().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut transition)
            .await
            .is_err()
    );
    // Same-epoch rechecks do not deadlock behind the waiting transition.
    ensure_pull_secret_rollout_authority_current(&pool)
        .await
        .unwrap();
    sweep.rollback().await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), transition)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        (9, 9)
    );
    assert!(matches!(
        pull_secret_mutation_guard(&pool).await,
        Err(DeployError::PullSecretReconcileDeferred(_))
    ));
    pool.close().await;
}

#[tokio::test]
async fn pull_secret_mutation_guard_keeps_its_lock_while_idle() {
    let _reset = ResetStaleRolloutAuthority;
    let pool = crate::test_support::database_test_pool().await;
    sqlx::query("UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0")
            .execute(&pool).await.unwrap();
    let guarded_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET idle_in_transaction_session_timeout = '50ms'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let guard = pull_secret_mutation_guard(&guarded_pool).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let mut transition = pool.begin().await.unwrap();
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(278225)")
        .fetch_one(&mut *transition)
        .await
        .unwrap();
    assert!(
        !acquired,
        "idle timeout released authority during a mutation"
    );
    guard.rollback().await.unwrap();
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(278225)")
        .fetch_one(&mut *transition)
        .await
        .unwrap();
    assert!(
        acquired,
        "authority transition remained blocked after mutation"
    );
    transition.rollback().await.unwrap();
    guarded_pool.close().await;
    pool.close().await;
}

#[tokio::test]
async fn stale_replica_does_not_recreate_secret_deleted_by_newer_rollout() {
    let _reset = ResetStaleRolloutAuthority;
    let pool = crate::test_support::database_test_pool().await;
    sqlx::query(
            "UPDATE tenant_pull_secret_rollout_authority SET max_scope_epoch = 0, max_credential_epoch = 0",
        )
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tenant_pull_secret_scope_fences WHERE namespace = $1")
        .bind("devin-stale-rollout-ns")
        .execute(&pool)
        .await
        .unwrap();
    unsafe {
        std::env::set_var("TENANT_IMAGE_PULL_SCOPE_GENERATION", "1");
        std::env::set_var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION", "1");
    }
    let cluster = Arc::new(Mutex::new(FakeCluster {
        echo_namespace_generation: Some(2),
        raise_rollout_authority_on_secret_get: Some((9, 9)),
        rollout_authority_pool: Some(pool.clone()),
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let manifests = stale_rollout_manifests("devin-stale-rollout-ns");
    let config = TenantImagePullSecretConfig {
        name: "enclava-registry-auth".to_string(),
        username: "cap-bot".to_string(),
        token: "ghp_broad".to_string(),
        allowed_repositories: Vec::new(),
    };
    let (_lost_tx, lost_rx) = tokio::sync::watch::channel(false);
    let mutation =
        crate::mutation_leases::tests::test_app_mutation_lease_for_pool(pool.clone(), lost_rx);
    let error = apply_all_with_tenant_image_pull_secret(
        &engine,
        &pool,
        Uuid::nil(),
        Uuid::nil(),
        &manifests,
        "hash",
        Some(&config),
        MutationGeneration::new(2).unwrap(),
        &mutation,
    )
    .await
    .unwrap_err();
    let secret_count = cluster.lock().unwrap().secrets.len();
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)) && secret_count == 0,
        "a newer epoch published after the pre-write check must defer the create, got {error:?}; secrets={secret_count}"
    );
}

/// Reviewer follow-up on #243 (Critical): the per-deploy reconcile (the
/// Fenced path) must NOT run the repair pass — its own SSA of the
/// generated ServiceAccount is about to re-decide `imagePullSecrets`, so
/// an up-front restore would be pruned and the record lost. Instead the
/// deploy discharges stale intents after its applies.
#[tokio::test]
async fn deploy_reconcile_skips_repair_and_discharges_stale_intent_after_apply() {
    use std::sync::{Arc, Mutex};

    // A stale intent from an earlier sweep: a replacement lives under the
    // name (a sweep would restore the reference), and the recorded UID
    // no longer matches anything.
    let mut stale_intent = fake_service_account("cap-tenant-app", &[]);
    stale_intent.metadata.annotations = Some(std::collections::BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-long-gone".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_replacement_secret("enclava-registry-auth")],
        service_accounts: vec![stale_intent],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());

    // The deploy-path reconcile (Fenced) neither restores the reference
    // nor touches the intent.
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        &reconcile_settings(),
        &PullSecretAccountScope::uniform(false),
        PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
    )
    .await
    .unwrap();
    assert!(converged);
    {
        let state = cluster.lock().unwrap();
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            0,
            "the deploy-path reconcile must not restore ahead of its own ServiceAccount apply"
        );
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]).len(),
            1,
            "the deploy-path reconcile leaves the intent to the post-apply discharge"
        );
    }

    // A deploy of a different configured name must not forget the UID
    // ownership proof for a renamed pre-label secret.
    discharge_reference_repair_intent_after_deploy(
        &engine,
        "tenant-ns",
        &["cap-tenant-app".to_string()],
        "different-configured-name",
    )
    .await
    .unwrap();
    let state = cluster.lock().unwrap();
    assert_eq!(
        pending_reference_repairs(&state.service_accounts[0]).len(),
        1,
        "the renamed secret's UID repair stays durable"
    );
    assert_eq!(
        state.service_accounts[0]
            .image_pull_secrets
            .as_ref()
            .map_or(0, |references| references.len()),
        0,
        "the deploy's decision stands: no reference"
    );
}

fn image_pull_secret_names(account: &ServiceAccount) -> BTreeSet<String> {
    account
        .image_pull_secrets
        .iter()
        .flatten()
        .map(|reference| reference.name.clone())
        .collect()
}

/// Codex review on #276, P1: an older replica that loses the create race
/// must recheck the winner's scope epoch. Accepting a placeable newer
/// rollout and attaching it to this replica's broader account set exposes
/// the platform credential to accounts the narrowing excluded.
#[tokio::test]
async fn create_conflict_defers_when_winner_has_newer_scope_epoch() {
    use std::sync::{Arc, Mutex};
    let mut winner = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    winner.metadata.uid = Some("uid-newer-rollout".to_string());
    winner
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
            pull_secret_scope_generation().saturating_add(1).to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        service_accounts: vec![
            fake_service_account("broad-in-scope", &[]),
            fake_service_account("narrowed-out", &[]),
        ],
        inject_secret_on_create: Some(winner),
        ..Default::default()
    }));
    let error = reconcile_managed_pull_secrets(
        &reconcile_engine(cluster.clone()),
        "tenant-ns",
        &["broad-in-scope".into(), "narrowed-out".into()],
        &reconcile_settings(),
        &PullSecretAccountScope {
            namespace_in_scope: true,
            in_scope_accounts: ["broad-in-scope".into()].into(),
        },
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .expect_err("a newer scope epoch after create conflict must defer");
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "got {error:?}"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(
        state.secrets[0].metadata.uid.as_deref(),
        Some("uid-newer-rollout"),
        "the newer rollout's object must not be replaced"
    );
    for account in &state.service_accounts {
        assert!(
            image_pull_secret_names(account).is_empty(),
            "{} must not receive the newer secret under the stale scope",
            account.metadata.name.as_deref().unwrap_or("")
        );
    }
}

/// A same-epoch create conflict is still a usable configured secret. The
/// epoch recheck must not defer every 409.
#[tokio::test]
async fn create_conflict_same_epoch_still_attaches_in_scope_accounts() {
    use std::sync::{Arc, Mutex};
    let mut winner = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    winner.metadata.uid = Some("uid-same-epoch".to_string());
    winner
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
            pull_secret_scope_generation().to_string(),
        );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        service_accounts: vec![
            fake_service_account("in-scope", &[]),
            fake_service_account("out-of-scope", &[]),
        ],
        inject_secret_on_create: Some(winner),
        ..Default::default()
    }));
    assert!(
        reconcile_managed_pull_secrets(
            &reconcile_engine(cluster.clone()),
            "tenant-ns",
            &["in-scope".into(), "out-of-scope".into()],
            &reconcile_settings(),
            &PullSecretAccountScope {
                namespace_in_scope: true,
                in_scope_accounts: ["in-scope".into()].into(),
            },
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state.secrets[0].metadata.uid.as_deref(),
        Some("uid-same-epoch")
    );
    assert_eq!(
        image_pull_secret_names(&state.service_accounts[0]),
        BTreeSet::from(["enclava-registry-auth".to_string()])
    );
    assert!(image_pull_secret_names(&state.service_accounts[1]).is_empty());
}

/// Codex review on #276, P2: a kept configured secret with a
/// deletionTimestamp does not satisfy reconciliation. Do not attach it or
/// report convergence; after it is gone, the next pass recreates and
/// attaches the configured secret.
#[tokio::test]
async fn terminating_configured_secret_does_not_satisfy_reconciliation() {
    use std::sync::{Arc, Mutex};
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
    secret.metadata.deletion_timestamp = Some(
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::jiff::Timestamp::now()),
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![secret],
        service_accounts: vec![
            fake_service_account("already", &["enclava-registry-auth"]),
            fake_service_account("waiting", &[]),
            fake_service_account("excluded", &["enclava-registry-auth"]),
        ],
        lingering_polls_left: 40,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let accounts = ["already".into(), "waiting".into(), "excluded".into()];
    let scope = PullSecretAccountScope {
        namespace_in_scope: true,
        in_scope_accounts: ["already".into(), "waiting".into()].into(),
    };
    let settings = reconcile_settings();
    let converged = reconcile_managed_pull_secrets(
        &engine,
        "tenant-ns",
        &accounts,
        &settings,
        &scope,
        PullSecretDeleteMode::Unfenced {
            namespace_generation: 0,
            lease_held: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !converged,
        "a terminating configured secret must keep the pass unconverged"
    );
    {
        let mut state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert!(state.secrets[0].metadata.deletion_timestamp.is_some());
        assert_eq!(
            image_pull_secret_names(&state.service_accounts[0]),
            BTreeSet::from(["enclava-registry-auth".to_string()]),
            "an existing in-scope reference is left in place while the finalizer holds the secret"
        );
        assert!(
            image_pull_secret_names(&state.service_accounts[1]).is_empty(),
            "do not attach a terminating secret to an account that lacks it"
        );
        assert!(
            pending_reference_repairs(&state.service_accounts[2]).is_empty(),
            "do not record the dying UID; a later recreate would be restored as a replacement"
        );
        state.secrets.clear();
    }
    // Recovery uses the next sweep's completed namespace-lease snapshot.
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &settings,
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 1,
                lease_held: false,
            },
        )
        .await
        .unwrap(),
        "once removal completes, the same pass recreates and attaches"
    );
    let state = cluster.lock().unwrap();
    assert_eq!(state.secrets.len(), 1);
    assert!(state.secrets[0].metadata.deletion_timestamp.is_none());
    assert!(is_labeled_managed_pull_secret(&state.secrets[0]));
    assert_eq!(
        image_pull_secret_names(&state.service_accounts[0]),
        BTreeSet::from(["enclava-registry-auth".to_string()])
    );
    assert_eq!(
        image_pull_secret_names(&state.service_accounts[1]),
        BTreeSet::from(["enclava-registry-auth".to_string()])
    );
    assert!(
        image_pull_secret_names(&state.service_accounts[2]).is_empty(),
        "the recreated secret must not be attached to the excluded account"
    );
}

/// Codex review on #276, P2: in a shared namespace that still has both the
/// configured secret and a referenced old name, attach the configured name
/// to newly qualifying accounts, but do not spread the legacy name. After
/// the original account drops that name, rename cleanup must remove it.
#[tokio::test]
async fn legacy_pull_secret_is_not_attached_to_unrelated_accounts() {
    use std::sync::{Arc, Mutex};
    let mut pending = fake_service_account("pending-old", &[]);
    pending.metadata.annotations = Some(BTreeMap::from([(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        "old-pull-secret=uid-old-pull-secret".to_string(),
    )]));
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![
            fake_managed_secret("old-pull-secret", true, "cap-bot", "ghp_old"),
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform"),
        ],
        service_accounts: vec![
            fake_service_account("original", &["old-pull-secret"]),
            fake_service_account("current-only", &["enclava-registry-auth"]),
            fake_service_account("newly-qualified", &[]),
            pending,
        ],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let accounts = [
        "original".to_string(),
        "current-only".to_string(),
        "newly-qualified".to_string(),
        "pending-old".to_string(),
    ];
    let scope = PullSecretAccountScope::uniform(true);
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    {
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 2, "both secrets stay while referenced");
        assert_eq!(
            image_pull_secret_names(&state.service_accounts[0]),
            BTreeSet::from([
                "old-pull-secret".to_string(),
                "enclava-registry-auth".to_string()
            ])
        );
        assert_eq!(
            image_pull_secret_names(&state.service_accounts[1]),
            BTreeSet::from(["enclava-registry-auth".to_string()]),
            "an account that only used the current name must not acquire the legacy name"
        );
        assert_eq!(
            image_pull_secret_names(&state.service_accounts[2]),
            BTreeSet::from(["enclava-registry-auth".to_string()]),
            "a newly qualifying account gets the configured name, not the legacy name"
        );
        assert_eq!(
            image_pull_secret_names(&state.service_accounts[3]),
            BTreeSet::from([
                "old-pull-secret".to_string(),
                "enclava-registry-auth".to_string()
            ]),
            "a pending repair still restores the legacy name"
        );
    }
    {
        let mut state = cluster.lock().unwrap();
        for account in &mut state.service_accounts {
            account.image_pull_secrets =
                Some(vec![k8s_openapi::api::core::v1::LocalObjectReference {
                    name: "enclava-registry-auth".to_string(),
                }]);
            if let Some(annotations) = account.metadata.annotations.as_mut() {
                annotations.remove(PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION);
            }
        }
    }
    assert!(
        reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &accounts,
            &reconcile_settings(),
            &scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
                lease_held: false,
            },
        )
        .await
        .unwrap()
    );
    let state = cluster.lock().unwrap();
    assert_eq!(
        state
            .secrets
            .iter()
            .filter_map(|secret| secret.metadata.name.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["enclava-registry-auth".to_string()]),
        "once no account references the legacy name, rename cleanup removes it"
    );
}

/// Codex review on #276, P1: a tenant replacement that lands before cleanup
/// has no foreign-replacement annotation. SSA of the generated out-of-scope
/// ServiceAccount must still keep that reference, and must not keep a
/// CAP-owned one.
#[tokio::test]
async fn unrecorded_tenant_pull_secret_reference_survives_out_of_scope_apply() {
    let mut replacement =
        fake_managed_secret("enclava-registry-auth", false, "tenant", "tenant-token");
    replacement.metadata.uid = Some("uid-tenant-replacement".to_string());
    let mut platform = fake_managed_secret("old-platform", true, "cap-bot", "ghp_platform");
    platform.metadata.uid = Some("uid-platform".to_string());
    let mut extra = fake_managed_secret("tenant-extra", false, "tenant", "other-token");
    extra.metadata.uid = Some("uid-tenant-extra".to_string());
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement, platform, extra],
        service_accounts: vec![fake_service_account(
            "deploying",
            &[
                "enclava-registry-auth",
                "old-platform",
                "tenant-extra",
                "missing-secret",
            ],
        )],
        ..Default::default()
    })));
    let desired = service_account_preserving_pull_secret_records(
        &engine,
        "tenant-ns",
        &fake_service_account("deploying", &[]),
    )
    .await
    .unwrap();
    let names: Vec<_> = desired
        .image_pull_secrets
        .unwrap()
        .into_iter()
        .map(|reference| reference.name)
        .collect();
    assert_eq!(names, vec!["enclava-registry-auth", "tenant-extra"]);
    assert_eq!(
        desired.metadata.annotations.unwrap()[FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION],
        "enclava-registry-auth=uid-tenant-replacement,tenant-extra=uid-tenant-extra"
    );
}

/// A stale foreign UID for the name must not hide the live tenant object.
/// Merge keeps the reference only while a recorded UID matches; the live
/// UID has to be written even when another UID is already recorded.
#[tokio::test]
async fn stale_foreign_record_does_not_drop_recreated_tenant_reference() {
    let mut live = fake_managed_secret("enclava-registry-auth", false, "tenant", "tenant-token");
    live.metadata.uid = Some("uid-live".to_string());
    let mut platform = fake_managed_secret("old-platform", true, "cap-bot", "ghp_platform");
    platform.metadata.uid = Some("uid-platform-new".to_string());
    let mut existing =
        fake_service_account("deploying", &["enclava-registry-auth", "old-platform"]);
    existing.metadata.annotations = Some(BTreeMap::from([(
        FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
        "enclava-registry-auth=uid-stale,old-platform=uid-platform-old".to_string(),
    )]));
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
        secrets: vec![live, platform],
        service_accounts: vec![existing],
        ..Default::default()
    })));
    let desired = service_account_preserving_pull_secret_records(
        &engine,
        "tenant-ns",
        &fake_service_account("deploying", &[]),
    )
    .await
    .unwrap();
    let names: Vec<_> = desired
        .image_pull_secrets
        .unwrap()
        .into_iter()
        .map(|reference| reference.name)
        .collect();
    assert_eq!(
        names,
        vec!["enclava-registry-auth"],
        "the live tenant UID must survive; a recreated CAP secret must not"
    );
    assert_eq!(
        desired.metadata.annotations.unwrap()[FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION],
        "enclava-registry-auth=uid-live"
    );
}

#[tokio::test]
async fn unrecorded_tenant_pull_secret_without_uid_blocks_service_account_apply() {
    let mut replacement =
        fake_managed_secret("enclava-registry-auth", false, "tenant", "tenant-token");
    replacement.metadata.uid = None;
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
        secrets: vec![replacement],
        service_accounts: vec![fake_service_account(
            "deploying",
            &["enclava-registry-auth"],
        )],
        ..Default::default()
    })));
    let error = service_account_preserving_pull_secret_records(
        &engine,
        "tenant-ns",
        &fake_service_account("deploying", &[]),
    )
    .await
    .expect_err("a UID-less tenant reference must block SSA");
    assert!(
        matches!(error, DeployError::PullSecretReconcileDeferred(_)),
        "got {error:?}"
    );
}

#[tokio::test]
async fn unrecorded_tenant_pull_secret_lookup_failure_blocks_service_account_apply() {
    let engine = reconcile_engine(Arc::new(Mutex::new(FakeCluster {
        secrets: vec![fake_managed_secret(
            "tenant-pull",
            false,
            "tenant",
            "tenant-token",
        )],
        service_accounts: vec![fake_service_account("deploying", &["tenant-pull"])],
        secret_get_status: Some(500),
        ..Default::default()
    })));
    assert!(
        service_account_preserving_pull_secret_records(
            &engine,
            "tenant-ns",
            &fake_service_account("deploying", &[]),
        )
        .await
        .is_err(),
        "a Secret lookup failure must prevent apply from pruning the reference"
    );
}

/// Managed-fields entry proving `manager` owns the given annotation and
/// label keys — the ownership half of creation evidence.
fn owned_managed_fields(
    manager: &str,
    annotation_keys: &[&str],
    label_keys: &[&str],
) -> Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry> {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{FieldsV1, ManagedFieldsEntry};
    let owned = |keys: &[&str]| {
        keys.iter()
            .map(|key| (format!("f:{key}"), serde_json::json!({})))
            .collect::<serde_json::Map<String, serde_json::Value>>()
    };
    vec![ManagedFieldsEntry {
        manager: Some(manager.to_string()),
        operation: Some("Apply".to_string()),
        fields_v1: Some(FieldsV1(serde_json::json!({
            "f:metadata": {
                "f:annotations": owned(annotation_keys),
                "f:labels": owned(label_keys),
            }
        }))),
        ..Default::default()
    }]
}

/// A pre-stored Secret shaped like a create this apply may or may not own.
fn recovery_secret(
    manager: &str,
    nonce: Option<&str>,
    owned_evidence: bool,
    generation: i64,
) -> Secret {
    use enclava_engine::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION,
    };
    let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap", "pat-token");
    let annotations = secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    annotations.insert(
        RESOURCE_CREATED_BY_ANNOTATION.to_string(),
        generation.to_string(),
    );
    annotations.insert(
        MUTATION_GENERATION_ANNOTATION.to_string(),
        generation.to_string(),
    );
    if let Some(nonce) = nonce {
        annotations.insert(
            PULL_SECRET_CREATE_NONCE_ANNOTATION.to_string(),
            nonce.to_string(),
        );
    }
    if owned_evidence {
        secret.metadata.managed_fields = Some(owned_managed_fields(
            manager,
            &[
                RESOURCE_CREATED_BY_ANNOTATION,
                MUTATION_GENERATION_ANNOTATION,
                PULL_SECRET_CREATE_NONCE_ANNOTATION,
            ],
            &[MANAGED_BY_LABEL, TENANT_PULL_SECRET_LABEL],
        ));
    }
    secret
}

/// Devin review on #280, SEC "Unproven Secret gains deletion authority":
/// a re-read Secret that does not carry this apply's create nonce is
/// neither recorded as ours (the record is what grants failed-deployment
/// cleanup its deletion authority) nor deleted (it may be the name-race
/// winner's) — even platform-labeled and unmarked, which the previous
/// "could be this POST" rule deleted. The nonce proves ownership and
/// unlocks both.
#[tokio::test(start_paused = true)]
async fn recovery_requires_nonce_proven_create_for_authority() {
    use std::sync::{Arc, Mutex};
    let generation = 3i64;
    let nonce = "nonce-recovery-test";

    // (a) Unmarked, platform-labeled, no nonce: foreign. Must survive,
    // stay unrecorded, and keep the deployment deferred.
    let foreign = fake_managed_secret("enclava-registry-auth", true, "cap", "pat-token");
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![foreign],
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(ledger.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    let result = recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await;
    assert!(
        result.is_err(),
        "an unproven object keeps the deploy deferred"
    );
    assert!(
        api.get("enclava-registry-auth").await.is_ok(),
        "a foreign Secret must not be deleted"
    );
    assert!(
        !ledger.contains_name_uid("enclava-registry-auth", "uid-enclava-registry-auth"),
        "a foreign Secret must not gain deletion authority"
    );

    // (b) Nonce plus owned evidence: provably ours — recorded.
    let ours = recovery_secret(
        &engine.config().field_manager,
        Some(nonce),
        true,
        generation,
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![ours],
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(ledger.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await
    .expect("a nonce-proven creation with owned evidence is recorded");
    assert!(ledger.contains_name_uid("enclava-registry-auth", "uid-enclava-registry-auth"));

    // (c) Nonce but ownership unproven (webhook moved managedFields):
    // still ours to compensate — deleted, and the deploy stays deferred.
    let stripped = recovery_secret(
        &engine.config().field_manager,
        Some(nonce),
        false,
        generation,
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![stripped],
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    let result = recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await;
    assert!(result.is_err());
    assert!(
        api.get("enclava-registry-auth").await.is_err(),
        "a nonce-proven create is compensated even when ownership is stripped"
    );
}

/// Codex review on #280, P1 "Poll for the full late-commit window": a
/// create still executing server-side past the client's first probes must
/// still be found and recorded (the previous three-404 loop concluded in
/// ~2 s), and an absent object keeps the probe running until the window
/// closes rather than releasing the ambiguity early.
#[tokio::test(start_paused = true)]
async fn recovery_probes_the_full_late_commit_window() {
    use std::sync::{Arc, Mutex};
    let generation = 3i64;
    let nonce = "nonce-window-test";

    // (a) Absent for the first 25 probes (50 s of 404s), then visible.
    let ours = recovery_secret(
        &reconcile_engine(Arc::new(Mutex::new(FakeCluster::default())))
            .config()
            .field_manager,
        Some(nonce),
        true,
        generation,
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![ours],
        secret_get_404s_left: 25,
        ..Default::default()
    }));
    let ledger = Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new());
    let engine = reconcile_engine(cluster.clone()).with_creation_ledger(ledger.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await
    .expect("a late-committing create is found within the window");
    assert!(ledger.contains_name_uid("enclava-registry-auth", "uid-enclava-registry-auth"));

    // (b) Absent throughout: the probe spans the whole window.
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secret_get_404s_left: u8::MAX,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    let started = tokio::time::Instant::now();
    let result = recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await;
    assert!(result.is_err());
    assert!(
        started.elapsed() >= PULL_SECRET_CREATE_LATE_COMMIT_WINDOW,
        "404s must not conclude the probe before the late-commit window closes"
    );
}

/// Devin review on #280: a stalled DELETE or deletion poll must not hold
/// the deploy's mutation guard and apply permit indefinitely — the bounded
/// recovery returns a deferred error once its budget is spent, while the
/// mutation lease's reclaim quarantine keeps any late create fenced.
#[tokio::test(start_paused = true)]
async fn recovery_budget_bounds_stalled_compensation() {
    use std::sync::{Arc, Mutex};
    let generation = 3i64;
    let nonce = "nonce-budget-test";
    let ours = recovery_secret(
        &reconcile_engine(Arc::new(Mutex::new(FakeCluster::default())))
            .config()
            .field_manager,
        Some(nonce),
        false,
        generation,
    );
    let cluster = Arc::new(Mutex::new(FakeCluster {
        secrets: vec![ours],
        stall_secret_deletes: true,
        ..Default::default()
    }));
    let engine = reconcile_engine(cluster.clone());
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), "tenant-ns");
    let started = tokio::time::Instant::now();
    let result = bounded_recover_ambiguous_pull_secret_create(
        &engine,
        &api,
        "tenant-ns",
        "enclava-registry-auth",
        MutationGeneration::new(generation).unwrap(),
        true,
        nonce,
    )
    .await;
    assert!(
        matches!(result, Err(DeployError::PullSecretReconcileDeferred(_))),
        "a stalled compensation falls out as a deferred error"
    );
    assert!(started.elapsed() >= PULL_SECRET_CREATE_RECOVERY_BUDGET);
}

fn publication_row(
    id: Uuid,
    fence: &[i64],
    published: bool,
    provenance_incomplete: bool,
) -> PublicationRecoveryDeployment {
    PublicationRecoveryDeployment {
        id,
        manifest_hash: Some("hash-a".to_string()),
        fence_generations: fence.to_vec(),
        provenance_incomplete,
        published,
    }
}

#[test]
fn publication_recovery_stamps_the_live_deployment_id_not_an_entered_apply() {
    let written = Uuid::new_v4();
    let entered_only = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: Some(written),
        mutation_generation: Some(7),
        manifest_hash: Some("hash-a".to_string()),
    };
    let rows = vec![
        publication_row(entered_only, &[8], false, false),
        publication_row(written, &[7], false, false),
    ];
    assert_eq!(
        decide_workload_publication_recovery(&live, &rows),
        PublicationRecoveryDecision::Stamp(written)
    );
}

#[test]
fn publication_recovery_does_not_treat_a_planned_hash_as_a_write() {
    // The live object still names the previous generation. A later row that
    // stored the same manifest hash before reaching the StatefulSet is not it.
    let previous = Uuid::new_v4();
    let planned = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: Some(previous),
        mutation_generation: Some(4),
        manifest_hash: Some("hash-a".to_string()),
    };
    let rows = vec![
        publication_row(previous, &[4], true, false),
        publication_row(planned, &[], false, false),
    ];
    assert_eq!(
        decide_workload_publication_recovery(&live, &rows),
        PublicationRecoveryDecision::AlreadyRecorded
    );
}

#[test]
fn publication_recovery_accepts_a_fenced_generation_when_the_label_was_stripped() {
    let written = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: None,
        mutation_generation: Some(9),
        manifest_hash: Some("hash-a".to_string()),
    };
    assert_eq!(
        decide_workload_publication_recovery(
            &live,
            &[publication_row(written, &[9], false, false)]
        ),
        PublicationRecoveryDecision::Stamp(written)
    );
}

#[test]
fn publication_recovery_refuses_a_stripped_label_when_the_manifest_hash_disagrees() {
    let written = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: None,
        mutation_generation: Some(9),
        manifest_hash: Some("live-hash".to_string()),
    };
    let mut row = publication_row(written, &[9], false, false);
    row.manifest_hash = Some("row-hash".to_string());
    assert_eq!(
        decide_workload_publication_recovery(&live, &[row]),
        PublicationRecoveryDecision::Ambiguous
    );
}

#[test]
fn publication_recovery_covers_a_historical_label_without_fence_provenance() {
    let historical = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: Some(historical),
        mutation_generation: Some(3),
        manifest_hash: None,
    };
    let mut row = publication_row(historical, &[], false, true);
    row.manifest_hash = None;
    assert_eq!(
        decide_workload_publication_recovery(&live, &[row]),
        PublicationRecoveryDecision::Stamp(historical)
    );
}

#[test]
fn publication_recovery_refuses_disagreeing_label_and_generation() {
    let labeled = Uuid::new_v4();
    let fenced = Uuid::new_v4();
    let live = LiveWorkloadPublication {
        deployment_id: Some(labeled),
        mutation_generation: Some(5),
        manifest_hash: Some("hash-a".to_string()),
    };
    let rows = vec![
        publication_row(labeled, &[4], false, false),
        publication_row(fenced, &[5], false, false),
    ];
    assert_eq!(
        decide_workload_publication_recovery(&live, &rows),
        PublicationRecoveryDecision::Ambiguous
    );
}

#[test]
fn live_workload_publication_reads_the_applied_spec_identity() {
    let deployment_id = Uuid::new_v4();
    let sts: k8s_openapi::api::apps::v1::StatefulSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "app",
            "namespace": "cap-app",
            "annotations": {
                "enclava.dev/cap-provider-mutation-generation": "12",
                "enclava.dev/manifest-hash": "abc"
            }
        },
        "spec": {
            "template": {
                "metadata": {
                    "labels": { "enclava.dev/deployment-id": deployment_id.to_string() }
                }
            }
        }
    }))
    .expect("statefulset publication fixture");
    assert_eq!(
        live_workload_publication(&sts),
        LiveWorkloadPublication {
            deployment_id: Some(deployment_id),
            mutation_generation: Some(12),
            manifest_hash: Some("abc".to_string()),
        }
    );
}

pub(crate) fn publication_statefulset_client(deployment_id: Uuid, fail: bool) -> kube::Client {
    use axum::http::{Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use tower::service_fn;

    kube::Client::new(
        service_fn(move |request: Request<Body>| async move {
            let _ = request.into_body().collect().await;
            if fail {
                let status = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "ServerTimeout",
                    "message": "timed out",
                    "code": 500,
                });
                return Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(500)
                        .body(Body::from(serde_json::to_vec(&status).unwrap()))
                        .unwrap(),
                );
            }
            let sts = serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {
                    "name": "queued-app",
                    "namespace": "cap-queued-app",
                    "annotations": {
                        "enclava.dev/cap-provider-mutation-generation": "4",
                        "enclava.dev/manifest-hash": "written"
                    }
                },
                "spec": {
                    "replicas": 1,
                    "template": {
                        "metadata": {
                            "labels": { "enclava.dev/deployment-id": deployment_id.to_string() }
                        }
                    }
                }
            });
            Ok(Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_vec(&sts).unwrap()))
                .unwrap())
        }),
        "default",
    )
}

#[tokio::test]
async fn recover_unpublished_workload_spec_stamps_the_live_generation() {
    let pool = crate::test_support::database_test_pool().await;
    let (app, deployment_id, _, _) = crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
    sqlx::query(
        "UPDATE deployments
            SET status = 'applying',
                apply_committed_at = clock_timestamp(),
                manifest_hash = 'written',
                namespace_fence_generations = ARRAY[4]::bigint[],
                workload_spec_published_at = NULL
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("mark the crash window");

    recover_unpublished_workload_spec(
        &pool,
        &publication_statefulset_client(deployment_id, false),
        app.id,
        &app.namespace,
        &app.name,
        PublicationRecoveryMode::BeforeSupersession,
    )
    .await
    .expect("recover the written spec");
    let stamped: bool = sqlx::query_scalar(
        "SELECT workload_spec_published_at IS NOT NULL FROM deployments WHERE id = $1",
    )
    .bind(deployment_id)
    .fetch_one(&pool)
    .await
    .expect("read recovered stamp");
    assert!(
        stamped,
        "the live deployment id must recover the lost stamp"
    );

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("delete publication recovery fixture");
}

#[tokio::test]
async fn deleting_publication_recovery_bumps_policy_generation_with_the_stamp() {
    let pool = crate::test_support::database_test_pool().await;
    let (app, deployment_id, _, _) = crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
    sqlx::query(
        "UPDATE apps
            SET status = 'deleting',
                workload_teardown_required = true,
                workload_teardown_completed_at = NULL
          WHERE id = $1",
    )
    .bind(app.id)
    .execute(&pool)
    .await
    .expect("mark deleting teardown");
    sqlx::query(
        "UPDATE deployments
            SET status = 'failed',
                apply_committed_at = clock_timestamp(),
                manifest_hash = 'written',
                namespace_fence_generations = ARRAY[4]::bigint[],
                workload_spec_published_at = NULL
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("open the crash window");
    let before: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read policy generation");

    let stamped = recover_deleting_workload_publications(
        &pool,
        &publication_statefulset_client(deployment_id, false),
    )
    .await
    .expect("recover deleting publication");
    assert!(stamped);
    let (published, after): (bool, i64) = sqlx::query_as(
        "SELECT deployment.workload_spec_published_at IS NOT NULL,
                reconciliation.desired_generation
           FROM deployments AS deployment
           CROSS JOIN kbs_signed_policy_reconciliation AS reconciliation
          WHERE deployment.id = $1
            AND reconciliation.singleton",
    )
    .bind(deployment_id)
    .fetch_one(&pool)
    .await
    .expect("read stamp and generation");
    assert!(published, "the live generation must be stamped");
    assert_eq!(
        after,
        before + 1,
        "the selector change needs a new policy generation"
    );

    let again = recover_deleting_workload_publications(
        &pool,
        &publication_statefulset_client(deployment_id, false),
    )
    .await
    .expect("second recovery is a no-op");
    assert!(!again, "an already stamped generation must not bump again");

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("delete generation-bump fixture");
}

#[tokio::test]
async fn recover_unpublished_workload_spec_refuses_an_unreadable_in_flight_write() {
    let pool = crate::test_support::database_test_pool().await;
    let (app, deployment_id, _, _) = crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
    sqlx::query(
        "UPDATE deployments
            SET status = 'applying',
                apply_committed_at = clock_timestamp(),
                workload_spec_published_at = NULL
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("mark an in-flight StatefulSet attempt");

    let error = recover_unpublished_workload_spec(
        &pool,
        &publication_statefulset_client(deployment_id, true),
        app.id,
        &app.namespace,
        &app.name,
        PublicationRecoveryMode::BeforeSupersession,
    )
    .await
    .expect_err("an unreadable in-flight write must not be superseded");
    assert!(matches!(error, DeployError::PublicationUnclassified));

    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .execute(&pool)
        .await
        .expect("delete unreadable publication fixture");
}
