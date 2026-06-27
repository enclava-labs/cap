//! Wire-contract tests pinning CLI types against the actual shapes
//! produced by the Platform API. Every assertion here corresponds to a
//! real bug caught in manual E2E testing on 2026-04-18.

use enclava_cli::api_types::*;

#[test]
fn signup_request_includes_provider() {
    let req = SignupRequest {
        provider: "email".to_string(),
        email: Some("a@b.com".to_string()),
        password: Some("hunter2".to_string()),
        npub: None,
        display_name: None,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(v["provider"], "email");
}

#[test]
fn login_request_uses_nostr_event_field_name() {
    let req = LoginRequest {
        provider: "nostr".to_string(),
        email: None,
        password: None,
        npub: None,
        nostr_event: Some(r#"{"id":"x"}"#.to_string()),
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert!(v.get("nostr_event").is_some());
    assert!(v.get("signed_event").is_none());
}

#[test]
fn auth_response_matches_server_shape() {
    // Exact server payload from crates/enclava-api/src/routes/auth.rs AuthResponse.
    let body = serde_json::json!({
        "user_id": "c5277e9d-c1bc-4daa-bbb4-43a625952eec",
        "org_id":  "d28131d5-f605-46e9-9b5a-6ee26a2d31dd",
        "org_name": "personal-cli",
        "token": "jwt.jwt.jwt"
    });
    let resp: AuthResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.token, "jwt.jwt.jwt");
    assert_eq!(resp.org_name, "personal-cli");
}

#[test]
fn current_user_accepts_deploy_eligibility_fields() {
    let body = serde_json::json!({
        "user_id": "c5277e9d-c1bc-4daa-bbb4-43a625952eec",
        "display_name": "CLI User",
        "active_org": {
            "id": "d28131d5-f605-46e9-9b5a-6ee26a2d31dd",
            "name": "personal-cli",
            "display_name": null,
            "role": "owner",
            "is_personal": true,
            "entitlement_class": "core",
            "deploy_allowed": true,
            "deploy_block_reason": null
        },
        "orgs": []
    });
    let resp: CurrentUserResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.active_org.entitlement_class.as_deref(), Some("core"));
    assert_eq!(resp.active_org.deploy_allowed, Some(true));
}

#[test]
fn list_orgs_deserializes_bare_array() {
    let body = serde_json::json!([
        { "id": "3bd1e7b1", "name": "testco", "display_name": null, "entitlement_class": "core", "is_personal": false }
    ]);
    let orgs: Vec<OrgResponse> = serde_json::from_value(body).unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].name, "testco");
}

#[test]
fn list_members_deserializes_bare_array() {
    let body = serde_json::json!([
        { "user_id": "c97a082c", "display_name": "CLI", "role": "owner" }
    ]);
    let members: Vec<MemberResponse> = serde_json::from_value(body).unwrap();
    assert_eq!(members[0].role, "owner");
}

#[test]
fn list_apps_deserializes_bare_array() {
    let body = serde_json::json!([
        {
            "id": "8d1e6166", "name": "testapp", "namespace": "cap-x-y",
            "instance_id": "cli-x-y", "domain": "testapp.enclava.local",
            "custom_domain": null, "unlock_mode": "auto",
            "status": "creating", "created_at": "2026-04-18T14:14:35Z"
        }
    ]);
    let apps: Vec<AppResponse> = serde_json::from_value(body).unwrap();
    assert_eq!(apps[0].name, "testapp");
}

#[test]
fn app_response_accepts_phase7_fields_when_server_exposes_them() {
    let body = serde_json::json!({
        "id": "8d1e6166",
        "name": "testapp",
        "namespace": "cap-x-y",
        "instance_id": "cli-x-y",
        "domain": "testapp.enclava.local",
        "app_domain": "testapp.apps.enclava.dev",
        "tee_domain": "testapp.tee.enclava.local",
        "custom_domain": null,
        "unlock_mode": "password",
        "status": "creating",
        "signer_identity_subject": "https://github.com/acme/repo/.github/workflows/deploy.yml@refs/heads/main",
        "signer_identity_issuer": "https://token.actions.githubusercontent.com",
        "template_slug": "debian-ssh-ngrok",
        "template_version": "2026-06-18",
        "template_expected": {
            "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
            "future_non_secret_expectation": "kept"
        },
        "created_at": "2026-04-18T14:14:35Z"
    });
    let app: AppResponse = serde_json::from_value(body).unwrap();
    assert_eq!(app.app_domain.as_deref(), Some("testapp.apps.enclava.dev"));
    assert_eq!(app.tee_domain.as_deref(), Some("testapp.tee.enclava.local"));
    assert!(app.signer_identity_subject.unwrap().contains("github.com"));
    assert_eq!(app.template_slug.as_deref(), Some("debian-ssh-ngrok"));
    assert_eq!(
        app.template_expected.stable_ssh_endpoint.as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        app.template_expected
            .extra
            .get("future_non_secret_expectation")
            .and_then(|value| value.as_str()),
        Some("kept")
    );
}

#[test]
fn deploy_request_serializes_signed_artifact_blobs() {
    let req = DeployRequest {
        image: Some("registry.example.com/acme/web@sha256:abc".to_string()),
        customer_descriptor_blob: Some(r#"{"descriptor":{}}"#.to_string()),
        org_keyring_blob: Some(r#"{"keyring":{}}"#.to_string()),
        signed_policy_artifact: Some(r#"{"metadata":{}}"#.to_string()),
    };
    let value = serde_json::to_value(&req).unwrap();
    assert_eq!(
        value["customer_descriptor_blob"],
        serde_json::json!(r#"{"descriptor":{}}"#)
    );
    assert_eq!(
        value["org_keyring_blob"],
        serde_json::json!(r#"{"keyring":{}}"#)
    );
    assert_eq!(
        value["signed_policy_artifact"],
        serde_json::json!(r#"{"metadata":{}}"#)
    );
}

#[test]
fn unlock_mode_transition_request_contains_only_mode() {
    let req = UpdateUnlockModeRequest {
        mode: "auto-unlock".to_string(),
        transition_receipt: None,
        transition_attestation: None,
        customer_descriptor_blob: None,
        org_keyring_blob: None,
        signed_policy_artifact: None,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(v, serde_json::json!({ "mode": "auto-unlock" }));
    assert!(v.get("password").is_none());
}

#[test]
fn unlock_mode_transition_response_deserializes() {
    let body = serde_json::json!({
        "app_name": "acme-web",
        "unlock_mode": "auto",
        "deployment_id": "90dc3149-02e2-4d44-8398-67637abbcbbe",
        "status": "deploying"
    });
    let resp: UpdateUnlockModeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.app_name, "acme-web");
    assert_eq!(resp.unlock_mode, "auto");
    assert!(resp.deployment_id.is_some());
}

#[test]
fn deployment_entry_accepts_legacy_deployment_id_field() {
    let body = serde_json::json!({
        "deployment_id": "90dc3149-02e2-4d44-8398-67637abbcbbe",
        "status": "running",
        "image_digest": "sha256:abc",
        "template_slug": "debian-ssh-ngrok",
        "template_version": "2026-06-18",
        "template_expected": {
            "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958"
        },
        "created_at": "2026-05-24T10:00:00Z",
        "completed_at": null
    });

    let entry: DeploymentEntry = serde_json::from_value(body).unwrap();

    assert_eq!(entry.id, "90dc3149-02e2-4d44-8398-67637abbcbbe");
    assert_eq!(entry.template_slug.as_deref(), Some("debian-ssh-ngrok"));
    assert_eq!(
        entry.template_expected.stable_ssh_endpoint.as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
}

#[test]
fn hosted_template_response_accepts_stable_ssh_endpoint_metadata() {
    let body = serde_json::json!({
        "slug": "debian-ssh-ngrok",
        "name": "Debian Stable SSH Endpoint",
        "description": "Confidential Debian shell with a stable SSH endpoint backed by ngrok TCP.",
        "version": "2026-06-18",
        "image": "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        "source_provider": "github",
        "source_repository": "enclava-labs/enclava-paas",
        "signer_subject": "https://github.com/enclava-labs/enclava-paas/.github/workflows/debian-ssh-ngrok-template-image.yml@refs/heads/main",
        "signer_issuer": "https://token.actions.githubusercontent.com",
        "container_name": "web",
        "unlock_mode": "auto",
        "health_path": "/healthz",
        "health_interval": 15,
        "health_timeout": 5,
        "resources": {
            "cpu": "2",
            "memory": "4Gi",
            "storage": "10Gi"
        },
        "persistence_path": "/home/user",
        "tls_policy": "confidential_per_instance_tls",
        "workload_security_profile": "rootful-sudo",
        "security_notes": ["SSH access is enabled."],
        "egress_allowlist": [
            { "host": "connect.ngrok-agent.com", "ports": [443] }
        ],
        "config_keys": [
            {
                "key": "NGROK_TCP_URL",
                "label": "Stable SSH endpoint",
                "description": "Optional existing reserved stable SSH endpoint.",
                "input_type": "text",
                "required": false,
                "secret": false,
                "generated": true,
                "default_value": null,
                "validation": {
                    "format": "ngrok_tcp_url",
                    "example": "6.tcp.eu.ngrok.io:17958",
                    "max_bytes": 255,
                    "allowed_algorithms": []
                }
            },
            {
                "key": "DEBIAN_SSH_AUTHORIZED_KEYS",
                "label": "SSH public keys",
                "description": "One SSH public key per line.",
                "input_type": "ssh_public_keys",
                "required": true,
                "secret": false,
                "generated": false,
                "validation": {
                    "max_bytes": 32768,
                    "max_items": 10,
                    "allowed_algorithms": ["ssh-ed25519"]
                }
            }
        ]
    });

    let template: HostedTemplate = serde_json::from_value(body).unwrap();

    assert_eq!(template.slug, "debian-ssh-ngrok");
    assert_eq!(template.name, "Debian Stable SSH Endpoint");
    assert!(
        template.description.contains("stable SSH endpoint"),
        "stable SSH template description should lead with the stable SSH endpoint offering"
    );
    assert!(
        !template
            .description
            .contains("SSH exposed through an ngrok TCP tunnel"),
        "stable SSH template description should not frame ngrok as the product surface"
    );
    let stable = template
        .config_keys
        .iter()
        .find(|entry| entry.key == "NGROK_TCP_URL")
        .expect("stable ssh config key");
    assert_eq!(stable.label, "Stable SSH endpoint");
    assert!(
        stable.description.contains("stable SSH endpoint"),
        "stable SSH endpoint metadata description should name the stable SSH endpoint"
    );
    assert!(!stable.required);
    let stable_validation = stable.validation.as_ref().expect("stable validation");
    assert_eq!(stable_validation.format.as_deref(), Some("ngrok_tcp_url"));
    assert_eq!(
        stable_validation.example.as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert!(
        template
            .config_keys
            .iter()
            .all(|entry| entry.key != "NGROK_AUTHTOKEN"),
        "PaaS-managed ngrok token must not be exposed in hosted template config keys"
    );
}

#[test]
fn template_instance_response_accepts_config_token_and_cap_payload() {
    let body = serde_json::json!({
        "template": {
            "slug": "debian-ssh-ngrok",
            "name": "Debian Stable SSH Endpoint",
            "description": "Confidential Debian shell with a stable SSH endpoint backed by ngrok TCP.",
            "version": "2026-06-18",
            "image": "ghcr.io/enclava-labs/debian-ssh-ngrok-template@sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            "config_keys": []
        },
        "app": {
            "name": "shell",
            "status": "creating",
            "template_expected": {
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958"
            }
        },
        "deployment": {
            "cap_deployment_id": "00000000-0000-0000-0000-000000000001",
            "status": "pending",
            "template_expected": {
                "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958"
            }
        },
        "config_token": {
            "token": "redacted",
            "tee_url": "https://shell.tee.enclava.dev/.well-known/confidential/config",
            "expires_in_seconds": 300
        },
        "cap": {
            "app_domain": "shell.enclava.dev",
            "domain": "legacy-shell.enclava.dev"
        }
    });

    let response: TemplateInstanceResponse = serde_json::from_value(body).unwrap();

    assert_eq!(response.template.slug, "debian-ssh-ngrok");
    assert_eq!(
        response
            .app
            .template_expected
            .stable_ssh_endpoint
            .as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        response
            .deployment
            .template_expected
            .stable_ssh_endpoint
            .as_deref(),
        Some("6.tcp.eu.ngrok.io:17958")
    );
    assert_eq!(
        response.deployment.cap_deployment_id.as_deref(),
        Some("00000000-0000-0000-0000-000000000001")
    );
    assert_eq!(
        response.config_token.unwrap().tee_url.as_deref(),
        Some("https://shell.tee.enclava.dev/.well-known/confidential/config")
    );
    assert_eq!(response.cap["app_domain"], "shell.enclava.dev");
    assert_eq!(response.cap["domain"], "legacy-shell.enclava.dev");
}

#[test]
fn ssh_command_response_accepts_pending_and_ready_states() {
    let pending: SshCommandResponse = serde_json::from_value(serde_json::json!({
        "status": "pending",
        "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
        "command": null,
        "endpoint": null,
        "app_url": null
    }))
    .unwrap();
    assert_eq!(pending.status, "pending");
    assert_eq!(pending.stable_ssh_endpoint, "6.tcp.eu.ngrok.io:17958");
    assert!(pending.command.is_none());
    assert!(pending.endpoint.is_none());

    let ready: SshCommandResponse = serde_json::from_value(serde_json::json!({
        "status": "ready",
        "stable_ssh_endpoint": "6.tcp.eu.ngrok.io:17958",
        "command": "ssh -p 17958 user@6.tcp.eu.ngrok.io",
        "endpoint": "6.tcp.eu.ngrok.io:17958",
        "app_url": "https://shell.enclava.dev"
    }))
    .unwrap();
    assert_eq!(ready.status, "ready");
    assert_eq!(ready.stable_ssh_endpoint, "6.tcp.eu.ngrok.io:17958");
    assert_eq!(
        ready.command.as_deref(),
        Some("ssh -p 17958 user@6.tcp.eu.ngrok.io")
    );
    assert_eq!(ready.endpoint.as_deref(), Some("6.tcp.eu.ngrok.io:17958"));
    assert_eq!(ready.app_url.as_deref(), Some("https://shell.enclava.dev"));
}

#[test]
fn create_template_instance_request_can_omit_stable_endpoint_expectation() {
    let req = CreateTemplateInstanceRequest {
        template_slug: "debian-ssh-ngrok".to_string(),
        instance_name: "shell".to_string(),
        config: serde_json::json!({}),
        customer_descriptor_blob: None,
        org_keyring_blob: None,
        signed_policy_artifact: None,
    };

    let value = serde_json::to_value(&req).unwrap();

    assert_eq!(value["template_slug"], "debian-ssh-ngrok");
    assert_eq!(value["instance_name"], "shell");
    assert_eq!(value["config"], serde_json::json!({}));
}
