use chrono::{TimeZone, Utc};
use enclava_cli::descriptor::{
    CapAppOciRuntimeSpecInput, Capabilities, DeploymentDescriptorBuildInput, EnvVar, Mount,
    OciRuntimeSpec, Port, Resources, SecurityContext, Sidecars, SignerIdentity, build_descriptor,
    cap_app_oci_runtime_spec, sign, verify,
};
use enclava_cli::keyring::{Role, sign_keyring, single_member_keyring, verify_keyring};
use enclava_cli::keys::UserSigningKey;
use enclava_engine::manifest::containers::build_app_container;
use enclava_engine::testutil::sample_app;
use std::collections::BTreeMap;
use uuid::Uuid;

fn fixed_oci_spec() -> OciRuntimeSpec {
    OciRuntimeSpec {
        command: Vec::new(),
        args: Vec::new(),
        env: Vec::<EnvVar>::new(),
        ports: vec![Port {
            container_port: 3000,
            protocol: "TCP".to_string(),
        }],
        mounts: vec![Mount {
            source: "/data/data".to_string(),
            destination: "/data".to_string(),
            mount_type: "bind".to_string(),
            options: vec!["rw".to_string()],
        }],
        capabilities: Capabilities::default(),
        security_context: SecurityContext::default(),
        resources: Resources::default(),
    }
}

#[test]
fn cap_oci_runtime_spec_matches_rendered_app_container_fields() {
    let app = sample_app();
    let primary = app.primary_container().unwrap();
    let descriptor_oci = cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
        container_name: primary.name.clone(),
        port: primary.port.unwrap(),
        workload_command: primary.command.clone().unwrap_or_default(),
        storage_paths: primary.storage_paths.clone(),
        cpu_limit: app.resources.cpu.clone(),
        memory_limit: app.resources.memory.clone(),
    });
    let rendered = build_app_container(&app);

    assert_eq!(descriptor_oci.command, rendered.command.unwrap());
    assert_eq!(descriptor_oci.args, rendered.args.unwrap_or_default());

    let rendered_env: BTreeMap<_, _> = rendered
        .env
        .unwrap()
        .into_iter()
        .filter_map(|env| env.value.map(|value| (env.name, value)))
        .collect();
    for env in &descriptor_oci.env {
        assert_eq!(
            rendered_env.get(&env.name).map(String::as_str),
            Some(env.value.as_str())
        );
    }

    let rendered_port = rendered.ports.unwrap()[0].container_port as u32;
    assert_eq!(descriptor_oci.ports[0].container_port, rendered_port);
    assert_eq!(descriptor_oci.ports[0].protocol, "TCP");

    let rendered_sc = rendered.security_context.unwrap();
    assert_eq!(
        descriptor_oci.security_context.run_as_user,
        rendered_sc.run_as_user.unwrap() as u32
    );
    assert_eq!(
        descriptor_oci.security_context.run_as_group,
        rendered_sc.run_as_group.unwrap() as u32
    );
    assert_eq!(
        descriptor_oci.security_context.read_only_root_fs,
        rendered_sc.read_only_root_filesystem.unwrap()
    );
    assert_eq!(
        descriptor_oci.security_context.allow_privilege_escalation,
        rendered_sc.allow_privilege_escalation.unwrap()
    );
    assert_eq!(
        descriptor_oci.security_context.privileged,
        rendered_sc.privileged.unwrap()
    );
    assert_eq!(
        descriptor_oci.capabilities.drop,
        rendered_sc
            .capabilities
            .as_ref()
            .unwrap()
            .drop
            .clone()
            .unwrap()
    );
    assert!(descriptor_oci.capabilities.add.is_empty());

    let rendered_resources = rendered.resources.unwrap();
    let requests = rendered_resources.requests.unwrap();
    let limits = rendered_resources.limits.unwrap();
    assert_eq!(
        descriptor_oci
            .resources
            .requests
            .iter()
            .find(|r| r.name == "cpu")
            .unwrap()
            .value,
        requests["cpu"].0
    );
    assert_eq!(
        descriptor_oci
            .resources
            .requests
            .iter()
            .find(|r| r.name == "memory")
            .unwrap()
            .value,
        requests["memory"].0
    );
    assert_eq!(
        descriptor_oci
            .resources
            .limits
            .iter()
            .find(|r| r.name == "cpu")
            .unwrap()
            .value,
        limits["cpu"].0
    );
    assert_eq!(
        descriptor_oci
            .resources
            .limits
            .iter()
            .find(|r| r.name == "memory")
            .unwrap()
            .value,
        limits["memory"].0
    );

    let rendered_mounts = rendered.volume_mounts.unwrap();
    for mount in &descriptor_oci.mounts {
        if mount.destination != "/state" {
            continue;
        }
        let rendered_mount = rendered_mounts
            .iter()
            .find(|m| m.mount_path == mount.destination)
            .unwrap();
        assert_eq!(
            rendered_mount.mount_propagation.as_deref(),
            Some("HostToContainer")
        );
    }
    assert!(rendered_mounts.iter().all(|m| m.sub_path.is_none()));
}

#[test]
fn cap_oci_runtime_spec_uses_app_data_source_for_state_app_data_path() {
    let mut app = sample_app();
    app.containers[0].storage_paths = vec!["/state/app-data".to_string()];
    let primary = app.primary_container().unwrap();

    let descriptor_oci = cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
        container_name: primary.name.clone(),
        port: primary.port.unwrap(),
        workload_command: primary.command.clone().unwrap_or_default(),
        storage_paths: primary.storage_paths.clone(),
        cpu_limit: app.resources.cpu.clone(),
        memory_limit: app.resources.memory.clone(),
    });

    let app_data_mount = descriptor_oci
        .mounts
        .iter()
        .find(|mount| mount.destination == "/state/app-data")
        .expect("state app-data mount must be present");
    assert_eq!(app_data_mount.source, "state-mount:app-data");
}

#[test]
fn cap_oci_runtime_spec_preserves_workload_command_as_wait_exec_args() {
    let mut app = sample_app();
    app.containers[0].command = Some(vec!["/app/server".to_string(), "--serve".to_string()]);
    let primary = app.primary_container().unwrap();
    let descriptor_oci = cap_app_oci_runtime_spec(CapAppOciRuntimeSpecInput {
        container_name: primary.name.clone(),
        port: primary.port.unwrap(),
        workload_command: primary.command.clone().unwrap_or_default(),
        storage_paths: primary.storage_paths.clone(),
        cpu_limit: app.resources.cpu.clone(),
        memory_limit: app.resources.memory.clone(),
    });
    let rendered = build_app_container(&app);

    assert_eq!(descriptor_oci.command, rendered.command.unwrap());
    assert_eq!(descriptor_oci.args, rendered.args.unwrap());
}

#[test]
fn deploy_descriptor_and_keyring_envelopes_serialize_for_deploy_request() {
    let deployer =
        UserSigningKey::generate(Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap());
    let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let descriptor = build_descriptor(DeploymentDescriptorBuildInput {
        org_id,
        org_slug: "acme".to_string(),
        app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        app_name: "demo".to_string(),
        deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        created_at: Utc.with_ymd_and_hms(2026, 4, 28, 12, 0, 0).unwrap(),
        app_domain: "demo.acme.enclava.dev".to_string(),
        tee_domain: "demo.acme.tee.enclava.dev".to_string(),
        custom_domains: Vec::new(),
        namespace: "cap-acme-demo".to_string(),
        service_account: "cap-demo-sa".to_string(),
        identity_hash: [1; 32],
        image_ref:
            "ghcr.io/enclava-labs/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        signer_identity: SignerIdentity {
            subject: "https://github.com/acme/repo/.github/workflows/deploy.yml@refs/heads/main"
                .to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        },
        oci_runtime_spec: fixed_oci_spec(),
        sidecars: Sidecars {
            attestation_proxy_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            caddy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
        },
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        expected_firmware_measurement: [2; 32],
        expected_runtime_class: "kata-qemu-snp".to_string(),
        kbs_resource_path: "default/cap-acme-demo-owner".to_string(),
        unlock_mode: "password".to_string(),
        policy_template_id: "enclava-kbs-policy-v1".to_string(),
        policy_template_sha256: [3; 32],
        platform_release_version: "0.1.0".to_string(),
        expected_agent_policy_hash: [6; 32],
        expected_cc_init_data_hash: [4; 32],
        expected_kbs_policy_hash: [5; 32],
    });
    let descriptor_envelope = sign(&deployer, descriptor, "cli-key".to_string());
    verify(&descriptor_envelope, &deployer.public).unwrap();

    let keyring = single_member_keyring(
        org_id,
        1,
        &deployer,
        Role::Deployer,
        Utc.with_ymd_and_hms(2026, 4, 28, 12, 0, 0).unwrap(),
    );
    let keyring_envelope = sign_keyring(&deployer, keyring);
    verify_keyring(&keyring_envelope, &deployer.public).unwrap();

    let descriptor_blob = serde_json::to_string(&descriptor_envelope).unwrap();
    let keyring_blob = serde_json::to_string(&keyring_envelope).unwrap();
    let descriptor_value: serde_json::Value = serde_json::from_str(&descriptor_blob).unwrap();
    let keyring_value: serde_json::Value = serde_json::from_str(&keyring_blob).unwrap();

    assert_eq!(descriptor_value["signing_key_id"], "cli-key");
    assert_eq!(
        descriptor_value["descriptor"]["image_ref"],
        "ghcr.io/enclava-labs/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        descriptor_value["signing_pubkey"].as_str().unwrap().len(),
        64
    );
    assert_eq!(descriptor_value["signature"].as_str().unwrap().len(), 128);
    assert_eq!(keyring_value["signing_pubkey"].as_str().unwrap().len(), 64);
    assert_eq!(keyring_value["signature"].as_str().unwrap().len(), 128);
}
