//! Reference test vectors for D11 canonical encoding (Phase 7).
//!
//! These vectors lock the byte layout of `descriptor_canonical_bytes` and
//! `descriptor_core_canonical_bytes` so a future signing service in another
//! repository can validate interop without running the CLI.
//!
//! When the descriptor record set legitimately changes, regenerate the
//! fixtures and bump the purpose label per D11's versioning rule.

use chrono::TimeZone;
use chrono::Utc;
use enclava_cli::descriptor::{
    Capabilities, DeploymentDescriptor, EnvVar, OciRuntimeSpec, Port, Resources, SecurityContext,
    Sidecars, SignerIdentity, descriptor_canonical_bytes, descriptor_core_canonical_bytes,
    descriptor_core_hash,
};
use std::path::PathBuf;
use uuid::Uuid;

fn fixed_descriptor() -> DeploymentDescriptor {
    DeploymentDescriptor {
        schema_version: "v1".to_string(),
        org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        org_slug: "abcd1234".to_string(),
        app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        app_name: "demo".to_string(),
        deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        created_at: Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap(),
        nonce: [7; 32],
        app_domain: "demo.abcd1234.enclava.dev".to_string(),
        tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
        custom_domains: vec!["app.example.com".to_string()],
        namespace: "cap-abcd1234-demo".to_string(),
        service_account: "cap-demo-sa".to_string(),
        identity_hash: [9; 32],
        image_ref: "ghcr.io/enclava-labs/demo@sha256:aaaa".to_string(),
        image_digest: "sha256:aaaa".to_string(),
        signer_identity: SignerIdentity {
            subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        },
        oci_runtime_spec: OciRuntimeSpec {
            command: vec!["/app".to_string()],
            args: vec!["--serve".to_string()],
            env: vec![
                EnvVar {
                    name: "A".to_string(),
                    value: "1".to_string(),
                },
                EnvVar {
                    name: "B".to_string(),
                    value: "2".to_string(),
                },
            ],
            ports: vec![Port {
                container_port: 3000,
                protocol: "TCP".to_string(),
            }],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        },
        sidecars: Sidecars {
            attestation_proxy_digest: "sha256:1111".to_string(),
            caddy_digest: "sha256:2222".to_string(),
        },
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        independent_verification: false,
        expected_firmware_measurement: [3; 32].into(),
        expected_runtime_class: "kata-qemu-snp".to_string(),
        kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
        unlock_mode: "password".to_string(),
        policy_template_id: "kbs-release-policy-v3".to_string(),
        policy_template_sha256: [4; 32],
        platform_release_version: "platform-2026.04".to_string(),
        expected_agent_policy_hash: [7; 32],
        expected_cc_init_data_hash: [5; 32],
        expected_kbs_policy_hash: [6; 32],
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn descriptor_canonical_bytes_matches_fixture() {
    let bytes = descriptor_canonical_bytes(&fixed_descriptor());
    let fixture = fixtures_dir().join("descriptor_canonical_v1.bin");
    if std::env::var("REGENERATE_FIXTURES").is_ok() {
        std::fs::write(&fixture, &bytes).unwrap();
    }
    let expected = std::fs::read(&fixture).expect(
        "fixtures/descriptor_canonical_v1.bin missing; \
         run with REGENERATE_FIXTURES=1 to create",
    );
    assert_eq!(bytes, expected);
}

#[test]
fn descriptor_core_canonical_bytes_matches_fixture() {
    let bytes = descriptor_core_canonical_bytes(&fixed_descriptor());
    let fixture = fixtures_dir().join("descriptor_core_canonical_v1.bin");
    if std::env::var("REGENERATE_FIXTURES").is_ok() {
        std::fs::write(&fixture, &bytes).unwrap();
    }
    let expected = std::fs::read(&fixture).expect(
        "fixtures/descriptor_core_canonical_v1.bin missing; \
         run with REGENERATE_FIXTURES=1 to create",
    );
    assert_eq!(bytes, expected);
}

#[test]
fn descriptor_core_hash_is_stable() {
    let h = descriptor_core_hash(&fixed_descriptor());
    let fixture = fixtures_dir().join("descriptor_core_hash_v1.hex");
    if std::env::var("REGENERATE_FIXTURES").is_ok() {
        std::fs::write(&fixture, hex::encode(h)).unwrap();
    }
    let expected = std::fs::read_to_string(&fixture).expect("fixture missing");
    assert_eq!(hex::encode(h), expected.trim());
}

#[test]
fn independent_verification_descriptor_core_hash_is_stable() {
    let mut descriptor = fixed_descriptor();
    descriptor.independent_verification = true;
    assert_eq!(
        hex::encode(descriptor_core_hash(&descriptor)),
        "01defa6dd84c96010cc0322a903177bda834c50779eb058b1a3ed70f40c0fbd3"
    );
}
