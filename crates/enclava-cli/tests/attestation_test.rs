use chrono::{TimeZone, Utc};
use enclava_cli::attestation::{
    AmdSnpChainStatus, AttestationBundle, AttestationError, AttestationExpectations,
    ParsedSnpReport, tee_tls_transcript_hash, verify_attestation_bundle,
};
use enclava_cli::descriptor::{
    Capabilities, DeploymentDescriptor, EnvVar, OciRuntimeSpec, Port, Resources, SecurityContext,
    Sidecars, SignerIdentity,
};
use sha2::{Digest, Sha256};
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
        image_ref:
            "ghcr.io/enclava-ai/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        signer_identity: SignerIdentity {
            subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        },
        oci_runtime_spec: OciRuntimeSpec {
            command: vec!["/app".to_string()],
            args: vec!["--serve".to_string()],
            env: vec![EnvVar {
                name: "A".to_string(),
                value: "1".to_string(),
            }],
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
        expected_firmware_measurement: [3; 32],
        expected_runtime_class: "kata-qemu-snp".to_string(),
        kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
        policy_template_id: "kbs-release-policy-v3".to_string(),
        policy_template_sha256: [4; 32],
        platform_release_version: "platform-2026.04".to_string(),
        expected_agent_policy_hash: [7; 32],
        expected_cc_init_data_hash: [0; 32],
        expected_kbs_policy_hash: [6; 32],
    }
}

fn cc_init_data_toml(descriptor: &DeploymentDescriptor) -> Vec<u8> {
    format!(
        r#"version = "0.1.0"
algorithm = "sha256"

[data]
image_digest = "{}"
runtime_class = "{}"
namespace = "{}"
service_account = "{}"
identity_hash = "{}"
signer_identity_subject = "{}"
signer_identity_issuer = "{}"
sidecar_digests = '{{"attestation_proxy":"{}","caddy_ingress":"{}"}}'
"#,
        descriptor.image_digest,
        descriptor.expected_runtime_class,
        descriptor.namespace,
        descriptor.service_account,
        hex::encode(descriptor.identity_hash),
        descriptor.signer_identity.subject,
        descriptor.signer_identity.issuer,
        descriptor.sidecars.attestation_proxy_digest,
        descriptor.sidecars.caddy_digest
    )
    .into_bytes()
}

struct ValidCase {
    bundle: AttestationBundle,
    descriptor: DeploymentDescriptor,
    domain: &'static str,
    nonce: [u8; 32],
}

impl ValidCase {
    fn expectations(&self) -> AttestationExpectations<'_> {
        AttestationExpectations {
            domain: self.domain,
            nonce: self.nonce,
            descriptor: &self.descriptor,
        }
    }
}

fn valid_case() -> ValidCase {
    let mut descriptor = fixed_descriptor();
    let cc_init_data = cc_init_data_toml(&descriptor);
    descriptor.expected_cc_init_data_hash = Sha256::digest(&cc_init_data).into();

    let domain = "demo.abcd1234.tee.enclava.dev";
    let nonce = [8; 32];
    let tls_pubkey_spki_der = b"fake test spki der".to_vec();
    let receipt_pubkey_raw = [0x42; 32];
    let leaf_spki_hash: [u8; 32] = Sha256::digest(&tls_pubkey_spki_der).into();
    let receipt_pubkey_hash: [u8; 32] = Sha256::digest(receipt_pubkey_raw).into();
    let transcript = tee_tls_transcript_hash(domain, &nonce, &leaf_spki_hash);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&transcript);
    report_data[32..].copy_from_slice(&receipt_pubkey_hash);

    let bundle = AttestationBundle {
        snp_report_bytes: Vec::new(),
        parsed_snp_report: ParsedSnpReport {
            report_data,
            host_data: Sha256::digest(&cc_init_data).into(),
            firmware_measurement: descriptor.expected_firmware_measurement,
        },
        cc_init_data_toml: cc_init_data,
        tls_pubkey_spki_der,
        receipt_pubkey_raw,
    };
    ValidCase {
        bundle,
        descriptor,
        domain,
        nonce,
    }
}

#[test]
fn verifies_local_rev14_bindings() {
    let case = valid_case();
    let verified = verify_attestation_bundle(&case.bundle, &case.expectations()).unwrap();
    assert_eq!(
        verified.amd_chain_status,
        AmdSnpChainStatus::CertChainUnavailable
    );
}

#[test]
fn rejects_host_data_mismatch() {
    let mut case = valid_case();
    case.bundle.parsed_snp_report.host_data[0] ^= 1;
    assert!(matches!(
        verify_attestation_bundle(&case.bundle, &case.expectations()),
        Err(AttestationError::HostDataMismatch)
    ));
}

#[test]
fn rejects_descriptor_expected_cc_init_data_hash_mismatch() {
    let mut case = valid_case();
    case.descriptor.expected_cc_init_data_hash[0] ^= 1;
    assert!(matches!(
        verify_attestation_bundle(&case.bundle, &case.expectations()),
        Err(AttestationError::DescriptorCcInitDataHashMismatch)
    ));
}

#[test]
fn rejects_report_data_spki_mismatch() {
    let mut case = valid_case();
    case.bundle.tls_pubkey_spki_der.push(0xff);
    assert!(matches!(
        verify_attestation_bundle(&case.bundle, &case.expectations()),
        Err(AttestationError::ReportDataTranscriptMismatch)
    ));
}

#[test]
fn rejects_receipt_pubkey_mismatch() {
    let mut case = valid_case();
    case.bundle.receipt_pubkey_raw[0] ^= 1;
    assert!(matches!(
        verify_attestation_bundle(&case.bundle, &case.expectations()),
        Err(AttestationError::ReceiptPubkeyHashMismatch)
    ));
}

#[test]
fn rejects_descriptor_claim_mismatch() {
    let mut case = valid_case();
    case.descriptor.namespace = "cap-other-demo".to_string();
    assert!(matches!(
        verify_attestation_bundle(&case.bundle, &case.expectations()),
        Err(AttestationError::ClaimMismatch { claim: "namespace" })
    ));
}
