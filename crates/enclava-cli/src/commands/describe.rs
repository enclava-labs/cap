use std::path::PathBuf;

use clap::Args;
use enclava_common::descriptor::DeploymentDescriptor;
use enclava_verifier::{
    observed_artifact_anchors, parse_amd_endorsements, parse_proof_bundle, parse_snp_report,
    report_data_matches, tls_leaf_spki_sha256, verify_amd_certificate_chain, verify_snp_signature,
    verify_vcek_report_binding,
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::verify::{fetch_bundle, normalize_origin};

/// The checks `enclava verify` can appraise; a skeleton policy requests all of
/// them so the operator edits anchors rather than discovering missing checks.
const ALL_CHECKS: [&str; 25] = [
    "binding.challenge_nonce",
    "binding.target_origin",
    "policy.structure",
    "amd.report_structure",
    "amd.endorsements_structure",
    "binding.tls_leaf_certificate",
    "amd.certificate_chain",
    "amd.report_signature",
    "amd.vcek_binding",
    "amd.revocation.freshness",
    "amd.measurement",
    "amd.tcb",
    "amd.guest_policy",
    "binding.report_data",
    "policy.target_origin",
    "artifacts.signatures",
    "artifacts.relationships",
    "artifacts.descriptor_measurement",
    "supply_chain.image_policy",
    "platform.runtime_class",
    "platform.sidecars",
    "platform.release",
    "deployment.identity",
    "supply_chain.portable_integrity",
    "supply_chain.signatures",
];

#[derive(Args)]
pub struct DescribeArgs {
    /// HTTPS origin to observe live, or a path to a saved proof bundle
    #[arg(value_name = "HTTPS_ORIGIN_OR_BUNDLE_PATH")]
    target: String,
    /// Save the exact live proof-bundle bytes
    #[arg(long, value_name = "PATH")]
    save_bundle: Option<PathBuf>,
    /// Emit a trust-policy skeleton from the observed values (TOFU: edit
    /// before use, especially the sigstore block; record via a channel the
    /// target cannot influence)
    #[arg(long, value_name = "PATH")]
    policy_skeleton: Option<PathBuf>,
    /// Emit the observation as compact JSON
    #[arg(long)]
    json: bool,
}

pub async fn run(args: DescribeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let historical = !args.target.starts_with("https://");
    let (bytes, live) = if historical {
        (tokio::fs::read(&args.target).await?, None)
    } else {
        let origin = normalize_origin(&args.target)?;
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let (bytes, channel_spki) = fetch_bundle(&origin, &nonce).await?;
        if let Some(path) = &args.save_bundle {
            tokio::fs::write(path, &bytes).await?;
        }
        (bytes, Some((origin, nonce, channel_spki)))
    };

    let observation = observe(&bytes, live.as_ref())?;
    if args.json {
        println!("{}", serde_json::to_string(&observation)?);
    } else {
        print_human(&observation);
        if historical {
            eprintln!("Historical evidence: this saved bundle does not prove current liveness.");
        }
    }
    if let Some(path) = &args.policy_skeleton {
        let skeleton = policy_skeleton(&observation)?;
        tokio::fs::write(path, serde_json::to_vec_pretty(&skeleton)?).await?;
        if !args.json {
            eprintln!(
                "Wrote {}: TOFU skeleton — review every anchor and fill the sigstore \
                 block (supply-chain trust is yours, not the target's) before appraising.",
                path.display()
            );
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct Observation {
    schema_version: &'static str,
    observation_not_appraisal: bool,
    historical: bool,
    target_origin: String,
    bundle_sha256: String,
    created_at_unix_seconds: u64,
    workload: WorkloadView,
    platform: PlatformView,
    amd: AmdView,
    evidence_authenticity: AuthenticityView,
    observed_anchors: AnchorsView,
}

#[derive(serde::Serialize)]
struct WorkloadView {
    image_digest: String,
    signer_subject: String,
    signer_issuer: String,
}

#[derive(serde::Serialize)]
struct PlatformView {
    runtime_class: String,
    platform_release_version: String,
    attestation_proxy_digest: String,
    caddy_digest: String,
    organization_id: String,
    application_id: String,
}

#[derive(serde::Serialize)]
struct AmdView {
    product: String,
    measurement: String,
    tcb: TcbView,
    guest_policy: String,
    ark_sha256: String,
}

#[derive(serde::Serialize)]
struct TcbView {
    bootloader: u8,
    tee: u8,
    fmc: u8,
    snp: u8,
    microcode: u8,
}

#[derive(serde::Serialize)]
struct AuthenticityView {
    certificate_chain_internally_consistent: bool,
    report_signature_verifies: bool,
    vcek_report_binding_verifies: bool,
    report_data_self_consistent: bool,
    live_channel_matches_bundle_leaf: Option<bool>,
}

/// Trust anchors the target presented about itself. Observable facts, not
/// endorsements: a skeleton records them so a later appraisal can detect
/// change, which is strictly weaker than approving them up front.
#[derive(serde::Serialize)]
struct AnchorsView {
    org_keyring_sha256: String,
    policy_signing_pubkey: String,
}

fn tcb_view(reported_tcb: u64) -> TcbView {
    let bytes = reported_tcb.to_le_bytes();
    TcbView {
        bootloader: bytes[0],
        tee: bytes[1],
        fmc: bytes[2],
        snp: bytes[6],
        microcode: bytes[7],
    }
}

#[derive(Deserialize)]
struct WorkloadArtifactsView {
    descriptor_payload: DeploymentDescriptor,
}

fn observe(
    bytes: &[u8],
    live: Option<&(String, [u8; 32], [u8; 32])>,
) -> Result<Observation, Box<dyn std::error::Error>> {
    let bundle = parse_proof_bundle(bytes)?;
    let report = parse_snp_report(bundle.snp_report)?;
    let endorsements = parse_amd_endorsements(bundle.amd_endorsements)?;
    let artifacts: WorkloadArtifactsView = serde_json::from_slice(bundle.workload_artifacts_json)?;
    let descriptor = &artifacts.descriptor_payload;
    let leaf_spki = tls_leaf_spki_sha256(bundle.tls_leaf_der)?;
    let ark_sha256: [u8; 32] = Sha256::digest(endorsements.ark_der).into();
    let (keyring_sha256, policy_signing_pubkey) =
        observed_artifact_anchors(bundle.workload_artifacts_json)?;

    // Evidence authenticity only: internal consistency of the material the
    // target presented. None of these decide whether the values are *good*.
    let receipt_key: [u8; 32] = bundle
        .proxy_receipt_public_key
        .try_into()
        .map_err(|_| "proxy receipt public key must be 32 bytes")?;
    let chain_ok = verify_amd_certificate_chain(
        endorsements.ark_der,
        endorsements.ask_der,
        endorsements.vcek_der,
        &ark_sha256,
    )
    .is_ok();
    let signature_ok = verify_snp_signature(&report, endorsements.vcek_der).is_ok();
    let vcek_binding_ok = verify_vcek_report_binding(&report, endorsements.vcek_der).is_ok();
    let (report_origin, report_nonce) = match live {
        Some((origin, nonce, _)) => (origin.as_str(), *nonce),
        None => (bundle.target_origin, bundle.challenge_nonce),
    };
    let report_data_ok = report_data_matches(
        &report,
        report_origin,
        &report_nonce,
        &leaf_spki,
        &receipt_key,
    );
    let live_channel = live.map(|(_, _, channel_spki)| channel_spki == &leaf_spki);

    Ok(Observation {
        schema_version: "enclava-proof-bundle-v1",
        observation_not_appraisal: true,
        historical: live.is_none(),
        target_origin: bundle.target_origin.to_owned(),
        bundle_sha256: hex::encode(Sha256::digest(bytes)),
        created_at_unix_seconds: bundle.created_at_unix_seconds,
        workload: WorkloadView {
            image_digest: descriptor.image_digest.clone(),
            signer_subject: descriptor.signer_identity.subject.clone(),
            signer_issuer: descriptor.signer_identity.issuer.clone(),
        },
        platform: PlatformView {
            runtime_class: descriptor.expected_runtime_class.clone(),
            platform_release_version: descriptor.platform_release_version.clone(),
            attestation_proxy_digest: descriptor.sidecars.attestation_proxy_digest.clone(),
            caddy_digest: descriptor.sidecars.caddy_digest.clone(),
            organization_id: descriptor.org_id.to_string(),
            application_id: descriptor.app_id.to_string(),
        },
        amd: AmdView {
            product: endorsements.product.to_owned(),
            measurement: hex::encode(report.measurement),
            tcb: tcb_view(report.reported_tcb),
            guest_policy: format!("{:#x}", report.guest_policy),
            ark_sha256: hex::encode(ark_sha256),
        },
        evidence_authenticity: AuthenticityView {
            certificate_chain_internally_consistent: chain_ok,
            report_signature_verifies: signature_ok,
            vcek_report_binding_verifies: vcek_binding_ok,
            report_data_self_consistent: report_data_ok,
            live_channel_matches_bundle_leaf: live_channel,
        },
        observed_anchors: AnchorsView {
            org_keyring_sha256: keyring_sha256,
            policy_signing_pubkey,
        },
    })
}

fn fact(ok: bool) -> &'static str {
    if ok { "consistent" } else { "INCONSISTENT" }
}

fn print_human(observation: &Observation) {
    println!("Enclava proof bundle v1 — observation, not appraisal");
    println!(
        "  origin {} · created {} (unix) · bundle sha256 {}{}",
        observation.target_origin,
        observation.created_at_unix_seconds,
        observation.bundle_sha256,
        if observation.historical {
            " · historical"
        } else {
            " · fetched live"
        }
    );
    println!();
    println!("Workload");
    println!("  image   {}", observation.workload.image_digest);
    println!("  signer  {}", observation.workload.signer_subject);
    println!("  issuer  {}", observation.workload.signer_issuer);
    println!();
    println!("Platform");
    println!("  runtime {}", observation.platform.runtime_class);
    println!(
        "  release {}",
        observation.platform.platform_release_version
    );
    println!(
        "  proxy   {}",
        observation.platform.attestation_proxy_digest
    );
    println!("  caddy   {}", observation.platform.caddy_digest);
    println!(
        "  ids     org {} · app {}",
        observation.platform.organization_id, observation.platform.application_id
    );
    println!();
    println!("AMD SEV-SNP ({})", observation.amd.product);
    println!("  measurement {}", observation.amd.measurement);
    let tcb = &observation.amd.tcb;
    println!(
        "  tcb         boot {} · tee {} · fmc {} · snp {} · microcode {}",
        tcb.bootloader, tcb.tee, tcb.fmc, tcb.snp, tcb.microcode
    );
    println!("  guest policy {}", observation.amd.guest_policy);
    println!("  ark sha256  {}", observation.amd.ark_sha256);
    println!();
    println!("Evidence authenticity (internal consistency only)");
    let auth = &observation.evidence_authenticity;
    println!(
        "  certificate chain {} (ARK self-signed, ASK←ARK, VCEK←ASK)",
        fact(auth.certificate_chain_internally_consistent)
    );
    println!(
        "  report signature {} against presented VCEK",
        fact(auth.report_signature_verifies)
    );
    println!(
        "  VCEK↔report binding {}",
        fact(auth.vcek_report_binding_verifies)
    );
    if observation.historical {
        println!(
            "  report_data {} with the bundle's own nonce/origin/leaf",
            fact(auth.report_data_self_consistent)
        );
    } else {
        println!(
            "  report_data {} with the challenge nonce sent",
            fact(auth.report_data_self_consistent)
        );
        if let Some(matches) = auth.live_channel_matches_bundle_leaf {
            println!(
                "  TLS channel {} the leaf in the bundle",
                if matches { "matches" } else { "DOES NOT match" }
            );
        }
    }
    println!();
    println!("Observed anchors (recorded, not endorsed)");
    println!(
        "  org keyring sha256     {}",
        observation.observed_anchors.org_keyring_sha256
    );
    println!(
        "  policy signing pubkey  {}",
        observation.observed_anchors.policy_signing_pubkey
    );
}

fn policy_skeleton(
    observation: &Observation,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let tcb = &observation.amd.tcb;
    Ok(serde_json::json!({
        "schema_version": "enclava-trust-policy-v1",
        "label": format!(
            "TOFU skeleton observed {} {}",
            observed_at, observation.target_origin
        ),
        "required_checks": ALL_CHECKS,
        "amd": {
            "trusted_ark_sha256": [observation.amd.ark_sha256],
            "allowed_measurements": [observation.amd.measurement],
            "minimum_tcb": {
                "bootloader": tcb.bootloader,
                "tee": tcb.tee,
                "fmc": tcb.fmc,
                "snp": tcb.snp,
                "microcode": tcb.microcode,
            },
            "guest_policy_mask": u64::from_str_radix("ffffffffffffffff", 16).unwrap(),
            "guest_policy_value": u64::from_str_radix(
                observation.amd.guest_policy.trim_start_matches("0x"),
                16
            )?,
            "revocation_max_age_seconds": 3_888_000,
        },
        "target": {
            "origins": [observation.target_origin],
            "image_digests": [observation.workload.image_digest],
            "runtime_classes": [observation.platform.runtime_class],
            "attestation_proxy_digests": [observation.platform.attestation_proxy_digest],
            "caddy_digests": [observation.platform.caddy_digest],
            "platform_release_versions": [observation.platform.platform_release_version],
            "organization_ids": [observation.platform.organization_id],
            "application_ids": [observation.platform.application_id],
        },
        "trusted_org_keyring_sha256": [observation.observed_anchors.org_keyring_sha256],
        "trusted_policy_signing_pubkeys": [observation.observed_anchors.policy_signing_pubkey],
        "sigstore": {
            "fulcio_roots_der_base64": ["REPLACE_WITH_TRUSTED_FULCIO_ROOTS"],
            "fulcio_intermediates_der_base64": ["REPLACE_WITH_TRUSTED_FULCIO_INTERMEDIATES"],
            "trusted_fulcio_root_sha256": ["REPLACE_WITH_TRUSTED_FULCIO_ROOT_SHA256"],
            "rekor_spki_der_base64": ["REPLACE_WITH_TRUSTED_REKOR_SPKI"],
            "certificate_identity": "REPLACE_WITH_EXPECTED_SIGNER_IDENTITY",
            "oidc_issuer": "REPLACE_WITH_EXPECTED_OIDC_ISSUER",
            "source_repository": "REPLACE_WITH_SOURCE_REPOSITORY",
            "workflow_ref": "REPLACE_WITH_WORKFLOW_REF",
            "provenance_builder_id": "REPLACE_WITH_PROVENANCE_BUILDER_ID",
        },
        "transport": {
            "require_tls_channel_spki": false,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_bytes() -> Vec<u8> {
        use base64::Engine as _;
        let encoded: String =
            include_str!("../../../enclava-verifier/tests/fixtures/prove-it-live.bundle.b64")
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .map(|byte| byte as char)
                .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }

    #[test]
    fn observes_fixture_bundle_without_appraisal() {
        let observation = observe(&fixture_bytes(), None).unwrap();
        assert!(observation.historical);
        assert!(observation.observation_not_appraisal);
        assert!(observation.target_origin.starts_with("https://"));
        assert!(observation.workload.image_digest.contains("sha256:"));
        assert_eq!(observation.amd.measurement.len(), 96);
        assert!(
            observation
                .evidence_authenticity
                .report_data_self_consistent
        );
        assert!(observation.observed_anchors.org_keyring_sha256.len() == 64);
    }

    #[test]
    fn skeleton_round_trips_through_policy_parser() {
        let observation = observe(&fixture_bytes(), None).unwrap();
        let skeleton = policy_skeleton(&observation).unwrap();
        let bytes = serde_json::to_vec(&skeleton).unwrap();
        let parsed = enclava_verifier::TrustPolicy::parse(&bytes)
            .expect("skeleton must satisfy the trust-policy structure");
        assert_eq!(parsed.required_checks.len(), 25);
        assert_eq!(parsed.amd.allowed_measurements.len(), 1);
    }
}
