use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub schema_version: String,
    #[serde(default)]
    #[serde(rename = "label")]
    pub _label: Option<String>,
    pub required_checks: Vec<String>,
    pub amd: AmdPolicy,
    pub target: TargetPolicy,
    pub trusted_org_keyring_sha256: Vec<String>,
    pub trusted_policy_signing_pubkeys: Vec<String>,
    pub sigstore: SigstorePolicy,
    #[serde(default)]
    pub transport: TransportPolicy,
    #[serde(default)]
    pub appraiser: AppraiserPolicy,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppraiserPolicy {
    #[serde(default)]
    pub keys: Vec<AppraiserKeyPolicy>,
    #[serde(default)]
    pub maximum_receipt_lifetime_seconds: u64,
    #[serde(default)]
    pub clock_skew_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppraiserKeyPolicy {
    pub key_id: String,
    pub public_key_base64: String,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmdPolicy {
    pub trusted_ark_sha256: Vec<String>,
    pub allowed_measurements: Vec<String>,
    pub minimum_tcb: TcbPolicy,
    pub guest_policy_mask: u64,
    pub guest_policy_value: u64,
    pub revocation_max_age_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcbPolicy {
    #[serde(default)]
    pub bootloader: u8,
    #[serde(default)]
    pub tee: u8,
    #[serde(default)]
    pub fmc: u8,
    #[serde(default)]
    pub snp: u8,
    #[serde(default)]
    pub microcode: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPolicy {
    pub origins: Vec<String>,
    pub image_digests: Vec<String>,
    pub runtime_classes: Vec<String>,
    pub attestation_proxy_digests: Vec<String>,
    pub caddy_digests: Vec<String>,
    pub platform_release_versions: Vec<String>,
    pub organization_ids: Vec<String>,
    pub application_ids: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPolicy {
    #[serde(default)]
    pub require_tls_channel_spki: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstorePolicy {
    pub fulcio_roots_der_base64: Vec<String>,
    pub fulcio_intermediates_der_base64: Vec<String>,
    pub trusted_fulcio_root_sha256: Vec<String>,
    pub rekor_spki_der_base64: Vec<String>,
    pub certificate_identity: String,
    pub oidc_issuer: String,
    pub source_repository: String,
    pub workflow_ref: String,
    pub provenance_builder_id: String,
}

impl TrustPolicy {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let policy: Self = serde_json::from_slice(bytes).ok()?;
        (policy.schema_version == "enclava-trust-policy-v1"
            && !policy.required_checks.is_empty()
            && !policy.amd.trusted_ark_sha256.is_empty()
            && policy
                .amd
                .trusted_ark_sha256
                .iter()
                .all(|hash| decode_32(hash).is_some())
            && !policy.amd.allowed_measurements.is_empty()
            && policy
                .amd
                .allowed_measurements
                .iter()
                .all(|measurement| decode_48(measurement).is_some())
            && !policy.target.origins.is_empty()
            && !policy.target.image_digests.is_empty()
            && !policy.target.runtime_classes.is_empty()
            && !policy.target.attestation_proxy_digests.is_empty()
            && !policy.target.caddy_digests.is_empty()
            && !policy.target.platform_release_versions.is_empty()
            && !policy.target.organization_ids.is_empty()
            && !policy.target.application_ids.is_empty()
            && !policy.trusted_org_keyring_sha256.is_empty()
            && policy
                .trusted_org_keyring_sha256
                .iter()
                .all(|hash| decode_32(hash).is_some())
            && !policy.trusted_policy_signing_pubkeys.is_empty()
            && policy
                .trusted_policy_signing_pubkeys
                .iter()
                .all(|key| decode_32(key).is_some())
            && !policy.sigstore.fulcio_roots_der_base64.is_empty()
            && !policy.sigstore.fulcio_intermediates_der_base64.is_empty()
            && !policy.sigstore.trusted_fulcio_root_sha256.is_empty()
            && !policy.sigstore.rekor_spki_der_base64.is_empty()
            && !policy.sigstore.certificate_identity.is_empty()
            && !policy.sigstore.oidc_issuer.is_empty()
            && !policy.sigstore.source_repository.is_empty()
            && !policy.sigstore.workflow_ref.is_empty()
            && !policy.sigstore.provenance_builder_id.is_empty())
        .then_some(policy)
    }
}

pub fn decode_32(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

pub fn decode_48(value: &str) -> Option<[u8; 48]> {
    hex::decode(value).ok()?.try_into().ok()
}

pub fn tcb_meets(reported: u64, minimum: &TcbPolicy) -> bool {
    let bytes = reported.to_le_bytes();
    bytes[0] >= minimum.bootloader
        && bytes[1] >= minimum.tee
        && bytes[2] >= minimum.fmc
        && bytes[6] >= minimum.snp
        && bytes[7] >= minimum.microcode
}
