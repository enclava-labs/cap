use enclava_common::canonical::ce_v1_decode;

pub const PROOF_BUNDLE_MEDIA_TYPE: &str = "application/vnd.enclava.proof-bundle.v1";
pub const MAX_PROOF_BUNDLE_BYTES: usize = 1_048_576;
pub const MAX_STATIC_VERIFICATION_MATERIAL_BYTES: usize = 716_800;

const PURPOSE: &[u8] = b"enclava-proof-bundle";
const SCHEMA_VERSION: &[u8] = b"1";

const FIELDS: [(&str, usize); 14] = [
    ("purpose", 64),
    ("schema_version", 16),
    ("target_origin", 2_048),
    ("challenge_nonce", 32),
    ("created_at_unix_seconds", 20),
    ("snp_report", 4_096),
    ("tls_leaf_der", 16_384),
    ("proxy_receipt_public_key", 4_096),
    ("amd_endorsements", 131_072),
    ("cc_init_data_toml", 196_608),
    ("workload_artifacts_json", 196_608),
    ("trustee_policy_json", 49_152),
    ("sigstore_material", 196_608),
    ("provenance_oci_material", 311_296),
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("proof bundle exceeds {MAX_PROOF_BUNDLE_BYTES} bytes")]
    BundleTooLarge,
    #[error("invalid CE-v1 proof bundle: {0}")]
    InvalidEncoding(String),
    #[error("expected field {expected} at index {index}, found {actual}")]
    UnexpectedField {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("proof bundle contains {actual} fields, expected {expected}")]
    FieldCount { expected: usize, actual: usize },
    #[error("field {field} exceeds its {limit}-byte limit")]
    FieldTooLarge { field: &'static str, limit: usize },
    #[error("unsupported proof bundle purpose or schema version")]
    UnsupportedVersion,
    #[error("target origin is not UTF-8 HTTPS origin")]
    InvalidTargetOrigin,
    #[error("challenge nonce must be exactly 32 bytes")]
    InvalidNonce,
    #[error("creation time must be canonical unsigned decimal seconds")]
    InvalidCreationTime,
    #[error("static verification material exceeds {MAX_STATIC_VERIFICATION_MATERIAL_BYTES} bytes")]
    StaticMaterialTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBundle<'a> {
    pub target_origin: &'a str,
    pub challenge_nonce: [u8; 32],
    pub created_at_unix_seconds: u64,
    pub snp_report: &'a [u8],
    pub tls_leaf_der: &'a [u8],
    pub proxy_receipt_public_key: &'a [u8],
    pub amd_endorsements: &'a [u8],
    pub cc_init_data_toml: &'a [u8],
    pub workload_artifacts_json: &'a [u8],
    pub trustee_policy_json: &'a [u8],
    pub sigstore_material: &'a [u8],
    pub provenance_oci_material: &'a [u8],
}

pub fn parse_proof_bundle(bytes: &[u8]) -> Result<ProofBundle<'_>, BundleError> {
    if bytes.len() > MAX_PROOF_BUNDLE_BYTES {
        return Err(BundleError::BundleTooLarge);
    }
    let records =
        ce_v1_decode(bytes).map_err(|error| BundleError::InvalidEncoding(error.to_string()))?;
    if records.len() != FIELDS.len() {
        return Err(BundleError::FieldCount {
            expected: FIELDS.len(),
            actual: records.len(),
        });
    }
    for (index, (record, (expected, limit))) in records.iter().zip(FIELDS).enumerate() {
        if record.label != expected {
            return Err(BundleError::UnexpectedField {
                index,
                expected,
                actual: record.label.to_owned(),
            });
        }
        if record.value.len() > limit {
            return Err(BundleError::FieldTooLarge {
                field: expected,
                limit,
            });
        }
    }
    if records[0].value != PURPOSE || records[1].value != SCHEMA_VERSION {
        return Err(BundleError::UnsupportedVersion);
    }
    let target_origin = std::str::from_utf8(records[2].value)
        .ok()
        .and_then(|origin| {
            let parsed = url::Url::parse(origin).ok()?;
            (parsed.scheme() == "https"
                && parsed.host().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.origin().ascii_serialization() == origin)
                .then_some(origin)
        })
        .ok_or(BundleError::InvalidTargetOrigin)?;
    let challenge_nonce = records[3]
        .value
        .try_into()
        .map_err(|_| BundleError::InvalidNonce)?;
    let creation_time = std::str::from_utf8(records[4].value)
        .ok()
        .filter(|value| *value == "0" || !value.starts_with('0'))
        .and_then(|value| value.parse().ok())
        .ok_or(BundleError::InvalidCreationTime)?;
    let static_size = records[9..]
        .iter()
        .map(|record| 2 + record.label.len() + 4 + record.value.len())
        .sum::<usize>();
    if static_size > MAX_STATIC_VERIFICATION_MATERIAL_BYTES {
        return Err(BundleError::StaticMaterialTooLarge);
    }

    Ok(ProofBundle {
        target_origin,
        challenge_nonce,
        created_at_unix_seconds: creation_time,
        snp_report: records[5].value,
        tls_leaf_der: records[6].value,
        proxy_receipt_public_key: records[7].value,
        amd_endorsements: records[8].value,
        cc_init_data_toml: records[9].value,
        workload_artifacts_json: records[10].value,
        trustee_policy_json: records[11].value,
        sigstore_material: records[12].value,
        provenance_oci_material: records[13].value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::canonical::{ce_v1_bytes, ce_v1_decode};

    fn valid_bundle() -> Vec<u8> {
        ce_v1_bytes(&[
            ("purpose", PURPOSE),
            ("schema_version", SCHEMA_VERSION),
            ("target_origin", b"https://app.example"),
            ("challenge_nonce", &[7; 32]),
            ("created_at_unix_seconds", b"1770000000"),
            ("snp_report", b"report"),
            ("tls_leaf_der", b"certificate"),
            ("proxy_receipt_public_key", b"public-key"),
            ("amd_endorsements", b"endorsements"),
            ("cc_init_data_toml", b"cc-init"),
            ("workload_artifacts_json", b"artifacts"),
            ("trustee_policy_json", b"trustee-policy"),
            ("sigstore_material", b"sigstore"),
            ("provenance_oci_material", b"provenance"),
        ])
    }

    #[test]
    fn parses_fixed_order_bundle() {
        let bytes = valid_bundle();
        let bundle = parse_proof_bundle(&bytes).unwrap();
        assert_eq!(bundle.target_origin, "https://app.example");
        assert_eq!(bundle.challenge_nonce, [7; 32]);
    }

    #[test]
    fn rejects_reordered_fields() {
        let bytes = valid_bundle();
        let decoded = ce_v1_decode(&bytes).unwrap();
        let mut records = decoded
            .iter()
            .map(|record| (record.label, record.value))
            .collect::<Vec<_>>();
        records.swap(0, 1);
        assert!(matches!(
            parse_proof_bundle(&ce_v1_bytes(&records)),
            Err(BundleError::UnexpectedField { index: 0, .. })
        ));
    }

    #[test]
    fn accepts_realistic_raw_genpolicy_material_within_static_limit() {
        let bytes = valid_bundle();
        let decoded = ce_v1_decode(&bytes).unwrap();
        let cc_init_data = vec![b'a'; 150_000];
        let workload_artifacts = vec![b'b'; 150_000];
        let mut records = decoded
            .iter()
            .map(|record| (record.label, record.value))
            .collect::<Vec<_>>();
        records[9].1 = &cc_init_data;
        records[10].1 = &workload_artifacts;

        parse_proof_bundle(&ce_v1_bytes(&records)).unwrap();
    }
}
