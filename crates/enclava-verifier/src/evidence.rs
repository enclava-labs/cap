use enclava_common::canonical::{ce_v1_decode, ce_v1_hash};
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

use crate::SnpReport;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("evidence has invalid CE-v1 encoding")]
    InvalidEncoding,
    #[error("evidence field is missing or out of order")]
    UnexpectedField,
    #[error("evidence purpose or version is unsupported")]
    UnsupportedVersion,
    #[error("TLS leaf certificate is invalid")]
    InvalidTlsCertificate,
}

#[derive(Debug)]
pub struct AmdEndorsements<'a> {
    pub product: &'a str,
    pub ark_der: &'a [u8],
    pub ask_der: &'a [u8],
    pub vcek_der: &'a [u8],
    pub crl_der: &'a [u8],
}

pub fn parse_amd_endorsements(bytes: &[u8]) -> Result<AmdEndorsements<'_>, EvidenceError> {
    const FIELDS: [&str; 7] = [
        "purpose",
        "schema_version",
        "product",
        "ark_der",
        "ask_der",
        "vcek_der",
        "crl_der",
    ];
    let records = ce_v1_decode(bytes).map_err(|_| EvidenceError::InvalidEncoding)?;
    if records.len() != FIELDS.len()
        || records
            .iter()
            .zip(FIELDS)
            .any(|(record, expected)| record.label != expected)
    {
        return Err(EvidenceError::UnexpectedField);
    }
    if records[0].value != b"enclava-amd-endorsements" || records[1].value != b"1" {
        return Err(EvidenceError::UnsupportedVersion);
    }
    let product = std::str::from_utf8(records[2].value)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(EvidenceError::InvalidEncoding)?;
    Ok(AmdEndorsements {
        product,
        ark_der: records[3].value,
        ask_der: records[4].value,
        vcek_der: records[5].value,
        crl_der: records[6].value,
    })
}

pub fn tls_leaf_spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32], EvidenceError> {
    let certificate =
        Certificate::from_der(certificate_der).map_err(|_| EvidenceError::InvalidTlsCertificate)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| EvidenceError::InvalidTlsCertificate)?;
    Ok(Sha256::digest(spki).into())
}

pub fn expected_report_data(
    target_origin: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
    receipt_public_key: &[u8],
) -> Result<[u8; 64], EvidenceError> {
    let url = url::Url::parse(target_origin).map_err(|_| EvidenceError::InvalidEncoding)?;
    let domain = url.host_str().ok_or(EvidenceError::InvalidEncoding)?;
    let transcript_hash = ce_v1_hash(&[
        ("purpose", b"enclava-tee-tls-v1"),
        ("domain", domain.as_bytes()),
        ("nonce", nonce),
        ("leaf_spki_sha256", leaf_spki_sha256),
    ]);
    let receipt_pubkey_sha256: [u8; 32] = Sha256::digest(receipt_public_key).into();
    let binding_hash = ce_v1_hash(&[
        ("purpose", b"enclava-tee-report-data-v1"),
        ("transcript_hash", &transcript_hash),
        ("receipt_pubkey_sha256", &receipt_pubkey_sha256),
    ]);
    let encoded = hex::encode(binding_hash);
    Ok(encoded
        .as_bytes()
        .try_into()
        .expect("SHA-256 hex is 64 bytes"))
}

pub fn report_data_matches(
    report: &SnpReport<'_>,
    target_origin: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
    receipt_public_key: &[u8],
) -> bool {
    expected_report_data(target_origin, nonce, leaf_spki_sha256, receipt_public_key)
        .is_ok_and(|expected| report.report_data == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::canonical::ce_v1_bytes;

    #[test]
    fn endorsements_are_fixed_order() {
        let bytes = ce_v1_bytes(&[
            ("purpose", b"enclava-amd-endorsements"),
            ("schema_version", b"1"),
            ("product", b"Genoa"),
            ("ark_der", b"ark"),
            ("ask_der", b"ask"),
            ("vcek_der", b"vcek"),
            ("crl_der", b"crl"),
        ]);
        assert_eq!(parse_amd_endorsements(&bytes).unwrap().product, "Genoa");
        let mut records = ce_v1_decode(&bytes)
            .unwrap()
            .iter()
            .map(|r| (r.label, r.value))
            .collect::<Vec<_>>();
        records.swap(3, 4);
        assert_eq!(
            parse_amd_endorsements(&ce_v1_bytes(&records)).unwrap_err(),
            EvidenceError::UnexpectedField
        );
    }

    #[test]
    fn report_binding_changes_with_every_external_input() {
        let origin = "https://app.example";
        let nonce = [1; 32];
        let spki = [2; 32];
        let key = [3; 32];
        let expected = expected_report_data(origin, &nonce, &spki, &key).unwrap();
        assert_ne!(
            expected,
            expected_report_data("https://other.example", &nonce, &spki, &key).unwrap()
        );
        assert_ne!(
            expected,
            expected_report_data(origin, &[4; 32], &spki, &key).unwrap()
        );
        assert_ne!(
            expected,
            expected_report_data(origin, &nonce, &[5; 32], &key).unwrap()
        );
        assert_ne!(
            expected,
            expected_report_data(origin, &nonce, &spki, &[6; 32]).unwrap()
        );
    }
}
