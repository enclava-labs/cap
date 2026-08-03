pub const SNP_REPORT_BYTES: usize = 1_184;
const SIGNED_BYTES: usize = 0x2a0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpReport<'a> {
    pub signed_bytes: &'a [u8],
    pub version: u32,
    pub guest_policy: u64,
    pub signature_algorithm: u32,
    pub current_tcb: u64,
    pub platform_info: u64,
    pub key_info: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub reported_tcb: u64,
    pub cpuid_family: u8,
    pub cpuid_model: u8,
    pub cpuid_stepping: u8,
    pub chip_id: [u8; 64],
    pub signature_r_le: [u8; 48],
    pub signature_s_le: [u8; 48],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnpReportError {
    #[error("SNP report must be exactly {SNP_REPORT_BYTES} bytes")]
    InvalidLength,
    #[error("unsupported SNP report version {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported SNP signature algorithm {0}")]
    UnsupportedSignatureAlgorithm(u32),
    #[error("SNP report reserved bytes are nonzero")]
    NonzeroReserved,
    #[error("SNP signature integer is not canonical P-384 encoding")]
    NoncanonicalSignature,
}

pub fn parse_snp_report(bytes: &[u8]) -> Result<SnpReport<'_>, SnpReportError> {
    if bytes.len() != SNP_REPORT_BYTES {
        return Err(SnpReportError::InvalidLength);
    }
    let version = u32_at(bytes, 0x00);
    if !(2..=5).contains(&version) {
        return Err(SnpReportError::UnsupportedVersion(version));
    }
    let signature_algorithm = u32_at(bytes, 0x34);
    if signature_algorithm != 1 {
        return Err(SnpReportError::UnsupportedSignatureAlgorithm(
            signature_algorithm,
        ));
    }
    if !bytes[0x4c..0x50].iter().all(|byte| *byte == 0)
        || !bytes[0x18b..0x1a0].iter().all(|byte| *byte == 0)
        || !bytes[0x208..0x2a0].iter().all(|byte| *byte == 0)
        || !bytes[0x330..].iter().all(|byte| *byte == 0)
    {
        return Err(SnpReportError::NonzeroReserved);
    }
    if !bytes[0x2d0..0x2e8].iter().all(|byte| *byte == 0)
        || !bytes[0x318..0x330].iter().all(|byte| *byte == 0)
    {
        return Err(SnpReportError::NoncanonicalSignature);
    }

    Ok(SnpReport {
        signed_bytes: &bytes[..SIGNED_BYTES],
        version,
        guest_policy: u64_at(bytes, 0x08),
        signature_algorithm,
        current_tcb: u64_at(bytes, 0x38),
        platform_info: u64_at(bytes, 0x40),
        key_info: u32_at(bytes, 0x48),
        report_data: array_at(bytes, 0x50),
        measurement: array_at(bytes, 0x90),
        host_data: array_at(bytes, 0xc0),
        reported_tcb: u64_at(bytes, 0x180),
        cpuid_family: bytes[0x188],
        cpuid_model: bytes[0x189],
        cpuid_stepping: bytes[0x18a],
        chip_id: array_at(bytes, 0x1a0),
        signature_r_le: array_at(bytes, 0x2a0),
        signature_s_le: array_at(bytes, 0x2e8),
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(array_at(bytes, offset))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(array_at(bytes, offset))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("length checked")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    use super::*;

    fn fixture() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/genoa-snp-report.b64").trim())
            .unwrap()
    }

    #[test]
    fn parses_live_genoa_report_without_truncating_measurement() {
        let bytes = fixture();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "62a3e1ea86404a6b93639e24d76db1622408ab85f49cf86ffb524b4ae1ad3ce5"
        );
        let report = parse_snp_report(&bytes).unwrap();
        assert_eq!(report.version, 5);
        assert_eq!(report.cpuid_family, 25);
        assert_eq!(report.cpuid_model, 17);
        assert_eq!(
            hex::encode(report.measurement),
            "853739f980c88e3b2df5aa951d221cd33a35f13e16819ab9871949699ba6c7882c7b1b3ead64d214572ba452c09de96f"
        );
        assert_eq!(report.report_data.len(), 64);
        assert_eq!(report.signed_bytes.len(), SIGNED_BYTES);
    }

    #[test]
    fn rejects_mutated_reserved_and_security_fields() {
        let original = fixture();
        for (offset, expected) in [
            (0x00, SnpReportError::UnsupportedVersion(0)),
            (0x34, SnpReportError::UnsupportedSignatureAlgorithm(0)),
            (0x4c, SnpReportError::NonzeroReserved),
            (0x2d0, SnpReportError::NoncanonicalSignature),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = if offset == 0x00 || offset == 0x34 {
                0
            } else {
                1
            };
            assert_eq!(parse_snp_report(&bytes), Err(expected));
        }
    }
}
