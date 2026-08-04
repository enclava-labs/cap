use p384::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use pkcs1::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    der::{Decode, Encode},
};

use crate::SnpReport;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AmdVerificationError {
    #[error("AMD certificate is not valid DER")]
    InvalidCertificate,
    #[error("AMD certificate does not contain a P-384 public key")]
    InvalidPublicKey,
    #[error("AMD certificate contains an invalid ECDSA signature")]
    InvalidCertificateSignature,
    #[error("AMD certificate signature verification failed")]
    CertificateSignatureMismatch,
    #[error("AMD certificate does not use RSA-PSS")]
    UnsupportedCertificateSignature,
    #[error("AMD ARK fingerprint is not trusted by policy")]
    UntrustedArk,
    #[error("SNP report signature is invalid")]
    InvalidReportSignature,
    #[error("AMD VCEK does not match the SNP report chip ID and TCB")]
    VcekReportMismatch,
    #[error("AMD certificate is outside its validity interval")]
    CertificateTimeInvalid,
    #[error("AMD revocation list is invalid")]
    InvalidRevocationList,
    #[error("AMD VCEK is revoked")]
    Revoked,
    #[error("AMD revocation data has no signed nextUpdate")]
    RevocationTimeMissing,
    #[error("AMD revocation data is stale")]
    RevocationDataStale,
    #[error("AMD revocation data is expired")]
    RevocationDataExpired,
}

pub fn verify_amd_revocation(
    ark_der: &[u8],
    ask_der: &[u8],
    vcek_der: &[u8],
    crl_der: &[u8],
    now_unix_seconds: u64,
    maximum_age_seconds: u64,
) -> Result<(), AmdVerificationError> {
    let ark =
        Certificate::from_der(ark_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let ask =
        Certificate::from_der(ask_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let vcek =
        Certificate::from_der(vcek_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    for certificate in [&ark, &ask, &vcek] {
        let validity = &certificate.tbs_certificate.validity;
        if now_unix_seconds < validity.not_before.to_unix_duration().as_secs()
            || now_unix_seconds > validity.not_after.to_unix_duration().as_secs()
        {
            return Err(AmdVerificationError::CertificateTimeInvalid);
        }
    }
    let crl = CertificateList::from_der(crl_der)
        .map_err(|_| AmdVerificationError::InvalidRevocationList)?;
    if crl.signature_algorithm != crl.tbs_cert_list.signature
        || crl.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.10"
    {
        return Err(AmdVerificationError::InvalidRevocationList);
    }
    let signed = crl
        .tbs_cert_list
        .to_der()
        .map_err(|_| AmdVerificationError::InvalidRevocationList)?;
    let signature = crl
        .signature
        .as_bytes()
        .ok_or(AmdVerificationError::InvalidRevocationList)?;
    if !verify_rsa_certificate_list_signature(&ark, &signed, signature)
        && !verify_rsa_certificate_list_signature(&ask, &signed, signature)
    {
        return Err(AmdVerificationError::InvalidRevocationList);
    }
    verify_revocation_times(&crl, now_unix_seconds, maximum_age_seconds)?;
    if crl
        .tbs_cert_list
        .revoked_certificates
        .as_ref()
        .is_some_and(|revoked| {
            revoked
                .iter()
                .any(|entry| entry.serial_number == vcek.tbs_certificate.serial_number)
        })
    {
        return Err(AmdVerificationError::Revoked);
    }
    Ok(())
}

fn verify_revocation_times(
    crl: &CertificateList,
    now_unix_seconds: u64,
    maximum_age_seconds: u64,
) -> Result<(), AmdVerificationError> {
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
    let next_update = crl
        .tbs_cert_list
        .next_update
        .ok_or(AmdVerificationError::RevocationTimeMissing)?
        .to_unix_duration()
        .as_secs();
    if now_unix_seconds > next_update {
        return Err(AmdVerificationError::RevocationDataExpired);
    }
    if this_update > now_unix_seconds
        || now_unix_seconds.saturating_sub(this_update) > maximum_age_seconds
    {
        return Err(AmdVerificationError::RevocationDataStale);
    }
    Ok(())
}

fn verify_rsa_certificate_list_signature(
    issuer: &Certificate,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    let spki = issuer.tbs_certificate.subject_public_key_info.to_der().ok();
    spki.as_deref()
        .and_then(|spki| x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki).ok())
        .and_then(|spki| spki.subject_public_key.as_bytes())
        .and_then(|bytes| RsaPublicKey::from_der(bytes).ok())
        .is_some_and(|key| {
            verify_rsa_pss_sha384(
                key.modulus.as_bytes(),
                key.public_exponent.as_bytes(),
                signed,
                signature,
            )
        })
}

pub fn verify_amd_certificate_chain(
    ark_der: &[u8],
    ask_der: &[u8],
    vcek_der: &[u8],
    trusted_ark_sha256: &[u8; 32],
) -> Result<(), AmdVerificationError> {
    if Sha256::digest(ark_der).as_slice() != trusted_ark_sha256 {
        return Err(AmdVerificationError::UntrustedArk);
    }
    let ark =
        Certificate::from_der(ark_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let ask =
        Certificate::from_der(ask_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let vcek =
        Certificate::from_der(vcek_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    verify_certificate_signature(&ark, &ark)?;
    verify_certificate_signature(&ask, &ark)?;
    verify_certificate_signature(&vcek, &ask)
}

pub fn verify_snp_signature(
    report: &SnpReport<'_>,
    vcek_der: &[u8],
) -> Result<(), AmdVerificationError> {
    let vcek =
        Certificate::from_der(vcek_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let mut r = report.signature_r_le;
    let mut s = report.signature_s_le;
    r.reverse();
    s.reverse();
    let signature =
        Signature::from_scalars(r, s).map_err(|_| AmdVerificationError::InvalidReportSignature)?;
    verifying_key(&vcek)?
        .verify(report.signed_bytes, &signature)
        .map_err(|_| AmdVerificationError::InvalidReportSignature)
}

pub fn verify_vcek_report_binding(
    report: &SnpReport<'_>,
    vcek_der: &[u8],
) -> Result<(), AmdVerificationError> {
    let vcek =
        Certificate::from_der(vcek_der).map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let extensions = vcek
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(AmdVerificationError::VcekReportMismatch)?;
    let extension = |oid: &str| {
        extensions
            .iter()
            .find(|extension| extension.extn_id.to_string() == oid)
            .map(|extension| extension.extn_value.as_bytes())
            .ok_or(AmdVerificationError::VcekReportMismatch)
    };
    let reported_tcb = report.reported_tcb.to_le_bytes();
    let matches = der_u8(extension("1.3.6.1.4.1.3704.1.3.1")?) == Some(reported_tcb[0])
        && der_u8(extension("1.3.6.1.4.1.3704.1.3.2")?) == Some(reported_tcb[1])
        && der_u8(extension("1.3.6.1.4.1.3704.1.3.3")?) == Some(reported_tcb[6])
        && der_u8(extension("1.3.6.1.4.1.3704.1.3.8")?) == Some(reported_tcb[7])
        && bytes_64(extension("1.3.6.1.4.1.3704.1.4")?) == Some(report.chip_id);
    matches
        .then_some(())
        .ok_or(AmdVerificationError::VcekReportMismatch)
}

fn der_u8(value: &[u8]) -> Option<u8> {
    match value {
        [0x02, 0x01, byte] if *byte < 0x80 => Some(*byte),
        [0x02, 0x02, 0, byte] if *byte >= 0x80 => Some(*byte),
        _ => None,
    }
}

fn bytes_64(value: &[u8]) -> Option<[u8; 64]> {
    value.try_into().ok()
}

fn verify_certificate_signature(
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<(), AmdVerificationError> {
    if certificate.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.10"
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
    {
        return Err(AmdVerificationError::UnsupportedCertificateSignature);
    }
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(AmdVerificationError::InvalidCertificateSignature)?;
    let signed = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| AmdVerificationError::InvalidCertificate)?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| AmdVerificationError::InvalidPublicKey)?;
    let issuer_spki = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&spki)
        .map_err(|_| AmdVerificationError::InvalidPublicKey)?;
    let issuer_key = issuer_spki
        .subject_public_key
        .as_bytes()
        .and_then(|bytes| RsaPublicKey::from_der(bytes).ok())
        .ok_or(AmdVerificationError::InvalidPublicKey)?;
    verify_rsa_pss_sha384(
        issuer_key.modulus.as_bytes(),
        issuer_key.public_exponent.as_bytes(),
        &signed,
        signature,
    )
    .then_some(())
    .ok_or(AmdVerificationError::CertificateSignatureMismatch)
}

fn verifying_key(certificate: &Certificate) -> Result<VerifyingKey, AmdVerificationError> {
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| AmdVerificationError::InvalidPublicKey)?;
    VerifyingKey::from_public_key_der(&spki).map_err(|_| AmdVerificationError::InvalidPublicKey)
}

fn verify_rsa_pss_sha384(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    const HASH_BYTES: usize = 48;

    let modulus = num_bigint::BigUint::from_bytes_be(modulus);
    let exponent = num_bigint::BigUint::from_bytes_be(exponent);
    let modulus_bits = modulus.bits() as usize;
    let encoded_bits = modulus_bits.saturating_sub(1);
    let encoded_len = encoded_bits.div_ceil(8);
    if signature.len() != modulus_bits.div_ceil(8) || encoded_len < HASH_BYTES * 2 + 2 {
        return false;
    }
    let signature = num_bigint::BigUint::from_bytes_be(signature);
    if signature >= modulus {
        return false;
    }
    let mut encoded = signature.modpow(&exponent, &modulus).to_bytes_be();
    if encoded.len() > encoded_len {
        return false;
    }
    encoded.splice(0..0, std::iter::repeat_n(0, encoded_len - encoded.len()));
    if encoded.last() != Some(&0xbc) {
        return false;
    }

    let db_len = encoded_len - HASH_BYTES - 1;
    let (masked_db, hash_and_trailer) = encoded.split_at(db_len);
    let hash = &hash_and_trailer[..HASH_BYTES];
    let unused_bits = encoded_len * 8 - encoded_bits;
    if masked_db[0] >> (8 - unused_bits) != 0 {
        return false;
    }
    let mask = mgf1_sha384(hash, db_len);
    let mut db = masked_db
        .iter()
        .zip(mask)
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();
    db[0] &= 0xff >> unused_bits;
    let separator = db_len - HASH_BYTES - 1;
    if db[..separator].iter().any(|byte| *byte != 0) || db[separator] != 1 {
        return false;
    }
    let salt = &db[separator + 1..];
    let message_hash = Sha384::digest(message);
    let expected = Sha384::new()
        .chain_update([0; 8])
        .chain_update(message_hash)
        .chain_update(salt)
        .finalize();
    hash == expected.as_slice()
}

fn mgf1_sha384(seed: &[u8], len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(len);
    for counter in 0u32.. {
        output.extend_from_slice(
            &Sha384::new()
                .chain_update(seed)
                .chain_update(counter.to_be_bytes())
                .finalize(),
        );
        if output.len() >= len {
            output.truncate(len);
            return output;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;
    use crate::parse_snp_report;

    fn fixture(name: &str) -> Vec<u8> {
        let encoded = match name {
            "report" => include_str!("../tests/fixtures/genoa-snp-report.b64"),
            "ark" => include_str!("../tests/fixtures/genoa-ark.der.b64"),
            "ask" => include_str!("../tests/fixtures/genoa-ask.der.b64"),
            "vcek" => include_str!("../tests/fixtures/genoa-vcek.der.b64"),
            "crl" => include_str!("../tests/fixtures/genoa-crl.der.b64"),
            _ => unreachable!(),
        };
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .unwrap()
    }

    #[test]
    fn validates_live_amd_chain_and_report_signature() {
        let report_bytes = fixture("report");
        let ark = fixture("ark");
        let ask = fixture("ask");
        let vcek = fixture("vcek");
        let ark_sha256: [u8; 32] = Sha256::digest(&ark).into();
        verify_amd_certificate_chain(&ark, &ask, &vcek, &ark_sha256).unwrap();
        let report = parse_snp_report(&report_bytes).unwrap();
        verify_snp_signature(&report, &vcek).unwrap();
        verify_vcek_report_binding(&report, &vcek).unwrap();
    }

    #[test]
    fn rejects_untrusted_root_and_mutated_report() {
        let report_bytes = fixture("report");
        let ark = fixture("ark");
        let ask = fixture("ask");
        let vcek = fixture("vcek");
        assert_eq!(
            verify_amd_certificate_chain(&ark, &ask, &vcek, &[0; 32]),
            Err(AmdVerificationError::UntrustedArk)
        );

        let mut mutated = report_bytes;
        mutated[0x90] ^= 1;
        assert_eq!(
            verify_snp_signature(&parse_snp_report(&mutated).unwrap(), &vcek),
            Err(AmdVerificationError::InvalidReportSignature)
        );
    }

    #[test]
    fn rejects_vcek_for_a_different_chip_or_tcb() {
        let mut report_bytes = fixture("report");
        let vcek = fixture("vcek");
        report_bytes[0x1a0] ^= 1;
        assert_eq!(
            verify_vcek_report_binding(&parse_snp_report(&report_bytes).unwrap(), &vcek),
            Err(AmdVerificationError::VcekReportMismatch)
        );

        let mut report_bytes = fixture("report");
        report_bytes[0x180] ^= 1;
        assert_eq!(
            verify_vcek_report_binding(&parse_snp_report(&report_bytes).unwrap(), &vcek),
            Err(AmdVerificationError::VcekReportMismatch)
        );
    }

    #[test]
    fn enforces_fresh_stale_expired_missing_and_revoked_crl_states() {
        let ark = fixture("ark");
        let ask = fixture("ask");
        let vcek = fixture("vcek");
        let crl = fixture("crl");
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_785_844_800, 30 * 86_400),
            Ok(())
        );
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_787_227_200, 7 * 86_400),
            Err(AmdVerificationError::RevocationDataStale)
        );
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_790_812_800, 90 * 86_400),
            Err(AmdVerificationError::RevocationDataExpired)
        );

        let mut parsed_crl = CertificateList::from_der(&crl).unwrap();
        parsed_crl.tbs_cert_list.next_update = None;
        assert_eq!(
            verify_revocation_times(&parsed_crl, 1_785_844_800, 30 * 86_400),
            Err(AmdVerificationError::RevocationTimeMissing)
        );

        let mut revoked_vcek = Certificate::from_der(&vcek).unwrap();
        revoked_vcek.tbs_certificate.serial_number = parsed_crl
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .unwrap()[0]
            .serial_number
            .clone();
        assert_eq!(
            verify_amd_revocation(
                &ark,
                &ask,
                &revoked_vcek.to_der().unwrap(),
                &crl,
                1_785_844_800,
                30 * 86_400,
            ),
            Err(AmdVerificationError::Revoked)
        );
    }
}
