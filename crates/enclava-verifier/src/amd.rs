use p384::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use pkcs1::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::{
    Certificate,
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
        verify_snp_signature(&parse_snp_report(&report_bytes).unwrap(), &vcek).unwrap();
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
}
