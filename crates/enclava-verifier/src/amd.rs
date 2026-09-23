use p384::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use pkcs1::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    der::{
        Decode, Encode, Reader,
        asn1::{ContextSpecific, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef},
};

use crate::SnpReport;

/// id-RSASSA-PSS (RFC 8017 § 8.1): every AMD ARK/ASK-signed object the
/// verifier accepts must declare its PSS parameters under this OID.
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
/// id-sha384: the only hash and MGF1 hash algorithm implemented.
const PSS_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// id-mgf1: the only mask generation function implemented.
const PSS_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// Salt length the implementation recovers from the padded block; AMD ARK/ASK
/// declare 48, and only 48 is accepted.
const PSS_SALT_LENGTH: u64 = 48;

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
    #[error("AMD RSA-PSS parameters do not match the verification performed")]
    PssParameterMismatch,
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
    #[error("AMD ASK is revoked")]
    AskRevoked,
    #[error("AMD VCEK is revoked")]
    VcekRevoked,
    #[error("AMD revocation data has no signed nextUpdate")]
    RevocationTimeMissing,
    #[error("AMD revocation data is stale")]
    RevocationDataStale,
    #[error("AMD revocation data is expired")]
    RevocationDataExpired,
}

/// Maximum accepted RSA modulus size. AMD ARK/ASK use 4096-bit RSA; anything
/// larger is rejected before any modular exponentiation so that an
/// attacker-supplied key cannot force an unbounded `modpow` (CPU-exhaustion
/// DoS on the public appraiser).
const MAX_RSA_MODULUS_BITS: u64 = 8192;
/// Maximum accepted RSA public-exponent size (AMD uses 65537).
const MAX_RSA_EXPONENT_BITS: u64 = 64;

pub fn verify_amd_revocation(
    ark_der: &[u8],
    ask_der: &[u8],
    vcek_der: &[u8],
    crl_der: &[u8],
    now_unix_seconds: u64,
    maximum_age_seconds: u64,
    trusted_ark_sha256: &[[u8; 32]],
) -> Result<(), AmdVerificationError> {
    // The CRL is verified with the ARK's RSA key. Only a policy-pinned ARK may
    // reach that math: an unpinned, bundle-supplied ARK is attacker-chosen
    // input (the certificate-chain path already enforces the same pin).
    if !trusted_ark_sha256
        .iter()
        .any(|trusted| Sha256::digest(ark_der).as_slice() == trusted)
    {
        return Err(AmdVerificationError::UntrustedArk);
    }
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
        || crl.signature_algorithm.oid.to_string() != OID_RSASSA_PSS
        || !pss_parameters_match(&crl.signature_algorithm)
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
    if crl.tbs_cert_list.issuer != ark.tbs_certificate.subject
        || !verify_rsa_certificate_list_signature(&ark, &signed, signature)
    {
        return Err(AmdVerificationError::InvalidRevocationList);
    }
    verify_revocation_times(&crl, now_unix_seconds, maximum_age_seconds)?;
    // Defense-in-depth serial walk over the single ARK-signed product CRL
    // that AMD KDS publishes per product line. Today that list carries ASK
    // serials (the Genoa CRL's only entry, 020001, is the retired ASK); AMD
    // does not currently revoke individual VCEKs by serial — TCB
    // requirements supersede a chip's previous certificates, and shipped
    // VCEKs share serial 0 — and go-sev-guest therefore compares only the
    // ASK. If AMD ever does list a VCEK serial here, this check rejects it
    // instead of silently accepting a revoked endorsement key.
    //
    // Design note (issuer scoping): X.509 serial numbers are issuer-scoped,
    // and this CRL is ARK-issued, so strictly its entries revoke ARK-issued
    // certificates (like the ASK); a VCEK (ASK-issued) serial match could
    // in principle collide with an unrelated ARK-issued certificate. We
    // still fail closed (#126): the CRL reaching this walk is policy-pinned
    // to a trusted ARK and RSA-PSS signature-verified, i.e. AMD-authored
    // content either way, and shipped VCEKs share serial 0 — so a false
    // positive requires AMD deliberately listing serial 0 on a product CRL,
    // self-breakage the same trust could equally inflict by revoking the
    // ASK outright. Behavior on all current AMD CRL contents is identical
    // to go-sev-guest; this arm only fires if AMD ever publishes a VCEK
    // serial, and rejecting then is the safe reading.
    if let Some(revoked) = crl.tbs_cert_list.revoked_certificates.as_ref() {
        for entry in revoked {
            if entry.serial_number == ask.tbs_certificate.serial_number {
                return Err(AmdVerificationError::AskRevoked);
            }
            if entry.serial_number == vcek.tbs_certificate.serial_number {
                return Err(AmdVerificationError::VcekRevoked);
            }
        }
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
    if certificate.signature_algorithm.oid.to_string() != OID_RSASSA_PSS
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
        || !pss_parameters_match(&certificate.signature_algorithm)
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

/// Confirm that the PSS `AlgorithmIdentifier` parameters carried by an
/// AMD-signed object declare exactly the verification this module performs:
/// SHA-384 as the hash, MGF1 over SHA-384, a 48-byte salt, and trailer field
/// 0xBC (explicit value 1 or the DER default when the field is omitted).
///
/// `verify_rsa_pss_sha384` pins the separator at the declared salt length,
/// so a signature actually made with a different salt length is rejected
/// even when the declaration itself is well-formed — the declaration and
/// the encoded signature must agree (enclava-labs/cap#141 review).
/// RFC 4055 § 2.1 / RFC 8017 Appendix B: the digest AlgorithmIdentifiers
/// inside a RSASSA-PSS declaration (hashAlgorithm and the MGF1 hash) take
/// no parameters, so they must be absent or ASN.1 NULL. The parameters are
/// decoded as ASN.1 NULL rather than inspected by tag alone: a malformed
/// NULL that carries content bytes (e.g. `05 01 00`) has the right tag but
/// is not a valid NULL encoding and must fail closed (cap#168 review).
fn hash_parameters_are_absent_or_null(algorithm: &AlgorithmIdentifierRef<'_>) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|parameters| parameters.decode_as::<x509_cert::der::asn1::Null>().is_ok())
}

fn pss_parameters_match(algorithm: &AlgorithmIdentifierOwned) -> bool {
    let Some(parameters) = algorithm.parameters.as_ref() else {
        return false;
    };
    // RSASSA-PSS-params ::= SEQUENCE {
    //   hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
    //   maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
    //   saltLength         [2] INTEGER            DEFAULT 20,
    //   trailerField       [3] INTEGER            DEFAULT 1 }
    // DER requires DEFAULT fields to be omitted when they carry the default
    // value, so an absent field means the default (sha1 / mgf1-SHA1 / 20 / 1)
    // — everything we require must therefore be explicitly present, except
    // trailerField whose default (1) we accept.
    parameters
        .sequence(|fields| {
            let hash = ContextSpecific::<AlgorithmIdentifierRef<'_>>::decode_explicit(
                fields,
                x509_cert::der::TagNumber::N0,
            )?;
            let mgf = ContextSpecific::<AlgorithmIdentifierRef<'_>>::decode_explicit(
                fields,
                x509_cert::der::TagNumber::N1,
            )?;
            let salt =
                ContextSpecific::<u64>::decode_explicit(fields, x509_cert::der::TagNumber::N2)?;
            let trailer =
                ContextSpecific::<u64>::decode_explicit(fields, x509_cert::der::TagNumber::N3)?;
            if !fields.is_finished() {
                // Trailing garbage after trailerField: reject.
                return Err(x509_cert::der::Error::incomplete(
                    x509_cert::der::Length::ZERO,
                ));
            }
            Ok((hash, mgf, salt, trailer))
        })
        .is_ok_and(|(hash, mgf, salt, trailer)| {
            // RFC 8017 / RFC 4055 § 2.1: the hash AlgorithmIdentifier's
            // parameters must be absent or NULL — and per RFC 5280 § 4.1.1.2
            // an AlgorithmIdentifier with no defined parameters encodes them
            // as NULL, so "absent" is tolerated. Any other ASN.1 type (an
            // empty OCTET STRING, SEQUENCE, etc.) with the right OID is a
            // malformed declaration and rejected by checking the tag, not
            // just the encoded length (cap#168 review).
            let hash_ok = hash.is_some_and(|hash| {
                hash.value.oid == PSS_SHA384 && hash_parameters_are_absent_or_null(&hash.value)
            });
            // MGF1 params are AlgorithmIdentifier { algorithm id-sha384,
            // parameters NULL } — a plain SEQUENCE, not context-tagged.
            let mgf_ok = mgf.is_some_and(|mgf| {
                mgf.value.oid == PSS_MGF1
                    && mgf
                        .value
                        .parameters
                        .and_then(|parameters| {
                            parameters.decode_as::<AlgorithmIdentifierRef>().ok()
                        })
                        .is_some_and(|hash| {
                            hash.oid == PSS_SHA384 && hash_parameters_are_absent_or_null(&hash)
                        })
            });
            hash_ok
                && mgf_ok
                && salt.is_some_and(|salt| salt.value == PSS_SALT_LENGTH)
                && trailer.is_none_or(|trailer| trailer.value == 1)
        })
}

fn verify_rsa_pss_sha384(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    verify_rsa_pss_sha384_salt_len(modulus, exponent, message, signature, Some(PSS_SALT_LENGTH))
}

/// Verify with the salt length recovered from the encoded block instead of
/// fixed at the pinned 48 bytes (cap#141 review).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn verify_rsa_pss_sha384_recover_salt(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    verify_rsa_pss_sha384_salt_len(modulus, exponent, message, signature, None)
}

fn verify_rsa_pss_sha384_salt_len(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
    expected_salt_len: Option<u64>,
) -> bool {
    const HASH_BYTES: usize = 48;

    let modulus = num_bigint::BigUint::from_bytes_be(modulus);
    let exponent = num_bigint::BigUint::from_bytes_be(exponent);
    let modulus_bits = modulus.bits();
    if modulus_bits == 0 || modulus_bits > MAX_RSA_MODULUS_BITS {
        return false;
    }
    if exponent.bits() > MAX_RSA_EXPONENT_BITS {
        return false;
    }
    let modulus_bits = modulus_bits as usize;
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
    if unused_bits > 0 && masked_db[0] >> (8 - unused_bits) != 0 {
        return false;
    }
    let mask = mgf1_sha384(hash, db_len);
    let mut db = masked_db
        .iter()
        .zip(mask)
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();
    db[0] &= 0xff >> unused_bits;
    // RFC 8017 § 8.1.2 step 10/11: DB = PS || 0x01 || salt. With the salt
    // length pinned (the default), the separator position is fixed at
    // `db_len - salt_len - 1`, so a signature made with any other salt
    // length is rejected outright. `None` recovers the salt from the block
    // itself (tests / fuzzing only).
    let salt: &[u8] = match expected_salt_len {
        Some(salt_len) => {
            let salt_len = salt_len as usize;
            if db_len < salt_len + 1 {
                return false;
            }
            let separator = db_len - salt_len - 1;
            if db[..separator].iter().any(|byte| *byte != 0) || db[separator] != 1 {
                return false;
            }
            &db[separator + 1..]
        }
        None => {
            let separator = db.iter().position(|byte| *byte == 1);
            match separator {
                Some(separator)
                    if db[..separator].iter().all(|byte| *byte == 0) && db_len > separator =>
                {
                    &db[separator + 1..]
                }
                _ => return false,
            }
        }
    };
    let message_hash = Sha384::digest(message);
    let expected = Sha384::new()
        .chain_update([0; 8])
        .chain_update(message_hash)
        .chain_update(salt)
        .finalize();
    hash == expected.as_slice()
}

#[doc(hidden)]
#[cfg(feature = "fuzzing")]
pub fn verify_rsa_pss_sha384_for_fuzzing(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    verify_rsa_pss_sha384(modulus, exponent, message, signature)
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

    /// Minimal deterministic RNG so PSS interop tests are reproducible.
    struct TestRng(u64);
    impl rsa::rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.next_u32() as u64 | ((self.next_u32() as u64) << 32)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rsa::rand_core::CryptoRng for TestRng {}

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            let length_bytes = body.len().to_be_bytes();
            let first = length_bytes.iter().position(|byte| *byte != 0).unwrap();
            out.push(0x80 | (length_bytes.len() - first) as u8);
            out.extend_from_slice(&length_bytes[first..]);
        }
        out.extend_from_slice(body);
        out
    }

    fn minimal_der_integer(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0];
        }
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let mut body = bytes[first..].to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        body
    }

    fn oid_bytes(oid: &str) -> Vec<u8> {
        let parsed = ObjectIdentifier::new_unwrap(oid);
        parsed.to_der().unwrap()
    }

    /// Build a full RSASSA-PSS `AlgorithmIdentifier` with the given parameter
    /// mutations, exactly as a future AMD certificate would declare them.
    fn pss_algorithm_identifier(
        hash_oid: &str,
        mgf_hash_oid: &str,
        salt: u64,
        trailer: Option<u64>,
        trailing_garbage: bool,
    ) -> AlgorithmIdentifierOwned {
        let null = der_tlv(0x05, &[]);
        let hash_alg = der_tlv(0x30, &[oid_bytes(hash_oid), null.clone()].concat());
        let mgf_hash_alg = der_tlv(0x30, &[oid_bytes(mgf_hash_oid), null].concat());
        let mgf_alg = der_tlv(
            0x30,
            &[oid_bytes("1.2.840.113549.1.1.8"), mgf_hash_alg].concat(),
        );
        let mut params_body = Vec::new();
        params_body.extend(der_tlv(0xA0, &hash_alg));
        params_body.extend(der_tlv(0xA1, &mgf_alg));
        params_body.extend(der_tlv(0xA2, &der_tlv(0x02, &minimal_der_integer(salt))));
        if let Some(trailer) = trailer {
            params_body.extend(der_tlv(0xA3, &der_tlv(0x02, &minimal_der_integer(trailer))));
        }
        if trailing_garbage {
            params_body.extend(der_tlv(0xA4, &[0x00]));
        }
        let params = der_tlv(0x30, &params_body);
        let full = der_tlv(0x30, &[oid_bytes(OID_RSASSA_PSS), params].concat());
        AlgorithmIdentifierOwned::from_der(&full).unwrap()
    }

    /// Like [`pss_algorithm_identifier`] but with the message-hash
    /// AlgorithmIdentifier parameters set to an arbitrary TLV instead of
    /// NULL — used to prove non-NULL parameter tags fail closed.
    fn pss_algorithm_identifier_with_hash_params(
        tag: u8,
        value: &[u8],
    ) -> AlgorithmIdentifierOwned {
        pss_algorithm_identifier_with_params(tag, value, None)
    }

    /// Like [`pss_algorithm_identifier`] but with the MGF1 hash
    /// AlgorithmIdentifier parameters set to an arbitrary TLV instead of
    /// NULL.
    fn pss_algorithm_identifier_with_mgf_hash_params(
        tag: u8,
        value: &[u8],
    ) -> AlgorithmIdentifierOwned {
        pss_algorithm_identifier_with_params(tag, value, Some(()))
    }

    fn pss_algorithm_identifier_with_params(
        tag: u8,
        value: &[u8],
        mgf: Option<()>,
    ) -> AlgorithmIdentifierOwned {
        let null = der_tlv(0x05, &[]);
        let non_null = der_tlv(tag, value);
        let (hash_params, mgf_hash_params) = match mgf {
            None => (non_null.clone(), null),
            Some(()) => (null, non_null),
        };
        let hash_alg = der_tlv(
            0x30,
            &[oid_bytes("2.16.840.1.101.3.4.2.2"), hash_params].concat(),
        );
        let mgf_hash_alg = der_tlv(
            0x30,
            &[oid_bytes("2.16.840.1.101.3.4.2.2"), mgf_hash_params].concat(),
        );
        let mgf_alg = der_tlv(
            0x30,
            &[oid_bytes("1.2.840.113549.1.1.8"), mgf_hash_alg].concat(),
        );
        let mut params_body = Vec::new();
        params_body.extend(der_tlv(0xA0, &hash_alg));
        params_body.extend(der_tlv(0xA1, &mgf_alg));
        params_body.extend(der_tlv(0xA2, &der_tlv(0x02, &minimal_der_integer(48))));
        params_body.extend(der_tlv(0xA3, &der_tlv(0x02, &minimal_der_integer(1))));
        let params = der_tlv(0x30, &params_body);
        let full = der_tlv(0x30, &[oid_bytes(OID_RSASSA_PSS), params].concat());
        AlgorithmIdentifierOwned::from_der(&full).unwrap()
    }

    #[test]
    fn pss_declared_parameters_are_enforced() {
        let sha384 = "2.16.840.1.101.3.4.2.2";
        let sha256 = "2.16.840.1.101.3.4.2.1";
        // Exact declaration the verifier performs.
        assert!(pss_parameters_match(&pss_algorithm_identifier(
            sha384,
            sha384,
            48,
            Some(1),
            false
        )));
        // Omitted trailerField means the DER default (1): accepted.
        assert!(pss_parameters_match(&pss_algorithm_identifier(
            sha384, sha384, 48, None, false
        )));
        // Wrong hash, wrong MGF1 hash, wrong salt, wrong trailer: rejected.
        assert!(!pss_parameters_match(&pss_algorithm_identifier(
            sha256,
            sha384,
            48,
            Some(1),
            false
        )));
        assert!(!pss_parameters_match(&pss_algorithm_identifier(
            sha384,
            sha256,
            48,
            Some(1),
            false
        )));
        assert!(!pss_parameters_match(&pss_algorithm_identifier(
            sha384,
            sha384,
            32,
            Some(1),
            false
        )));
        assert!(!pss_parameters_match(&pss_algorithm_identifier(
            sha384,
            sha384,
            48,
            Some(2),
            false
        )));
        // Trailing garbage inside the parameters: rejected.
        assert!(!pss_parameters_match(&pss_algorithm_identifier(
            sha384,
            sha384,
            48,
            Some(1),
            true
        )));
        // Non-NULL zero-length hash parameters (empty OCTET STRING /
        // SEQUENCE / BOOLEAN) must be rejected even though they encode to
        // zero bytes — only absent-or-NULL is a valid SHA-384 declaration
        // (cap#168 review).
        for tag in [0x04u8, 0x30, 0x01] {
            let alg = pss_algorithm_identifier_with_hash_params(tag, &[]);
            assert!(
                !pss_parameters_match(&alg),
                "empty non-NULL hash parameters (tag {tag:#04x}) must be rejected"
            );
        }
        // Same for the MGF1 hash parameters.
        for tag in [0x04u8, 0x30, 0x01] {
            let alg = pss_algorithm_identifier_with_mgf_hash_params(tag, &[]);
            assert!(
                !pss_parameters_match(&alg),
                "empty non-NULL MGF1 hash parameters (tag {tag:#04x}) must be rejected"
            );
        }
        // A NULL-tagged value that carries content bytes (e.g. `05 01 00`)
        // is not a valid ASN.1 NULL encoding and must be rejected on both
        // the message-hash and MGF1-hash paths, even though the tag alone
        // is correct (cap#168 review).
        for value in [&[0x00u8][..], &[0x00, 0x00][..]] {
            let alg = pss_algorithm_identifier_with_hash_params(0x05, value);
            assert!(
                !pss_parameters_match(&alg),
                "NULL with content bytes {value:?} must be rejected on the hash path"
            );
            let alg = pss_algorithm_identifier_with_mgf_hash_params(0x05, value);
            assert!(
                !pss_parameters_match(&alg),
                "NULL with content bytes {value:?} must be rejected on the MGF1 hash path"
            );
        }
        // DEFAULT-omitted hash/MGF/salt (i.e. sha1/mgf1-SHA1/20): rejected.
        let params = der_tlv(0x30, &[]);
        let full = der_tlv(0x30, &[oid_bytes(OID_RSASSA_PSS), params].concat());
        let empty_params = AlgorithmIdentifierOwned::from_der(&full).unwrap();
        assert!(!pss_parameters_match(&empty_params));
        // No parameters at all: rejected.
        let full = der_tlv(0x30, &[oid_bytes(OID_RSASSA_PSS)].concat());
        assert!(!pss_parameters_match(
            &AlgorithmIdentifierOwned::from_der(&full).unwrap()
        ));
    }

    #[test]
    fn pss_params_parse_live_amd_certificates_and_crl() {
        let ark = fixture("ark");
        let crl = fixture("crl");
        assert!(pss_parameters_match(
            &Certificate::from_der(&ark).unwrap().signature_algorithm
        ));
        assert!(pss_parameters_match(
            &CertificateList::from_der(&crl).unwrap().signature_algorithm
        ));
    }

    #[test]
    fn hand_rolled_pss_interops_with_the_rsa_crate() {
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use rsa::traits::PublicKeyParts;
        use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
        use sha2::Sha384 as RsaSha384;

        let mut rng = TestRng(0x141);
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&key);
        let modulus = BigUint::to_bytes_be(public.n());
        let exponent = BigUint::to_bytes_be(public.e());

        let signing = SigningKey::<RsaSha384>::new_with_salt_len(key.clone(), 48);
        let message = b"enclava interop probe";
        let signature = signing.sign_with_rng(&mut rng, message).to_vec();
        assert!(verify_rsa_pss_sha384(
            &modulus, &exponent, message, &signature
        ));
        // Wrong message must not verify.
        assert!(!verify_rsa_pss_sha384(
            &modulus,
            &exponent,
            b"different message",
            &signature
        ));
        // Flipped signature bit must not verify.
        let mut corrupted = signature.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(!verify_rsa_pss_sha384(
            &modulus, &exponent, message, &corrupted
        ));

        // The pinned path fixes the separator at db_len - 48 - 1, so a PSS
        // signature made with a different salt length must be rejected —
        // the declared parameters and the encoded signature have to agree
        // (cap#141 review). The recover-salt variant (tests/fuzzing only)
        // still accepts it, proving the rejection comes from the salt-length
        // pin and not from a broken encoding.
        let odd_salt = SigningKey::<RsaSha384>::new_with_salt_len(key, 47);
        let signature = odd_salt.sign_with_rng(&mut rng, message).to_vec();
        assert!(!verify_rsa_pss_sha384(
            &modulus, &exponent, message, &signature
        ));
        assert!(verify_rsa_pss_sha384_recover_salt(
            &modulus, &exponent, message, &signature
        ));
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
    fn rsa_pss_rejects_zero_unused_bits_without_panicking() {
        let mut modulus = vec![0; 129];
        modulus[0] = 1; // 1025 bits, so the encoded message has zero unused bits.
        let mut signature = vec![0; 129];
        signature[128] = 0xbc;
        assert!(!verify_rsa_pss_sha384(
            &modulus,
            &[1],
            b"message",
            &signature
        ));
    }

    #[test]
    fn enforces_fresh_stale_expired_missing_and_revoked_crl_states() {
        let ark = fixture("ark");
        let ask = fixture("ask");
        let vcek = fixture("vcek");
        let crl = fixture("crl");
        let pinned: [u8; 32] = Sha256::digest(&ark).into();
        let trusted = &[pinned];
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_785_844_800, 30 * 86_400, trusted),
            Ok(())
        );
        assert_eq!(
            verify_amd_revocation(&ask, &ask, &vcek, &crl, 1_785_844_800, 30 * 86_400, trusted),
            Err(AmdVerificationError::UntrustedArk)
        );
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_787_227_200, 7 * 86_400, trusted),
            Err(AmdVerificationError::RevocationDataStale)
        );
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_790_812_800, 90 * 86_400, trusted),
            Err(AmdVerificationError::RevocationDataExpired)
        );

        let mut parsed_crl = CertificateList::from_der(&crl).unwrap();
        parsed_crl.tbs_cert_list.next_update = None;
        assert_eq!(
            verify_revocation_times(&parsed_crl, 1_785_844_800, 30 * 86_400),
            Err(AmdVerificationError::RevocationTimeMissing)
        );

        let mut revoked_ask = Certificate::from_der(&ask).unwrap();
        revoked_ask.tbs_certificate.serial_number = parsed_crl
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .unwrap()[0]
            .serial_number
            .clone();
        assert_eq!(
            verify_amd_revocation(
                &ark,
                &revoked_ask.to_der().unwrap(),
                &vcek,
                &crl,
                1_785_844_800,
                30 * 86_400,
                trusted,
            ),
            Err(AmdVerificationError::AskRevoked)
        );

        // #126: the serial walk must also reject a VCEK whose serial appears
        // on the ARK-signed CRL. Issuer-scoping counterargument considered
        // and documented in verify_amd_revocation; decision is fail-closed.
        // The unmodified ASK serial stays off the CRL, so an ASK-only check
        // would return Ok — exactly the gap #126 reports. This fixture is
        // not a chain-valid certificate: only the serial is under test.
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
                trusted,
            ),
            Err(AmdVerificationError::VcekRevoked)
        );
    }

    #[test]
    fn revocation_rejects_unpinned_ark_before_any_rsa_math() {
        let ark = fixture("ark");
        let ask = fixture("ask");
        let vcek = fixture("vcek");
        let crl = fixture("crl");
        // No pinned ARK (or a wrong pin) must be rejected before certificate
        // parsing or `modpow`, so attacker-supplied RSA parameters can never
        // drive the CRL verification path.
        assert_eq!(
            verify_amd_revocation(&ark, &ask, &vcek, &crl, 1_785_844_800, 30 * 86_400, &[]),
            Err(AmdVerificationError::UntrustedArk)
        );
        assert_eq!(
            verify_amd_revocation(
                &ark,
                &ask,
                &vcek,
                &crl,
                1_785_844_800,
                30 * 86_400,
                &[[0; 32]],
            ),
            Err(AmdVerificationError::UntrustedArk)
        );
    }

    #[test]
    fn rsa_pss_rejects_oversized_modulus_and_exponent_quickly() {
        // ~16 Kib modulus + oversized exponent: the historic CPU-exhaustion
        // primitive. The caps must reject without spending measurable time.
        let oversized_modulus = vec![0xff; 2048];
        let oversized_exponent = vec![0xff; 64];
        let signature = vec![0x00; 2048];
        let start = std::time::Instant::now();
        assert!(!verify_rsa_pss_sha384(
            &oversized_modulus,
            &[1],
            b"message",
            &signature
        ));
        assert!(!verify_rsa_pss_sha384(
            &[0xff; 512],
            &oversized_exponent,
            b"message",
            &[0x00; 512]
        ));
        assert!(!verify_rsa_pss_sha384(&[0x00], &[1], b"message", &[0]));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "oversized RSA parameters must be rejected before modpow"
        );
    }
}
