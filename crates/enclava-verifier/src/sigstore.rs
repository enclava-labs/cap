use base64::Engine as _;
use enclava_common::canonical::ce_v1_decode;
use p256::{
    ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier},
    pkcs8::DecodePublicKey as _,
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384Key};
use serde_json::Value;
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
    ext::pkix::{SubjectAltName, name::GeneralName},
};

use crate::policy::SigstorePolicy;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigstoreError {
    #[error("Sigstore material is malformed")]
    Malformed,
    #[error("Fulcio certificate chain is invalid or untrusted")]
    InvalidFulcioChain,
    #[error("Sigstore certificate identity is rejected")]
    IdentityRejected,
    #[error("DSSE signature or subject is invalid")]
    InvalidSignature,
    #[error("Rekor transparency evidence is invalid")]
    InvalidTransparency,
    #[error("Rekor inclusion promise is invalid")]
    InvalidInclusionPromise,
    #[error("Rekor inclusion proof is invalid")]
    InvalidInclusionProof,
    #[error("Rekor checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("build provenance is invalid or rejected")]
    InvalidProvenance,
}

pub fn verify_sigstore_and_provenance(
    sigstore_material: &[u8],
    provenance_material: &[u8],
    expected_image_digest: &str,
    policy: &SigstorePolicy,
) -> Result<(), SigstoreError> {
    let records = ce_v1_decode(sigstore_material).map_err(|_| SigstoreError::Malformed)?;
    let mut signatures = records
        .iter()
        .filter(|record| record.label == "signature_blob")
        .peekable();
    if signatures.peek().is_none() {
        return Err(SigstoreError::Malformed);
    }
    if !signatures
        .any(|record| verify_signature_blob(record.value, expected_image_digest, policy).is_ok())
    {
        return Err(SigstoreError::InvalidSignature);
    }
    verify_provenance(provenance_material, expected_image_digest, policy)
}

fn verify_signature_blob(
    signature_blob: &[u8],
    expected_image_digest: &str,
    policy: &SigstorePolicy,
) -> Result<(), SigstoreError> {
    let bundle: Value =
        serde_json::from_slice(signature_blob).map_err(|_| SigstoreError::Malformed)?;
    let certificate_der = decode_b64(pointer_str(
        &bundle,
        "/verificationMaterial/certificate/rawBytes",
    )?)?;
    let dsse = bundle.get("dsseEnvelope").ok_or(SigstoreError::Malformed)?;
    let payload_b64 = pointer_str(dsse, "/payload")?;
    let payload_type = pointer_str(dsse, "/payloadType")?;
    let signature_b64 = pointer_str(dsse, "/signatures/0/sig")?;
    let payload = decode_b64(payload_b64)?;
    let signature = decode_b64(signature_b64)?;

    let entries = bundle
        .pointer("/verificationMaterial/tlogEntries")
        .and_then(Value::as_array)
        .filter(|entries| !entries.is_empty())
        .ok_or(SigstoreError::Malformed)?;
    let (certificate, _) =
        verify_transparency_and_fulcio(entries, &payload, signature_b64, &certificate_der, policy)?;
    let pae = dsse_pae(payload_type, &payload);
    verify_p256_spki(
        &certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| SigstoreError::Malformed)?,
        &pae,
        &signature,
    )
    .map_err(|_| SigstoreError::InvalidSignature)?;
    let statement: Value =
        serde_json::from_slice(&payload).map_err(|_| SigstoreError::Malformed)?;
    if statement.pointer("/predicateType").and_then(Value::as_str)
        != Some("https://sigstore.dev/cosign/sign/v1")
        || !statement_has_subject(&statement, expected_image_digest)
    {
        return Err(SigstoreError::InvalidSignature);
    }
    Ok(())
}

fn verify_fulcio_chain(
    leaf_der: &[u8],
    at: u64,
    policy: &SigstorePolicy,
) -> Result<Certificate, SigstoreError> {
    let leaf = Certificate::from_der(leaf_der).map_err(|_| SigstoreError::Malformed)?;
    if !valid_at(&leaf, at) {
        return Err(SigstoreError::InvalidFulcioChain);
    }
    for intermediate_b64 in &policy.fulcio_intermediates_der_base64 {
        let intermediate_der = decode_b64(intermediate_b64)?;
        let intermediate =
            Certificate::from_der(&intermediate_der).map_err(|_| SigstoreError::Malformed)?;
        if !valid_at(&intermediate, at)
            || verify_certificate_signature(&leaf, &intermediate).is_err()
        {
            continue;
        }
        for root_b64 in &policy.fulcio_roots_der_base64 {
            let root_der = decode_b64(root_b64)?;
            if !policy.trusted_fulcio_root_sha256.iter().any(|trusted| {
                hex::decode(trusted).ok().as_deref() == Some(Sha256::digest(&root_der).as_slice())
            }) {
                continue;
            }
            let root = Certificate::from_der(&root_der).map_err(|_| SigstoreError::Malformed)?;
            if valid_at(&root, at) && verify_certificate_signature(&intermediate, &root).is_ok() {
                return Ok(leaf);
            }
        }
    }
    Err(SigstoreError::InvalidFulcioChain)
}

fn verify_certificate_signature(certificate: &Certificate, issuer: &Certificate) -> Result<(), ()> {
    if certificate.signature_algorithm != certificate.tbs_certificate.signature
        || certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject
    {
        return Err(());
    }
    let signed = certificate.tbs_certificate.to_der().map_err(|_| ())?;
    let signature = certificate.signature.as_bytes().ok_or(())?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ())?;
    match certificate.signature_algorithm.oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => verify_p256_spki(&spki, &signed, signature),
        "1.2.840.10045.4.3.3" => {
            let key = P384Key::from_public_key_der(&spki).map_err(|_| ())?;
            let signature = P384Signature::from_der(signature).map_err(|_| ())?;
            key.verify(&signed, &signature).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn verify_p256_spki(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ()> {
    let key = P256Key::from_public_key_der(spki).map_err(|_| ())?;
    let signature = P256Signature::from_der(signature).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

fn valid_at(certificate: &Certificate, at: u64) -> bool {
    let validity = &certificate.tbs_certificate.validity;
    validity.not_before.to_unix_duration().as_secs() <= at
        && at <= validity.not_after.to_unix_duration().as_secs()
}

fn verify_identity(
    certificate: &Certificate,
    policy: &SigstorePolicy,
) -> Result<(), SigstoreError> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(SigstoreError::IdentityRejected)?;
    let san = extensions
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.17")
        .and_then(|extension| SubjectAltName::from_der(extension.extn_value.as_bytes()).ok())
        .ok_or(SigstoreError::IdentityRejected)?;
    let identity_matches = san.0.iter().any(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => uri.as_str() == policy.certificate_identity,
        GeneralName::Rfc822Name(email) => email.as_str() == policy.certificate_identity,
        _ => false,
    });
    let issuer_matches = extensions
        .iter()
        .find(|extension| extension.extn_id.to_string() == "1.3.6.1.4.1.57264.1.1")
        .and_then(|extension| der_string(extension.extn_value.as_bytes()))
        .as_deref()
        == Some(policy.oidc_issuer.as_str());
    (identity_matches && issuer_matches)
        .then_some(())
        .ok_or(SigstoreError::IdentityRejected)
}

fn der_string(bytes: &[u8]) -> Option<String> {
    if bytes.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return String::from_utf8(bytes.to_vec()).ok();
    }
    if !matches!(bytes.first(), Some(0x0c | 0x16)) {
        return None;
    }
    let (length, offset) = match *bytes.get(1)? {
        length @ 0..=127 => (usize::from(length), 2),
        0x81 => (usize::from(*bytes.get(2)?), 3),
        0x82 => (
            usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?])),
            4,
        ),
        _ => return None,
    };
    let value = bytes.get(offset..offset + length)?;
    (offset + length == bytes.len())
        .then(|| String::from_utf8(value.to_vec()).ok())
        .flatten()
}

fn verify_tlog_entry(
    entry: &Value,
    payload: &[u8],
    signature_b64: &str,
    certificate_der: &[u8],
    policy: &SigstorePolicy,
) -> Result<u64, SigstoreError> {
    let integrated_time = pointer_str(entry, "/integratedTime")?
        .parse::<u64>()
        .map_err(|_| SigstoreError::Malformed)?;
    let Ok(body) = pointer_str(entry, "/canonicalizedBody").and_then(decode_b64) else {
        return Err(SigstoreError::InvalidTransparency);
    };
    let Ok(body_json) = serde_json::from_slice::<Value>(&body) else {
        return Err(SigstoreError::InvalidTransparency);
    };
    if pointer_str(&body_json, "/spec/payloadHash/value").ok()
        != Some(hex::encode(Sha256::digest(payload)).as_str())
        || pointer_str(&body_json, "/spec/signatures/0/signature").ok() != Some(signature_b64)
        || !pem_matches(
            pointer_str(&body_json, "/spec/signatures/0/verifier").unwrap_or_default(),
            certificate_der,
        )
    {
        return Err(SigstoreError::InvalidTransparency);
    }
    let Ok(set) = pointer_str(entry, "/inclusionPromise/signedEntryTimestamp").and_then(decode_b64)
    else {
        return Err(SigstoreError::InvalidInclusionPromise);
    };
    let rekor_keys = policy
        .rekor_spki_der_base64
        .iter()
        .filter_map(|key| decode_b64(key).ok())
        .collect::<Vec<_>>();
    // Rekor signs the SET over the entry JSON canonicalized per RFC 8785
    // (rekor pkg/verify/verify.go VerifySignedEntryTimestamp): keys sorted
    // by Unicode code point — body, integratedTime, logID, logIndex —
    // numbers as plain integers, strings with minimal escaping. Serialize
    // in exactly that order instead of relying on serde_json's BTreeMap
    // key ordering to coincide with it (cap#141).
    let log_id = pointer_str(entry, "/logId/keyId")
        .ok()
        .and_then(|value| decode_b64(value).ok())
        .map(hex::encode);
    let log_index = pointer_str(entry, "/logIndex")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let (integrated_time_i64, log_id, log_index) =
        match (i64::try_from(integrated_time).ok(), log_id, log_index) {
            (Some(integrated_time), Some(log_id), Some(log_index)) => {
                (integrated_time, log_id, log_index)
            }
            _ => return Err(SigstoreError::InvalidInclusionPromise),
        };
    let set_payload = format!(
        "{{\"body\":{},\"integratedTime\":{},\"logID\":{},\"logIndex\":{}}}",
        serde_json::to_string(&base64::engine::general_purpose::STANDARD.encode(&body))
            .map_err(|_| SigstoreError::InvalidInclusionPromise)?,
        integrated_time_i64,
        serde_json::to_string(&log_id).map_err(|_| SigstoreError::InvalidInclusionPromise)?,
        log_index,
    );
    let set_payload = set_payload.into_bytes();
    if !rekor_keys
        .iter()
        .any(|key| verify_p256_spki(key, &set_payload, &set).is_ok())
    {
        return Err(SigstoreError::InvalidInclusionPromise);
    }
    let Some(proof) = entry.pointer("/inclusionProof") else {
        return Err(SigstoreError::InvalidInclusionProof);
    };
    if !verify_inclusion_proof(proof, &body) {
        return Err(SigstoreError::InvalidInclusionProof);
    }
    verify_checkpoint(
        pointer_str(proof, "/checkpoint/envelope").unwrap_or_default(),
        proof,
        &rekor_keys,
    )
    .then_some(integrated_time)
    .ok_or(SigstoreError::InvalidCheckpoint)
}

fn verify_transparency_and_fulcio(
    entries: &[Value],
    payload: &[u8],
    signature_b64: &str,
    certificate_der: &[u8],
    policy: &SigstorePolicy,
) -> Result<(Certificate, u64), SigstoreError> {
    let mut transparency_error = SigstoreError::InvalidTransparency;
    let mut certificate_error = None;
    for entry in entries {
        match verify_tlog_entry(entry, payload, signature_b64, certificate_der, policy) {
            Ok(integrated_time) => {
                match verify_fulcio_chain(certificate_der, integrated_time, policy).and_then(
                    |certificate| {
                        verify_identity(&certificate, policy)?;
                        Ok(certificate)
                    },
                ) {
                    Ok(certificate) => return Ok((certificate, integrated_time)),
                    Err(error) => certificate_error = Some(error),
                }
            }
            Err(error) => transparency_error = error,
        }
    }
    Err(certificate_error.unwrap_or(transparency_error))
}

fn verify_inclusion_proof(proof: &Value, body: &[u8]) -> bool {
    let Ok(index) = pointer_str(proof, "/logIndex")
        .and_then(|value| value.parse::<u64>().map_err(|_| SigstoreError::Malformed))
    else {
        return false;
    };
    let Ok(tree_size) = pointer_str(proof, "/treeSize")
        .and_then(|value| value.parse::<u64>().map_err(|_| SigstoreError::Malformed))
    else {
        return false;
    };
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    let Ok(expected) = pointer_str(proof, "/rootHash").and_then(decode_b64) else {
        return false;
    };
    let Some(hashes) = proof.get("hashes").and_then(Value::as_array) else {
        return false;
    };
    let mut hash: [u8; 32] = Sha256::new()
        .chain_update([0])
        .chain_update(body)
        .finalize()
        .into();
    // RFC 6962 inclusion proof: the path splits at `inner` (size of the
    // perfect subtree containing the leaf) with `border` cofactor
    // hashes; the formula below is cross-checked against a reference
    // tree builder in the tests (merkle_inclusion_proof_matches_reference)
    // and fuzzed via fuzz_targets/verify_inclusion_proof.rs (cap#141).
    let inner = u64::BITS as usize - (index ^ (tree_size - 1)).leading_zeros() as usize;
    // A tree_size > 2^63 sets the MSB of `index ^ (tree_size - 1)`,
    // making inner == 64 — `index >> inner` is then a shift overflow
    // (panic in debug builds, silently wrapped in release). treeSize is
    // attacker-controlled inside the bundle's Rekor entry, and no real
    // transparency log approaches 2^63 entries, so reject before shifting
    // (cap#141 review).
    if inner >= u64::BITS as usize {
        return false;
    }
    let border = (index >> inner).count_ones() as usize;
    if hashes.len() != inner + border {
        return false;
    }
    for (level, sibling) in hashes.iter().enumerate() {
        let Some(encoded) = sibling.as_str() else {
            return false;
        };
        let Ok(sibling) = decode_b64(encoded) else {
            return false;
        };
        if sibling.len() != 32 {
            return false;
        }
        hash = if level >= inner || ((index >> level) & 1) == 1 {
            Sha256::new()
                .chain_update([1])
                .chain_update(&sibling)
                .chain_update(hash)
                .finalize()
                .into()
        } else {
            Sha256::new()
                .chain_update([1])
                .chain_update(hash)
                .chain_update(&sibling)
                .finalize()
                .into()
        };
    }
    expected.as_slice() == hash
}

/// Fuzzing hook (cap#141): exposes the hand-rolled RFC 6962 inclusion
/// proof verifier to cargo-fuzz so the inner/border formula can be
/// cross-checked against arbitrary attacker-controlled proofs.
#[doc(hidden)]
#[cfg(feature = "fuzzing")]
pub fn verify_inclusion_proof_for_fuzzing(proof: &[u8], body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(proof).is_ok_and(|proof| verify_inclusion_proof(&proof, body))
}

fn verify_checkpoint(envelope: &str, proof: &Value, rekor_keys: &[Vec<u8>]) -> bool {
    let Some((signed, signature_line)) = envelope.rsplit_once("\n— ") else {
        return false;
    };
    let signed = signed.to_owned();
    let mut parts = signature_line.split_whitespace();
    let _name = parts.next();
    let Some(encoded) = parts.next() else {
        return false;
    };
    let Ok(signature) = decode_b64(encoded) else {
        return false;
    };
    if signature.len() <= 4 {
        return false;
    }
    let lines = signed.lines().collect::<Vec<_>>();
    if lines.len() < 3
        || lines[1] != pointer_str(proof, "/treeSize").unwrap_or_default()
        || decode_b64(lines[2]).ok().as_deref()
            != pointer_str(proof, "/rootHash")
                .ok()
                .and_then(|value| decode_b64(value).ok())
                .as_deref()
    {
        return false;
    }
    rekor_keys
        .iter()
        .any(|key| verify_p256_spki(key, signed.as_bytes(), &signature[4..]).is_ok())
}

fn pem_matches(pem: &str, certificate_der: &[u8]) -> bool {
    let decoded;
    let pem = if pem.contains("-----BEGIN CERTIFICATE-----") {
        pem
    } else {
        decoded = decode_b64(pem)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
        &decoded
    };
    let encoded = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|value| value.split("-----END CERTIFICATE-----").next())
        .map(|value| value.split_whitespace().collect::<String>());
    encoded.and_then(|value| decode_b64(&value).ok()).as_deref() == Some(certificate_der)
}

fn verify_provenance(
    material: &[u8],
    expected_image_digest: &str,
    policy: &SigstorePolicy,
) -> Result<(), SigstoreError> {
    let records = ce_v1_decode(material).map_err(|_| SigstoreError::Malformed)?;
    let source_record = records
        .iter()
        .find(|record| record.label == "image_manifest")
        .ok_or(SigstoreError::Malformed)?;
    let source: Value =
        serde_json::from_slice(source_record.value).map_err(|_| SigstoreError::Malformed)?;
    let mut referenced = source
        .get("manifests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|descriptor| {
            descriptor
                .pointer("/annotations/vnd.docker.reference.type")
                .and_then(Value::as_str)
                != Some("attestation-manifest")
        })
        .filter_map(|descriptor| descriptor.get("digest").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut attestation_manifests = source
        .get("manifests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|descriptor| {
            descriptor
                .pointer("/annotations/vnd.docker.reference.type")
                .and_then(Value::as_str)
                == Some("attestation-manifest")
        })
        .filter_map(|descriptor| descriptor.get("digest").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let image_bound = source.get("schemaVersion").is_some()
        && format!(
            "sha256:{}",
            hex::encode(Sha256::digest(source_record.value))
        ) == expected_image_digest;
    if source.get("manifests").is_none() {
        referenced.push(expected_image_digest.to_string());
        attestation_manifests.extend(
            records
                .iter()
                .filter(|record| record.label == "provenance_manifest")
                .map(|record| format!("sha256:{}", hex::encode(Sha256::digest(record.value)))),
        );
    }
    if !image_bound || referenced.is_empty() || attestation_manifests.is_empty() {
        return Err(SigstoreError::InvalidProvenance);
    }
    let provenances = provenance_candidates(&records, &attestation_manifests)
        .filter_map(|blob| serde_json::from_slice::<Value>(blob).ok())
        .filter(|provenance| {
            provenance.pointer("/_type").and_then(Value::as_str)
                == Some("https://in-toto.io/Statement/v1")
                && provenance.pointer("/predicateType").and_then(Value::as_str)
                    == Some("https://slsa.dev/provenance/v1")
                && provenance
                    .pointer("/predicate/buildDefinition/internalParameters/github_repository")
                    .and_then(Value::as_str)
                    == Some(policy.source_repository.as_str())
                && provenance
                    .pointer("/predicate/buildDefinition/internalParameters/github_workflow_ref")
                    .and_then(Value::as_str)
                    == Some(policy.workflow_ref.as_str())
                && provenance
                    .pointer("/predicate/runDetails/builder/id")
                    .and_then(Value::as_str)
                    == Some(policy.provenance_builder_id.as_str())
        })
        .collect::<Vec<_>>();
    if referenced.iter().all(|digest| {
        provenances
            .iter()
            .any(|provenance| statement_has_subject(provenance, digest))
    }) {
        Ok(())
    } else {
        Err(SigstoreError::InvalidProvenance)
    }
}

fn provenance_candidates<'a>(
    records: &'a [enclava_common::canonical::CeV1Record<'a>],
    trusted_manifests: &[String],
) -> impl Iterator<Item = &'a [u8]> {
    records
        .iter()
        .enumerate()
        .filter_map(move |(index, record)| {
            (record.label == "provenance_blob").then_some(())?;
            let manifest = records[..index]
                .iter()
                .rev()
                .find(|candidate| candidate.label == "provenance_manifest")?;
            let manifest_trusted = trusted_manifests.iter().any(|digest| {
                *digest == format!("sha256:{}", hex::encode(Sha256::digest(manifest.value)))
            });
            let manifest: Value = serde_json::from_slice(manifest.value).ok()?;
            let blob_digest = format!("sha256:{}", hex::encode(Sha256::digest(record.value)));
            let blob_referenced = manifest
                .get("layers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|layer| layer.get("digest").and_then(Value::as_str) == Some(&blob_digest));
            (manifest_trusted && blob_referenced).then_some(record.value)
        })
}

fn statement_has_subject(statement: &Value, digest: &str) -> bool {
    let expected = digest.strip_prefix("sha256:").unwrap_or(digest);
    statement
        .get("subject")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|subject| subject.pointer("/digest/sha256").and_then(Value::as_str) == Some(expected))
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes()
    .into_iter()
    .chain(payload.iter().copied())
    .collect()
}

fn pointer_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, SigstoreError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(SigstoreError::Malformed)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, SigstoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| SigstoreError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::canonical::ce_v1_bytes;

    #[test]
    fn oversized_tree_size_is_rejected_without_overflow() {
        // cap#141 review: treeSize is attacker-controlled inside the
        // bundle's Rekor entry. A tree_size > 2^63 sets the MSB of
        // `index ^ (tree_size - 1)`, so inner == 64 and `index >> inner`
        // would shift-overflow (panic in debug builds). Must be rejected
        // as a plain malformed proof instead.
        let mut proof = serde_json::json!({
            "logIndex": "0",
            "treeSize": u64::MAX.to_string(),
            "rootHash": base64::engine::general_purpose::STANDARD.encode([0xab; 32]),
            "hashes": [],
        });
        assert!(!verify_inclusion_proof(&proof, b"body"));
        // Same for the largest power-of-two tree size with a small index.
        proof["treeSize"] = serde_json::json!((1u64 << 63).to_string());
        assert!(!verify_inclusion_proof(&proof, b"body"));
    }

    #[test]
    fn merkle_inclusion_proof_matches_reference_implementation() {
        // Reference RFC 6962 Merkle tree: leaves hash with 0x00, internal
        // nodes with 0x01; the root of a range is recursively
        // node(left[0:k], right[k:n]) with k the largest power of two
        // below n; the inclusion path for leaf m is
        // PATH(m, left) ++ [root(right)] when m < k, else
        // PATH(m-k, right) ++ [root(left)] (RFC 6962 §2.1.1). The
        // hand-rolled inner/border formula in verify_inclusion_proof must
        // accept a proof generated by this reference for every
        // (tree_size, index) pair, and reject any single-hash mutation
        // (cap#141).
        let leaf_hash = |body: &[u8]| -> [u8; 32] {
            Sha256::new()
                .chain_update([0])
                .chain_update(body)
                .finalize()
                .into()
        };
        let node_hash = |left: &[u8; 32], right: &[u8; 32]| -> [u8; 32] {
            Sha256::new()
                .chain_update([1])
                .chain_update(left)
                .chain_update(right)
                .finalize()
                .into()
        };
        // Largest power of two strictly below n (the RFC 6962 split).
        fn split(n: usize) -> usize {
            let mut k = 1;
            while k * 2 < n {
                k *= 2;
            }
            k
        }
        type NodeFn<'a> = &'a dyn Fn(&[u8; 32], &[u8; 32]) -> [u8; 32];
        fn mth(leaves: &[[u8; 32]], start: usize, end: usize, node: NodeFn<'_>) -> [u8; 32] {
            if end - start == 1 {
                return leaves[start];
            }
            let k = split(end - start);
            node(
                &mth(leaves, start, start + k, node),
                &mth(leaves, start + k, end, node),
            )
        }
        fn reference_path(
            leaves: &[[u8; 32]],
            start: usize,
            end: usize,
            index: usize,
            path: &mut Vec<[u8; 32]>,
            node: NodeFn<'_>,
        ) {
            if end - start == 1 {
                return;
            }
            let k = split(end - start);
            if index < start + k {
                reference_path(leaves, start, start + k, index, path, node);
                path.push(mth(leaves, start + k, end, node));
            } else {
                reference_path(leaves, start + k, end, index, path, node);
                path.push(mth(leaves, start, start + k, node));
            }
        }
        for tree_size in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 16, 17, 31, 33] {
            let bodies: Vec<Vec<u8>> = (0..tree_size)
                .map(|i| format!("rekor entry {i}").into_bytes())
                .collect();
            let leaves: Vec<[u8; 32]> = bodies.iter().map(|b| leaf_hash(b)).collect();
            let root = mth(&leaves, 0, tree_size, &node_hash);
            for (index, body) in bodies.iter().enumerate() {
                let mut path = Vec::new();
                reference_path(&leaves, 0, tree_size, index, &mut path, &node_hash);
                let proof = serde_json::json!({
                    "logIndex": index.to_string(),
                    "treeSize": tree_size.to_string(),
                    "rootHash": base64::engine::general_purpose::STANDARD.encode(root),
                    "hashes": path
                        .iter()
                        .map(|h| base64::engine::general_purpose::STANDARD.encode(h))
                        .collect::<Vec<_>>(),
                });
                assert!(
                    verify_inclusion_proof(&proof, body),
                    "reference proof must verify: tree {tree_size} index {index}"
                );
                // Flipping any single hash byte must invalidate.
                for mutated in 0..path.len() {
                    let mut bad = path.clone();
                    bad[mutated][0] ^= 0xff;
                    let proof = serde_json::json!({
                        "logIndex": index.to_string(),
                        "treeSize": tree_size.to_string(),
                        "rootHash": base64::engine::general_purpose::STANDARD.encode(root),
                        "hashes": bad
                            .iter()
                            .map(|h| base64::engine::general_purpose::STANDARD.encode(h))
                            .collect::<Vec<_>>(),
                    });
                    assert!(
                        !verify_inclusion_proof(&proof, body),
                        "mutated hash must fail: tree {tree_size} index {index} hash {mutated}"
                    );
                }
            }
        }
    }

    #[test]
    fn pae_is_unambiguous() {
        assert_eq!(dsse_pae("x", b"abc"), b"DSSEv1 1 x 3 abc");
        assert_ne!(dsse_pae("xa", b"bc"), dsse_pae("x", b"abc"));
    }

    #[test]
    fn der_string_rejects_trailing_bytes() {
        assert_eq!(der_string(b"\x0c\x03abc"), Some("abc".into()));
        assert_eq!(der_string(b"\x0c\x03abc!"), None);
    }

    #[test]
    fn certificate_time_comes_from_the_verified_tlog_entry() {
        let encoded = include_str!("../tests/fixtures/prove-it-live.bundle.b64")
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let bundle_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let proof = crate::parse_proof_bundle(&bundle_bytes).unwrap();
        let policy = crate::TrustPolicy::parse(include_bytes!(
            "../tests/fixtures/prove-it-live.policy.json"
        ))
        .unwrap();
        let signature_blob = ce_v1_decode(proof.sigstore_material)
            .unwrap()
            .into_iter()
            .find(|record| record.label == "signature_blob")
            .unwrap()
            .value;
        let bundle: Value = serde_json::from_slice(signature_blob).unwrap();
        let certificate_der =
            decode_b64(pointer_str(&bundle, "/verificationMaterial/certificate/rawBytes").unwrap())
                .unwrap();
        let dsse = bundle.get("dsseEnvelope").unwrap();
        let payload = decode_b64(pointer_str(dsse, "/payload").unwrap()).unwrap();
        let signature_b64 = pointer_str(dsse, "/signatures/0/sig").unwrap();
        let real_entry = bundle
            .pointer("/verificationMaterial/tlogEntries/0")
            .unwrap()
            .clone();
        let real_time = pointer_str(&real_entry, "/integratedTime")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let mut fabricated = real_entry.clone();
        fabricated["integratedTime"] = Value::String("1".into());
        fabricated["inclusionPromise"]["signedEntryTimestamp"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode([0; 64]));

        let (_, selected_time) = verify_transparency_and_fulcio(
            &[fabricated, real_entry],
            &payload,
            signature_b64,
            &certificate_der,
            &policy.sigstore,
        )
        .unwrap();
        assert_eq!(selected_time, real_time);
    }

    #[test]
    fn accepts_one_trusted_signature_among_multiple_blobs() {
        let encoded = include_str!("../tests/fixtures/prove-it-live.bundle.b64")
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let bundle_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let proof = crate::parse_proof_bundle(&bundle_bytes).unwrap();
        let records = ce_v1_decode(proof.sigstore_material).unwrap();
        let image_digest = std::str::from_utf8(
            records
                .iter()
                .find(|record| record.label == "image_digest")
                .unwrap()
                .value,
        )
        .unwrap();
        let mut fields = records
            .iter()
            .take(3)
            .map(|record| (record.label, record.value))
            .collect::<Vec<_>>();
        fields.push(("signature_blob", b"not a bundle"));
        fields.extend(
            records
                .iter()
                .skip(3)
                .map(|record| (record.label, record.value)),
        );
        let material = ce_v1_bytes(&fields);
        let policy = crate::TrustPolicy::parse(include_bytes!(
            "../tests/fixtures/prove-it-live.policy.json"
        ))
        .unwrap();
        verify_sigstore_and_provenance(
            &material,
            proof.provenance_oci_material,
            image_digest,
            &policy.sigstore,
        )
        .unwrap();
    }

    #[test]
    fn provenance_blob_must_belong_to_a_trusted_attestation_manifest() {
        let forged_blob = b"forged";
        let trusted_blob = b"trusted";
        let manifest = |blob: &[u8]| {
            serde_json::to_vec(&serde_json::json!({
                "layers": [{"digest": format!("sha256:{}", hex::encode(Sha256::digest(blob)))}]
            }))
            .unwrap()
        };
        let forged_manifest = manifest(forged_blob);
        let trusted_manifest = manifest(trusted_blob);
        let trusted_digest = format!("sha256:{}", hex::encode(Sha256::digest(&trusted_manifest)));
        let material = ce_v1_bytes(&[
            ("provenance_manifest", &forged_manifest),
            ("provenance_blob", forged_blob),
            ("provenance_manifest", &trusted_manifest),
            ("provenance_blob", trusted_blob),
        ]);
        let records = ce_v1_decode(&material).unwrap();
        assert_eq!(
            provenance_candidates(&records, &[trusted_digest]).collect::<Vec<_>>(),
            vec![trusted_blob.as_slice()]
        );
        assert!(provenance_candidates(&records, &[]).next().is_none());
    }

    #[test]
    fn provenance_must_cover_every_deployable_index_child() {
        let policy = crate::TrustPolicy::parse(include_bytes!(
            "../tests/fixtures/prove-it-live.policy.json"
        ))
        .unwrap()
        .sigstore;
        let children = [
            format!("sha256:{}", "11".repeat(32)),
            format!("sha256:{}", "22".repeat(32)),
        ];
        let provenance = |digest: &str| {
            serde_json::to_vec(&serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": digest.strip_prefix("sha256:").unwrap()}}],
                "predicate": {
                    "buildDefinition": {"internalParameters": {
                        "github_repository": policy.source_repository.as_str(),
                        "github_workflow_ref": policy.workflow_ref.as_str(),
                    }},
                    "runDetails": {"builder": {"id": policy.provenance_builder_id.as_str()}},
                },
            }))
            .unwrap()
        };
        let blobs = [provenance(&children[0]), provenance(&children[1])];
        let manifests = blobs.each_ref().map(|blob| {
            serde_json::to_vec(&serde_json::json!({
                "layers": [{"digest": format!("sha256:{}", hex::encode(Sha256::digest(blob)))}]
            }))
            .unwrap()
        });
        let source = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": children[0]},
                {"digest": children[1]},
                {
                    "digest": format!("sha256:{}", hex::encode(Sha256::digest(&manifests[0]))),
                    "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                },
                {
                    "digest": format!("sha256:{}", hex::encode(Sha256::digest(&manifests[1]))),
                    "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                },
            ],
        }))
        .unwrap();
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(&source)));
        let incomplete = ce_v1_bytes(&[
            ("image_manifest", &source),
            ("provenance_manifest", &manifests[0]),
            ("provenance_blob", &blobs[0]),
        ]);
        assert_eq!(
            verify_provenance(&incomplete, &expected, &policy),
            Err(SigstoreError::InvalidProvenance)
        );

        let complete = ce_v1_bytes(&[
            ("image_manifest", &source),
            ("provenance_manifest", &manifests[0]),
            ("provenance_blob", &blobs[0]),
            ("provenance_manifest", &manifests[1]),
            ("provenance_blob", &blobs[1]),
        ]);
        verify_provenance(&complete, &expected, &policy).unwrap();
    }

    #[test]
    fn provenance_supports_single_image_manifests() {
        let policy = crate::TrustPolicy::parse(include_bytes!(
            "../tests/fixtures/prove-it-live.policy.json"
        ))
        .unwrap()
        .sigstore;
        let source = br#"{"schemaVersion":2,"config":{"digest":"sha256:00"},"layers":[]}"#;
        let expected = format!("sha256:{}", hex::encode(Sha256::digest(source)));
        let blob = serde_json::to_vec(&serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"digest": {"sha256": expected.strip_prefix("sha256:").unwrap()}}],
            "predicate": {
                "buildDefinition": {"internalParameters": {
                    "github_repository": policy.source_repository.as_str(),
                    "github_workflow_ref": policy.workflow_ref.as_str(),
                }},
                "runDetails": {"builder": {"id": policy.provenance_builder_id.as_str()}},
            },
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "layers": [{"digest": format!("sha256:{}", hex::encode(Sha256::digest(&blob)))}]
        }))
        .unwrap();
        let material = ce_v1_bytes(&[
            ("image_manifest", source.as_slice()),
            ("provenance_manifest", &manifest),
            ("provenance_blob", &blob),
        ]);

        verify_provenance(&material, &expected, &policy).unwrap();

        let mut statement: Value = serde_json::from_slice(&blob).unwrap();
        statement.as_object_mut().unwrap().remove("predicateType");
        let blob = serde_json::to_vec(&statement).unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "layers": [{"digest": format!("sha256:{}", hex::encode(Sha256::digest(&blob)))}]
        }))
        .unwrap();
        let material = ce_v1_bytes(&[
            ("image_manifest", source.as_slice()),
            ("provenance_manifest", &manifest),
            ("provenance_blob", &blob),
        ]);
        assert_eq!(
            verify_provenance(&material, &expected, &policy),
            Err(SigstoreError::InvalidProvenance)
        );
    }
}
