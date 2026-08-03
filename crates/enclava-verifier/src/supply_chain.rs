use enclava_common::canonical::ce_v1_decode;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SupplyChainError {
    #[error("portable material is malformed")]
    Malformed,
    #[error("portable material is for a different image")]
    ImageMismatch,
    #[error("portable OCI object digest does not match its manifest")]
    DigestMismatch,
    #[error("portable material is incomplete")]
    Incomplete,
}

pub fn verify_portable_material(
    sigstore: &[u8],
    provenance: &[u8],
    expected_image_digest: &str,
) -> Result<(), SupplyChainError> {
    verify_material(
        sigstore,
        b"enclava-sigstore-material-v1",
        "signature_manifest",
        "signature_blob",
        expected_image_digest,
        false,
    )?;
    verify_material(
        provenance,
        b"enclava-provenance-oci-material-v1",
        "provenance_manifest",
        "provenance_blob",
        expected_image_digest,
        true,
    )
}

fn verify_material(
    bytes: &[u8],
    purpose: &[u8],
    manifest_label: &str,
    blob_label: &str,
    expected_image_digest: &str,
    has_source_manifest: bool,
) -> Result<(), SupplyChainError> {
    let records = ce_v1_decode(bytes).map_err(|_| SupplyChainError::Malformed)?;
    let minimum = if has_source_manifest { 5 } else { 4 };
    if records.len() < minimum
        || records[0].label != "purpose"
        || records[0].value != purpose
        || records[1].label != "image_digest"
        || records[1].value != expected_image_digest.as_bytes()
    {
        return Err(SupplyChainError::ImageMismatch);
    }
    let mut offset = 2;
    if has_source_manifest {
        if records[offset].label != "image_manifest"
            || digest(records[offset].value) != expected_image_digest
        {
            return Err(SupplyChainError::DigestMismatch);
        }
        serde_json::from_slice::<serde_json::Value>(records[offset].value)
            .map_err(|_| SupplyChainError::Malformed)?;
        offset += 1;
    }

    let mut manifests = Vec::new();
    let mut blobs = Vec::new();
    for record in &records[offset..] {
        match record.label {
            label if label == manifest_label => manifests.push(record.value),
            label if label == blob_label => blobs.push(record.value),
            _ => return Err(SupplyChainError::Malformed),
        }
    }
    if manifests.is_empty() || blobs.is_empty() {
        return Err(SupplyChainError::Incomplete);
    }
    let blob_digests = blobs.iter().map(|blob| digest(blob)).collect::<Vec<_>>();
    for manifest in manifests {
        let value: serde_json::Value =
            serde_json::from_slice(manifest).map_err(|_| SupplyChainError::Malformed)?;
        let layers = value
            .get("layers")
            .and_then(serde_json::Value::as_array)
            .ok_or(SupplyChainError::Malformed)?;
        if layers.is_empty() {
            return Err(SupplyChainError::Incomplete);
        }
        for layer in layers {
            let referenced = layer
                .get("digest")
                .and_then(serde_json::Value::as_str)
                .ok_or(SupplyChainError::Malformed)?;
            if !blob_digests.iter().any(|actual| actual == referenced) {
                return Err(SupplyChainError::DigestMismatch);
            }
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::canonical::ce_v1_bytes;

    fn object(purpose: &'static [u8], image: &str, source: Option<&[u8]>, blob: &[u8]) -> Vec<u8> {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "layers": [{"digest": digest(blob)}]
        }))
        .unwrap();
        let mut records = vec![("purpose", purpose), ("image_digest", image.as_bytes())];
        if let Some(source) = source {
            records.push(("image_manifest", source));
        }
        let manifest_label = if source.is_some() {
            "provenance_manifest"
        } else {
            "signature_manifest"
        };
        let blob_label = if source.is_some() {
            "provenance_blob"
        } else {
            "signature_blob"
        };
        records.push((manifest_label, &manifest));
        records.push((blob_label, blob));
        ce_v1_bytes(&records)
    }

    #[test]
    fn verifies_every_preserved_digest() {
        let source = br#"{"schemaVersion":2,"manifests":[]}"#;
        let image = digest(source);
        let signature = object(b"enclava-sigstore-material-v1", &image, None, b"signature");
        let provenance = object(
            b"enclava-provenance-oci-material-v1",
            &image,
            Some(source),
            b"provenance",
        );
        verify_portable_material(&signature, &provenance, &image).unwrap();
        let mut broken = provenance;
        *broken.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_portable_material(&signature, &broken, &image),
            Err(SupplyChainError::DigestMismatch)
        );
    }
}
