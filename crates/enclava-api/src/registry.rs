//! OCI registry client for resolving image tags to digests.
//!
//! Supports Docker Hub, GHCR, and any OCI-compliant registry.
//! Uses the distribution spec v2 manifest endpoint.

use crate::clients::{ClientError, RegistryClient};

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to resolve image tag: {0}")]
    ResolveFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image not found: {0}")]
    NotFound(String),
    #[error("unsupported registry: {0}")]
    UnsupportedRegistry(String),
    #[error("registry client rejected request: {0}")]
    Client(#[from] ClientError),
}

/// Resolve an image tag to a digest by querying the registry's manifest endpoint.
/// Returns the full digest string (e.g., "sha256:abcd...").
pub async fn resolve_tag_to_digest(
    client: &RegistryClient,
    registry: &str,
    repository: &str,
    tag: &str,
) -> Result<String, RegistryError> {
    let base_url = registry_base_url(registry)?;

    // HEAD request for the manifest, accepting OCI and Docker media types
    let url = format!("{base_url}/v2/{repository}/manifests/{tag}");
    client.check_url(&url)?;

    let response = client
        .inner()
        .head(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.index.v1+json, \
             application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(RegistryError::NotFound(format!(
            "{registry}/{repository}:{tag}"
        )));
    }

    if !response.status().is_success() {
        return Err(RegistryError::ResolveFailed(format!(
            "registry returned status {}",
            response.status()
        )));
    }

    // Resolve by GET and hash the returned manifest bytes ourselves instead
    // of trusting the Docker-Content-Digest header: a compromised or
    // MITM-positioned registry could serve one manifest body while claiming
    // a different (e.g. already-deployed and verified) digest, poisoning the
    // audit trail that later verification steps anchor on. A GET response
    // also still carries Docker-Content-Digest, so a mismatch between the
    // self-computed and advertised digests additionally proves the registry
    // is dishonest and is rejected outright (defense in depth, issue #140).
    let response = client
        .inner()
        .get(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.index.v1+json, \
             application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(RegistryError::NotFound(format!(
            "{registry}/{repository}:{tag}"
        )));
    }

    if !response.status().is_success() {
        return Err(RegistryError::ResolveFailed(format!(
            "registry returned status {}",
            response.status()
        )));
    }

    let advertised_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .or_else(|| response.headers().get("docker-content-digest"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            RegistryError::ResolveFailed("no Docker-Content-Digest header in response".to_string())
        })?;

    let manifest = response.bytes().await?;
    verify_advertised_digest(&advertised_digest, &manifest, registry, repository, tag)
}

/// Cross-check the registry-advertised digest against the digest computed
/// from the manifest bytes we actually received. Returns the verified digest.
fn verify_advertised_digest(
    advertised: &str,
    manifest: &[u8],
    registry: &str,
    repository: &str,
    tag: &str,
) -> Result<String, RegistryError> {
    let computed = compute_manifest_digest(manifest);
    if advertised != computed {
        return Err(RegistryError::ResolveFailed(format!(
            "registry header digest {advertised} does not match hashed manifest \
             {computed} for {registry}/{repository}:{tag}"
        )));
    }
    Ok(computed)
}

/// Canonical, algorithm-prefixed digest of raw manifest bytes.
fn compute_manifest_digest(manifest: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex_encode(&Sha256::digest(manifest)))
}

/// Lowercase hex without pulling in the `hex` crate for one call site.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Map registry hostname to base URL.
pub fn registry_base_url(registry: &str) -> Result<String, RegistryError> {
    match registry {
        "docker.io" => Ok("https://registry-1.docker.io".to_string()),
        "ghcr.io" => Ok("https://ghcr.io".to_string()),
        r if r.contains('.') => Ok(format!("https://{r}")),
        _ => Err(RegistryError::UnsupportedRegistry(registry.to_string())),
    }
}

/// Parse a full image reference and resolve the tag to a digest.
/// If the image already has a digest, returns it as-is.
pub async fn resolve_image_digest(
    client: &RegistryClient,
    image_ref: &enclava_common::image::ImageRef,
) -> Result<String, RegistryError> {
    if image_ref.has_digest() {
        return Ok(image_ref.digest().to_string());
    }

    let tag = image_ref
        .tag()
        .ok_or_else(|| RegistryError::ResolveFailed("image has no tag or digest".to_string()))?;

    resolve_tag_to_digest(client, image_ref.registry(), image_ref.repository(), tag).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::{AllowList, BlockedNetworks, ClientConfig};
    use std::sync::Arc;
    use std::time::Duration;

    fn registry_client() -> RegistryClient {
        RegistryClient::new(
            ClientConfig {
                blocked: Arc::new(BlockedNetworks::defaults()),
                body_limit_bytes: 1024,
                timeout: Duration::from_secs(2),
            },
            AllowList::from_env_or_default(None),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn tag_resolution_rejects_non_allowlisted_registry_before_network() {
        let image =
            enclava_common::image::ImageRef::parse("attacker.example/org/app:latest").unwrap();
        let err = resolve_image_digest(&registry_client(), &image)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RegistryError::Client(crate::clients::ClientError::HostNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn digest_pinned_image_does_not_need_registry_lookup() {
        let image = enclava_common::image::ImageRef::parse(
            "attacker.example/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let digest = resolve_image_digest(&registry_client(), &image)
            .await
            .unwrap();
        assert_eq!(
            digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn manifest_digest_hashing_matches_registry_content_addressing() {
        // Bytes of a real (trivial) manifest body; the digest must be the
        // plain sha256 over exactly the bytes received.
        let manifest = b"{\"schemaVersion\":2,\"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\"}";
        let expected = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(manifest);
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            compute_manifest_digest(manifest),
            format!("sha256:{expected}")
        );
    }

    #[test]
    fn advertised_digest_mismatch_is_rejected() {
        // A registry that serves manifest X while claiming a different
        // Docker-Content-Digest must not be trusted (issue #140).
        let manifest = b"manifest-bytes";
        let honest = compute_manifest_digest(manifest);
        let liar = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let ok = verify_advertised_digest(&honest, manifest, "ghcr.io", "org/app", "v1").unwrap();
        assert_eq!(ok, honest);

        let err = verify_advertised_digest(liar, manifest, "ghcr.io", "org/app", "v1").unwrap_err();
        assert!(
            err.to_string().contains("does not match hashed manifest"),
            "mismatch must name the disagreement: {err}"
        );
        assert!(
            err.to_string().contains("ghcr.io/org/app:v1"),
            "mismatch must name the image: {err}"
        );
    }

    #[test]
    fn hex_encoding_is_lowercase_and_dense() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex_encode(&[]), "");
    }
}
