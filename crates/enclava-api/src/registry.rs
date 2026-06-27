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

    // The digest is in the Docker-Content-Digest header
    let digest = response
        .headers()
        .get("Docker-Content-Digest")
        .or_else(|| response.headers().get("docker-content-digest"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            RegistryError::ResolveFailed("no Docker-Content-Digest header in response".to_string())
        })?;

    Ok(digest.to_string())
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
}
