//! Client-side OCI tag resolution for the CLI.
//!
//! `enclava deploy --image <ref>:<tag>` needs the content digest before the
//! deployment descriptor can be signed, so the CLI resolves the tag itself
//! with the same posture as the API's registry client: https-only, bounded
//! bodies, and a self-computed digest cross-checked against the advertised
//! one (a lying registry is rejected). The server independently resolves
//! `body.image` and refuses any digest disagreement with the signed
//! descriptor (signing_service.rs), so both resolutions must agree.

use std::net::IpAddr;
use std::sync::Arc;

use enclava_common::image::ImageRef;
use enclava_common::outbound_http::{BlockedNetworks, GuardedResolver};

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";
const MANIFEST_LIMIT: usize = 4 * 1024 * 1024;
const TOKEN_LIMIT: usize = 64 * 1024;

/// Resolve a tag-carrying image reference to its content digest
/// (`sha256:...`). Digest-pinned references are returned as-is.
pub async fn resolve_image_digest(image_ref: &ImageRef) -> Result<String, String> {
    if image_ref.has_digest() {
        return Ok(image_ref.digest().to_string());
    }
    let blocked = Arc::new(BlockedNetworks::from_env());
    let client = registry_client_builder(Arc::clone(&blocked))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    resolve_tag(image_ref, &client, &blocked).await
}

fn registry_client_builder(blocked: Arc<BlockedNetworks>) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(GuardedResolver::new(blocked)))
        // A proxy can resolve destinations remotely, bypassing the DNS guard.
        .no_proxy()
}

async fn resolve_tag(
    image_ref: &ImageRef,
    client: &reqwest::Client,
    blocked: &BlockedNetworks,
) -> Result<String, String> {
    let tag = image_ref
        .tag()
        .ok_or_else(|| format!("image {} has no tag or digest", image_ref.full_ref()))?;
    let base_url = registry_base_url(image_ref.registry())?;
    let repository =
        enclava_common::registry::manifest_repository(image_ref.registry(), image_ref.repository());
    let url = reqwest::Url::parse(&format!("{base_url}/v2/{repository}/manifests/{tag}"))
        .map_err(|e| format!("registry URL is not valid: {e}"))?;
    validate_destination(&url, blocked)?;

    let mut response = client
        .get(url.as_str())
        .header("Accept", MANIFEST_ACCEPT)
        .send()
        .await
        .map_err(|e| format!("registry request failed: {e}"))?;

    // Public manifests are commonly behind a bearer-token challenge
    // (401 + WWW-Authenticate); complete the token flow and retry.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = enclava_common::registry::select_bearer_challenge(
            response
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .filter_map(|v| v.to_str().ok()),
        )
        .ok_or_else(|| {
            "registry demanded authentication without a usable WWW-Authenticate challenge"
                .to_string()
        })?;
        let token = fetch_bearer_token(client, challenge, &base_url, &repository, blocked).await?;
        response = client
            .get(url.as_str())
            .header("Accept", MANIFEST_ACCEPT)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| format!("registry request failed: {e}"))?;
    }

    if !response.status().is_success() {
        return Err(format!(
            "registry returned status {} for {}/{}:{tag}",
            response.status(),
            image_ref.registry(),
            image_ref.repository()
        ));
    }

    let manifest = read_capped(&mut response, MANIFEST_LIMIT).await?;
    let digest = manifest_digest(&manifest);
    if let Some(advertised) = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        && advertised.trim() != digest
    {
        return Err(format!(
            "registry header digest {advertised} does not match hashed manifest {digest}"
        ));
    }
    Ok(digest)
}

fn validate_destination(url: &reqwest::Url, blocked: &BlockedNetworks) -> Result<(), String> {
    if url.scheme() != "https" {
        return Err("registry URL must use https".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "registry URL has no host".to_string())?;
    // Reqwest bypasses its DNS resolver for literal IP addresses.
    if let Ok(addr) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        && blocked.contains(addr)
    {
        return Err(format!("registry URL targets blocked address {addr}"));
    }
    Ok(())
}

/// Complete an RFC 7235 Bearer token flow against the challenge realm and
/// return the access token. The realm is registry-supplied input: https-only,
/// and its host must be the registry's own host (or a known auth service).
async fn fetch_bearer_token(
    client: &reqwest::Client,
    challenge: enclava_common::registry::BearerChallenge,
    base_url: &str,
    repository: &str,
    blocked: &BlockedNetworks,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&challenge.realm)
        .map_err(|e| format!("registry auth realm is not a valid URL: {e}"))?;
    validate_destination(&url, blocked)?;
    let registry_host = reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let realm_host = url.host_str().unwrap_or_default();
    if !enclava_common::registry::realm_host_allowed(&registry_host, realm_host) {
        return Err(format!(
            "registry auth realm host {realm_host} is not the registry host {registry_host} or its known registry auth service"
        ));
    }
    let scope = challenge
        .scope
        .unwrap_or_else(|| format!("repository:{repository}:pull"));
    {
        let mut query = url.query_pairs_mut();
        if let Some(service) = &challenge.service {
            query.append_pair("service", service);
        }
        query.append_pair("scope", &scope);
    }

    let mut response = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| format!("registry token request failed: {}", e.without_url()))?;
    if !response.status().is_success() {
        return Err(format!(
            "registry token endpoint returned status {}",
            response.status()
        ));
    }
    let body = read_capped(&mut response, TOKEN_LIMIT).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("registry token response is not parseable: {e}"))?;
    parsed
        .get("token")
        .or_else(|| parsed.get("access_token"))
        .and_then(|v| v.as_str())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "registry token response carried no token".to_string())
}

/// Map registry hostname to base URL (mirrors the API's registry client).
fn registry_base_url(registry: &str) -> Result<String, String> {
    match registry {
        "docker.io" => Ok("https://registry-1.docker.io".to_string()),
        "ghcr.io" => Ok("https://ghcr.io".to_string()),
        r if r.contains('.') => Ok(format!("https://{r}")),
        r => Err(format!("unsupported registry {r}")),
    }
}

/// Canonical, algorithm-prefixed digest of raw manifest bytes.
fn manifest_digest(manifest: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(manifest)))
}

/// Read a response body up to `limit` bytes; a body over the limit is an
/// error (chunked read, so a lying Content-Length does not bypass it).
async fn read_capped(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("registry response read failed: {e}"))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!("registry response exceeded {limit} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_digest_matches_known_vector() {
        // sha256 of the empty string.
        assert_eq!(
            manifest_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn base_url_maps_known_registries() {
        assert_eq!(
            registry_base_url("docker.io").unwrap(),
            "https://registry-1.docker.io"
        );
        assert_eq!(registry_base_url("ghcr.io").unwrap(), "https://ghcr.io");
        assert_eq!(
            registry_base_url("reg.example").unwrap(),
            "https://reg.example"
        );
        assert!(registry_base_url("localhost").is_err());
    }
}

#[cfg(test)]
mod network_tests;
