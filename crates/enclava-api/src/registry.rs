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

    // Resolve by GET and hash the returned manifest bytes ourselves instead
    // of trusting the Docker-Content-Digest header: a compromised or
    // MITM-positioned registry could serve one manifest body while claiming
    // a different (e.g. already-deployed and verified) digest, poisoning the
    // audit trail that later verification steps anchor on. A GET response
    // also still carries Docker-Content-Digest, so a mismatch between the
    // self-computed and advertised digests additionally proves the registry
    // is dishonest and is rejected outright (defense in depth, issue #140).
    let manifest_repository = enclava_common::registry::manifest_repository(registry, repository);
    // Refuse before the URL is built. reqwest removes dot segments (including
    // `%2e%2e` and `\`) from the path, so a non-literal repository or tag
    // would be fetched as a different image after a prefix allowlist had
    // already matched the named repository (issue #228).
    let Some(expected_path) =
        enclava_common::registry::literal_manifest_path(&manifest_repository, tag)
    else {
        return Err(RegistryError::ResolveFailed(
            "image reference is not a literal repository and OCI tag".to_string(),
        ));
    };
    let url = format!("{base_url}{expected_path}");
    let parsed = reqwest::Url::parse(&url).map_err(|error| {
        RegistryError::ResolveFailed(format!("registry manifest URL is not valid: {error}"))
    })?;
    if parsed.path() != expected_path || parsed.query().is_some() {
        return Err(RegistryError::ResolveFailed(
            "image reference does not round-trip to a literal manifest URL".to_string(),
        ));
    }
    let url = parsed.to_string();
    client.check_url(&url)?;

    const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
             application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.docker.distribution.manifest.list.v2+json";

    let mut response = client
        .inner()
        .get(&url)
        .header("Accept", MANIFEST_ACCEPT)
        .send()
        .await?;

    // Registries commonly protect even public manifests with a bearer-token
    // challenge (401 + WWW-Authenticate); complete the token flow and retry.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = enclava_common::registry::select_bearer_challenge(
            response
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .filter_map(|v| v.to_str().ok()),
        )
        .ok_or_else(|| {
            RegistryError::ResolveFailed(
                "registry demanded authentication without a usable WWW-Authenticate challenge"
                    .to_string(),
            )
        })?;
        let token = fetch_bearer_token(client, challenge, registry, &manifest_repository).await?;
        // The bearer token from the challenge exchange authorizes this retry.
        // Platform pull credentials are not attached here — only on the token
        // request, and only when the issue #228 guards match.
        response = client
            .inner()
            .get(&url)
            .header("Accept", MANIFEST_ACCEPT)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
    }

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

    // Cap the manifest read like every other registry body: an allowlisted
    // but hostile registry must not be able to OOM the API pod with an
    // oversized "manifest". The cap is enforced against the bytes actually
    // received (chunked read), not just an advertised or absent
    // Content-Length, so an unbounded stream is cut off at the limit
    // instead of being buffered first.
    let limit = client.body_limit();
    let manifest = crate::clients::read_body_capped(response, limit)
        .await
        .map_err(RegistryError::Client)?;
    verify_advertised_digest(&advertised_digest, &manifest, registry, repository, tag)
}

/// Complete an RFC 7235 Bearer token flow against the challenge realm and
/// return the access token. The realm URL is registry-supplied input, so it
/// goes through the same https + allowlist checks as the manifest request,
/// and its host must be the registry's own host (or a known auth service).
/// Platform pull credentials, when the issue #228 guards match, are attached
/// to this token request only — never to the manifest GET.
async fn fetch_bearer_token(
    client: &RegistryClient,
    challenge: enclava_common::registry::BearerChallenge,
    registry: &str,
    repository: &str,
) -> Result<String, RegistryError> {
    let request = prepare_bearer_token_request(client, &challenge, registry, repository)?;
    let response = client.inner().execute(request).await?;
    if !response.status().is_success() {
        return Err(RegistryError::ResolveFailed(format!(
            "registry token endpoint returned status {}",
            response.status()
        )));
    }
    let body = crate::clients::read_body_capped(response, client.body_limit()).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        RegistryError::ResolveFailed(format!("registry token response is not parseable: {e}"))
    })?;
    parsed
        .get("token")
        .or_else(|| parsed.get("access_token"))
        .and_then(|v| v.as_str())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            RegistryError::ResolveFailed("registry token response carried no token".to_string())
        })
}

/// Build the token-endpoint request. Host guard, then scope guard, then
/// `check_url`, then — only if both guards matched — Basic auth. A
/// credentialed request never honors a challenge-chosen scope: the realm is
/// registry-controlled, so an attacker-supplied `scope` (including one already
/// on the realm URL) would mint a token for a repository the allowlist did
/// not approve. Anonymous requests keep the historical challenge scope.
fn prepare_bearer_token_request(
    client: &RegistryClient,
    challenge: &enclava_common::registry::BearerChallenge,
    registry: &str,
    repository: &str,
) -> Result<reqwest::Request, RegistryError> {
    let mut url = reqwest::Url::parse(&challenge.realm).map_err(|e| {
        RegistryError::ResolveFailed(format!("registry auth realm is not a valid URL: {e}"))
    })?;
    if url.scheme() != "https" {
        return Err(RegistryError::ResolveFailed(format!(
            "registry auth realm {} is not https",
            challenge.realm
        )));
    }
    let registry_host = reqwest::Url::parse(&registry_base_url(registry)?)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let realm_host = url.host_str().unwrap_or_default().to_string();
    if !enclava_common::registry::realm_host_allowed(&registry_host, &realm_host) {
        return Err(RegistryError::ResolveFailed(format!(
            "registry auth realm host {realm_host} is not the registry host {registry_host} or its known registry auth service"
        )));
    }

    // Scope guard reads env only; it does not contact the realm. Decide
    // before the query is built so a credentialed exchange can drop
    // challenge-supplied scope parameters. Attach the header only after
    // check_url, so a rejected destination never carries credentials.
    let pull_auth = crate::deploy::resolution_pull_credentials(registry, repository);
    if pull_auth.is_some() {
        // Credentialed exchanges send only the pinned pull scope and the
        // ghcr.io token service. A challenge-chosen service, a realm query
        // (`offline_token`, `account`, a pre-set scope), or userinfo on the
        // realm URL must not ride along with the platform PAT.
        if url.set_username("").is_err() || url.set_password(None).is_err() {
            return Err(RegistryError::ResolveFailed(
                "registry auth realm URL could not be sanitized".to_string(),
            ));
        }
        // Pin the path too. url normalization rewrites `/token/../other` to
        // `/other` before this sanitizer runs; the PAT must only reach the
        // registry token endpoint.
        url.set_path("/token");
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("scope", &format!("repository:{repository}:pull"));
            query.append_pair("service", "ghcr.io");
        }
    } else {
        let scope = challenge
            .scope
            .clone()
            .unwrap_or_else(|| format!("repository:{repository}:pull"));
        let mut query = url.query_pairs_mut();
        if let Some(service) = &challenge.service {
            query.append_pair("service", service);
        }
        query.append_pair("scope", &scope);
    }
    client.check_url(url.as_str())?;

    let mut builder = client.inner().get(url.as_str());
    if let Some((username, token)) = pull_auth {
        // basic_auth base64-encodes the pair, so a newline in either value
        // cannot break out of the header. Neither value is logged.
        builder = builder.basic_auth(username, Some(token));
    }
    builder.build().map_err(|error| {
        RegistryError::ResolveFailed(format!(
            "registry token request could not be built: {}",
            error.without_url()
        ))
    })
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
    use crate::clients::{AllowList, ClientConfig};
    use enclava_common::outbound_http::BlockedNetworks;
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
    async fn tag_resolution_rejects_allowlisted_private_literal_registry_before_network() {
        // cap#241 review: a literal-IP registry listed in
        // REGISTRY_ALLOWLIST must still be refused before any connection —
        // reqwest bypasses GuardedResolver for literal hosts, so
        // check_url itself enforces the blocklist.
        let client = RegistryClient::new(
            ClientConfig {
                blocked: Arc::new(BlockedNetworks::defaults()),
                body_limit_bytes: 1024,
                timeout: Duration::from_secs(2),
            },
            AllowList::from_env_or_default(Some("10.0.5.7".into())),
        )
        .unwrap();
        let image = enclava_common::image::ImageRef::parse("10.0.5.7/team/app:latest").unwrap();
        let err = resolve_image_digest(&client, &image).await.unwrap_err();

        assert!(matches!(
            err,
            RegistryError::Client(crate::clients::ClientError::BlockedAddress(_))
        ));
    }

    #[tokio::test]
    async fn tag_resolution_rejects_dot_segment_repository_before_network() {
        let image =
            enclava_common::image::ImageRef::parse("ghcr.io/team/app/../other:tag").unwrap();
        let err = resolve_image_digest(&registry_client(), &image)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("literal repository and OCI tag"),
            "dot-segment repository must be refused before any request: {err}"
        );
    }

    #[tokio::test]
    async fn tag_resolution_rejects_path_rewriting_tags_before_network() {
        // These tags parse, and url 2.5.8 would rewrite the manifest path to
        // /v2/enclava-labs/private/manifests/latest. The resolver must refuse
        // before any request, so a prefix allowlist cannot authorize that GET.
        for tag in [
            "../../../enclava-labs/private/manifests/latest",
            "%2e%2e/%2e%2e/%2e%2e/enclava-labs/private/manifests/latest",
            r"..\..\..\enclava-labs\private\manifests\latest",
        ] {
            let raw = format!("ghcr.io/team/app:{tag}");
            let image = enclava_common::image::ImageRef::parse(&raw).unwrap();
            let err = resolve_image_digest(&registry_client(), &image)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("literal repository and OCI tag"),
                "{raw} must be refused before a retargeted manifest GET: {err}"
            );
        }
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

    fn challenge(realm: &str, scope: &str) -> enclava_common::registry::BearerChallenge {
        challenge_with_service(realm, scope, "ghcr.io")
    }

    fn challenge_with_service(
        realm: &str,
        scope: &str,
        service: &str,
    ) -> enclava_common::registry::BearerChallenge {
        enclava_common::registry::BearerChallenge {
            realm: realm.to_string(),
            service: Some(service.to_string()),
            scope: Some(scope.to_string()),
        }
    }

    fn authorization_basic(request: &reqwest::Request) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let header = request.headers().get(reqwest::header::AUTHORIZATION)?;
        let encoded = header.to_str().unwrap().strip_prefix("Basic ")?;
        Some(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
    }

    fn scope_param(request: &reqwest::Request) -> String {
        request
            .url()
            .query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    }

    /// Issue #228: a private tagged image whose repository is on the
    /// operator allowlist sends the platform pull credentials on the token
    /// request only, and pins the token scope to that repository — a
    /// challenge-chosen scope (header or realm query) must not be honored.
    /// Out-of-scope repositories, and realms that fail the host guard, stay
    /// anonymous / rejected and never carry the credential.
    #[test]
    fn private_tag_token_request_attaches_scoped_basic_auth() {
        const CHILD: &str = "CAP_228_TOKEN_AUTH_CHILD";
        if std::env::var(CHILD).ok().as_deref() == Some("1") {
            let client = registry_client();
            let token = "test-token-not-a-secret";
            let in_scope = prepare_bearer_token_request(
                &client,
                &challenge_with_service(
                    "https://user:secret@ghcr.io/token/../other?scope=repository:other/secret:pull&service=evil&offline_token=true",
                    "repository:other/secret:pull",
                    "evil.example",
                ),
                "ghcr.io",
                "team/app",
            )
            .unwrap();
            assert_eq!(
                authorization_basic(&in_scope).as_deref(),
                Some(format!("cap-bot:{token}").as_bytes()),
                "token request must carry the platform pull credential"
            );
            assert_eq!(scope_param(&in_scope), "repository:team/app:pull");
            assert!(
                !in_scope.url().as_str().contains("other/secret")
                    && !in_scope.url().as_str().contains("other%2Fsecret"),
                "credentialed token URL must not keep the challenge scope: {}",
                in_scope.url()
            );
            assert!(
                !in_scope.url().as_str().contains(token)
                    && !in_scope.url().as_str().contains("cap-bot"),
                "credentials must not be placed in the token URL: {}",
                in_scope.url()
            );
            let service = in_scope
                .url()
                .query_pairs()
                .find(|(key, _)| key == "service")
                .map(|(_, value)| value.into_owned());
            assert_eq!(service.as_deref(), Some("ghcr.io"));
            assert_eq!(in_scope.url().path(), "/token");
            let url = in_scope.url().as_str();
            assert!(
                !url.contains("offline_token")
                    && !url.contains("user:secret")
                    && !url.contains('@'),
                "credentialed token URL must drop realm userinfo and extra query: {url}"
            );
            assert!(
                in_scope.url().username().is_empty() && in_scope.url().password().is_none(),
                "credentialed token URL must not keep userinfo"
            );

            let wildcard = prepare_bearer_token_request(
                &client,
                &challenge("https://ghcr.io/token", "repository:other/secret:pull"),
                "GHCR.IO",
                "team/nested/child",
            )
            .unwrap();
            assert!(authorization_basic(&wildcard).is_some());
            assert_eq!(scope_param(&wildcard), "repository:team/nested/child:pull");

            let outside = prepare_bearer_token_request(
                &client,
                &challenge("https://ghcr.io/token", "repository:other/secret:pull"),
                "ghcr.io",
                "other/app",
            )
            .unwrap();
            assert!(
                authorization_basic(&outside).is_none(),
                "out-of-scope repository must stay anonymous"
            );
            assert_eq!(scope_param(&outside), "repository:other/secret:pull");

            let foreign = prepare_bearer_token_request(
                &client,
                &challenge("https://auth.docker.io/token", "repository:team/app:pull"),
                "docker.io",
                "team/app",
            )
            .unwrap();
            assert!(authorization_basic(&foreign).is_none());

            let hijacked = prepare_bearer_token_request(
                &client,
                &challenge(
                    "https://ghcr.io.attacker.example/token",
                    "repository:team/app:pull",
                ),
                "ghcr.io",
                "team/app",
            )
            .unwrap_err();
            let hijacked = hijacked.to_string();
            assert!(
                hijacked.contains("not the registry host"),
                "suffix host must be rejected: {hijacked}"
            );
            assert!(
                !hijacked.contains(token),
                "rejection must not echo the credential: {hijacked}"
            );

            // Egress allowlist still runs after the host guard and before any
            // credentialed request is returned. A ghcr.io realm that the
            // client's allowlist rejects must not come back as an authed request.
            let restricted = RegistryClient::new(
                ClientConfig {
                    blocked: Arc::new(BlockedNetworks::defaults()),
                    body_limit_bytes: 1024,
                    timeout: Duration::from_secs(2),
                },
                AllowList::from_env_or_default(Some("example.com".into())),
            )
            .unwrap();
            let blocked = prepare_bearer_token_request(
                &restricted,
                &challenge("https://ghcr.io/token", "repository:team/app:pull"),
                "ghcr.io",
                "team/app",
            )
            .unwrap_err();
            let blocked = blocked.to_string();
            assert!(
                blocked.contains("not on the registry allowlist"),
                "check_url must reject a realm the client allowlist excludes: {blocked}"
            );
            assert!(!blocked.contains(token));
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "registry::tests::private_tag_token_request_attaches_scoped_basic_auth",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("GHCR_USERNAME", "cap-bot")
            .env("GHCR_TOKEN", "test-token-not-a-secret")
            .env(
                "TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES",
                "ghcr.io/team/app,ghcr.io/team/nested/*",
            )
            .env_remove("REGISTRY_ALLOWLIST")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Absent credentials keep the historical anonymous token request: the
    /// challenge scope is forwarded and no Authorization header is set.
    /// Runs in a child so a developer environment with GHCR_* set cannot
    /// make this pass by accident.
    #[test]
    fn tag_resolution_without_credentials_stays_anonymous() {
        const CHILD: &str = "CAP_228_TOKEN_ANON_CHILD";
        if std::env::var(CHILD).ok().as_deref() == Some("1") {
            let request = prepare_bearer_token_request(
                &registry_client(),
                &challenge("https://ghcr.io/token", "repository:team/app:pull"),
                "ghcr.io",
                "team/app",
            )
            .unwrap();
            assert!(authorization_basic(&request).is_none());
            assert_eq!(scope_param(&request), "repository:team/app:pull");
            assert!(
                request
                    .headers()
                    .get(reqwest::header::AUTHORIZATION)
                    .is_none()
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "registry::tests::tag_resolution_without_credentials_stays_anonymous",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("GHCR_USERNAME")
            .env_remove("GHCR_TOKEN")
            .env_remove("TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES")
            .env_remove("REGISTRY_ALLOWLIST")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}
