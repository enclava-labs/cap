//! Cosign signature verification with per-app Fulcio identity policies.
//!
//! Verification model:
//! - Each app pins a `VerificationPolicy` (Fulcio URL/email identity, or a
//!   raw public key for advanced offline-signing users).
//! - The customer signs their own image — typically inside their own
//!   GitHub Actions runner via cosign keyless — and we verify the resulting
//!   signature against the app's pinned policy.
//! - Rekor inclusion is required: the trust root carries Rekor pubkeys, so
//!   `trusted_signature_layers` only returns layers whose Rekor bundle
//!   verifies. Signatures without Rekor evidence yield zero trusted layers
//!   and we reject.
//!
//! Trust root pinning:
//! - In production we pin to a TUF metadata snapshot bundled with the CAP
//!   release. Set `SIGSTORE_TUF_ROOT_PATH` to a trusted_root.json file
//!   shipped with the release artifact. Without that env var, the verifier
//!   falls back to the Sigstore Public Good Instance via TUF, which performs
//!   a network fetch — acceptable in dev, refused in production deployments
//!   by the surrounding ops policy.
//! - Refresh process: build a new CAP release with an updated bundled
//!   trusted_root.json fetched from the official Sigstore TUF repo, signed
//!   into the release artifact like any other dependency.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use futures::StreamExt as _;
use serde::Serialize;
use sigstore::cosign::CosignCapabilities;
use sigstore::cosign::verification_constraint::{
    CertSubjectEmailVerifier, CertSubjectUrlVerifier, PublicKeyVerifier, VerificationConstraintVec,
    cert_subject_email_verifier::StringVerifier,
};
use sigstore::cosign::{ClientBuilder, verify_constraints};
use sigstore::crypto::SigningScheme;
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::registry::registry_base_url;

const MAX_SIGSTORE_MATERIAL_BYTES: usize = 196_608;
const MAX_PROVENANCE_MATERIAL_BYTES: usize = 311_296;

#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    #[error("cosign verification failed: {0}")]
    VerificationFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image is not signed: {0}")]
    NotSigned(String),
    #[error("signer policy is not configured for this app")]
    PolicyNotConfigured,
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("trust root error: {0}")]
    TrustRoot(String),
}

/// Per-app verification policy.
///
/// `FulcioUrlIdentity` matches GitHub Actions OIDC subjects, which are URL-
/// shaped (e.g. `https://github.com/<org>/<repo>/.github/workflows/...`).
/// `FulcioEmailIdentity` is for OIDC issuers using email subjects (Google,
/// generic OIDC). `PublicKey` is for advanced users who sign offline.
#[derive(Debug, Clone)]
pub enum VerificationPolicy {
    FulcioUrlIdentity {
        fulcio_subject_url: String,
        fulcio_issuer: String,
    },
    FulcioEmailIdentity {
        email: String,
        fulcio_issuer: String,
    },
    PublicKey {
        pem: String,
    },
}

/// Result of a successful verification, recorded for audit/deployment.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedSignature {
    pub digest: String,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub rekor_log_index: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PortableVerificationMaterial {
    pub sigstore: Vec<u8>,
    pub provenance_oci: Vec<u8>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn registry_auth_from_env(registry: &str) -> Auth {
    if let Some(token) = env_nonempty("COSIGN_REGISTRY_BEARER_TOKEN") {
        return Auth::Bearer(token);
    }

    if let (Some(username), Some(password)) = (
        env_nonempty("COSIGN_REGISTRY_USERNAME"),
        env_nonempty("COSIGN_REGISTRY_PASSWORD"),
    ) {
        return Auth::Basic(username, password);
    }

    if registry == "ghcr.io"
        && let Some(token) = env_nonempty("GHCR_TOKEN")
    {
        let username = env_nonempty("GHCR_USERNAME").unwrap_or_else(|| "oauth2".to_string());
        return Auth::Basic(username, token);
    }

    Auth::Anonymous
}

fn looks_like_not_signed_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("manifest unknown")
        || lower.contains("name unknown")
        || lower.contains("not found")
        || lower.contains("404")
}

/// Convert a digest like "sha256:abcdef..." to the cosign tag format "sha256-abcdef..."
fn digest_to_cosign_tag(digest: &str, suffix: &str) -> String {
    let tag = digest.replace(':', "-");
    format!("{tag}.{suffix}")
}

/// Parse an image reference into (registry, repository) components.
fn parse_image_parts(image_ref: &str) -> Result<(String, String), CosignError> {
    let base = image_ref.split('@').next().unwrap_or(image_ref);
    let base = match (base.rfind('/'), base.rfind(':')) {
        (slash, Some(colon)) if slash.is_none_or(|slash| colon > slash) => &base[..colon],
        _ => base,
    };

    let parts: Vec<&str> = base.splitn(3, '/').collect();
    match parts.len() {
        1 => Ok(("docker.io".to_string(), format!("library/{}", parts[0]))),
        2 => {
            if parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost" {
                Ok((parts[0].to_string(), parts[1].to_string()))
            } else {
                Ok((
                    "docker.io".to_string(),
                    format!("{}/{}", parts[0], parts[1]),
                ))
            }
        }
        3 => Ok((parts[0].to_string(), format!("{}/{}", parts[1], parts[2]))),
        _ => Err(CosignError::VerificationFailed(format!(
            "cannot parse image reference: {image_ref}"
        ))),
    }
}

/// Build a sigstore trust root, preferring a bundled TUF snapshot when
/// `SIGSTORE_TUF_ROOT_PATH` is set.
async fn load_trust_root() -> Result<Arc<SigstoreTrustRoot>, CosignError> {
    if let Ok(path) = std::env::var("SIGSTORE_TUF_ROOT_PATH") {
        let data = std::fs::read(&path).map_err(|e| {
            CosignError::TrustRoot(format!("failed to read SIGSTORE_TUF_ROOT_PATH {path}: {e}"))
        })?;
        let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(&data).map_err(|e| {
            CosignError::TrustRoot(format!("invalid bundled trusted_root.json: {e}"))
        })?;
        return Ok(Arc::new(root));
    }

    let root = SigstoreTrustRoot::new(None)
        .await
        .map_err(|e| CosignError::TrustRoot(format!("sigstore TUF fetch failed: {e}")))?;
    Ok(Arc::new(root))
}

fn build_constraints(
    policy: &VerificationPolicy,
) -> Result<VerificationConstraintVec, CosignError> {
    let constraints: VerificationConstraintVec = match policy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url,
            fulcio_issuer,
        } => {
            if fulcio_subject_url.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio subject and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectUrlVerifier {
                url: fulcio_subject_url.clone(),
                issuer: fulcio_issuer.clone(),
            })]
        }
        VerificationPolicy::FulcioEmailIdentity {
            email,
            fulcio_issuer,
        } => {
            if email.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio email and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectEmailVerifier {
                email: StringVerifier::ExactMatch(email.clone()),
                issuer: Some(StringVerifier::ExactMatch(fulcio_issuer.clone())),
            })]
        }
        VerificationPolicy::PublicKey { pem } => {
            let verifier = PublicKeyVerifier::new(pem.as_bytes(), &SigningScheme::default())
                .map_err(|e| CosignError::InvalidPolicy(format!("invalid public key PEM: {e}")))?;
            vec![Box::new(verifier)]
        }
    };
    Ok(constraints)
}

/// Verify that a cosign signature exists for the given image digest and
/// satisfies the app's pinned verification policy.
pub async fn verify_image(
    image_ref: &str,
    image_digest: &str,
    policy: &VerificationPolicy,
) -> Result<VerifiedSignature, CosignError> {
    let trust_root = load_trust_root().await?;

    let image: OciReference = image_ref
        .parse()
        .map_err(|e| CosignError::VerificationFailed(format!("invalid image reference: {e}")))?;
    let (registry, _) = parse_image_parts(image_ref)?;

    let mut oci_client_config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        oci_client_config.protocol = ClientProtocol::Http;
    }

    let mut cosign_client = ClientBuilder::default()
        .with_oci_client_config(oci_client_config)
        .with_trust_repository(trust_root.as_ref())
        .map_err(|e| CosignError::TrustRoot(format!("trust repository setup failed: {e}")))?
        .build()
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to initialize sigstore client: {e}"))
        })?;

    let auth = registry_auth_from_env(&registry);
    let (_, source_image_digest) = cosign_client
        .triangulate(&image, &auth)
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to triangulate signature image: {e}"))
        })?;

    if source_image_digest != image_digest {
        return Err(CosignError::VerificationFailed(format!(
            "image digest mismatch: resolved {source_image_digest}, expected {image_digest}"
        )));
    }

    let signature_lookup_image = signature_lookup_source_image(&image, image_digest);
    let trusted_layers = cosign_client
        .trusted_signature_layers(&auth, &signature_lookup_image)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if looks_like_not_signed_error(&msg) {
                CosignError::NotSigned(format!("no cosign signature found for {image_digest}"))
            } else {
                CosignError::VerificationFailed(format!(
                    "failed to fetch/verify signature layers: {msg}"
                ))
            }
        })?;

    if trusted_layers.is_empty() {
        return Err(CosignError::NotSigned(format!(
            "no Rekor-attested signature layers for {image_digest}"
        )));
    }

    let constraints = build_constraints(policy)?;
    verify_constraints(&trusted_layers, constraints.iter()).map_err(|e| {
        CosignError::VerificationFailed(format!(
            "signature did not satisfy app's verification policy: {e}"
        ))
    })?;

    let (signer_subject, signer_issuer, rekor_log_index) =
        extract_signer_metadata(&trusted_layers, policy);

    Ok(VerifiedSignature {
        digest: image_digest.to_string(),
        signer_subject,
        signer_issuer,
        verified_at: Utc::now(),
        rekor_log_index,
    })
}

fn signature_lookup_source_image(image: &OciReference, image_digest: &str) -> OciReference {
    OciReference::with_digest(
        image.registry().to_string(),
        image.repository().to_string(),
        image_digest.to_string(),
    )
}

fn extract_signer_metadata(
    layers: &[sigstore::cosign::SignatureLayer],
    policy: &VerificationPolicy,
) -> (Option<String>, Option<String>, Option<i64>) {
    use sigstore::cosign::signature_layers::CertificateSubject;

    let layer = layers.iter().find(|l| l.certificate_signature.is_some());
    let mut subject: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut rekor_index: Option<i64> = None;

    if let Some(layer) = layer
        && let Some(cert) = &layer.certificate_signature
    {
        subject = match &cert.subject {
            CertificateSubject::Email(e) => Some(e.clone()),
            CertificateSubject::Uri(u) => Some(u.clone()),
        };
        issuer = cert.issuer.clone();
    }

    if let Some(layer) = layers.iter().find(|l| l.bundle.is_some())
        && let Some(bundle) = &layer.bundle
    {
        rekor_index = match bundle {
            sigstore::cosign::bundle_content::BundleContent::RekorBundle(bundle) => {
                Some(bundle.payload.log_index)
            }
            sigstore::cosign::bundle_content::BundleContent::SigstoreBundle(entry) => {
                Some(entry.log_index)
            }
        };
    }

    if subject.is_none() {
        match policy {
            VerificationPolicy::FulcioUrlIdentity {
                fulcio_subject_url,
                fulcio_issuer,
            } => {
                subject = Some(fulcio_subject_url.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::FulcioEmailIdentity {
                email,
                fulcio_issuer,
            } => {
                subject = Some(email.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::PublicKey { .. } => {}
        }
    }

    (subject, issuer, rekor_index)
}

/// Fetch provenance attestation and SBOM from OCI registry attestation tags.
pub async fn fetch_attestations(
    client: &reqwest::Client,
    image_ref: &str,
    digest: &str,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>), CosignError> {
    let (registry, repository) = parse_image_parts(image_ref)?;
    let base_url = registry_base_url(&registry)
        .map_err(|e| CosignError::VerificationFailed(format!("unsupported registry: {e}")))?;

    let provenance = fetch_attestation_tag(client, &base_url, &repository, digest, "att").await?;
    let sbom = fetch_attestation_tag(client, &base_url, &repository, digest, "sbom").await?;

    Ok((provenance, sbom))
}

/// Preserve the exact OCI manifests and signed layers needed for offline replay.
pub async fn fetch_portable_verification_material(
    image_ref: &str,
    image_digest: &str,
) -> Result<PortableVerificationMaterial, CosignError> {
    use oci_client::client::{Client, ClientConfig};
    use oci_client::secrets::RegistryAuth;

    const MANIFEST_TYPES: &[&str] = &[
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    let (registry, repository) = parse_image_parts(image_ref)?;
    let auth: RegistryAuth = (&registry_auth_from_env(&registry)).into();
    let mut config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        config.protocol = oci_client::client::ClientProtocol::Http;
    }
    let client = Client::new(config);
    let source = oci_client::Reference::with_digest(
        registry.clone(),
        repository.clone(),
        image_digest.to_string(),
    );
    let signature = oci_client::Reference::with_tag(
        registry.clone(),
        repository.clone(),
        digest_to_cosign_tag(image_digest, "sig"),
    );

    let (source_manifest, source_resolved) = client
        .pull_manifest_raw(&source, &auth, MANIFEST_TYPES)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    if source_resolved != image_digest {
        return Err(CosignError::VerificationFailed(
            "source manifest digest mismatch".into(),
        ));
    }
    let signature_objects =
        pull_signature_objects(&client, &source, &signature, &auth, MANIFEST_TYPES).await?;
    let provenance_objects = pull_provenance_objects(
        &client,
        &source_manifest,
        &registry,
        &repository,
        &auth,
        MANIFEST_TYPES,
    )
    .await?;

    let mut sigstore_records = vec![
        ("purpose", b"enclava-sigstore-material-v1".as_slice()),
        ("image_digest", image_digest.as_bytes()),
    ];
    for (manifest, blobs) in &signature_objects {
        sigstore_records.push(("signature_manifest", manifest.as_slice()));
        sigstore_records.extend(blobs.iter().map(|blob| ("signature_blob", blob.as_slice())));
    }
    let sigstore = enclava_common::canonical::ce_v1_bytes(&sigstore_records);

    let mut provenance_records = vec![
        ("purpose", b"enclava-provenance-oci-material-v1".as_slice()),
        ("image_digest", image_digest.as_bytes()),
        ("image_manifest", source_manifest.as_ref()),
    ];
    for (manifest, blobs) in &provenance_objects {
        provenance_records.push(("provenance_manifest", manifest.as_slice()));
        provenance_records.extend(
            blobs
                .iter()
                .map(|blob| ("provenance_blob", blob.as_slice())),
        );
    }
    let provenance_oci = enclava_common::canonical::ce_v1_bytes(&provenance_records);

    if sigstore.len() > MAX_SIGSTORE_MATERIAL_BYTES
        || provenance_oci.len() > MAX_PROVENANCE_MATERIAL_BYTES
    {
        return Err(CosignError::VerificationFailed(
            "portable verification material exceeds v1 limits".into(),
        ));
    }
    Ok(PortableVerificationMaterial {
        sigstore,
        provenance_oci,
    })
}

async fn pull_signature_objects(
    client: &oci_client::client::Client,
    source: &oci_client::Reference,
    legacy_signature: &oci_client::Reference,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
) -> Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>, CosignError> {
    if let Ok(object) = pull_oci_object(
        client,
        legacy_signature,
        auth,
        accepted_media_types,
        MAX_SIGSTORE_MATERIAL_BYTES,
    )
    .await
        && object.1.iter().any(|blob| is_portable_signature_blob(blob))
    {
        return Ok(vec![object]);
    }
    let referrers = client
        .pull_referrers(source, None)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    let mut objects = Vec::new();
    for descriptor in referrers.manifests {
        let reference = oci_client::Reference::with_digest(
            source.resolve_registry().to_string(),
            source.repository().to_string(),
            descriptor.digest,
        );
        let Ok(object) = pull_oci_object(
            client,
            &reference,
            auth,
            accepted_media_types,
            MAX_SIGSTORE_MATERIAL_BYTES,
        )
        .await
        else {
            continue;
        };
        let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&object.0) else {
            continue;
        };
        if manifest
            .pointer("/annotations/dev.sigstore.bundle.predicateType")
            .and_then(serde_json::Value::as_str)
            == Some("https://sigstore.dev/cosign/sign/v1")
            && object.1.iter().any(|blob| is_portable_signature_blob(blob))
        {
            if objects.iter().map(oci_object_size).sum::<usize>() + oci_object_size(&object)
                > MAX_SIGSTORE_MATERIAL_BYTES
            {
                return Err(portable_material_too_large());
            }
            objects.push(object);
        }
    }
    if objects.is_empty() {
        return Err(CosignError::NotSigned(
            "no portable Sigstore signature object found".into(),
        ));
    }
    Ok(objects)
}

fn is_portable_signature_blob(blob: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(blob).is_ok_and(|bundle| {
        bundle.get("dsseEnvelope").is_some()
            && bundle
                .pointer("/verificationMaterial/certificate/rawBytes")
                .is_some()
            && bundle
                .pointer("/verificationMaterial/tlogEntries")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|entries| !entries.is_empty())
    })
}

async fn pull_provenance_objects(
    client: &oci_client::client::Client,
    source_manifest: &[u8],
    registry: &str,
    repository: &str,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
) -> Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>, CosignError> {
    use oci_client::manifest::OciManifest;

    let source: OciManifest = serde_json::from_slice(source_manifest).map_err(|error| {
        CosignError::VerificationFailed(format!("invalid source OCI manifest: {error}"))
    })?;
    let references = match source {
        OciManifest::ImageIndex(index) => index
            .manifests
            .into_iter()
            .filter(|descriptor| {
                descriptor
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get("vnd.docker.reference.type"))
                    .is_some_and(|kind| kind == "attestation-manifest")
            })
            .map(|descriptor| {
                oci_client::Reference::with_digest(
                    registry.to_string(),
                    repository.to_string(),
                    descriptor.digest,
                )
            })
            .collect::<Vec<_>>(),
        OciManifest::Image(_) => Vec::new(),
    };
    if references.is_empty() {
        return Err(CosignError::VerificationFailed(
            "source index has no bound provenance manifests".into(),
        ));
    }
    let mut objects = Vec::with_capacity(references.len());
    for reference in references {
        let object = pull_oci_object(
            client,
            &reference,
            auth,
            accepted_media_types,
            MAX_PROVENANCE_MATERIAL_BYTES,
        )
        .await?;
        if objects.iter().map(oci_object_size).sum::<usize>() + oci_object_size(&object)
            > MAX_PROVENANCE_MATERIAL_BYTES
        {
            return Err(portable_material_too_large());
        }
        objects.push(object);
    }
    Ok(objects)
}

async fn pull_oci_object(
    client: &oci_client::client::Client,
    reference: &oci_client::Reference,
    auth: &oci_client::secrets::RegistryAuth,
    accepted_media_types: &[&str],
    maximum_bytes: usize,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), CosignError> {
    use oci_client::manifest::OciManifest;

    let (raw, _) = client
        .pull_manifest_raw(reference, auth, accepted_media_types)
        .await
        .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
    let manifest: OciManifest = serde_json::from_slice(&raw).map_err(|error| {
        CosignError::VerificationFailed(format!("invalid OCI manifest: {error}"))
    })?;
    let OciManifest::Image(manifest) = manifest else {
        return Err(CosignError::VerificationFailed(
            "verification object is not an OCI image manifest".into(),
        ));
    };
    let mut total = raw.len();
    let mut blobs = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let declared_size =
            usize::try_from(layer.size).map_err(|_| portable_material_too_large())?;
        if total.saturating_add(declared_size) > maximum_bytes {
            return Err(portable_material_too_large());
        }
        let mut bytes = Vec::new();
        let mut stream = client
            .pull_blob_stream(reference, layer)
            .await
            .map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|error| CosignError::VerificationFailed(error.to_string()))?;
            extend_bounded(&mut bytes, &chunk, total, maximum_bytes)?;
        }
        total += bytes.len();
        blobs.push(bytes);
    }
    Ok((raw.to_vec(), blobs))
}

fn oci_object_size((manifest, blobs): &(Vec<u8>, Vec<Vec<u8>>)) -> usize {
    manifest.len() + blobs.iter().map(Vec::len).sum::<usize>()
}

fn portable_material_too_large() -> CosignError {
    CosignError::VerificationFailed("portable verification material exceeds v1 limits".into())
}

fn extend_bounded(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    previous_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), CosignError> {
    if previous_bytes
        .saturating_add(bytes.len())
        .saturating_add(chunk.len())
        > maximum_bytes
    {
        return Err(portable_material_too_large());
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

async fn fetch_attestation_tag(
    client: &reqwest::Client,
    base_url: &str,
    repository: &str,
    digest: &str,
    suffix: &str,
) -> Result<Option<serde_json::Value>, CosignError> {
    let tag = digest_to_cosign_tag(digest, suffix);
    let url = format!("{base_url}/v2/{repository}/manifests/{tag}");

    let response = client
        .get(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        tracing::warn!(
            "registry returned {} when fetching {}.{} attestation",
            response.status(),
            digest,
            suffix
        );
        return Ok(None);
    }

    let body = response.text().await?;
    match serde_json::from_str(&body) {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            tracing::warn!("failed to parse {} attestation as JSON: {}", suffix, e);
            Ok(None)
        }
    }
}

/// Per-sidecar pinned signer identity (Phase 11).
#[derive(Debug, Clone)]
pub struct SidecarPin {
    pub label: &'static str,
    pub image_ref: String,
    pub image_digest: String,
    pub policy: VerificationPolicy,
}

/// Verified sidecar digests, returned in fixed sidecar-name order so they can
/// be bound into `cc_init_data.sidecar_digests` and the KBS Rego.
#[derive(Debug, Clone)]
pub struct VerifiedSidecars {
    pub attestation_proxy: String,
    pub caddy_ingress: String,
}

/// Verify the platform-controlled sidecar images at API startup. Refuses to
/// return Ok unless every configured sidecar has a Rekor-attested cosign
/// signature satisfying the pinned signer identity.
///
/// `SKIP_COSIGN_VERIFY` (debug builds only — release rejects via env_gates)
/// short-circuits this check. Production must always verify.
pub async fn verify_sidecars_at_startup(
    pins: &[SidecarPin],
) -> Result<VerifiedSidecars, CosignError> {
    if std::env::var("SKIP_COSIGN_VERIFY")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
    {
        tracing::warn!("SKIP_COSIGN_VERIFY: sidecar startup verification bypassed (debug only)");
        let mut ap = String::new();
        let mut ca = String::new();
        for p in pins {
            match p.label {
                "attestation_proxy" => ap = p.image_digest.clone(),
                "caddy_ingress" => ca = p.image_digest.clone(),
                _ => {}
            }
        }
        return Ok(VerifiedSidecars {
            attestation_proxy: ap,
            caddy_ingress: ca,
        });
    }

    let mut ap = String::new();
    let mut ca = String::new();
    for pin in pins {
        let v = verify_image(&pin.image_ref, &pin.image_digest, &pin.policy).await?;
        tracing::info!(
            sidecar = %pin.label,
            digest = %v.digest,
            subject = ?v.signer_subject,
            issuer = ?v.signer_issuer,
            "sidecar cosign verified at startup"
        );
        match pin.label {
            "attestation_proxy" => ap = v.digest,
            "caddy_ingress" => ca = v.digest,
            _ => {}
        }
    }
    if ap.is_empty() || ca.is_empty() {
        return Err(CosignError::PolicyNotConfigured);
    }
    Ok(VerifiedSidecars {
        attestation_proxy: ap,
        caddy_ingress: ca,
    })
}

/// Build sidecar pins from environment variables. Returns `None` if neither
/// sidecar image is configured (developer mode); returns an error if the
/// signer-identity vars are missing for a configured image.
pub fn sidecar_pins_from_env() -> Result<Option<Vec<SidecarPin>>, CosignError> {
    let proxy_image = std::env::var("ATTESTATION_PROXY_IMAGE").ok();
    let caddy_image = std::env::var("CADDY_INGRESS_IMAGE").ok();
    sidecar_pins_from_images(proxy_image.as_deref(), caddy_image.as_deref())
}

/// Build sidecar pins from resolved image references while still reading the
/// signer policy from environment. This lets the API use signed platform
/// release image anchors instead of trusting image refs only from env.
pub fn sidecar_pins_from_images(
    proxy_image: Option<&str>,
    caddy_image: Option<&str>,
) -> Result<Option<Vec<SidecarPin>>, CosignError> {
    if proxy_image.is_none() && caddy_image.is_none() {
        return Ok(None);
    }

    let mut pins = Vec::new();
    if let Some(image) = proxy_image {
        pins.push(build_pin_from_env(
            "attestation_proxy",
            image,
            "ATTESTATION_PROXY_SIGNER_PUBLIC_KEY_BASE64",
            "ATTESTATION_PROXY_SIGNER_PUBLIC_KEY_PEM",
            "ATTESTATION_PROXY_SIGNER_SUBJECT",
            "ATTESTATION_PROXY_SIGNER_ISSUER",
        )?);
    }
    if let Some(image) = caddy_image {
        pins.push(build_pin_from_env(
            "caddy_ingress",
            image,
            "CADDY_INGRESS_SIGNER_PUBLIC_KEY_BASE64",
            "CADDY_INGRESS_SIGNER_PUBLIC_KEY_PEM",
            "CADDY_INGRESS_SIGNER_SUBJECT",
            "CADDY_INGRESS_SIGNER_ISSUER",
        )?);
    }
    Ok(Some(pins))
}

fn build_pin_from_env(
    label: &'static str,
    image_ref: &str,
    public_key_b64_var: &str,
    public_key_pem_var: &str,
    subject_var: &str,
    issuer_var: &str,
) -> Result<SidecarPin, CosignError> {
    let digest = image_ref
        .split('@')
        .nth(1)
        .ok_or_else(|| {
            CosignError::InvalidPolicy(format!("{label} image is not digest-pinned: {image_ref}"))
        })?
        .to_string();

    if let Some(pem) = read_public_key_policy(public_key_b64_var, public_key_pem_var)? {
        return Ok(SidecarPin {
            label,
            image_ref: image_ref.to_string(),
            image_digest: digest,
            policy: VerificationPolicy::PublicKey { pem },
        });
    }

    let subject = std::env::var(subject_var).map_err(|_| {
        CosignError::InvalidPolicy(format!("missing {subject_var} for sidecar {label}"))
    })?;
    let issuer = std::env::var(issuer_var).map_err(|_| {
        CosignError::InvalidPolicy(format!("missing {issuer_var} for sidecar {label}"))
    })?;

    let policy = if subject.starts_with("https://") {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: subject,
            fulcio_issuer: issuer,
        }
    } else {
        VerificationPolicy::FulcioEmailIdentity {
            email: subject,
            fulcio_issuer: issuer,
        }
    };
    Ok(SidecarPin {
        label,
        image_ref: image_ref.to_string(),
        image_digest: digest,
        policy,
    })
}

fn read_public_key_policy(
    public_key_b64_var: &str,
    public_key_pem_var: &str,
) -> Result<Option<String>, CosignError> {
    for name in [
        public_key_b64_var,
        "PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64",
    ] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            let decoded = B64
                .decode(value.trim())
                .map_err(|e| CosignError::InvalidPolicy(format!("invalid {name}: {e}")))?;
            let pem = String::from_utf8(decoded)
                .map_err(|e| CosignError::InvalidPolicy(format!("{name} is not UTF-8: {e}")))?;
            return Ok(Some(pem));
        }
    }

    for name in [public_key_pem_var, "PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM"] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return Ok(Some(value));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_policy() -> VerificationPolicy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url:
                "https://github.com/example/repo/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    #[test]
    fn signature_lookup_source_is_digest_pinned_for_mutable_tags() {
        let image: OciReference = "registry.example.test/team/app:latest".parse().unwrap();
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let lookup = signature_lookup_source_image(&image, digest);

        assert_eq!(
            lookup.whole(),
            format!("registry.example.test/team/app@{digest}")
        );
        assert_eq!(lookup.digest(), Some(digest));
        assert_eq!(lookup.tag(), None);
    }

    #[test]
    fn build_pin_from_env_rejects_non_digest_image() {
        let err = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y:tag",
            "TEST_PUBLIC_KEY_BASE64",
            "TEST_PUBLIC_KEY_PEM",
            "TEST_SUBJECT_VAR",
            "TEST_ISSUER_VAR",
        )
        .unwrap_err();
        assert!(matches!(err, CosignError::InvalidPolicy(msg) if msg.contains("digest-pinned")));
    }

    #[test]
    fn build_pin_from_env_url_subject_picks_url_policy() {
        unsafe {
            std::env::set_var(
                "TEST_SIDECAR_SUBJECT_URL",
                "https://github.com/x/y/.github/workflows/build.yml@refs/heads/main",
            );
            std::env::set_var(
                "TEST_SIDECAR_ISSUER_URL",
                "https://token.actions.githubusercontent.com",
            );
        }
        let pin = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_PUBLIC_KEY_BASE64",
            "TEST_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_SUBJECT_URL",
            "TEST_SIDECAR_ISSUER_URL",
        )
        .expect("pin");
        assert!(matches!(
            pin.policy,
            VerificationPolicy::FulcioUrlIdentity { .. }
        ));
        assert_eq!(
            pin.image_digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn build_pin_from_env_public_key_overrides_fulcio_vars() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeDjxjxz1f2yWqSX+F2TSLujEc5tMLMMIRxI2CPOXKv8=\n-----END PUBLIC KEY-----\n";
        unsafe {
            std::env::set_var("TEST_SIDECAR_PUBLIC_KEY_B64", B64.encode(pem));
            std::env::remove_var("TEST_SIDECAR_PUBLIC_KEY_PEM");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM");
        }
        let pin = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_SIDECAR_PUBLIC_KEY_B64",
            "TEST_SIDECAR_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_MISSING_SUBJECT",
            "TEST_SIDECAR_MISSING_ISSUER",
        )
        .expect("pin");
        assert!(matches!(pin.policy, VerificationPolicy::PublicKey { .. }));
    }

    #[test]
    fn build_pin_from_env_rejects_invalid_public_key_base64() {
        unsafe {
            std::env::set_var("TEST_SIDECAR_BAD_PUBLIC_KEY_B64", "not base64");
            std::env::remove_var("TEST_SIDECAR_BAD_PUBLIC_KEY_PEM");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_BASE64");
            std::env::remove_var("PLATFORM_SIDECAR_SIGNER_PUBLIC_KEY_PEM");
        }
        let err = build_pin_from_env(
            "attestation_proxy",
            "ghcr.io/x/y@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "TEST_SIDECAR_BAD_PUBLIC_KEY_B64",
            "TEST_SIDECAR_BAD_PUBLIC_KEY_PEM",
            "TEST_SIDECAR_MISSING_SUBJECT",
            "TEST_SIDECAR_MISSING_ISSUER",
        )
        .unwrap_err();
        assert!(
            matches!(err, CosignError::InvalidPolicy(msg) if msg.contains("TEST_SIDECAR_BAD_PUBLIC_KEY_B64"))
        );
    }

    #[test]
    fn build_constraints_url_policy_ok() {
        let c = build_constraints(&url_policy()).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_email_policy_ok() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: "https://accounts.google.com".to_string(),
        };
        let c = build_constraints(&policy).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_rejects_empty_url_subject() {
        let policy = VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: String::new(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_empty_email_issuer() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: String::new(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_invalid_public_key() {
        let policy = VerificationPolicy::PublicKey {
            pem: "not a real PEM".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn parse_image_parts_handles_common_shapes() {
        assert_eq!(
            parse_image_parts("nginx").unwrap(),
            ("docker.io".to_string(), "library/nginx".to_string())
        );
        assert_eq!(
            parse_image_parts("ghcr.io/org/repo:v1").unwrap(),
            ("ghcr.io".to_string(), "org/repo".to_string())
        );
        assert_eq!(
            parse_image_parts("user/repo:tag").unwrap(),
            ("docker.io".to_string(), "user/repo".to_string())
        );
        assert_eq!(
            parse_image_parts("registry.example:5000/org/repo:tag").unwrap(),
            ("registry.example:5000".to_string(), "org/repo".to_string())
        );
    }

    #[test]
    fn portable_signature_blobs_require_bundle_material() {
        assert!(!is_portable_signature_blob(
            br#"{"critical":{"image":{"docker-manifest-digest":"sha256:00"}}}"#
        ));
        assert!(is_portable_signature_blob(
            br#"{"dsseEnvelope":{},"verificationMaterial":{"certificate":{"rawBytes":"AA=="},"tlogEntries":[{}]}}"#
        ));
    }

    #[test]
    fn portable_blob_buffer_stops_at_limit() {
        let mut bytes = vec![1; 2];
        extend_bounded(&mut bytes, &[2, 3], 1, 5).unwrap();
        assert!(extend_bounded(&mut bytes, &[4], 1, 5).is_err());
    }

    #[test]
    fn registry_auth_from_env_uses_basic_credentials() {
        unsafe {
            std::env::set_var("COSIGN_REGISTRY_USERNAME", "cap-bot");
            std::env::set_var("COSIGN_REGISTRY_PASSWORD", "ghp_example");
            std::env::remove_var("COSIGN_REGISTRY_BEARER_TOKEN");
            std::env::remove_var("GHCR_USERNAME");
            std::env::remove_var("GHCR_TOKEN");
        }

        let auth = registry_auth_from_env("ghcr.io");

        assert!(matches!(
            auth,
            Auth::Basic(username, password) if username == "cap-bot" && password == "ghp_example"
        ));
    }
}
