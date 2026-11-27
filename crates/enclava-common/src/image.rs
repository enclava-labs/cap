use serde::{Deserialize, Serialize};

/// A parsed OCI image reference. Supports registry/repo:tag and registry/repo@sha256:digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ImageRefError {
    #[error("invalid image reference: {0}")]
    Invalid(String),
    #[error("image must be pinned by digest (@sha256:...), got: {0}")]
    DigestRequired(String),
}

impl ImageRef {
    pub fn parse(raw: &str) -> Result<Self, ImageRefError> {
        let (name, digest) = match raw.split_once('@') {
            Some((name, digest)) => {
                crate::validate::validate_image_digest(digest)
                    .map_err(|e| ImageRefError::Invalid(e.to_string()))?;
                (name, digest.to_string())
            }
            None => (raw, String::new()),
        };

        let (name, tag) = split_tag(name);
        if let Some(tag) = tag {
            validate_tag(tag)?;
        }
        let (registry, repository) = split_name(name)?;
        Ok(Self {
            registry,
            repository,
            tag: tag.map(str::to_string),
            digest,
        })
    }

    pub fn registry(&self) -> &str {
        &self.registry
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn has_digest(&self) -> bool {
        !self.digest.is_empty()
    }

    /// Returns the full digest-pinned reference: registry/repo@digest.
    /// Panics if no digest is present -- call `has_digest()` or `require_digest()` first.
    pub fn digest_ref(&self) -> String {
        format!("{}/{}@{}", self.registry, self.repository, self.digest)
    }

    /// Validates that this image has a digest. Returns error if tag-only.
    /// CAP requires all deployed images to be digest-pinned for attestation.
    pub fn require_digest(&self) -> Result<(), ImageRefError> {
        if self.has_digest() {
            Ok(())
        } else {
            Err(ImageRefError::DigestRequired(self.full_ref()))
        }
    }

    /// Returns the full reference as provided (tag or digest form).
    pub fn full_ref(&self) -> String {
        if self.has_digest() {
            self.digest_ref()
        } else if let Some(tag) = &self.tag {
            format!("{}/{}:{}", self.registry, self.repository, tag)
        } else {
            format!("{}/{}", self.registry, self.repository)
        }
    }
}

/// Splits an optional `:tag` off a `registry/repository[:tag]` name. The first
/// colon after the first `/` starts a tag; one before it is a registry port.
fn split_tag(name: &str) -> (&str, Option<&str>) {
    let tag_search_start = name.find('/').unwrap_or(0);
    match name[tag_search_start..].find(':') {
        Some(pos) => {
            let colon = tag_search_start + pos;
            (&name[..colon], Some(&name[colon + 1..]))
        }
        None => (name, None),
    }
}

/// Rejects anything but one literal OCI tag (`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`).
fn validate_tag(tag: &str) -> Result<(), ImageRefError> {
    if crate::registry::tag_is_literal_oci(tag) {
        Ok(())
    } else {
        Err(ImageRefError::Invalid(format!(
            "invalid image tag: {tag:?}"
        )))
    }
}

fn split_name(name: &str) -> Result<(String, String), ImageRefError> {
    if name.len() > 255 {
        return Err(ImageRefError::Invalid(
            "image reference too long".to_string(),
        ));
    }

    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '/' || c == ':' || c == '.' || c == '-' || c == '_'
    }) {
        return Err(ImageRefError::Invalid(
            "invalid characters in image reference".to_string(),
        ));
    }

    if let Some(pos) = name.find('/') {
        let registry = &name[..pos];
        let repository = &name[pos + 1..];

        if registry.is_empty() {
            return Err(ImageRefError::Invalid("empty registry".to_string()));
        }

        if !registry.contains('.') && !registry.contains(':') {
            Ok(("docker.io".to_string(), name.to_string()))
        } else {
            if !registry
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '-')
            {
                return Err(ImageRefError::Invalid(
                    "invalid registry format".to_string(),
                ));
            }
            Ok((registry.to_string(), repository.to_string()))
        }
    } else {
        Ok(("docker.io".to_string(), format!("library/{name}")))
    }
}
