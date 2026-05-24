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
        // Split on @ first (digest takes priority)
        if let Some((name, digest)) = raw.split_once('@') {
            crate::validate::validate_image_digest(digest)
                .map_err(|e| ImageRefError::Invalid(e.to_string()))?;
            let (registry, repository) = split_name(name)?;
            return Ok(Self {
                registry,
                repository,
                tag: None,
                digest: digest.to_string(),
            });
        }

        // Split on : for tag -- find the last : after the first /
        let (name, tag) = if let Some(slash_pos) = raw.find('/') {
            if let Some(colon_pos) = raw[slash_pos..].rfind(':') {
                let abs_pos = slash_pos + colon_pos;
                (&raw[..abs_pos], Some(raw[abs_pos + 1..].to_string()))
            } else {
                (raw, None)
            }
        } else if let Some((name, tag)) = raw.split_once(':') {
            (name, Some(tag.to_string()))
        } else {
            (raw, None)
        };

        let (registry, repository) = split_name(name)?;
        Ok(Self {
            registry,
            repository,
            tag,
            digest: String::new(),
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
