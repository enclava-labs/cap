use std::collections::BTreeMap;
use std::sync::LazyLock;

use reqwest::Url;
use serde::Deserialize;
use serde_json::value::RawValue;
use thiserror::Error;

pub const FIXTURE_ROOT: &str = "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd";
pub const BUNDLED_PROFILES: &str = include_str!("../platform-release-profiles.json");

#[derive(Debug, Error)]
#[error("platform release profile: {0}")]
pub struct ProfileError(pub String);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProfile {
    pub api_origins: Vec<String>,
    pub root_pubkey_hex: String,
    pub baseline: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProfiles {
    dev: ReleaseProfile,
    preprod: ReleaseProfile,
    production: ReleaseProfile,
}

#[derive(Deserialize)]
struct BaselineIdentity<'a> {
    #[serde(borrow)]
    payload: InstallationIdentity<'a>,
}

#[derive(Deserialize)]
struct InstallationIdentity<'a> {
    #[serde(borrow)]
    signing_service_pubkey_hex: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    trustee_kbs_ca_cert_pem: std::borrow::Cow<'a, str>,
}

fn identity(raw: &str) -> Result<InstallationIdentity<'_>, ProfileError> {
    serde_json::from_str::<BaselineIdentity<'_>>(raw)
        .map(|baseline| baseline.payload)
        .map_err(|error| ProfileError(format!("invalid installation identity: {error}")))
}

fn canonical_origin(value: &str) -> Result<String, ProfileError> {
    let url =
        Url::parse(value).map_err(|error| ProfileError(format!("invalid API URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProfileError(
            "API URL must be HTTP(S) without credentials, query or fragment".into(),
        ));
    }
    Ok(url.origin().ascii_serialization())
}

impl ReleaseProfiles {
    pub fn parse(raw: &str, strict: bool) -> Result<Self, ProfileError> {
        let profiles: Self = serde_json::from_str(raw)
            .map_err(|error| ProfileError(format!("invalid profile bundle: {error}")))?;
        let mut origins = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for (name, profile) in profiles.iter() {
            let mut root = [0u8; 32];
            hex::decode_to_slice(&profile.root_pubkey_hex, &mut root).map_err(|_| {
                ProfileError(format!("{name}: root must be a 32-byte hex public key"))
            })?;
            if strict && profile.root_pubkey_hex.eq_ignore_ascii_case(FIXTURE_ROOT) {
                return Err(ProfileError(format!(
                    "{name}: release builds must not trust the fixture root"
                )));
            }
            if profile.api_origins.is_empty() {
                return Err(ProfileError(format!("{name}: no API origins")));
            }
            for origin in &profile.api_origins {
                let normalized = canonical_origin(origin)?;
                if origin != &normalized {
                    return Err(ProfileError(format!(
                        "{name}: API origins must be canonical origins without a path"
                    )));
                }
                let url = Url::parse(origin).map_err(|error| ProfileError(error.to_string()))?;
                let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
                if url.scheme() != "https" && (strict || !local) {
                    return Err(ProfileError(format!(
                        "{name}: public API origins require HTTPS"
                    )));
                }
                if origins.insert(origin, name).is_some() {
                    return Err(ProfileError(format!(
                        "{name}: duplicate or ambiguous API origin"
                    )));
                }
            }
            let installation = identity(profile.baseline.get())?;
            let mut signing_key = [0u8; 32];
            hex::decode_to_slice(
                installation.signing_service_pubkey_hex.as_bytes(),
                &mut signing_key,
            )
            .map_err(|_| ProfileError(format!("{name}: invalid signing-service identity")))?;
            if installation.trustee_kbs_ca_cert_pem.trim().is_empty() {
                return Err(ProfileError(format!("{name}: missing Trustee CA identity")));
            }
            let binding = (
                root,
                signing_key,
                installation.trustee_kbs_ca_cert_pem.into_owned(),
            );
            if identities.insert(binding, name).is_some() {
                return Err(ProfileError(
                    "profiles sharing a root must have distinct installation identities".into(),
                ));
            }
        }
        Ok(profiles)
    }

    pub fn named(&self, name: &str) -> Result<&ReleaseProfile, ProfileError> {
        match name {
            "dev" => Ok(&self.dev),
            "preprod" => Ok(&self.preprod),
            "production" => Ok(&self.production),
            _ => Err(ProfileError(format!("unknown profile {name:?}"))),
        }
    }

    pub fn for_api(&self, api_url: &str) -> Result<&ReleaseProfile, ProfileError> {
        let origin = canonical_origin(api_url)?;
        self.iter()
            .map(|(_, profile)| profile)
            .find(|profile| profile.api_origins.contains(&origin))
            .ok_or_else(|| ProfileError(format!("no trusted profile for API origin {origin}")))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ReleaseProfile)> {
        [
            ("dev", &self.dev),
            ("preprod", &self.preprod),
            ("production", &self.production),
        ]
        .into_iter()
    }
}

impl ReleaseProfile {
    pub fn require_installation_identity(
        &self,
        signing_key: &str,
        trustee_ca: &str,
    ) -> Result<(), ProfileError> {
        let expected = identity(self.baseline.get())?;
        if !expected
            .signing_service_pubkey_hex
            .eq_ignore_ascii_case(signing_key)
            || expected.trustee_kbs_ca_cert_pem != trustee_ca
        {
            return Err(ProfileError("release belongs to a different installation; verify the target and its approved trust profile".into()));
        }
        Ok(())
    }
}

pub fn bundled() -> Result<&'static ReleaseProfiles, ProfileError> {
    static PROFILES: LazyLock<Result<ReleaseProfiles, ProfileError>> =
        LazyLock::new(|| ReleaseProfiles::parse(BUNDLED_PROFILES, cfg!(feature = "prod-strict")));
    PROFILES
        .as_ref()
        .map_err(|error| ProfileError(error.0.clone()))
}

pub fn server_profile(name: Option<&str>) -> Result<&'static ReleaseProfile, ProfileError> {
    let name = match name {
        Some(name) if !name.is_empty() => name,
        None if !cfg!(feature = "prod-strict") => "dev",
        _ => {
            return Err(ProfileError(
                "ENCLAVA_PLATFORM_RELEASE_PROFILE must select dev, preprod or production".into(),
            ));
        }
    };
    bundled()?.named(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_origin_is_canonicalized_without_accepting_foreign_authority() {
        let profiles = ReleaseProfiles::parse(BUNDLED_PROFILES, false).unwrap();
        assert!(std::ptr::eq(
            profiles
                .for_api("https://CAP.PREPROD.ENCLAVA.DEV:443/api/v1")
                .unwrap(),
            profiles.named("preprod").unwrap(),
        ));
        for target in [
            "https://cap.preprod.enclava.dev.attacker.test",
            "https://attacker@cap.preprod.enclava.dev",
            "https://cap.preprod.enclava.dev?profile=production",
            "http://cap.preprod.enclava.dev",
            "https://cap.preprod.enclava.dev:444",
        ] {
            assert!(profiles.for_api(target).is_err(), "{target}");
        }
        assert!(profiles.named("staging").is_err());
    }

    #[test]
    fn malformed_ambiguous_and_fixture_profiles_fail_closed() {
        let original: serde_json::Value = serde_json::from_str(BUNDLED_PROFILES).unwrap();
        for root in ["", "not-a-key", "5b94"] {
            let mut altered = original.clone();
            altered["dev"]["root_pubkey_hex"] = root.into();
            assert!(ReleaseProfiles::parse(&altered.to_string(), false).is_err());
        }
        for root in [FIXTURE_ROOT.to_string(), FIXTURE_ROOT.to_uppercase()] {
            let mut altered = original.clone();
            altered["dev"]["root_pubkey_hex"] = root.into();
            assert!(ReleaseProfiles::parse(&altered.to_string(), true).is_err());
        }
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("production");
        assert!(ReleaseProfiles::parse(&missing.to_string(), false).is_err());
        let mut ambiguous = original.clone();
        ambiguous["production"]["api_origins"] = original["preprod"]["api_origins"].clone();
        assert!(ReleaseProfiles::parse(&ambiguous.to_string(), false).is_err());
        ambiguous = original.clone();
        ambiguous["production"]["baseline"] = original["preprod"]["baseline"].clone();
        assert!(ReleaseProfiles::parse(&ambiguous.to_string(), false).is_err());
    }
}
