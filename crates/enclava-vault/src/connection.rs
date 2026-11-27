//! Connection model: which credential may be sent where, and in which
//! position of a request.

use std::fmt;
use std::sync::Arc;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Every placeholder starts with this, followed by `<connection>_<random>`.
pub const PLACEHOLDER_PREFIX: &str = "encv_";

/// Headers that describe one hop. The proxy never forwards them, so they
/// cannot carry a credential either.
pub const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

const MAX_NAME_LEN: usize = 32;
const MAX_EXPOSE_AS_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    #[error("invalid connection name: {0}")]
    Name(&'static str),
    #[error("invalid origin: {0}")]
    Origin(&'static str),
    #[error("invalid path prefix: {0}")]
    PathPrefix(&'static str),
    #[error("invalid position: {0}")]
    Position(&'static str),
    #[error("invalid expose_as: {0}")]
    ExposeAs(&'static str),
    #[error("invalid secret: {0}")]
    Secret(&'static str),
    #[error("invalid placeholder")]
    Placeholder,
}

/// An HTTPS origin: a DNS host name and a port. IP literals are rejected so
/// that every destination goes through name resolution and the post-DNS
/// network check in the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    /// Parses `https://host[:port]`. A single trailing `/` is accepted.
    pub fn parse(value: &str) -> Result<Self, ConnectionError> {
        let rest = value
            .get(..8)
            .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
            .map(|_| &value[8..])
            .ok_or(ConnectionError::Origin("must start with https://"))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) {
            return Err(ConnectionError::Origin(
                "must not carry a path, query, fragment or userinfo",
            ));
        }
        let (host, port) = split_host_port(rest).ok_or(ConnectionError::Origin("bad port"))?;
        Self::from_host_port(host, port.unwrap_or(443))
    }

    pub fn from_host_port(host: &str, port: u16) -> Result<Self, ConnectionError> {
        let host = host.to_ascii_lowercase();
        validate_dns_name(&host)?;
        if port == 0 {
            return Err(ConnectionError::Origin("port must not be 0"));
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// `host` for the default port, `host:port` otherwise.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// True when a `Host` header or `:authority` value names this origin.
    pub fn matches_authority(&self, authority: &str) -> bool {
        if authority.contains('@') {
            return false;
        }
        match split_host_port(authority) {
            Some((host, port)) => {
                host.eq_ignore_ascii_case(&self.host) && port.unwrap_or(443) == self.port
            }
            None => false,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.authority())
    }
}

impl Serialize for Origin {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Origin::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Splits `host[:port]`. Returns `None` for a malformed port or an IPv6
/// literal.
fn split_host_port(value: &str) -> Option<(&str, Option<u16>)> {
    if value.starts_with('[') {
        return None;
    }
    match value.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((host, Some(port.parse().ok()?)))
        }
        None => Some((value, None)),
    }
}

fn validate_dns_name(host: &str) -> Result<(), ConnectionError> {
    if host.is_empty() || host.len() > 253 {
        return Err(ConnectionError::Origin("host must be 1 to 253 characters"));
    }
    let mut last = "";
    for label in host.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(ConnectionError::Origin("host is not a DNS name"));
        }
        last = label;
    }
    // A numeric final label is how an IPv4 literal looks.
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConnectionError::Origin("host must not be an IP address"));
    }
    Ok(())
}

/// The one place in a request where a placeholder is swapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Position {
    /// Inside the value of the named header, e.g. `Authorization: Bearer <p>`.
    Header { name: String },
    /// As the whole value of the named query parameter.
    Query { name: String },
    /// Inside the decoded `Authorization: Basic` credentials.
    BasicAuth,
    /// Inside the request path.
    PathSegment,
}

impl Position {
    fn validate(&self) -> Result<(), ConnectionError> {
        match self {
            Position::Header { name } => {
                let parsed = http::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ConnectionError::Position("not a header name"))?;
                if parsed == http::header::HOST {
                    return Err(ConnectionError::Position("Host cannot carry a credential"));
                }
                if parsed == http::header::TE || HOP_BY_HOP.contains(&parsed.as_str()) {
                    return Err(ConnectionError::Position(
                        "hop-by-hop headers are not forwarded",
                    ));
                }
                Ok(())
            }
            Position::Query { name } => {
                let valid = !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
                if valid {
                    Ok(())
                } else {
                    Err(ConnectionError::Position(
                        "query parameter name must be [A-Za-z0-9._-]+",
                    ))
                }
            }
            Position::BasicAuth | Position::PathSegment => Ok(()),
        }
    }
}

/// What the owner declares for one credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSpec {
    pub name: String,
    pub origin: Origin,
    pub path_prefix: String,
    pub position: Position,
    /// Config key under which the workload is handed the placeholder.
    pub expose_as: Option<String>,
}

impl ConnectionSpec {
    pub fn validate(&self) -> Result<(), ConnectionError> {
        validate_name(&self.name)?;
        validate_path_prefix(&self.path_prefix)?;
        self.position.validate()?;
        if let Some(key) = &self.expose_as {
            let mut bytes = key.bytes();
            let first_ok = bytes
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
            if !first_ok
                || key.len() > MAX_EXPOSE_AS_LEN
                || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(ConnectionError::ExposeAs(
                    "must match [A-Za-z_][A-Za-z0-9_]*",
                ));
            }
        }
        Ok(())
    }
}

pub fn validate_name(name: &str) -> Result<(), ConnectionError> {
    let mut bytes = name.bytes();
    if !bytes.next().is_some_and(|b| b.is_ascii_lowercase()) {
        return Err(ConnectionError::Name("must start with a lowercase letter"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ConnectionError::Name("must be at most 32 characters"));
    }
    if !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(ConnectionError::Name("must match [a-z][a-z0-9_]*"));
    }
    Ok(())
}

fn validate_path_prefix(prefix: &str) -> Result<(), ConnectionError> {
    if !prefix.starts_with('/') {
        return Err(ConnectionError::PathPrefix("must start with /"));
    }
    if prefix != "/" && prefix.ends_with('/') {
        return Err(ConnectionError::PathPrefix("must not end with /"));
    }
    if prefix.contains("//") {
        return Err(ConnectionError::PathPrefix("must not contain //"));
    }
    let chars_ok = prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~'));
    if !chars_ok {
        return Err(ConnectionError::PathPrefix(
            "may only contain [A-Za-z0-9._~-] and /",
        ));
    }
    if prefix
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(ConnectionError::PathPrefix("must not contain dot segments"));
    }
    Ok(())
}

/// Checks that `secret` can be written into `position` without changing the
/// shape of the request.
pub fn validate_secret(position: &Position, secret: &str) -> Result<(), ConnectionError> {
    if secret.is_empty() {
        return Err(ConnectionError::Secret("must not be empty"));
    }
    if secret.contains(PLACEHOLDER_PREFIX) {
        return Err(ConnectionError::Secret("looks like a placeholder"));
    }
    match position {
        Position::Header { .. } => {
            let visible = secret.bytes().all(|b| (0x20..0x7f).contains(&b));
            if !visible {
                return Err(ConnectionError::Secret(
                    "a header credential must be printable ASCII",
                ));
            }
        }
        Position::Query { .. } | Position::BasicAuth | Position::PathSegment => {
            if secret.chars().any(char::is_control) {
                return Err(ConnectionError::Secret(
                    "must not contain control characters",
                ));
            }
        }
    }
    // A path credential must stay inside one segment, or writing it into
    // the path could point the request at a different resource.
    if *position == Position::PathSegment
        && (secret.contains(['/', '\\']) || secret == "." || secret == "..")
    {
        return Err(ConnectionError::Secret(
            "a path credential must not contain / or \\, or be a dot segment",
        ));
    }
    Ok(())
}

/// A fresh placeholder for `name`. 128 random bits, and only `[a-z0-9_]`, so
/// it survives headers, URLs and shells unchanged.
pub fn new_placeholder(name: &str) -> String {
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    format!("{PLACEHOLDER_PREFIX}{name}_{}", hex::encode(random))
}

pub fn validate_placeholder(name: &str, placeholder: &str) -> Result<(), ConnectionError> {
    let random = placeholder
        .strip_prefix(PLACEHOLDER_PREFIX)
        .and_then(|rest| rest.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix('_'))
        .ok_or(ConnectionError::Placeholder)?;
    let valid = random.len() == 32
        && random
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if valid {
        Ok(())
    } else {
        Err(ConnectionError::Placeholder)
    }
}

/// A stored connection: the declaration, the placeholder the workload holds
/// and the real credential.
#[derive(Clone)]
pub struct Connection {
    pub spec: ConnectionSpec,
    pub placeholder: String,
    pub secret: Zeroizing<String>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("spec", &self.spec)
            .field("placeholder", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// An immutable view of every stored connection.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    connections: Vec<Arc<Connection>>,
}

impl Snapshot {
    pub fn new(connections: Vec<Connection>) -> Self {
        Self {
            connections: connections.into_iter().map(Arc::new).collect(),
        }
    }

    pub fn connections(&self) -> &[Arc<Connection>] {
        &self.connections
    }

    pub fn has_origin(&self, origin: &Origin) -> bool {
        self.connections.iter().any(|c| &c.spec.origin == origin)
    }
}

/// True when `path` is `prefix` or lies below it, compared by whole segments.
pub fn path_within_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// False for a path an upstream might resolve to a different resource than
/// the one a prefix check sees: dot segments (plain or percent-encoded),
/// encoded slashes and backslashes.
pub fn path_is_safe(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\\') {
        return false;
    }
    let lowered = path.to_ascii_lowercase();
    if lowered.contains("%2f") || lowered.contains("%5c") {
        return false;
    }
    path.split('/').all(|segment| {
        let decoded = percent_encoding::percent_decode_str(segment).decode_utf8_lossy();
        decoded != "." && decoded != ".."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_parses_and_normalizes() {
        let origin = Origin::parse("HTTPS://API.GitHub.com/").unwrap();
        assert_eq!(origin.host(), "api.github.com");
        assert_eq!(origin.port(), 443);
        assert_eq!(origin.to_string(), "https://api.github.com");
        assert_eq!(
            Origin::parse("https://example.com:8443")
                .unwrap()
                .authority(),
            "example.com:8443"
        );
    }

    #[test]
    fn origin_rejects_everything_but_a_plain_https_dns_origin() {
        for bad in [
            "http://example.com",
            "example.com",
            "https://",
            "https://example.com/path",
            "https://example.com?x=1",
            "https://user@example.com",
            "https://127.0.0.1",
            "https://10.0.0.1:8443",
            "https://[::1]",
            "https://example.com:0",
            "https://example.com:notaport",
            "https://exa mple.com",
            "https://-bad.example.com",
            "https://example.com.",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn authority_matching_is_exact_on_host_and_port() {
        let origin = Origin::parse("https://api.example.com").unwrap();
        assert!(origin.matches_authority("api.example.com"));
        assert!(origin.matches_authority("API.example.com:443"));
        assert!(!origin.matches_authority("api.example.com:8443"));
        assert!(!origin.matches_authority("evil.example.com"));
        assert!(!origin.matches_authority("api.example.com@evil.example.com"));
        assert!(!origin.matches_authority("api.example.com:"));
    }

    #[test]
    fn spec_validation_covers_each_field() {
        let spec = |name: &str, prefix: &str, position: Position, expose: Option<&str>| {
            ConnectionSpec {
                name: name.into(),
                origin: Origin::parse("https://api.example.com").unwrap(),
                path_prefix: prefix.into(),
                position,
                expose_as: expose.map(Into::into),
            }
            .validate()
        };
        let header = || Position::Header {
            name: "Authorization".into(),
        };
        assert!(spec("github", "/", header(), Some("GITHUB_TOKEN")).is_ok());
        assert!(spec("github", "/repos/acme", header(), None).is_ok());
        assert!(spec("GitHub", "/", header(), None).is_err());
        assert!(spec("../x", "/", header(), None).is_err());
        assert!(spec("github", "repos", header(), None).is_err());
        assert!(spec("github", "/repos/", header(), None).is_err());
        assert!(spec("github", "/a/../b", header(), None).is_err());
        assert!(spec("github", "/a%2fb", header(), None).is_err());
        assert!(spec("github", "/", header(), Some("1BAD")).is_err());
        let host = Position::Header {
            name: "Host".into(),
        };
        assert!(spec("github", "/", host, None).is_err());
        for stripped in ["Proxy-Authorization", "connection", "TE", "Upgrade"] {
            let position = Position::Header {
                name: stripped.into(),
            };
            assert!(spec("github", "/", position, None).is_err(), "{stripped}");
        }
        let query = Position::Query { name: "a&b".into() };
        assert!(spec("github", "/", query, None).is_err());
    }

    #[test]
    fn secret_validation_depends_on_position() {
        let header = Position::Header {
            name: "authorization".into(),
        };
        assert!(validate_secret(&header, "ghp_abc123").is_ok());
        assert!(validate_secret(&header, "").is_err());
        assert!(validate_secret(&header, "line\r\nbreak").is_err());
        assert!(validate_secret(&header, "snowman-☃").is_err());
        assert!(validate_secret(&Position::BasicAuth, "pässword").is_ok());
        assert!(validate_secret(&Position::PathSegment, "a\nb").is_err());
        assert!(validate_secret(&Position::PathSegment, "123:AB c").is_ok());
        for moving in ["a/b", "a\\b", ".", ".."] {
            assert!(
                validate_secret(&Position::PathSegment, moving).is_err(),
                "{moving}"
            );
            assert!(
                validate_secret(&Position::BasicAuth, moving).is_ok(),
                "{moving}"
            );
        }
        assert!(validate_secret(&Position::BasicAuth, "encv_other_00").is_err());
    }

    #[test]
    fn placeholders_are_unique_and_well_formed() {
        let a = new_placeholder("github");
        let b = new_placeholder("github");
        assert_ne!(a, b);
        assert!(validate_placeholder("github", &a).is_ok());
        assert!(validate_placeholder("gitlab", &a).is_err());
        assert!(validate_placeholder("github", "encv_github_short").is_err());
    }

    #[test]
    fn prefix_match_is_by_whole_segment() {
        assert!(path_within_prefix("/anything", "/"));
        assert!(path_within_prefix("/repos", "/repos"));
        assert!(path_within_prefix("/repos/acme", "/repos"));
        assert!(!path_within_prefix("/reposx", "/repos"));
        assert!(!path_within_prefix("/other", "/repos"));
    }

    #[test]
    fn unsafe_paths_are_detected() {
        assert!(path_is_safe("/repos/acme/issues"));
        assert!(path_is_safe("/v1/file.name.json"));
        assert!(!path_is_safe("/repos/../admin"));
        assert!(!path_is_safe("/repos/%2e%2e/admin"));
        assert!(!path_is_safe("/repos/%2E./admin"));
        assert!(!path_is_safe("/repos/./x"));
        assert!(!path_is_safe("/repos%2Fadmin"));
        assert!(!path_is_safe("/repos\\admin"));
        assert!(!path_is_safe("/repos%5cadmin"));
        assert!(!path_is_safe("relative"));
    }
}
