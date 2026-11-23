//! Placeholder substitution on a decrypted request head.
//!
//! This is the security core of the vault. A placeholder is swapped for its
//! credential only when all of these hold:
//!
//! - the request is on a tunnel for the connection's exact origin, and its
//!   `Host`/`:authority` names that origin;
//! - the request path is safe and lies under the connection's path prefix;
//! - the placeholder sits in the position the connection declares.
//!
//! A known placeholder anywhere else in the request head makes the whole
//! request fail, so nothing is forwarded. Request bodies are not inspected:
//! a placeholder in a body is never swapped, and it is worthless upstream.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::header::{AUTHORIZATION, HOST, HeaderName, HeaderValue};
use http::request::Parts;
use http::uri::{PathAndQuery, Uri};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::connection::{Connection, Origin, Position, Snapshot, path_is_safe, path_within_prefix};

/// Everything except RFC 3986 unreserved characters is escaped when a
/// credential is written into a URL.
const URL_SECRET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Why a request was not forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `Host` or `:authority` does not name the tunnel's origin.
    HostMismatch,
    /// The placeholder belongs to a connection for another origin.
    WrongOrigin { connection: String },
    /// The path has dot segments, encoded slashes or backslashes.
    UnsafePath,
    /// The path is outside the connection's prefix.
    PathNotAllowed { connection: String },
    /// The placeholder is somewhere other than the declared position.
    Misplaced { connection: String },
    /// The request could not be rebuilt after substitution.
    Malformed,
}

impl Refusal {
    /// Stable machine-readable reason, safe to return to the workload.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::HostMismatch => "host_mismatch",
            Refusal::WrongOrigin { .. } => "placeholder_wrong_origin",
            Refusal::UnsafePath => "unsafe_path",
            Refusal::PathNotAllowed { .. } => "path_not_allowed",
            Refusal::Misplaced { .. } => "placeholder_misplaced",
            Refusal::Malformed => "malformed_request",
        }
    }

    pub fn connection(&self) -> Option<&str> {
        match self {
            Refusal::WrongOrigin { connection }
            | Refusal::PathNotAllowed { connection }
            | Refusal::Misplaced { connection } => Some(connection),
            Refusal::HostMismatch | Refusal::UnsafePath | Refusal::Malformed => None,
        }
    }
}

/// Names of the connections whose credential was written into the request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    pub substituted: Vec<String>,
}

/// Rewrites `parts` in place for a request on a tunnel to `origin`.
///
/// On `Err` the request must not be forwarded; `parts` may be partly
/// rewritten and must be dropped.
pub fn rewrite(
    parts: &mut Parts,
    origin: &Origin,
    snapshot: &Snapshot,
) -> Result<Outcome, Refusal> {
    check_authority(parts, origin)?;

    let basic = decoded_basic_credentials(parts);
    let present: Vec<&Connection> = snapshot
        .connections()
        .iter()
        .map(|c| c.as_ref())
        .filter(|c| {
            head_contains(parts, &c.placeholder)
                || (c.spec.position == Position::BasicAuth
                    && basic.as_deref().is_some_and(|b| b.contains(&c.placeholder)))
        })
        .collect();
    if present.is_empty() {
        return Ok(Outcome::default());
    }

    let path = parts.uri.path().to_owned();
    if !path_is_safe(&path) {
        return Err(Refusal::UnsafePath);
    }
    for connection in &present {
        let name = || connection.spec.name.clone();
        if &connection.spec.origin != origin {
            return Err(Refusal::WrongOrigin { connection: name() });
        }
        if !path_within_prefix(&path, &connection.spec.path_prefix) {
            return Err(Refusal::PathNotAllowed { connection: name() });
        }
    }

    let mut outcome = Outcome::default();
    for connection in &present {
        apply(parts, connection)?;
        outcome.substituted.push(connection.spec.name.clone());
    }
    // Whatever is left was outside the declared position.
    for connection in &present {
        if head_contains(parts, &connection.placeholder) {
            return Err(Refusal::Misplaced {
                connection: connection.spec.name.clone(),
            });
        }
    }
    Ok(outcome)
}

fn check_authority(parts: &Parts, origin: &Origin) -> Result<(), Refusal> {
    let mut hosts = parts.headers.get_all(HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(Refusal::HostMismatch);
    }
    if let Some(host) = host {
        let host = host.to_str().map_err(|_| Refusal::HostMismatch)?;
        if !origin.matches_authority(host) {
            return Err(Refusal::HostMismatch);
        }
    }
    let authority = parts.uri.authority();
    if let Some(authority) = authority
        && !origin.matches_authority(authority.as_str())
    {
        return Err(Refusal::HostMismatch);
    }
    if host.is_none() && authority.is_none() {
        return Err(Refusal::HostMismatch);
    }
    Ok(())
}

fn head_contains(parts: &Parts, placeholder: &str) -> bool {
    let needle = placeholder.as_bytes();
    let in_uri = parts
        .uri
        .path_and_query()
        .is_some_and(|pq| contains_bytes(pq.as_str().as_bytes(), needle));
    in_uri
        || parts
            .headers
            .values()
            .any(|value| contains_bytes(value.as_bytes(), needle))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len() + replacement.len());
    let mut rest = haystack;
    while let Some(at) = rest
        .windows(needle.len())
        .position(|window| window == needle)
    {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(replacement);
        rest = &rest[at + needle.len()..];
    }
    out.extend_from_slice(rest);
    out
}

fn basic_payload(value: &HeaderValue) -> Option<&[u8]> {
    let bytes = value.as_bytes();
    let scheme = bytes.get(..6)?;
    scheme
        .eq_ignore_ascii_case(b"basic ")
        .then(|| bytes[6..].trim_ascii())
}

fn decoded_basic_credentials(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get_all(AUTHORIZATION)
        .iter()
        .find_map(|value| {
            let decoded = BASE64.decode(basic_payload(value)?).ok()?;
            String::from_utf8(decoded).ok()
        })
}

fn sensitive(bytes: &[u8]) -> Result<HeaderValue, Refusal> {
    let mut value = HeaderValue::from_bytes(bytes).map_err(|_| Refusal::Malformed)?;
    value.set_sensitive(true);
    Ok(value)
}

fn apply(parts: &mut Parts, connection: &Connection) -> Result<(), Refusal> {
    let placeholder = connection.placeholder.as_str();
    let secret = connection.secret.as_str();
    match &connection.spec.position {
        Position::Header { name } => {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| Refusal::Malformed)?;
            rewrite_header(parts, &name, |value| {
                contains_bytes(value.as_bytes(), placeholder.as_bytes()).then(|| {
                    replace_bytes(value.as_bytes(), placeholder.as_bytes(), secret.as_bytes())
                })
            })
        }
        Position::BasicAuth => rewrite_header(parts, &AUTHORIZATION, |value| {
            let decoded = BASE64.decode(basic_payload(value)?).ok()?;
            let decoded = String::from_utf8(decoded).ok()?;
            decoded.contains(placeholder).then(|| {
                let credentials = decoded.replace(placeholder, secret);
                format!("Basic {}", BASE64.encode(credentials)).into_bytes()
            })
        }),
        Position::Query { name } => {
            let Some(query) = parts.uri.query() else {
                return Ok(());
            };
            let encoded = utf8_percent_encode(secret, URL_SECRET).to_string();
            let rewritten: Vec<String> = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((key, value))
                        if value == placeholder
                            && percent_decode_str(key).decode_utf8_lossy() == name.as_str() =>
                    {
                        format!("{key}={encoded}")
                    }
                    _ => pair.to_owned(),
                })
                .collect();
            let path_and_query = format!("{}?{}", parts.uri.path(), rewritten.join("&"));
            set_path_and_query(parts, &path_and_query)
        }
        Position::PathSegment => {
            let path = parts.uri.path();
            if !path.contains(placeholder) {
                return Ok(());
            }
            let encoded = utf8_percent_encode(secret, URL_SECRET).to_string();
            let mut path_and_query = path.replace(placeholder, &encoded);
            if let Some(query) = parts.uri.query() {
                path_and_query.push('?');
                path_and_query.push_str(query);
            }
            set_path_and_query(parts, &path_and_query)
        }
    }
}

/// Replaces each value of `name` for which `rewrite` returns new bytes,
/// keeping the other values and their order.
fn rewrite_header(
    parts: &mut Parts,
    name: &HeaderName,
    rewrite: impl Fn(&HeaderValue) -> Option<Vec<u8>>,
) -> Result<(), Refusal> {
    let values: Vec<HeaderValue> = parts.headers.get_all(name).iter().cloned().collect();
    if !values.iter().any(|value| rewrite(value).is_some()) {
        return Ok(());
    }
    parts.headers.remove(name);
    for value in values {
        let value = match rewrite(&value) {
            Some(bytes) => sensitive(&bytes)?,
            None => value,
        };
        parts.headers.append(name.clone(), value);
    }
    Ok(())
}

fn set_path_and_query(parts: &mut Parts, path_and_query: &str) -> Result<(), Refusal> {
    let path_and_query: PathAndQuery = path_and_query.parse().map_err(|_| Refusal::Malformed)?;
    let mut uri = std::mem::take(&mut parts.uri).into_parts();
    uri.path_and_query = Some(path_and_query);
    parts.uri = Uri::from_parts(uri).map_err(|_| Refusal::Malformed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::Request;
    use zeroize::Zeroizing;

    use super::*;
    use crate::connection::ConnectionSpec;

    const GITHUB: &str = "encv_github_00000000000000000000000000000001";
    const MAPS: &str = "encv_maps_00000000000000000000000000000002";
    const REGISTRY: &str = "encv_registry_00000000000000000000000000000003";
    const BOT: &str = "encv_bot_00000000000000000000000000000004";
    const OTHER: &str = "encv_other_00000000000000000000000000000005";

    fn connection(
        name: &str,
        origin: &str,
        prefix: &str,
        position: Position,
        placeholder: &str,
        secret: &str,
    ) -> Connection {
        Connection {
            spec: ConnectionSpec {
                name: name.into(),
                origin: Origin::parse(origin).unwrap(),
                path_prefix: prefix.into(),
                position,
                expose_as: None,
            },
            placeholder: placeholder.into(),
            secret: Zeroizing::new(secret.into()),
        }
    }

    fn snapshot() -> Snapshot {
        let api = "https://api.example.com";
        Snapshot::new(vec![
            connection(
                "github",
                api,
                "/repos",
                Position::Header {
                    name: "Authorization".into(),
                },
                GITHUB,
                "ghp_real",
            ),
            connection(
                "maps",
                api,
                "/",
                Position::Query { name: "key".into() },
                MAPS,
                "k/e y&1",
            ),
            connection(
                "registry",
                api,
                "/",
                Position::BasicAuth,
                REGISTRY,
                "p@ss:word",
            ),
            connection("bot", api, "/", Position::PathSegment, BOT, "123:AB/c"),
            connection(
                "other",
                "https://other.example.com",
                "/",
                Position::Header {
                    name: "x-api-key".into(),
                },
                OTHER,
                "other-real",
            ),
        ])
    }

    fn origin() -> Origin {
        Origin::parse("https://api.example.com").unwrap()
    }

    fn parts(uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder()
            .uri(uri)
            .header("host", "api.example.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn run(uri: &str, headers: &[(&str, &str)]) -> (Parts, Result<Outcome, Refusal>) {
        let mut parts = parts(uri, headers);
        let result = rewrite(&mut parts, &origin(), &snapshot());
        (parts, result)
    }

    #[test]
    fn request_without_a_placeholder_is_untouched() {
        let (parts, result) = run("/anything?x=1", &[("authorization", "Bearer own-token")]);
        assert_eq!(result.unwrap(), Outcome::default());
        assert_eq!(parts.headers["authorization"], "Bearer own-token");
        assert_eq!(parts.uri, "/anything?x=1");
    }

    #[test]
    fn header_placeholder_is_swapped_inside_the_value() {
        let bearer = format!("Bearer {GITHUB}");
        let (parts, result) = run("/repos/acme", &[("authorization", &bearer)]);
        assert_eq!(result.unwrap().substituted, ["github"]);
        let value = &parts.headers["authorization"];
        assert_eq!(value, "Bearer ghp_real");
        assert!(value.is_sensitive());
    }

    #[test]
    fn header_placeholder_outside_the_prefix_is_refused() {
        let bearer = format!("Bearer {GITHUB}");
        for path in ["/user", "/reposx", "/"] {
            let (_, result) = run(path, &[("authorization", &bearer)]);
            assert_eq!(
                result.unwrap_err(),
                Refusal::PathNotAllowed {
                    connection: "github".into()
                },
                "{path}"
            );
        }
    }

    #[test]
    fn traversal_out_of_the_prefix_is_refused() {
        let bearer = format!("Bearer {GITHUB}");
        for path in ["/repos/../user", "/repos/%2e%2e/user", "/repos%2f..%2fuser"] {
            let (_, result) = run(path, &[("authorization", &bearer)]);
            assert_eq!(result.unwrap_err(), Refusal::UnsafePath, "{path}");
        }
    }

    #[test]
    fn placeholder_in_another_header_is_refused() {
        let (_, result) = run("/repos/acme", &[("x-debug", GITHUB)]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::Misplaced {
                connection: "github".into()
            }
        );
    }

    #[test]
    fn placeholder_in_the_right_header_and_also_elsewhere_is_refused() {
        let bearer = format!("Bearer {GITHUB}");
        let uri = format!("/repos/acme?leak={GITHUB}");
        let (_, result) = run(&uri, &[("authorization", &bearer)]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::Misplaced {
                connection: "github".into()
            }
        );
    }

    #[test]
    fn placeholder_for_another_origin_is_refused() {
        let (_, result) = run("/", &[("x-api-key", OTHER)]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::WrongOrigin {
                connection: "other".into()
            }
        );
    }

    #[test]
    fn host_must_name_the_tunnel_origin() {
        let bearer = format!("Bearer {GITHUB}");
        let mut fronted = Request::builder()
            .uri("/repos/acme")
            .header("host", "evil.example.com")
            .header("authorization", &bearer)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(
            rewrite(&mut fronted, &origin(), &snapshot()).unwrap_err(),
            Refusal::HostMismatch
        );

        let mut two_hosts = parts("/repos/acme", &[("host", "evil.example.com")]);
        assert_eq!(
            rewrite(&mut two_hosts, &origin(), &snapshot()).unwrap_err(),
            Refusal::HostMismatch
        );

        let mut no_host = Request::builder()
            .uri("/repos/acme")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(
            rewrite(&mut no_host, &origin(), &snapshot()).unwrap_err(),
            Refusal::HostMismatch
        );
    }

    #[test]
    fn http2_authority_is_checked_and_accepted() {
        let bearer = format!("Bearer {GITHUB}");
        let request = |uri: &str| {
            Request::builder()
                .uri(uri)
                .header("authorization", &bearer)
                .body(())
                .unwrap()
                .into_parts()
                .0
        };
        let mut good = request("https://api.example.com/repos/acme");
        assert!(rewrite(&mut good, &origin(), &snapshot()).is_ok());
        assert_eq!(good.uri, "https://api.example.com/repos/acme");
        assert_eq!(good.headers["authorization"], "Bearer ghp_real");

        let mut bad = request("https://evil.example.com/repos/acme");
        assert_eq!(
            rewrite(&mut bad, &origin(), &snapshot()).unwrap_err(),
            Refusal::HostMismatch
        );
    }

    #[test]
    fn query_placeholder_is_swapped_and_escaped() {
        let uri = format!("/maps/geocode?address=x&key={MAPS}&z=1");
        let (parts, result) = run(&uri, &[]);
        assert_eq!(result.unwrap().substituted, ["maps"]);
        assert_eq!(parts.uri, "/maps/geocode?address=x&key=k%2Fe%20y%261&z=1");
    }

    #[test]
    fn query_placeholder_under_another_parameter_is_refused() {
        let uri = format!("/maps/geocode?token={MAPS}");
        let (_, result) = run(&uri, &[]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::Misplaced {
                connection: "maps".into()
            }
        );
        let uri = format!("/maps/geocode?key=prefix-{MAPS}");
        let (_, result) = run(&uri, &[]);
        assert!(matches!(result.unwrap_err(), Refusal::Misplaced { .. }));
    }

    #[test]
    fn basic_auth_placeholder_is_swapped_inside_the_credentials() {
        let value = format!("Basic {}", BASE64.encode(format!("ci-user:{REGISTRY}")));
        let (parts, result) = run("/v2/", &[("authorization", &value)]);
        assert_eq!(result.unwrap().substituted, ["registry"]);
        let sent = parts.headers["authorization"].to_str().unwrap();
        let decoded = BASE64.decode(sent.strip_prefix("Basic ").unwrap()).unwrap();
        assert_eq!(decoded, b"ci-user:p@ss:word");
    }

    #[test]
    fn basic_auth_placeholder_sent_as_a_bearer_token_is_refused() {
        let bearer = format!("Bearer {REGISTRY}");
        let (_, result) = run("/v2/", &[("authorization", &bearer)]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::Misplaced {
                connection: "registry".into()
            }
        );
    }

    #[test]
    fn path_placeholder_is_swapped_and_escaped() {
        let uri = format!("/bot{BOT}/sendMessage?chat=1");
        let (parts, result) = run(&uri, &[]);
        assert_eq!(result.unwrap().substituted, ["bot"]);
        assert_eq!(parts.uri, "/bot123%3AAB%2Fc/sendMessage?chat=1");
    }

    #[test]
    fn path_placeholder_in_the_query_is_refused() {
        let uri = format!("/send?token={BOT}");
        let (_, result) = run(&uri, &[]);
        assert_eq!(
            result.unwrap_err(),
            Refusal::Misplaced {
                connection: "bot".into()
            }
        );
    }

    #[test]
    fn two_connections_can_be_used_in_one_request() {
        let bearer = format!("Bearer {GITHUB}");
        let uri = format!("/repos/acme?key={MAPS}");
        let (parts, result) = run(&uri, &[("authorization", &bearer)]);
        let mut substituted = result.unwrap().substituted;
        substituted.sort();
        assert_eq!(substituted, ["github", "maps"]);
        assert_eq!(parts.headers["authorization"], "Bearer ghp_real");
        assert_eq!(parts.uri, "/repos/acme?key=k%2Fe%20y%261");
    }

    #[test]
    fn refusal_codes_never_carry_secrets_or_placeholders() {
        let (_, result) = run("/repos/acme", &[("x-debug", GITHUB)]);
        let refusal = result.unwrap_err();
        assert_eq!(refusal.code(), "placeholder_misplaced");
        assert_eq!(refusal.connection(), Some("github"));
        let debug = format!("{refusal:?}");
        assert!(!debug.contains(GITHUB) && !debug.contains("ghp_real"));
    }
}
