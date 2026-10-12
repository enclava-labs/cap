//! Shared OCI registry helpers (pure functions, no I/O).

/// Parsed `WWW-Authenticate: Bearer ...` challenge parameters from a
/// registry token flow (RFC 7235 Bearer scheme, Docker/OCI flavor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parse a `WWW-Authenticate` header value in the Bearer scheme, e.g.
/// `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/app:pull"`.
/// Returns `None` for other schemes or a challenge without a realm.
/// Quoted-string values may contain commas and backslash escapes (RFC 7235).
pub fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    select_bearer_challenge([header].into_iter())
}

/// Select the Bearer challenge from all `WWW-Authenticate` field values.
/// A response may advertise several challenges (e.g. `Basic` and `Bearer` as
/// separate field values, or joined in one value); only the Bearer one is
/// usable for the anonymous token flow.
pub fn select_bearer_challenge<'a, I: Iterator<Item = &'a str>>(
    values: I,
) -> Option<BearerChallenge> {
    for (scheme, params) in values.flat_map(|value| group_challenges(value.trim())) {
        if scheme.eq_ignore_ascii_case("bearer")
            && let Some(challenge) = challenge_from_params(&params)
        {
            return Some(challenge);
        }
    }
    None
}

/// Group auth parameters into challenges: a top-level segment whose first
/// token is a scheme (contains no '=') starts a new challenge, and following
/// key=value segments belong to it. Commas never split a challenge's own
/// parameters (they may hide inside quoted values), so joined challenges are
/// separated at scheme tokens only.
fn group_challenges(value: &str) -> Vec<(String, Vec<&str>)> {
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for part in split_auth_params(value) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once(char::is_whitespace) {
            // A new challenge starts with a scheme token followed by params;
            // a continuation param with bad whitespace around '=' (RFC 7235
            // allows `key = value`) has its rest starting with '='.
            Some((first, rest)) if !first.contains('=') && !rest.trim_start().starts_with('=') => {
                groups.push((first.to_string(), vec![rest]));
            }
            None if !part.contains('=') => {
                groups.push((part.to_string(), Vec::new()));
            }
            _ => {
                if let Some((_, params)) = groups.last_mut() {
                    params.push(part);
                }
            }
        }
    }
    groups
}

fn challenge_from_params(params: &[&str]) -> Option<BearerChallenge> {
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for pair in params {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = unquote_auth_param(value.trim());
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }

    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

/// Split auth parameters on commas outside quoted strings.
fn split_auth_params(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in params.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ',' && !in_quotes {
            parts.push(&params[start..i]);
            start = i + 1;
        }
    }
    parts.push(&params[start..]);
    parts
}

/// Unquote an auth parameter value, resolving backslash escapes inside a
/// quoted string. Unquoted values are returned as-is.
fn unquote_auth_param(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Cross-host auth services, keyed by the registry host they serve: a
/// challenge realm may live on the registry's own host or on that registry's
/// known auth service — never an unrelated host.
pub fn realm_host_allowed(registry_host: &str, realm_host: &str) -> bool {
    realm_host == registry_host
        || matches!(
            (registry_host, realm_host),
            ("registry-1.docker.io", "auth.docker.io") | ("registry.gitlab.com", "gitlab.com")
        )
}

/// Repository path to use in registry requests: Docker Hub serves
/// single-component official images under the `library/` namespace.
pub fn manifest_repository(registry: &str, repository: &str) -> String {
    if registry == "docker.io" && !repository.contains('/') {
        format!("library/{repository}")
    } else {
        repository.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ghcr_style_challenge() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:enclava-labs/enclava-canary:pull""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:enclava-labs/enclava-canary:pull")
        );
    }

    #[test]
    fn parses_docker_hub_style_challenge() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
    }

    #[test]
    fn tolerates_unquoted_params_and_unknown_keys() {
        let challenge = parse_bearer_challenge(
            "Bearer realm=https://reg.example/token,foo=bar,service=reg.example",
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://reg.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
        assert_eq!(challenge.scope, None);
    }

    #[test]
    fn rejects_non_bearer_scheme() {
        assert_eq!(parse_bearer_challenge(r#"Basic realm="reg""#), None);
    }

    #[test]
    fn rejects_challenge_without_realm() {
        assert_eq!(
            parse_bearer_challenge(r#"Bearer service="reg.example""#),
            None
        );
    }

    #[test]
    fn quoted_commas_survive() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://reg.example/token?aud=a,b",service="reg.example",scope="repository:org/app,extra:pull""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://reg.example/token?aud=a,b");
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:org/app,extra:pull")
        );
    }

    #[test]
    fn escaped_quotes_survive() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://reg.example/token?q=\"x,y\"",service="reg.example""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://reg.example/token?q=\"x,y\"");
    }

    #[test]
    fn joined_challenges_keep_their_own_parameters() {
        // Bearer after Basic, with Bearer's continuation params intact.
        let challenge = parse_bearer_challenge(
            r#"Basic realm="https://basic.example/auth", Bearer realm="https://reg.example/token",service="reg.example",scope="repository:org/app:pull""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://reg.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
        assert_eq!(challenge.scope.as_deref(), Some("repository:org/app:pull"));
    }

    #[test]
    fn spaced_auth_params_stay_in_their_challenge() {
        // RFC 7235 allows bad whitespace around '=' (BWS): `key = value`.
        let challenge = parse_bearer_challenge(
            r#"Bearer service = "reg.example", realm = "https://reg.example/token""#,
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://reg.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
    }

    #[test]
    fn selects_bearer_among_multiple_field_values() {
        assert_eq!(
            select_bearer_challenge(
                [
                    r#"Basic realm="reg""#,
                    r#"Bearer realm="https://reg.example/token",service="reg.example""#
                ]
                .into_iter()
            ),
            parse_bearer_challenge(
                r#"Bearer realm="https://reg.example/token",service="reg.example""#
            )
        );
        assert_eq!(
            select_bearer_challenge([r#"Basic realm="reg""#].into_iter()),
            None
        );
    }

    #[test]
    fn realm_binding_maps_only_known_auth_services() {
        assert!(realm_host_allowed("ghcr.io", "ghcr.io"));
        assert!(realm_host_allowed("registry-1.docker.io", "auth.docker.io"));
        assert!(realm_host_allowed("registry.gitlab.com", "gitlab.com"));
        assert!(!realm_host_allowed("ghcr.io", "auth.docker.io"));
        assert!(!realm_host_allowed("quay.io", "gitlab.com"));
    }

    #[test]
    fn docker_hub_official_images_normalize_to_library() {
        assert_eq!(manifest_repository("docker.io", "nginx"), "library/nginx");
        assert_eq!(
            manifest_repository("docker.io", "library/nginx"),
            "library/nginx"
        );
        assert_eq!(manifest_repository("docker.io", "enclava/x"), "enclava/x");
        assert_eq!(manifest_repository("ghcr.io", "org/app"), "org/app");
    }
}
