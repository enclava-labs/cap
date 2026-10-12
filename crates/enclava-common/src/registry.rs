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
    let header = header.trim();
    let (scheme, params) = header.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for pair in split_auth_params(params) {
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
}
