use axum::{
    Json,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::Row;

use crate::{auth::middleware::AuthContext, models::Role, state::AppState};

const MAX_LOG_TAIL_LINES: i64 = 1_000;
const DEFAULT_LOG_TAIL_LINES: i64 = 200;
const DEFAULT_FOLLOW_TAIL_LINES: i64 = 100;
const MAX_LOG_SINCE_SECONDS: i64 = 86_400;
const MAX_FOLLOW_SINCE_SECONDS: i64 = 3_600;

type RouteError = (StatusCode, Json<serde_json::Value>);

#[derive(Clone, Debug, Deserialize)]
pub struct RawLogQuery {
    pub follow: Option<String>,
    pub tail_lines: Option<String>,
    pub since_seconds: Option<String>,
    pub container: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedLogQuery {
    follow: bool,
    tail_lines: i64,
    since_seconds: Option<i64>,
    container: Option<String>,
}

pub async fn paas_app_logs(
    auth: AuthContext,
    state: AppState,
    app_name: String,
    raw_query: RawLogQuery,
) -> Result<Response, RouteError> {
    let query = validate_query(raw_query)?;
    if !matches!(auth.role, Role::Owner | Role::Admin) {
        return Err(json_error(StatusCode::FORBIDDEN, "scope_not_allowed"));
    }
    require_log_entitlement(&state, &auth).await?;
    let app = sqlx::query(
        "SELECT id::text AS id, name, domain, tee_domain FROM apps WHERE org_id = $1 AND name = $2",
    )
    .bind(auth.org_id)
    .bind(&app_name)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let Some(app) = app else {
        return Err(json_error(StatusCode::NOT_FOUND, "app_not_found"));
    };
    let app_id: String = app.try_get("id").map_err(|_| db_error())?;
    let app_name: String = app.try_get("name").map_err(|_| db_error())?;
    let domain: String = app.try_get("domain").map_err(|_| db_error())?;
    let tee_domain: Option<String> = app.try_get("tee_domain").map_err(|_| db_error())?;
    let encrypted_logs_configured = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT COALESCE((
            SELECT spec_snapshot ? 'log_encryption'
               AND spec_snapshot->'log_encryption' <> 'null'::jsonb
              FROM deployments
             WHERE app_id = $1::uuid
             ORDER BY created_at DESC
             LIMIT 1
        ), false)
        "#,
    )
    .bind(&app_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;
    if !encrypted_logs_configured {
        return Ok(encrypted_logs_required_response());
    }
    proxy_encrypted_logs_from_tee(&state, &app_name, &domain, tee_domain.as_deref(), &query).await
}

async fn require_log_entitlement(state: &AppState, auth: &AuthContext) -> Result<(), RouteError> {
    let deploy_allowed = sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE((
             SELECT deploy_allowed
               FROM organization_entitlements
              WHERE org_id = $1
              ORDER BY version DESC
              LIMIT 1
         ), false)",
    )
    .bind(auth.org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;
    if deploy_allowed {
        Ok(())
    } else {
        Err(json_error(StatusCode::FORBIDDEN, "scope_not_allowed"))
    }
}

fn validate_query(raw: RawLogQuery) -> Result<ValidatedLogQuery, RouteError> {
    let follow = match raw.follow.as_deref().map(str::trim) {
        None | Some("") | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(json_error(StatusCode::BAD_REQUEST, "invalid_log_query")),
    };
    let tail_lines = raw
        .tail_lines
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<i64>())
        .transpose()
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid_log_query"))?
        .unwrap_or(if follow {
            DEFAULT_FOLLOW_TAIL_LINES
        } else {
            DEFAULT_LOG_TAIL_LINES
        });
    if !(1..=MAX_LOG_TAIL_LINES).contains(&tail_lines) {
        return Err(json_error(StatusCode::BAD_REQUEST, "invalid_log_query"));
    }
    let since_seconds = raw
        .since_seconds
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<i64>())
        .transpose()
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid_log_query"))?;
    if let Some(since_seconds) = since_seconds {
        let max = if follow {
            MAX_FOLLOW_SINCE_SECONDS
        } else {
            MAX_LOG_SINCE_SECONDS
        };
        if !(1..=max).contains(&since_seconds) {
            return Err(json_error(StatusCode::BAD_REQUEST, "invalid_log_query"));
        }
    }
    let container = raw
        .container
        .map(|container| container.trim().to_string())
        .filter(|container| !container.is_empty())
        .map(validate_container_name)
        .transpose()?;
    Ok(ValidatedLogQuery {
        follow,
        tail_lines,
        since_seconds,
        container,
    })
}

fn validate_container_name(value: String) -> Result<String, RouteError> {
    if value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(json_error(StatusCode::BAD_REQUEST, "invalid_log_query"));
    }
    Ok(value)
}

impl ValidatedLogQuery {
    fn tee_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("follow", self.follow.to_string()),
            ("tail_lines", self.tail_lines.to_string()),
        ];
        if let Some(since_seconds) = self.since_seconds {
            pairs.push(("since_seconds", since_seconds.to_string()));
        }
        if let Some(container) = &self.container {
            pairs.push(("container", container.clone()));
        }
        pairs
    }
}

fn encrypted_logs_required_response() -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "code": "encrypted_logs_required",
            "error": "encrypted_logs_required",
            "message": "Hosted workload logs require tenant-controlled encrypted log streaming before plaintext can leave the confidential workload boundary"
        })),
    )
        .into_response();
    add_no_store_headers(response.headers_mut());
    response
}

async fn proxy_encrypted_logs_from_tee(
    state: &AppState,
    app_name: &str,
    domain: &str,
    tee_domain: Option<&str>,
    query: &ValidatedLogQuery,
) -> Result<Response, RouteError> {
    let confidential_domain = tee_domain.unwrap_or(domain);
    let url = format!("https://{confidential_domain}/.well-known/confidential/logs");
    let upstream = state
        .tee_http_client
        .get(url)
        .query(&query.tee_query_pairs())
        .send()
        .await
        .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "encrypted_log_stream_unavailable"))?;
    if !upstream.status().is_success() {
        return Err(match upstream.status() {
            reqwest::StatusCode::NOT_FOUND => {
                json_error(StatusCode::NOT_FOUND, "container_not_available")
            }
            reqwest::StatusCode::CONFLICT => json_error(StatusCode::CONFLICT, "logs_not_ready"),
            _ => json_error(StatusCode::BAD_GATEWAY, "encrypted_log_stream_unavailable"),
        });
    }
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(upstream.bytes_stream()))
        .map_err(|_| db_error())?;
    add_no_store_headers(response.headers_mut());
    response.headers_mut().insert(
        "x-enclava-log-format",
        HeaderValue::from_static("encrypted-jsonl; version=enclava-log-frame-v1"),
    );
    response.headers_mut().insert(
        "x-enclava-log-source",
        HeaderValue::from_str(app_name).unwrap_or_else(|_| HeaderValue::from_static("app")),
    );
    Ok(response)
}

fn json_error(status: StatusCode, error: impl Into<String>) -> RouteError {
    let error = error.into();
    (
        status,
        Json(serde_json::json!({
            "code": error,
            "error": error
        })),
    )
}

fn db_error() -> RouteError {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn add_no_store_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_logs_validates_log_query_defaults_and_bounds() {
        let query = validate_query(RawLogQuery {
            follow: None,
            tail_lines: None,
            since_seconds: None,
            container: None,
        })
        .unwrap();
        assert_eq!(query.tail_lines, DEFAULT_LOG_TAIL_LINES);
        assert!(!query.follow);

        assert!(
            validate_query(RawLogQuery {
                follow: Some("sometimes".to_string()),
                tail_lines: None,
                since_seconds: None,
                container: None,
            })
            .is_err()
        );
    }

    #[test]
    fn app_logs_validates_optional_container_name_without_reading_kubernetes() {
        let query = validate_query(RawLogQuery {
            follow: Some("true".to_string()),
            tail_lines: Some("10".to_string()),
            since_seconds: Some("30".to_string()),
            container: Some("app".to_string()),
        })
        .unwrap();

        assert!(query.follow);
        assert_eq!(query.tail_lines, 10);
        assert_eq!(query.since_seconds, Some(30));
        assert_eq!(query.container.as_deref(), Some("app"));
        assert!(
            validate_query(RawLogQuery {
                follow: None,
                tail_lines: None,
                since_seconds: None,
                container: Some("../sidecar".to_string()),
            })
            .is_err()
        );
    }
}
