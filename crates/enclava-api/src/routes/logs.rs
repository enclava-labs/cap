use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

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
    let _query = validate_query(raw_query)?;
    if !matches!(auth.role, Role::Owner | Role::Admin) {
        return Err(json_error(StatusCode::FORBIDDEN, "scope_not_allowed"));
    }
    require_log_entitlement(&state, &auth).await?;
    let app_exists =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM apps WHERE org_id = $1 AND name = $2")
            .bind(auth.org_id)
            .bind(&app_name)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| db_error())?
            .is_some();
    if !app_exists {
        return Err(json_error(StatusCode::NOT_FOUND, "app_not_found"));
    }
    Ok(encrypted_logs_required_response())
}

async fn require_log_entitlement(state: &AppState, auth: &AuthContext) -> Result<(), RouteError> {
    let deploy_allowed = sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE((SELECT deploy_allowed FROM organization_entitlements WHERE org_id = $1), false)",
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
