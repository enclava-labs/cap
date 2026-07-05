use std::convert::Infallible;

use axum::{
    Json,
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::DateTime;
use enclava_engine::apply::watch::pod_label_selector;
use futures::{AsyncBufReadExt, StreamExt, stream};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client, Config,
    api::{ListParams, LogParams},
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::middleware::AuthContext,
    models::{App, Role},
    state::AppState,
};

const MAX_LOG_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_LOG_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_LOG_TAIL_LINES: i64 = 1_000;
const DEFAULT_LOG_TAIL_LINES: i64 = 200;
const DEFAULT_FOLLOW_TAIL_LINES: i64 = 100;
const MAX_LOG_SINCE_SECONDS: i64 = 86_400;
const MAX_FOLLOW_SINCE_SECONDS: i64 = 3_600;
const CAP_LOG_READER_TOKEN_PATH_ENV: &str = "CAP_LOG_READER_TOKEN_PATH";

type RouteError = (StatusCode, Json<serde_json::Value>);

#[derive(Clone, Debug, Deserialize)]
pub struct RawLogQuery {
    pub follow: Option<String>,
    pub tail_lines: Option<String>,
    pub since_seconds: Option<String>,
    pub container: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLogQuery {
    pub follow: bool,
    pub tail_lines: i64,
    pub since_seconds: Option<i64>,
    pub container: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogLine {
    pub timestamp: String,
    pub container: String,
    pub message: String,
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

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "app_not_found"))?;
    let container = resolve_log_container(&state, &app, query.container.as_deref()).await?;
    let client = log_reader_client().await?;
    let pod_name = select_log_pod_name(&client, &app.namespace, &app.name).await?;

    let pods: Api<Pod> = Api::namespaced(client, &app.namespace);
    let params = LogParams {
        container: Some(container.clone()),
        follow: query.follow,
        limit_bytes: Some(MAX_LOG_RESPONSE_BYTES as i64),
        since_seconds: query.since_seconds,
        tail_lines: Some(query.tail_lines),
        timestamps: true,
        ..LogParams::default()
    };
    let reader = pods
        .log_stream(&pod_name, &params)
        .await
        .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_read_failed"))?;

    if query.follow {
        let lines = reader.lines();
        let container = container.clone();
        let stream = stream::unfold(lines, move |mut lines| {
            let container = container.clone();
            async move {
                match lines.next().await {
                    Some(Ok(raw)) => match parse_kube_log_line(&raw, &container) {
                        Ok(line) => Some((
                            Ok::<Bytes, Infallible>(Bytes::from(frame_line(&line))),
                            lines,
                        )),
                        Err(_) => None,
                    },
                    Some(Err(_)) | None => None,
                }
            }
        });
        let mut response = Response::new(Body::from_stream(stream));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        add_no_store_headers(response.headers_mut());
        return Ok(response);
    }

    let mut lines = reader.lines();
    let mut response_lines = Vec::new();
    let mut total_bytes = 0usize;
    while let Some(raw) = lines.next().await {
        let raw = raw.map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_read_failed"))?;
        total_bytes = total_bytes.saturating_add(raw.len());
        if total_bytes > MAX_LOG_RESPONSE_BYTES {
            return Err(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "log_response_too_large",
            ));
        }
        response_lines.push(parse_kube_log_line(&raw, &container)?);
    }
    let mut response = (StatusCode::OK, Json(response_lines)).into_response();
    add_no_store_headers(response.headers_mut());
    Ok(response)
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

async fn resolve_log_container(
    state: &AppState,
    app: &App,
    requested: Option<&str>,
) -> Result<String, RouteError> {
    let rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT name, is_primary FROM app_containers WHERE app_id = $1")
            .bind(app.id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| db_error())?;
    let primary = rows
        .iter()
        .filter(|(_, primary)| *primary)
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    let [primary] = primary.as_slice() else {
        return Err(json_error(StatusCode::CONFLICT, "logs_pod_not_ready"));
    };
    if let Some(requested) = requested
        && requested != *primary
    {
        return Err(json_error(StatusCode::NOT_FOUND, "container_not_available"));
    }
    Ok((*primary).to_string())
}

async fn log_reader_client() -> Result<Client, RouteError> {
    let mut config = Config::infer()
        .await
        .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_read_failed"))?;
    if let Ok(path) = std::env::var(CAP_LOG_READER_TOKEN_PATH_ENV) {
        apply_log_reader_token_path(&mut config, path.trim());
    }
    Client::try_from(config).map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_read_failed"))
}

fn apply_log_reader_token_path(config: &mut Config, path: &str) {
    if !path.is_empty() {
        config.auth_info.token = None;
        config.auth_info.token_file = Some(path.to_string());
    }
}

async fn select_log_pod_name(
    client: &Client,
    namespace: &str,
    app_name: &str,
) -> Result<String, RouteError> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pod_list = pods
        .list(&ListParams::default().labels(&pod_label_selector(app_name)))
        .await
        .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_read_failed"))?;
    select_log_pod(&pod_list.items)
        .and_then(|pod| pod.metadata.name.clone())
        .ok_or_else(|| json_error(StatusCode::CONFLICT, "logs_pod_not_ready"))
}

fn select_log_pod(pods: &[Pod]) -> Option<&Pod> {
    pods.iter()
        .filter(|pod| pod.metadata.deletion_timestamp.is_none())
        .find(|pod| {
            pod.status
                .as_ref()
                .and_then(|status| status.phase.as_deref())
                == Some("Running")
        })
        .or_else(|| {
            pods.iter()
                .find(|pod| pod.metadata.deletion_timestamp.is_none())
        })
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

fn parse_kube_log_line(raw: &str, container: &str) -> Result<LogLine, RouteError> {
    let (timestamp, message) = raw
        .split_once(' ')
        .ok_or_else(|| json_error(StatusCode::BAD_GATEWAY, "cap_log_decode_failed"))?;
    DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| json_error(StatusCode::BAD_GATEWAY, "cap_log_decode_failed"))?;
    if message.len() > MAX_LOG_MESSAGE_BYTES {
        return Err(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "log_response_too_large",
        ));
    }
    Ok(LogLine {
        timestamp: timestamp.to_string(),
        container: container.to_string(),
        message: message.to_string(),
    })
}

fn frame_line(line: &LogLine) -> String {
    format!("{} {} {}\n", line.timestamp, line.container, line.message)
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

fn json_error(status: StatusCode, error: impl Into<String>) -> RouteError {
    (status, Json(serde_json::json!({"error": error.into()})))
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
    use k8s_openapi::{
        api::core::v1::PodStatus,
        apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time},
        jiff::Timestamp,
    };

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
    fn app_logs_parses_kubernetes_timestamped_log_line() {
        let line = parse_kube_log_line("2026-07-05T00:00:00Z hello world", "app").unwrap();
        assert_eq!(line.container, "app");
        assert_eq!(line.message, "hello world");
        assert!(parse_kube_log_line("hello world", "app").is_err());
    }

    #[test]
    fn app_logs_running_pod_is_preferred_for_logs() {
        let terminating = pod("old", "Running", true);
        let pending = pod("new", "Pending", false);
        let running = pod("ready", "Running", false);
        let pods = [terminating, pending, running];
        let selected = select_log_pod(&pods).unwrap();
        assert_eq!(selected.metadata.name.as_deref(), Some("ready"));
    }

    #[test]
    fn app_logs_log_reader_token_path_overrides_default_auth() {
        let mut config = Config::new("https://127.0.0.1".parse().unwrap());
        config.auth_info.token_file = Some("/default/token".to_string());

        apply_log_reader_token_path(&mut config, "/var/run/secrets/cap-log-reader/token");

        assert_eq!(
            config.auth_info.token_file.as_deref(),
            Some("/var/run/secrets/cap-log-reader/token")
        );
        assert!(config.auth_info.token.is_none());
    }

    fn pod(name: &str, phase: &str, terminating: bool) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                deletion_timestamp: terminating.then(|| {
                    Time(
                        "2026-07-05T00:00:00Z"
                            .parse::<Timestamp>()
                            .expect("timestamp parses"),
                    )
                }),
                ..ObjectMeta::default()
            },
            status: Some(PodStatus {
                phase: Some(phase.to_string()),
                ..PodStatus::default()
            }),
            ..Pod::default()
        }
    }
}
