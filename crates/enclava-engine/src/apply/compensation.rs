//! Durable identity of an object whose post-create compensating DELETE did
//! not resolve (cap#254).
//!
//! The apply path observes the exact UID on the create POST response. If the
//! UID-pinned DELETE times out, conflicts, or cannot be confirmed, that UID
//! must be durable before the apply path returns — a log line does not
//! survive a crash, and failed-apply cleanup correctly refuses to delete an
//! unmarked object by name. The control plane installs a
//! [`UnresolvedCompensationSink`] that writes the row before the compensating
//! DELETE is issued, so a crash during the delete is recoverable. A sink
//! write that fails is not treated as recorded.

use std::future::Future;
use std::pin::Pin;

/// One server-observed create whose compensating delete has not been
/// confirmed. The UID is the POST response UID, never a name lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedCompensationRecord {
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
    pub mutation_generation: i64,
}

/// Control-plane hook that makes an unresolved compensation durable.
///
/// Implemented in the API crate against Postgres. The engine has no database.
/// Both methods must be idempotent: a retried apply re-observes the same UID,
/// and a confirmed absence clears the row the reconciler would otherwise retry.
pub trait UnresolvedCompensationSink: Send + Sync {
    fn persist<'a>(
        &'a self,
        record: &'a UnresolvedCompensationRecord,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    fn clear_resolved<'a>(
        &'a self,
        uid: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::engine::ApplyEngine;
    use crate::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION,
    };
    use crate::apply::namespace::apply_namespace;
    use axum::http::{Method, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
    use kube::Client;
    use kube::api::Api;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tower::service_fn;

    struct MemorySink {
        records: Mutex<Vec<UnresolvedCompensationRecord>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl UnresolvedCompensationSink for MemorySink {
        fn persist<'a>(
            &'a self,
            record: &'a UnresolvedCompensationRecord,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().expect("events").push("persist");
                if self.fail {
                    return Err("db down".to_string());
                }
                self.records.lock().expect("records").push(record.clone());
                Ok(())
            })
        }

        fn clear_resolved<'a>(
            &'a self,
            _uid: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().expect("events").push("clear");
                Ok(())
            })
        }
    }

    fn stripped_create_response(mut body: Value, uid: &str) -> Value {
        body["metadata"]["uid"] = json!(uid);
        body["metadata"]["resourceVersion"] = json!("1");
        if let Some(annotations) = body
            .pointer_mut("/metadata/annotations")
            .and_then(Value::as_object_mut)
        {
            annotations.remove(RESOURCE_CREATED_BY_ANNOTATION);
            annotations.remove(crate::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION);
        }
        body
    }

    fn client(
        events: Arc<Mutex<Vec<&'static str>>>,
        uid: &'static str,
        hang_delete: bool,
    ) -> Client {
        Client::new(
            service_fn(move |request: Request<kube::client::Body>| {
                let events = Arc::clone(&events);
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    if method == Method::GET {
                        return Ok::<_, std::io::Error>(status(StatusCode::NOT_FOUND));
                    }
                    if method == Method::POST {
                        let payload: Value = serde_json::from_slice(&body).unwrap();
                        let response = stripped_create_response(payload, uid);
                        return Ok(json_response(StatusCode::CREATED, &response));
                    }
                    if method == Method::DELETE {
                        events.lock().expect("events").push("delete");
                        let payload = String::from_utf8_lossy(&body);
                        assert!(
                            payload.contains(uid) && payload.contains("preconditions"),
                            "delete was not UID-preconditioned: {payload}"
                        );
                        if hang_delete {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                        return Ok(status(StatusCode::NOT_FOUND));
                    }
                    Err(std::io::Error::other(format!("unexpected {method} {path}")))
                }
            }),
            "default",
        )
    }

    fn status(code: StatusCode) -> Response<kube::client::Body> {
        let reason = if code == StatusCode::NOT_FOUND {
            "NotFound"
        } else {
            "Failure"
        };
        json_response(
            code,
            &json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": reason,
                "message": reason,
                "code": code.as_u16()
            }),
        )
    }

    fn json_response(code: StatusCode, value: &Value) -> Response<kube::client::Body> {
        Response::builder()
            .status(code)
            .body(kube::client::Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    }

    fn engine(
        events: Arc<Mutex<Vec<&'static str>>>,
        sink: Arc<MemorySink>,
        hang_delete: bool,
    ) -> ApplyEngine {
        ApplyEngine::new(
            client(events, "post-uid-254", hang_delete),
            Default::default(),
        )
        .with_compensation_sink(sink)
        .with_compensation_budget(Duration::from_millis(250))
    }

    #[tokio::test]
    async fn timed_out_delete_persists_post_uid_before_returning() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink {
            records: Mutex::new(Vec::new()),
            events: Arc::clone(&events),
            fail: false,
        });
        let engine = engine(Arc::clone(&events), Arc::clone(&sink), true);
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "tenant-ns");
        let desired: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "pull-secret", "namespace": "tenant-ns"}
        }))
        .unwrap();
        let error = crate::apply::generation::apply_resource(
            &engine,
            &api,
            &desired,
            crate::apply::generation::MutationGeneration::new(7).unwrap(),
            false,
            false,
        )
        .await
        .expect_err("stripped creation evidence must fail the apply");
        assert!(
            matches!(
                error,
                crate::apply::engine::ApplyError::ProviderGenerationNotApplied { expected: 7, .. }
            ),
            "{error:?}"
        );
        let records = sink.records.lock().expect("records").clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].uid, "post-uid-254");
        assert_eq!(records[0].kind, "ConfigMap");
        assert_eq!(records[0].name, "pull-secret");
        assert_eq!(records[0].namespace.as_deref(), Some("tenant-ns"));
        assert_eq!(records[0].mutation_generation, 7);
        let events = events.lock().expect("events").clone();
        let persist_at = events.iter().position(|event| *event == "persist").unwrap();
        let delete_at = events.iter().position(|event| *event == "delete").unwrap();
        assert!(
            persist_at < delete_at,
            "persist must precede the unresolved delete: {events:?}"
        );
        assert!(
            !records[0].uid.is_empty(),
            "a same-named replacement must not replace the POST uid"
        );
    }

    #[tokio::test]
    async fn namespace_create_persists_post_uid_on_unresolved_compensation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink {
            records: Mutex::new(Vec::new()),
            events: Arc::clone(&events),
            fail: false,
        });
        let engine = engine(events, Arc::clone(&sink), true);
        let namespace: Namespace = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "tenant-ns"}
        }))
        .unwrap();
        let error = apply_namespace(
            &engine,
            &namespace,
            crate::apply::generation::MutationGeneration::new(7).unwrap(),
        )
        .await
        .expect_err("stripped namespace stamp must fail closed");
        assert!(
            matches!(
                error,
                crate::apply::engine::ApplyError::NamespaceNotReady(_)
            ),
            "{error:?}"
        );
        let records = sink.records.lock().expect("records").clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "Namespace");
        assert_eq!(records[0].name, "tenant-ns");
        assert_eq!(records[0].namespace, None);
        assert_eq!(records[0].uid, "post-uid-254");
        assert_eq!(records[0].mutation_generation, 7);
    }

    #[tokio::test]
    async fn failed_persist_still_pins_the_delete_and_does_not_record_success() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink {
            records: Mutex::new(Vec::new()),
            events: Arc::clone(&events),
            fail: true,
        });
        let engine = ApplyEngine::new(
            client(Arc::clone(&events), "post-uid-254", false),
            Default::default(),
        )
        .with_compensation_sink(sink.clone())
        .with_compensation_budget(Duration::from_secs(2));
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "tenant-ns");
        let desired: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "pull-secret", "namespace": "tenant-ns"}
        }))
        .unwrap();
        let _ = crate::apply::generation::apply_resource(
            &engine,
            &api,
            &desired,
            crate::apply::generation::MutationGeneration::new(7).unwrap(),
            false,
            false,
        )
        .await
        .expect_err("apply stays failed");
        assert!(sink.records.lock().expect("records").is_empty());
        let events = events.lock().expect("events").clone();
        assert!(events.iter().filter(|event| **event == "persist").count() >= 1);
        assert!(
            events.contains(&"delete"),
            "UID-pinned delete still attempted: {events:?}"
        );
        let _ = MUTATION_GENERATION_ANNOTATION;
    }
}
