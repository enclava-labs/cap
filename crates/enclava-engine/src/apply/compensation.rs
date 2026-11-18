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

    /// A fresh read showed this UID is no longer the failed create. `reason`
    /// is `later_generation` or `stale_replacement`. Idempotent. A failed
    /// write leaves the row due and must not cause another delete.
    fn resolve_refused<'a>(
        &'a self,
        uid: &'a str,
        reason: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::engine::ApplyEngine;
    use crate::apply::generation::RESOURCE_CREATED_BY_ANNOTATION;
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
        hang: bool,
    }

    impl UnresolvedCompensationSink for MemorySink {
        fn persist<'a>(
            &'a self,
            record: &'a UnresolvedCompensationRecord,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().expect("events").push("persist");
                if self.hang {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
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

        fn resolve_refused<'a>(
            &'a self,
            _uid: &'a str,
            _reason: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().expect("events").push("resolve_refused");
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
                            payload.contains(uid)
                                && payload.contains("preconditions")
                                && payload.contains("resourceVersion")
                                && payload.contains("Orphan"),
                            "delete was not pinned to UID and resourceVersion with orphan propagation: {payload}"
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
            hang: false,
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
            hang: false,
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
            hang: false,
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
    }

    #[derive(Clone, Copy)]
    enum LiveAfterPost {
        SameUid,
        LaterGeneration,
        DifferentUid,
    }

    fn conflict_client(deletes: Arc<Mutex<Vec<String>>>, live: LiveAfterPost) -> Client {
        let posted = Arc::new(Mutex::new(false));
        let gone = Arc::new(Mutex::new(false));
        Client::new(
            service_fn(move |request: Request<kube::client::Body>| {
                let deletes = Arc::clone(&deletes);
                let posted = Arc::clone(&posted);
                let gone = Arc::clone(&gone);
                async move {
                    let method = request.method().clone();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    if method == Method::GET {
                        if !*posted.lock().expect("posted") || *gone.lock().expect("gone") {
                            return Ok::<_, std::io::Error>(status(StatusCode::NOT_FOUND));
                        }
                        let (uid, generation) = match live {
                            LiveAfterPost::SameUid => ("post-uid-254", None),
                            LiveAfterPost::LaterGeneration => ("post-uid-254", Some(99_i64)),
                            LiveAfterPost::DifferentUid => ("replacement-uid", None),
                        };
                        let mut annotations = serde_json::Map::new();
                        if let Some(generation) = generation {
                            annotations.insert(
                                crate::apply::generation::MUTATION_GENERATION_ANNOTATION
                                    .to_string(),
                                json!(generation.to_string()),
                            );
                        }
                        let object = json!({
                            "apiVersion": "v1",
                            "kind": "ConfigMap",
                            "metadata": {
                                "name": "pull-secret",
                                "namespace": "tenant-ns",
                                "uid": uid,
                                "resourceVersion": "2",
                                "annotations": annotations,
                            }
                        });
                        return Ok(json_response(StatusCode::OK, &object));
                    }
                    if method == Method::POST {
                        *posted.lock().expect("posted") = true;
                        let payload: Value = serde_json::from_slice(&body).unwrap();
                        let response = stripped_create_response(payload, "post-uid-254");
                        return Ok(json_response(StatusCode::CREATED, &response));
                    }
                    if method == Method::DELETE {
                        let payload = String::from_utf8_lossy(&body).to_string();
                        deletes.lock().expect("deletes").push(payload.clone());
                        let options: Value = serde_json::from_str(&payload).unwrap();
                        let version = options
                            .pointer("/preconditions/resourceVersion")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let uid = options
                            .pointer("/preconditions/uid")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        // Only a fresh pin of the original UID succeeds. A stale
                        // version, a missing pin, or any other UID conflicts.
                        if version == "2"
                            && uid == "post-uid-254"
                            && matches!(live, LiveAfterPost::SameUid)
                        {
                            *gone.lock().expect("gone") = true;
                            return Ok(json_response(
                                StatusCode::OK,
                                &json!({
                                    "apiVersion": "v1",
                                    "kind": "ConfigMap",
                                    "metadata": {
                                        "name": "pull-secret",
                                        "namespace": "tenant-ns",
                                        "uid": "post-uid-254",
                                        "resourceVersion": "2"
                                    }
                                }),
                            ));
                        }
                        return Ok(status(StatusCode::CONFLICT));
                    }
                    Err(std::io::Error::other(format!("unexpected {method}")))
                }
            }),
            "default",
        )
    }

    async fn expect_stripped_configmap_failure(engine: &ApplyEngine) {
        let api: Api<ConfigMap> = Api::namespaced(engine.client().clone(), "tenant-ns");
        let desired: ConfigMap = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "pull-secret", "namespace": "tenant-ns"}
        }))
        .unwrap();
        let error = crate::apply::generation::apply_resource(
            engine,
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
    }

    fn assert_pinned_orphan(payload: &str, uid: &str, version: &str) {
        let options: Value = serde_json::from_str(payload).expect("delete body");
        assert_eq!(options["propagationPolicy"], "Orphan", "{payload}");
        assert_eq!(options["preconditions"]["uid"], uid, "{payload}");
        assert_eq!(
            options["preconditions"]["resourceVersion"], version,
            "{payload}"
        );
    }

    #[tokio::test]
    async fn stale_post_version_conflict_rereads_and_deletes_same_uid_without_a_sink() {
        let deletes = Arc::new(Mutex::new(Vec::new()));
        let engine = ApplyEngine::new(
            conflict_client(Arc::clone(&deletes), LiveAfterPost::SameUid),
            Default::default(),
        )
        .with_compensation_budget(Duration::from_secs(5));
        expect_stripped_configmap_failure(&engine).await;
        let deletes = deletes.lock().expect("deletes").clone();
        assert!(
            deletes.len() >= 2,
            "a 409 on the POST version must be retried with the fresh version: {deletes:?}"
        );
        assert_pinned_orphan(&deletes[0], "post-uid-254", "1");
        assert_pinned_orphan(&deletes[1], "post-uid-254", "2");
        assert!(
            deletes.iter().all(|payload| {
                let options: Value = serde_json::from_str(payload).unwrap();
                options["preconditions"]["uid"].as_str() == Some("post-uid-254")
                    && options["preconditions"]["resourceVersion"].is_string()
            }),
            "a conflict must not fall back to a name-only delete: {deletes:?}"
        );
    }

    #[tokio::test]
    async fn conflict_refuses_a_later_generation_without_another_delete() {
        let deletes = Arc::new(Mutex::new(Vec::new()));
        let engine = ApplyEngine::new(
            conflict_client(Arc::clone(&deletes), LiveAfterPost::LaterGeneration),
            Default::default(),
        )
        .with_compensation_budget(Duration::from_secs(5));
        expect_stripped_configmap_failure(&engine).await;
        let deletes = deletes.lock().expect("deletes").clone();
        assert_eq!(
            deletes.len(),
            1,
            "a newer generation must not be deleted: {deletes:?}"
        );
        assert_pinned_orphan(&deletes[0], "post-uid-254", "1");
    }

    #[tokio::test]
    async fn conflict_refuses_a_replacement_uid_without_another_delete() {
        let deletes = Arc::new(Mutex::new(Vec::new()));
        let engine = ApplyEngine::new(
            conflict_client(Arc::clone(&deletes), LiveAfterPost::DifferentUid),
            Default::default(),
        )
        .with_compensation_budget(Duration::from_secs(5));
        expect_stripped_configmap_failure(&engine).await;
        let deletes = deletes.lock().expect("deletes").clone();
        assert_eq!(
            deletes.len(),
            1,
            "a different UID must not be deleted by name: {deletes:?}"
        );
        assert_pinned_orphan(&deletes[0], "post-uid-254", "1");
    }

    #[tokio::test]
    async fn stalled_persist_is_bounded_by_the_compensation_deadline() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(MemorySink {
            records: Mutex::new(Vec::new()),
            events: Arc::clone(&events),
            fail: false,
            hang: true,
        });
        let engine = ApplyEngine::new(
            client(Arc::clone(&events), "post-uid-254", false),
            Default::default(),
        )
        .with_compensation_sink(sink.clone())
        .with_compensation_budget(Duration::from_millis(300));
        let started = std::time::Instant::now();
        expect_stripped_configmap_failure(&engine).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "stalled persist held the fence for {elapsed:?}"
        );
        assert!(
            sink.records.lock().expect("records").is_empty(),
            "a timed-out persist must not be treated as recorded"
        );
        assert!(
            events.lock().expect("events").contains(&"persist"),
            "persist must be attempted"
        );
    }
}
