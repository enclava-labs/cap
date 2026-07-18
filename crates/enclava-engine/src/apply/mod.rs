pub mod cleanup;
pub mod drift;
pub mod engine;
pub mod gateway;
pub mod generation;
pub mod namespace;
pub mod network_policy;
pub mod orchestrator;
pub mod resources;
pub mod statefulset;
pub mod teardown;
pub mod types;
pub mod watch;

/// Bound each individual Kubernetes mutation. Long rollout observation may
/// legitimately take minutes, but at most one accepted write can be in doubt
/// when a durable mutation heartbeat is lost.
pub async fn bounded_kube_write<F, T>(future: F) -> Result<T, engine::ApplyError>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    tokio::time::timeout(std::time::Duration::from_secs(30), future)
        .await
        .map_err(|_| engine::ApplyError::ProviderWriteTimeout)?
        .map_err(engine::ApplyError::Kube)
}
