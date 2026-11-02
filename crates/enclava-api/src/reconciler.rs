use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Runs one named background loop until `shutdown` is cancelled.
///
/// Each loop keeps its own cadence and state inside `task`; cancellation drops
/// the loop at its next await point, which is how the process already stopped
/// these loops before graceful shutdown existed.
pub fn spawn_reconciler<F>(
    name: &'static str,
    shutdown: CancellationToken,
    task: F,
) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        tokio::select! {
            () = shutdown.cancelled() => {
                tracing::info!(reconciler = name, "background loop stopped for shutdown");
            }
            () = task => {
                tracing::warn!(reconciler = name, "background loop exited");
            }
        }
    })
}
