pub mod api_client;
pub mod api_types;
pub mod app_config;
pub mod attestation;
pub mod config;
pub mod descriptor;
mod fslock;
pub mod keyring;
pub mod keys;
pub mod platform_release;
pub mod policy_artifact;
pub mod registry;
pub mod tee_client;

/// Serializes tests that mutate process-global state (environment variables
/// or the working directory). Every env/CWD-mutating test in this crate takes
/// this one lock; `commands` compiles into the `enclava` binary so its tests
/// run in a separate process and share `commands::env_lock` there.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap()
}
