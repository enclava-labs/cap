//! End-to-end pin of the bind child's exit-code half of the cap#428 step
//! contract: the real `enclava-init --bind-mount-into-ns` binary exits with
//! the fixed table code (3/4/5) when its error carries a typed step, and
//! exit 1 for every untyped failure. The parent's mapping half is pinned in
//! `main/namespace_bind.rs` (the shared `InitFailedStep::from_child_exit_code`
//! table plus the typed-error construction), and the table itself by the
//! round-trip tests in `safe_diagnostics`.
//!
//! A missing source fails inside the child before any namespace-privileged
//! step, so the subprocess runs unprivileged in CI.

use std::process::Command;
use tempfile::TempDir;

/// A guard-owned source path that is guaranteed NOT to exist: a fresh
/// tempdir nobody else can create files in, plus an absent child path. The
/// child therefore always takes the missing-source branch (open fails),
/// never whatever a previous process left at a fixed shared path.
fn missing_source() -> (TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing-source");
    assert!(!path.exists());
    (dir, path.to_string_lossy().to_string())
}

fn run_child(pid: &str, source: &str, target: &str) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_enclava-init"))
        .arg("--bind-mount-into-ns")
        .arg(pid)
        .arg(source)
        .arg(target)
        .output()
        .expect("spawn the real binder child")
        .status
}

#[test]
fn child_exits_with_the_typed_source_step_code() {
    // A missing source fails at the child's open: the typed step is
    // bind_source_failed, so the child exits 3 (the fixed table).
    let (_guard, source) = missing_source();
    let status = run_child("1", &source, "/data");
    assert_eq!(
        status.code(),
        Some(3),
        "the child must exit with the bind_source_failed table code"
    );
}

#[test]
fn child_exits_untyped_for_a_bad_argument_shape() {
    // A wrong argument count is not an instrumented site: exit 1, exactly
    // as before cap#428.
    let status = Command::new(env!("CARGO_BIN_EXE_enclava-init"))
        .arg("--bind-mount-into-ns")
        .arg("only-one-arg")
        .output()
        .expect("spawn the real binder child")
        .status;
    assert_eq!(status.code(), Some(1));
}
