use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Without an encrypted-log recipient the wrapper must not leave the workload
// on inherited stdio: the generated Kata guest policy blocks ReadStream, so a
// runtime pipe that is never drained back-pressures the first workload that
// logs enough (staging 2026-09-14: SSH stalled pre-banner, supervisor frozen,
// pod 4/4 Ready). The no-recipient branch discards stdout/stderr instead, so
// the workload completes and nothing is emitted into the undrained pipe.
#[test]
fn no_recipient_stdio_is_discarded_not_backpressured() {
    let dir = std::env::temp_dir().join(format!(
        "enclava-wait-exec-stdio-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let started = dir.join("started");
    let ready = dir.join("ready");
    let progress = dir.join("progress");
    fs::create_dir_all(&started).unwrap();
    fs::write(&ready, "ready\n").unwrap();

    // ~170 KiB of alternating stdout/stderr lines, then a completion marker
    // and a successful exit.
    let script = format!(
        "i=0; while [ $i -lt 4096 ]; do \
            printf 'line %s: workload log output to stderr\\n' \"$i\" >&2; \
            printf 'line %s: workload log output to stdout\\n' \"$i\"; \
            i=$((i + 1)); \
         done; printf finished > '{}'; exit 0",
        progress.display()
    );

    // The read ends stay in these bindings, never read: the undrained
    // runtime pipe.
    let mut child = Command::new(env!("CARGO_BIN_EXE_enclava-wait-exec"))
        .args(["/bin/sh", "-c", &script])
        .env("ENCLAVA_CONTAINER_NAME", "web")
        .env("ENCLAVA_STARTED_DIR", &started)
        .env("ENCLAVA_INIT_READY_FILE", &ready)
        .env_remove("ENCLAVA_LOG_ENCRYPTION_KEY_ID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout_read = child.stdout.take();
    let stderr_read = child.stderr.take();

    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // Reap before failing so no subprocess is left behind.
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("workload blocked on undrained stdio pipes; killed, exit={status:?}");
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    };
    assert!(status.success(), "workload exited {status:?}");
    assert_eq!(fs::read_to_string(&progress).unwrap(), "finished");

    let mut emitted = Vec::new();
    if let Some(mut stream) = stdout_read {
        stream.read_to_end(&mut emitted).unwrap();
    }
    if let Some(mut stream) = stderr_read {
        stream.read_to_end(&mut emitted).unwrap();
    }
    assert!(
        emitted.is_empty(),
        "no-recipient branch must not emit workload output into the undrained runtime pipe"
    );

    fs::remove_dir_all(&dir).ok();
}
