use std::env;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn encrypted_log_wrapper_forwards_sigterm_to_child() {
    let dir = env::temp_dir().join(format!(
        "enclava-wait-exec-signal-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let started = dir.join("started");
    let ready = dir.join("ready");
    let child_ready = dir.join("child-ready");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&ready, "ready\n").unwrap();

    let keypair = enclava_common::log_encryption::generate_log_keypair();
    let script = format!(
        "trap 'exit 42' TERM; touch '{}'; while :; do sleep 1; done",
        child_ready.display()
    );
    let mut wrapper = Command::new(env!("CARGO_BIN_EXE_enclava-wait-exec"))
        .args(["/bin/sh", "-c", &script])
        .env("ENCLAVA_CONTAINER_NAME", "web")
        .env("ENCLAVA_STARTED_DIR", &started)
        .env("ENCLAVA_INIT_READY_FILE", &ready)
        .env("ENCLAVA_LOG_ENCRYPTION_KEY_ID", "test-key")
        .env(
            "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL",
            keypair.public_key_base64url,
        )
        .env(
            "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256",
            keypair.public_key_sha256,
        )
        .env("ENCLAVA_LOG_ORG_ID", "test-org")
        .env("ENCLAVA_LOG_APP_NAME", "test-app")
        .env("ENCLAVA_LOG_DEPLOYMENT_ID", "test-deployment")
        .env("ENCLAVA_LOG_SPOOL_PATH", dir.join("logs.jsonl"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !child_ready.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(child_ready.exists(), "wrapped child did not start");

    // SAFETY: wrapper.id() identifies the live child process created above.
    assert_eq!(
        unsafe { nix::libc::kill(wrapper.id() as i32, nix::libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = wrapper.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "wrapper did not exit after SIGTERM"
        );
        thread::sleep(Duration::from_millis(20));
    };

    assert_eq!(status.code(), Some(42), "status: {status:?}");
    assert_eq!(status.signal(), None);
    fs::remove_dir_all(dir).unwrap();
}
