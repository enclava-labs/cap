//! Unix socket framing for the unlock handoff between attestation-proxy
//! (which terminates the TLS-pinned ownership endpoints) and enclava-init.
//!
//! Wire format: a single line of UTF-8 text. Legacy clients write the password
//! followed by `\n`. Stateful CAP clients write
//! `owner-seed-v1:<base64url-32-byte-seed>\n`. enclava-init replies with
//! `OK\n` or `ERR <reason>\n`.

use base64::Engine as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::errors::{InitError, Result};
use crate::secrets::OwnerSeed;

pub const MAX_PASSWORD_LEN: usize = 1024;
pub const OWNER_SEED_REQUEST_PREFIX: &str = "owner-seed-v1:";

#[derive(Clone)]
pub enum UnlockRequest {
    Password(String),
    OwnerSeed(OwnerSeed),
}

pub fn bind(socket_path: &Path) -> Result<UnixListener> {
    bind_with_peer_gid(socket_path, None)
}

pub fn bind_with_peer_gid(socket_path: &Path, peer_gid: Option<u32>) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    if let Some(gid) = peer_gid {
        nix::unistd::chown(socket_path, None, Some(nix::unistd::Gid::from_raw(gid))).map_err(
            |err| {
                InitError::Config(format!(
                    "failed to chown unlock socket {} to gid {gid}: {err}",
                    socket_path.display()
                ))
            },
        )?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    } else {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

fn read_request_line(stream: &mut UnixStream) -> Result<String> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut buf = String::new();
    let n = reader.read_line(&mut buf)?;
    if n == 0 {
        return Err(InitError::Config("empty unlock request".into()));
    }
    if n > MAX_PASSWORD_LEN {
        return Err(InitError::Config("unlock request too large".into()));
    }
    let line = buf.trim_end_matches(['\r', '\n']).to_string();
    Ok(line)
}

pub fn read_unlock_request(stream: &mut UnixStream) -> Result<UnlockRequest> {
    let line = read_request_line(stream)?;
    if let Some(encoded) = line.strip_prefix(OWNER_SEED_REQUEST_PREFIX) {
        return decode_owner_seed_request(encoded).map(UnlockRequest::OwnerSeed);
    }
    Ok(UnlockRequest::Password(line))
}

pub fn read_password_line(stream: &mut UnixStream) -> Result<String> {
    match read_unlock_request(stream)? {
        UnlockRequest::Password(password) => Ok(password),
        UnlockRequest::OwnerSeed(_) => Err(InitError::Config(
            "owner-seed unlock request cannot be handled as a password".to_string(),
        )),
    }
}

fn decode_owner_seed_request(encoded: &str) -> Result<OwnerSeed> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()))
        .map_err(|_| InitError::Config("owner seed request is not base64".to_string()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        InitError::Config(format!(
            "owner seed request must decode to 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(OwnerSeed(seed))
}

pub fn reply_ok(stream: &mut UnixStream) -> Result<()> {
    stream.write_all(b"OK\n")?;
    Ok(())
}

pub fn reply_err(stream: &mut UnixStream, reason: &str) -> Result<()> {
    let line = format!("ERR {reason}\n");
    stream.write_all(line.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn bind_creates_socket_with_mode_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        let _l = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn read_password_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        let listener = bind(&path).unwrap();

        let path_clone = path.clone();
        let handle = thread::spawn(move || {
            let mut client = UnixStream::connect(&path_clone).unwrap();
            client.write_all(b"hunter2\n").unwrap();
            let mut reader = BufReader::new(client);
            let mut reply = String::new();
            reader.read_line(&mut reply).unwrap();
            reply
        });

        let (mut server_stream, _) = listener.accept().unwrap();
        let pw = read_password_line(&mut server_stream).unwrap();
        assert_eq!(pw, "hunter2");
        reply_ok(&mut server_stream).unwrap();
        drop(server_stream);
        let reply = handle.join().unwrap();
        assert_eq!(reply.trim(), "OK");
    }

    #[test]
    fn read_owner_seed_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        let listener = bind(&path).unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);

        let path_clone = path.clone();
        let handle = thread::spawn(move || {
            let mut client = UnixStream::connect(&path_clone).unwrap();
            client
                .write_all(format!("{OWNER_SEED_REQUEST_PREFIX}{encoded}\n").as_bytes())
                .unwrap();
            let mut reader = BufReader::new(client);
            let mut reply = String::new();
            reader.read_line(&mut reply).unwrap();
            reply
        });

        let (mut server_stream, _) = listener.accept().unwrap();
        let request = read_unlock_request(&mut server_stream).unwrap();
        let UnlockRequest::OwnerSeed(seed) = request else {
            panic!("expected owner seed request");
        };
        assert_eq!(seed.as_bytes(), &[0x42u8; 32]);
        reply_ok(&mut server_stream).unwrap();
        drop(server_stream);
        let reply = handle.join().unwrap();
        assert_eq!(reply.trim(), "OK");
    }
}
