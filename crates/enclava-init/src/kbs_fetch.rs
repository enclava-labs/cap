//! Autounlock-mode KBS read of the wrap key via the local Confidential Data
//! Hub (CDH) endpoint exposed by the Kata agent.
//!
//! The CDH endpoint forwards to Trustee with the workload's SNP attestation
//! token. Trustee's resource policy gates release. This client is the
//! workload-side caller; Phase 6 enrollment lives elsewhere.
//!
//! Wire shape: `GET <kbs_url><resource_path>` returns the raw 32-byte wrap
//! key on 200, 401 if attestation rejected, 403 if Rego denied, 404 if no
//! such resource (first-write-wins enrollment hasn't happened yet).

use std::time::Duration;

use crate::errors::{InitError, Result};
use crate::secrets::WrapKey;

#[derive(Debug, Clone)]
pub struct KbsClient {
    pub kbs_url: String,
    pub resource_path: String,
    pub timeout: Duration,
}

impl KbsClient {
    pub fn new(kbs_url: String, resource_path: String) -> Self {
        Self {
            kbs_url,
            resource_path,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn fetch_wrap_key(&self) -> Result<WrapKey> {
        let url = format!(
            "{}/{}",
            self.kbs_url.trim_end_matches('/'),
            self.resource_path.trim_start_matches('/')
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| InitError::Kbs(format!("client build: {e}")))?;
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| InitError::Kbs(format!("GET {url}: {e}")))?;
        let status = resp.status();
        match status.as_u16() {
            200 => {
                let bytes = resp
                    .bytes()
                    .map_err(|e| InitError::Kbs(format!("read body: {e}")))?;
                if bytes.len() != 32 {
                    return Err(InitError::Kbs(format!(
                        "wrap key wrong length: got {}, want 32",
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(WrapKey(out))
            }
            401 => Err(InitError::Kbs("attestation rejected (401)".into())),
            403 => Err(InitError::Kbs("rego denied (403)".into())),
            404 => Err(InitError::Kbs("resource not found (404)".into())),
            other => Err(InitError::Kbs(format!("unexpected status {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn read_request(stream: &mut TcpStream) -> String {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    fn spawn_server(response_status: u16, body: Vec<u8>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _req = read_request(&mut s);
                let reason = match response_status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    _ => "Other",
                };
                let resp = format!(
                    "HTTP/1.1 {response_status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                s.write_all(resp.as_bytes()).unwrap();
                s.write_all(&body).unwrap();
            }
        });
        port
    }

    #[test]
    fn fetch_wrap_key_200_returns_bytes() {
        let port = spawn_server(200, vec![0xABu8; 32]);
        let c = KbsClient::new(format!("http://127.0.0.1:{port}"), "wrap".into());
        let wk = c.fetch_wrap_key().unwrap();
        assert_eq!(wk.as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn fetch_wrap_key_401_attestation_rejected() {
        let port = spawn_server(401, vec![]);
        let c = KbsClient::new(format!("http://127.0.0.1:{port}"), "wrap".into());
        let err = match c.fetch_wrap_key() {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, InitError::Kbs(s) if s.contains("401")));
    }

    #[test]
    fn fetch_wrap_key_403_rego_denied() {
        let port = spawn_server(403, vec![]);
        let c = KbsClient::new(format!("http://127.0.0.1:{port}"), "wrap".into());
        let err = match c.fetch_wrap_key() {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, InitError::Kbs(s) if s.contains("403")));
    }

    #[test]
    fn fetch_wrap_key_404_not_found() {
        let port = spawn_server(404, vec![]);
        let c = KbsClient::new(format!("http://127.0.0.1:{port}"), "wrap".into());
        let err = match c.fetch_wrap_key() {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, InitError::Kbs(s) if s.contains("404")));
    }

    #[test]
    fn fetch_wrap_key_wrong_length() {
        let port = spawn_server(200, vec![0u8; 16]);
        let c = KbsClient::new(format!("http://127.0.0.1:{port}"), "wrap".into());
        let err = match c.fetch_wrap_key() {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, InitError::Kbs(s) if s.contains("wrong length")));
    }
}
