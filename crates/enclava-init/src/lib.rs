//! enclava-init: in-TEE Rust replacement for the legacy bootstrap_script.sh.
//!
//! Runs as a long-running mounter sidecar inside a Kata SEV-SNP guest. It
//! waits for app/caddy wait-exec sentinels, performs Argon2id-based password
//! unlock or KBS-fetched autounlock, opens both LUKS devices (state and
//! tls-state), runs the in-TEE Trustee policy verification chain, writes
//! per-component HKDF-derived seeds, marks a readiness sentinel, and stays
//! alive so the decrypted mount propagation source remains present for
//! workload containers. All secret types use Zeroize so key material is wiped
//! on drop.

#[cfg(all(feature = "prod-strict", feature = "luks-integration"))]
compile_error!("prod-strict builds must not enable enclava-init/luks-integration");

pub mod chown;
pub mod config;
pub mod errors;
pub mod kbs_fetch;
pub mod luks;
pub mod secrets;
pub mod seeds;
pub mod socket;
pub mod tls_certificate;
pub mod trustee_verify;
pub mod unlock;
pub mod writes;
