//! Offline ceremony helper for signed platform-release envelopes.
//!
//! The production root keypair must be generated and held outside this
//! repository. This helper exists so the rotation ceremony uses the exact
//! canonical encoding the CLI and API verify, instead of a hand-rolled
//! signer:
//!
//! ```text
//! # generate the production root (seed stays offline):
//! openssl genpkey -algorithm ed25519 -out root.pem
//! openssl pkey -in root.pem -noout -text         # read seed + pubkey hex
//!
//! # produce a signed envelope from a payload document. The root seed is
//! # read from stdin — redirect it from a protected file so it never
//! # appears in argv or shell history:
//! cargo run --locked -p enclava-cli --example platform-release -- sign \
//!     payload.json < root-seed.hex > platform-release.json
//!
//! # verify the envelope a build would bundle, before setting secrets:
//! cargo run --locked -p enclava-cli --example platform-release -- verify \
//!     platform-release.json <root-pubkey-hex>
//! ```
//!
//! Then set BOTH repository secrets together:
//! `ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX` (pubkey hex) and
//! `ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON` (the envelope file contents).

use std::io::Read;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};
use enclava_cli::platform_release::{
    PlatformRelease, PlatformReleaseEnvelope, canonical_platform_release_bytes,
    verify_envelope_with_root,
};

const USAGE: &str = "usage: platform-release sign <payload.json> <root-seed-hex-on-stdin>\n       platform-release verify <envelope.json> <root-pubkey-hex>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("sign") if args.len() > 3 => {
            Err("the root seed must be piped on stdin, not passed as an argument".to_string())
        }
        Some("sign") => sign(args.get(2)),
        Some("verify") => verify(args.get(2), args.get(3)),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn sign(payload_path: Option<&String>) -> Result<(), String> {
    let payload_path = payload_path.ok_or(USAGE)?;
    // The root seed is the platform trust anchor: it must never appear in
    // argv (shell history, process listings). Read it from stdin and decode
    // straight into a zeroized buffer so no intermediate copy survives.
    let mut seed_hex = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut seed_hex)
        .map_err(|err| format!("read root seed from stdin: {err}"))?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(seed_hex.trim(), &mut *seed)
        .map_err(|err| format!("root seed must be 32 bytes of hex: {err}"))?;
    let key = SigningKey::from_bytes(&seed);

    let raw = std::fs::read_to_string(payload_path)
        .map_err(|err| format!("read {payload_path}: {err}"))?;
    let payload: PlatformRelease = serde_json::from_str(&raw)
        .map_err(|err| format!("parse {payload_path} as platform-release payload: {err}"))?;
    let canonical =
        canonical_platform_release_bytes(&payload).map_err(|err| format!("payload: {err}"))?;
    let signature = key.sign(&canonical);
    let envelope = PlatformReleaseEnvelope {
        payload,
        signature: hex::encode(signature.to_bytes()),
        signing_pubkey: hex::encode(key.verifying_key().as_bytes()),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &envelope)
        .map_err(|err| format!("write envelope: {err}"))?;
    Ok(())
}

fn verify(envelope_path: Option<&String>, root_hex: Option<&String>) -> Result<(), String> {
    let envelope_path = envelope_path.ok_or(USAGE)?;
    let root_hex = root_hex.ok_or(USAGE)?;
    let raw = std::fs::read_to_string(envelope_path)
        .map_err(|err| format!("read {envelope_path}: {err}"))?;
    let envelope: PlatformReleaseEnvelope =
        serde_json::from_str(&raw).map_err(|err| format!("parse {envelope_path}: {err}"))?;
    let version = verify_envelope_with_root(envelope, root_hex)
        .map_err(|err| format!("{envelope_path}: {err}"))?
        .platform_release_version;
    println!("{envelope_path}: {version} verifies against the pinned root");
    Ok(())
}
