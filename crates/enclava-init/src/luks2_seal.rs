//! HMAC sealing and strict validation of LUKS2 headers (cap#242).
//!
//! Threat model: the host controls the persistent disk. A raw LUKS2 header is
//! unauthenticated, so a hostile host can swap it for one whose segment (or
//! keyslot area) cipher is `cipher_null` and recompute the unkeyed header
//! checksums — the guest then unlocks with the real passphrase and mounts a
//! plaintext volume while believing it is encrypted (Trail of Bits
//! CVE-2025-59054 / CVE-2025-58356 class).
//!
//! Defense, in layers:
//!
//! 1. **HMAC-SHA256 over the whole header region** (`[0, data_offset)`:
//!    both binary+JSON metadata copies and the keyslots area), keyed by a
//!    dedicated HKDF branch of the owner seed (distinct from every volume
//!    passphrase). The 64-byte MAC is stored in a reserved slot of the
//!    binary-header padding of *both* metadata copies at format time and
//!    verified at every open; any mismatch fails closed. Storing a nonzero
//!    slot also makes the on-disk header checksum-invalid for stock
//!    cryptsetup, so nothing but this code can parse the sealed header.
//! 2. **Open through a detached header copy on tmpfs**: the on-disk header is
//!    never handed to cryptsetup. After MAC verification the region is copied
//!    to `/run/enclava/...` with the MAC slots zeroed and every cryptsetup
//!    operation (test-passphrase, activate) uses `--header <copy>`, so there
//!    is no verify-then-use window on host-controlled bytes.
//! 3. **Strict metadata validation** at format, open, and adoption: exactly
//!    one keyslot (0, luks2, argon2id, raw area `aes-xts-plain64`), no
//!    tokens, exactly one crypt segment (`aes-xts-plain64`, sector 512),
//!    one digest bound to keyslot 0 and segment 0, and a layout where
//!    `data_offset == 2*hdr_size + keyslots_size`. A `cipher_null`-swapped
//!    header fails these checks before cryptsetup is ever invoked.
//! 4. **cryptsetup version floor** (>= 2.8.1, where null keyslot ciphers are
//!    rejected for nonempty passwords), enforced at boot and baked into the
//!    guest image from a sha256-pinned source build.
//!
//! Pre-existing volumes formatted before this change carry no MAC. They are
//! *adopted* on first open: the (strictly validated) header must pass a
//! passphrase test through the detached copy, after which the MAC is written
//! and the volume is sealed. Adoption never falls back to an in-place open.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::errors::{InitError, Result};
use crate::secrets::DerivedSeed;

/// Size of one LUKS2 metadata copy (binary header + JSON area). `hdr_size` in
/// the on-disk binary header; cryptsetup has always used 16 KiB and our
/// formatter pins it. A device with any other value is not one of ours.
pub const LUKS2_METADATA_COPY_SIZE: usize = 0x4000;

/// Offset of the JSON area inside each metadata copy.
pub const LUKS2_JSON_SUB_OFFSET: usize = 0x1000;

/// Offset of the 64-byte HMAC slot inside each binary-header copy. Chosen in
/// the zero padding after the header checksum field (csum occupies
/// `[0x1c0,0x1e0)`): verified empirically that nonzero bytes here invalidate
/// the header for stock cryptsetup while a copy with the slot re-zeroed
/// remains valid.
pub const HEADER_MAC_SLOT_OFFSET: usize = 0x240;
pub const HEADER_MAC_LEN: usize = 64;

/// Upper bound on the keyslots area we are willing to read and MAC. Stock
/// default is 16 MiB; anything beyond this is not a volume we formatted.
pub const MAX_KEYSLOTS_AREA: u64 = 128 * 1024 * 1024;

/// Minimum cryptsetup version (null keyslot ciphers rejected for nonempty
/// passwords). Enforced at boot; the guest image ships 2.8.8 from a
/// sha256-pinned source build.
pub const MIN_CRYPTSETUP_VERSION: (u64, u64, u64) = (2, 8, 1);

type HmacSha256 = Hmac<Sha256>;

/// Parsed, cross-checked LUKS2 on-disk layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks2Layout {
    pub hdr_size: u64,
    pub keyslots_size: u64,
    pub data_offset: u64,
}

/// Result of checking the on-disk MAC slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSeal {
    /// MAC present and valid (or freshly written).
    Sealed,
    /// Both slots zero: a legacy pre-seal volume, eligible for adoption.
    Unsealed,
}

/// The full authenticated header region `[0, data_offset)` read from disk.
pub struct Luks2Region {
    pub bytes: Vec<u8>,
    pub layout: Luks2Layout,
}

impl Luks2Region {
    fn slot(&self, copy: usize) -> &[u8] {
        let start = copy + HEADER_MAC_SLOT_OFFSET;
        &self.bytes[start..start + HEADER_MAC_LEN]
    }

    /// Copy of the region with both MAC slots zeroed — the form handed to
    /// cryptsetup as a detached header and the form the MAC is computed over.
    pub fn detached_bytes(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        zero_mac_slots(&mut out);
        out
    }
}

fn zero_mac_slots(bytes: &mut [u8]) {
    for copy in [0, LUKS2_METADATA_COPY_SIZE] {
        let start = copy + HEADER_MAC_SLOT_OFFSET;
        bytes[start..start + HEADER_MAC_LEN].fill(0);
    }
}

fn luks_error(message: String) -> InitError {
    InitError::Luks(message)
}

/// LUKS2 magic check for a metadata copy. The secondary copy is written by
/// cryptsetup with the brand bytes reversed (`SKUL\xba\xbe`), so `mirrored`
/// accepts either form there.
fn has_luks2_magic(copy: &[u8], mirrored: bool) -> bool {
    if copy.len() < 8 {
        return false;
    }
    let primary = &copy[..6] == b"LUKS\xba\xbe" || (mirrored && &copy[..6] == b"SKUL\xba\xbe");
    primary && u16::from_be_bytes([copy[6], copy[7]]) == 2
}

/// Read the header region of a LUKS2 device and parse its layout.
///
/// Only structural facts are extracted here; cryptographic validation lives
/// in [`validate_metadata_strict`] and [`verify_header_seal`].
pub fn read_header_region(device: &Path) -> Result<Luks2Region> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(device)
        .map_err(|e| luks_error(format!("open {} for header read: {e}", device.display())))?;

    let mut first = vec![0u8; 2 * LUKS2_METADATA_COPY_SIZE];
    file.read_exact(&mut first)
        .map_err(|e| luks_error(format!("read header head {}: {e}", device.display())))?;

    if !has_luks2_magic(&first, false) {
        return Err(luks_error(format!(
            "{} does not carry a LUKS2 header magic",
            device.display()
        )));
    }
    let hdr_size = u64::from_be_bytes(first[8..16].try_into().expect("8 byte slice"));
    if hdr_size != LUKS2_METADATA_COPY_SIZE as u64 {
        return Err(luks_error(format!(
            "unexpected LUKS2 hdr_size {hdr_size} (expected {LUKS2_METADATA_COPY_SIZE}); \
             refusing header not produced by enclava-init"
        )));
    }

    let json = parse_json_copy(&first[..LUKS2_METADATA_COPY_SIZE])?;
    let layout = parse_layout(&json)?;
    if layout.data_offset > 2 * LUKS2_METADATA_COPY_SIZE as u64 + MAX_KEYSLOTS_AREA {
        return Err(luks_error(format!(
            "LUKS2 data_offset {} exceeds the {} byte ceiling; refusing",
            layout.data_offset,
            2 * LUKS2_METADATA_COPY_SIZE as u64 + MAX_KEYSLOTS_AREA
        )));
    }

    let mut bytes = vec![0u8; layout.data_offset as usize];
    file.seek(SeekFrom::Start(0))
        .map_err(|e| luks_error(format!("seek {}: {e}", device.display())))?;
    file.read_exact(&mut bytes)
        .map_err(|e| luks_error(format!("read header region {}: {e}", device.display())))?;

    Ok(Luks2Region { bytes, layout })
}

/// Parse the JSON metadata of the first metadata copy, trimming NUL padding.
pub fn parse_json_copy(copy: &[u8]) -> Result<Value> {
    let json_area = &copy[LUKS2_JSON_SUB_OFFSET..];
    let end = json_area
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(json_area.len());
    serde_json::from_slice(&json_area[..end])
        .map_err(|e| luks_error(format!("parse LUKS2 JSON metadata: {e}")))
}

/// Extract and cross-check the on-disk layout from parsed JSON metadata.
pub fn parse_layout(json: &Value) -> Result<Luks2Layout> {
    let config = json
        .get("config")
        .ok_or_else(|| luks_error("LUKS2 metadata missing config".into()))?;
    let keyslots_size = parse_json_u64_field(config, "keyslots_size")?;
    let hdr_size = LUKS2_METADATA_COPY_SIZE as u64;

    let segments = json
        .get("segments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| luks_error("LUKS2 metadata missing segments".into()))?;
    if segments.len() != 1 || !segments.contains_key("0") {
        return Err(luks_error(
            "LUKS2 metadata must contain exactly segment 0".into(),
        ));
    }
    let data_offset = parse_json_u64_field(&segments["0"], "offset")?;

    if keyslots_size == 0 || keyslots_size > MAX_KEYSLOTS_AREA {
        return Err(luks_error(format!(
            "LUKS2 keyslots_size {keyslots_size} outside (0, {MAX_KEYSLOTS_AREA}]"
        )));
    }
    if data_offset != 2 * hdr_size + keyslots_size {
        return Err(luks_error(format!(
            "LUKS2 data_offset {data_offset} != 2*hdr_size + keyslots_size ({})",
            2 * hdr_size + keyslots_size
        )));
    }

    Ok(Luks2Layout {
        hdr_size,
        keyslots_size,
        data_offset,
    })
}

/// Strict validation of LUKS2 metadata against the exact shape enclava-init
/// formats: single keyslot 0 (argon2id, raw `aes-xts-plain64` area), no
/// tokens, single `aes-xts-plain64` crypt segment at 512-byte sectors, one
/// sha256 digest binding keyslot 0 to segment 0.
///
/// This is the ToB-recommended fallback floor and the adoption gate: a
/// `cipher_null`-swapped header fails here, before cryptsetup runs.
pub fn validate_metadata_strict(json: &Value, layout: &Luks2Layout) -> Result<()> {
    let keyslots = json
        .get("keyslots")
        .and_then(|v| v.as_object())
        .ok_or_else(|| luks_error("LUKS2 metadata missing keyslots".into()))?;
    if keyslots.len() != 1 || !keyslots.contains_key("0") {
        return Err(luks_error(
            "strict header validation: exactly keyslot 0 is allowed".into(),
        ));
    }
    let ks = &keyslots["0"];
    expect_str(ks, "type", "luks2", "keyslot 0 type")?;
    expect_u64(ks, "key_size", 64, "keyslot 0 key_size")?;

    let af = object_field(ks, "af", "keyslot 0 af")?;
    expect_str(af, "type", "luks1", "keyslot 0 af type")?;
    expect_str(af, "hash", "sha256", "keyslot 0 af hash")?;
    expect_u64(af, "stripes", 4000, "keyslot 0 af stripes")?;

    let area = object_field(ks, "area", "keyslot 0 area")?;
    expect_str(area, "type", "raw", "keyslot 0 area type")?;
    expect_str(
        area,
        "encryption",
        "aes-xts-plain64",
        "keyslot 0 area encryption",
    )
    .map_err(|_| {
        luks_error(
            "strict header validation: keyslot area cipher must be aes-xts-plain64 \
             (cipher_null header swap refused)"
                .into(),
        )
    })?;
    expect_u64(area, "key_size", 64, "keyslot 0 area key_size")?;
    let area_offset = parse_json_u64_field(area, "offset")?;
    if area_offset != 2 * layout.hdr_size {
        return Err(luks_error(format!(
            "strict header validation: keyslot 0 area offset {area_offset} != keyslots area start {}",
            2 * layout.hdr_size
        )));
    }
    let area_size = parse_json_u64_field(area, "size")?;
    if area_size == 0 || area_size > layout.keyslots_size {
        return Err(luks_error(
            "strict header validation: keyslot 0 area size outside keyslots area".into(),
        ));
    }

    let kdf = object_field(ks, "kdf", "keyslot 0 kdf")?;
    expect_str(kdf, "type", "argon2id", "keyslot 0 kdf type").map_err(|_| {
        luks_error(
            "strict header validation: keyslot KDF must be argon2id (weaker/unknown KDF \
                 refused)"
                .into(),
        )
    })?;

    let tokens = json
        .get("tokens")
        .and_then(|v| v.as_object())
        .ok_or_else(|| luks_error("LUKS2 metadata missing tokens".into()))?;
    if !tokens.is_empty() {
        return Err(luks_error(
            "strict header validation: tokens must be absent".into(),
        ));
    }

    let segments = json
        .get("segments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| luks_error("LUKS2 metadata missing segments".into()))?;
    if segments.len() != 1 || !segments.contains_key("0") {
        return Err(luks_error(
            "strict header validation: exactly segment 0 is allowed".into(),
        ));
    }
    let seg = &segments["0"];
    expect_str(seg, "type", "crypt", "segment 0 type")?;
    expect_str(seg, "encryption", "aes-xts-plain64", "segment 0 encryption").map_err(|_| {
        luks_error(
            "strict header validation: segment cipher must be aes-xts-plain64 \
             (cipher_null header swap refused)"
                .into(),
        )
    })?;
    expect_u64(seg, "sector_size", 512, "segment 0 sector_size")?;
    expect_str(seg, "iv_tweak", "0", "segment 0 iv_tweak")?;
    expect_str(seg, "size", "dynamic", "segment 0 size")?;
    let seg_offset = parse_json_u64_field(seg, "offset")?;
    if seg_offset != layout.data_offset {
        return Err(luks_error(format!(
            "strict header validation: segment 0 offset {seg_offset} != data_offset {}",
            layout.data_offset
        )));
    }

    let digests = json
        .get("digests")
        .and_then(|v| v.as_object())
        .ok_or_else(|| luks_error("LUKS2 metadata missing digests".into()))?;
    if digests.len() != 1 || !digests.contains_key("0") {
        return Err(luks_error(
            "strict header validation: exactly digest 0 is allowed".into(),
        ));
    }
    let digest = &digests["0"];
    expect_str(digest, "type", "pbkdf2", "digest 0 type")?;
    expect_str(digest, "hash", "sha256", "digest 0 hash")?;
    expect_str_list(digest, "keyslots", &["0"], "digest 0 keyslots")?;
    expect_str_list(digest, "segments", &["0"], "digest 0 segments")?;

    Ok(())
}

/// Region-level validation: both metadata copies must parse, carry the LUKS2
/// magic (reversed in the secondary copy, as cryptsetup writes it), and be
/// byte-identical in JSON; then strict shape validation runs.
///
/// Requiring copy equality removes cryptsetup's higher-seqid copy selection
/// as an attacker-controlled degree of freedom during adoption; for sealed
/// headers any divergence already breaks the MAC.
pub fn validate_region(region: &Luks2Region) -> Result<()> {
    let copy2 = &region.bytes[LUKS2_METADATA_COPY_SIZE..2 * LUKS2_METADATA_COPY_SIZE];
    if !has_luks2_magic(copy2, true) {
        return Err(luks_error(
            "second LUKS2 metadata copy lost its header magic; refusing".into(),
        ));
    }
    let json1 = parse_json_copy(&region.bytes[..LUKS2_METADATA_COPY_SIZE])?;
    let json2 = parse_json_copy(copy2)?;
    if json1 != json2 {
        return Err(luks_error(
            "LUKS2 JSON metadata copies differ; refusing (possible host tampering)".into(),
        ));
    }
    validate_metadata_strict(&json1, &region.layout)
}

/// Compute the header MAC over the region with both slots zeroed.
pub fn compute_header_mac(region: &[u8], mac_key: &DerivedSeed) -> Result<[u8; HEADER_MAC_LEN]> {
    let mut mac = HmacSha256::new_from_slice(mac_key.as_bytes())
        .map_err(|e| luks_error(format!("header MAC init: {e}")))?;
    let mut zeroed = region.to_vec();
    zero_mac_slots(&mut zeroed);
    mac.update(&zeroed);
    let tag = mac.finalize().into_bytes();
    let mut slot = [0u8; HEADER_MAC_LEN];
    slot[..tag.len()].copy_from_slice(&tag);
    Ok(slot)
}

/// Check the on-disk MAC slots. Fails closed on any inconsistency.
pub fn verify_header_seal(region: &Luks2Region, mac_key: &DerivedSeed) -> Result<HeaderSeal> {
    let slot1 = region.slot(0);
    let slot2 = region.slot(LUKS2_METADATA_COPY_SIZE);
    if slot1.iter().all(|&b| b == 0) && slot2.iter().all(|&b| b == 0) {
        return Ok(HeaderSeal::Unsealed);
    }
    if slot1.ct_eq(slot2).unwrap_u8() != 1 {
        return Err(luks_error(
            "LUKS2 header MAC copies differ; refusing to open (possible host tampering)".into(),
        ));
    }
    let expected = compute_header_mac(&region.bytes, mac_key)?;
    if slot1.ct_eq(&expected).unwrap_u8() == 1 {
        Ok(HeaderSeal::Sealed)
    } else {
        Err(luks_error(
            "LUKS2 header MAC mismatch; refusing to open (possible host tampering)".into(),
        ))
    }
}

/// Write the MAC into both on-disk slots, sealing the header.
pub fn seal_on_disk(device: &Path, region: &Luks2Region, mac_key: &DerivedSeed) -> Result<()> {
    let slot = compute_header_mac(&region.bytes, mac_key)?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(device)
        .map_err(|e| luks_error(format!("open {} for header seal: {e}", device.display())))?;
    for copy in [0, LUKS2_METADATA_COPY_SIZE] {
        file.seek(SeekFrom::Start((copy + HEADER_MAC_SLOT_OFFSET) as u64))
            .map_err(|e| luks_error(format!("seek {} seal slot: {e}", device.display())))?;
        file.write_all(&slot)
            .map_err(|e| luks_error(format!("write {} seal slot: {e}", device.display())))?;
    }
    file.sync_all()
        .map_err(|e| luks_error(format!("sync {} seal: {e}", device.display())))?;
    Ok(())
}

/// Write a tmpfs copy of the region (MAC slots zeroed) for detached-header
/// cryptsetup operations. Never on the host-controlled disk.
pub fn write_detached_copy(region: &Luks2Region, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| luks_error(format!("create {}: {e}", parent.display())))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| luks_error(format!("create detached header {}: {e}", path.display())))?;
    file.write_all(&region.detached_bytes())
        .map_err(|e| luks_error(format!("write detached header {}: {e}", path.display())))?;
    file.sync_all()
        .map_err(|e| luks_error(format!("sync detached header {}: {e}", path.display())))?;
    Ok(())
}

/// Best-effort wipe of a detached header copy (zeroize then remove).
pub fn wipe_detached_copy(path: &Path, len: usize) {
    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; len];
        let _ = file.write_all(&zeros);
        let _ = file.sync_all();
    }
    let _ = std::fs::remove_file(path);
}

/// Parse `cryptsetup --version` output (e.g. `cryptsetup 2.8.8 flags: ...`
/// or `cryptsetup 2.6.1-4~deb12u2`).
pub fn parse_cryptsetup_version(output: &str) -> Option<(u64, u64, u64)> {
    let line = output.lines().next()?;
    let rest = line.strip_prefix("cryptsetup")?.trim_start();
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

/// Read the installed cryptsetup CLI version.
pub fn cryptsetup_version() -> Result<(u64, u64, u64)> {
    let output = std::process::Command::new("cryptsetup")
        .arg("--version")
        .output()
        .map_err(|e| luks_error(format!("cryptsetup --version: {e}")))?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_cryptsetup_version(&text)
        .ok_or_else(|| luks_error(format!("unparseable cryptsetup version: {text:?}")))
}

/// Enforce the cryptsetup floor at boot. Fail closed below
/// [`MIN_CRYPTSETUP_VERSION`].
pub fn ensure_cryptsetup_floor() -> Result<(u64, u64, u64)> {
    let version = cryptsetup_version()?;
    if version < MIN_CRYPTSETUP_VERSION {
        return Err(luks_error(format!(
            "cryptsetup {0}.{1}.{2} is below the required floor {3}.{4}.{5} \
             (null-cipher keyslot hardening); refusing LUKS operations",
            version.0,
            version.1,
            version.2,
            MIN_CRYPTSETUP_VERSION.0,
            MIN_CRYPTSETUP_VERSION.1,
            MIN_CRYPTSETUP_VERSION.2
        )));
    }
    tracing::info!(
        version = format!("{}.{}.{}", version.0, version.1, version.2),
        "cryptsetup version floor satisfied"
    );
    Ok(version)
}

fn object_field<'v>(value: &'v Value, key: &str, ctx: &str) -> Result<&'v Value> {
    let field = value.get(key).ok_or_else(|| {
        luks_error(format!(
            "strict header validation: {ctx} missing {key} object"
        ))
    })?;
    if !field.is_object() {
        return Err(luks_error(format!(
            "strict header validation: {ctx} {key} is not an object"
        )));
    }
    Ok(field)
}

fn expect_str(value: &Value, key: &str, expected: &str, ctx: &str) -> Result<()> {
    let got = value
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| luks_error(format!("strict header validation: {ctx} missing {key}")))?;
    if got != expected {
        return Err(luks_error(format!(
            "strict header validation: {ctx} {key} must be {expected:?}, got {got:?}"
        )));
    }
    Ok(())
}

fn expect_u64(value: &Value, key: &str, expected: u64, ctx: &str) -> Result<()> {
    let got = value
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| luks_error(format!("strict header validation: {ctx} missing {key}")))?;
    if got != expected {
        return Err(luks_error(format!(
            "strict header validation: {ctx} {key} must be {expected}, got {got}"
        )));
    }
    Ok(())
}

fn expect_str_list(value: &Value, key: &str, expected: &[&str], ctx: &str) -> Result<()> {
    let got = value
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| luks_error(format!("strict header validation: {ctx} missing {key}")))?;
    let got: Vec<&str> = got.iter().map(|v| v.as_str().unwrap_or("")).collect();
    if got.as_slice() != expected {
        return Err(luks_error(format!(
            "strict header validation: {ctx} {key} must be {expected:?}, got {got:?}"
        )));
    }
    Ok(())
}

fn parse_json_u64_field(value: &Value, key: &str) -> Result<u64> {
    match value.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| luks_error(format!("LUKS2 field {key} not a u64"))),
        Some(Value::String(s)) => s
            .parse::<u64>()
            .map_err(|_| luks_error(format!("LUKS2 field {key} not a u64 string: {s:?}"))),
        _ => Err(luks_error(format!("LUKS2 field {key} missing"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JSON: &str = r#"{
      "keyslots":{
        "0":{
          "type":"luks2",
          "key_size":64,
          "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
          "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
          "kdf":{"type":"argon2id","time":4,"memory":704452,"cpus":4,"salt":"AA=="}
        }
      },
      "tokens":{},
      "segments":{
        "0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}
      },
      "digests":{
        "0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":114774,"salt":"AA==","digest":"AA=="}
      },
      "config":{"json_size":"12288","keyslots_size":"16744448"}
    }"#;

    fn synth_region(json: &str) -> Luks2Region {
        let mut bytes = vec![0u8; 16777216];
        // cryptsetup writes the secondary metadata copy with reversed brand
        // bytes ("SKUL"); mirror that here so fixtures match real headers.
        let copies = [
            (0usize, &[b'L', b'U', b'K', b'S', 0xba, 0xbe][..]),
            (
                LUKS2_METADATA_COPY_SIZE,
                &[b'S', b'K', b'U', b'L', 0xba, 0xbe][..],
            ),
        ];
        for (copy, magic) in copies {
            bytes[copy..copy + 6].copy_from_slice(magic);
            bytes[copy + 6..copy + 8].copy_from_slice(&2u16.to_be_bytes());
            bytes[copy + 8..copy + 16]
                .copy_from_slice(&(LUKS2_METADATA_COPY_SIZE as u64).to_be_bytes());
            let json_bytes = json.as_bytes();
            let start = copy + LUKS2_JSON_SUB_OFFSET;
            bytes[start..start + json_bytes.len()].copy_from_slice(json_bytes);
        }
        let parsed = parse_json_copy(&bytes[..LUKS2_METADATA_COPY_SIZE]).expect("fixture json");
        let layout = parse_layout(&parsed).expect("fixture layout");
        Luks2Region { bytes, layout }
    }

    fn edited_json(mutate: fn(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(VALID_JSON).unwrap();
        mutate(&mut v);
        v.to_string()
    }

    fn assert_rejects(json: &str, needle: &str) {
        let region = synth_region(json);
        let result = validate_metadata_strict(
            &parse_json_copy(&region.bytes[..LUKS2_METADATA_COPY_SIZE]).unwrap(),
            &region.layout,
        );
        let err = result.expect_err("validation must fail");
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in {err}"
        );
    }

    #[test]
    fn valid_metadata_passes_strict_validation() {
        let region = synth_region(VALID_JSON);
        let json = parse_json_copy(&region.bytes[..LUKS2_METADATA_COPY_SIZE]).unwrap();
        validate_metadata_strict(&json, &region.layout).expect("valid header passes");
        assert_eq!(region.layout.data_offset, 16777216);
        assert_eq!(region.layout.keyslots_size, 16744448);
    }

    #[test]
    fn cipher_null_segment_is_refused() {
        assert_rejects(
            &edited_json(|v| v["segments"]["0"]["encryption"] = "cipher_null-plain64".into()),
            "cipher_null",
        );
    }

    #[test]
    fn cipher_null_keyslot_area_is_refused() {
        assert_rejects(
            &edited_json(|v| {
                v["keyslots"]["0"]["area"]["encryption"] = "cipher_null-plain64".into()
            }),
            "cipher_null",
        );
    }

    #[test]
    fn non_argon2id_kdf_is_refused() {
        assert_rejects(
            &edited_json(|v| v["keyslots"]["0"]["kdf"]["type"] = "pbkdf2".into()),
            "argon2id",
        );
    }

    #[test]
    fn second_keyslot_is_refused() {
        assert_rejects(
            &edited_json(|v| {
                v["keyslots"]["1"] = v["keyslots"]["0"].clone();
            }),
            "exactly keyslot 0",
        );
    }

    #[test]
    fn tokens_are_refused() {
        assert_rejects(
            &edited_json(|v| {
                v["tokens"]["0"] = serde_json::json!({"type":"secboot"});
            }),
            "tokens must be absent",
        );
    }

    #[test]
    fn non_default_sector_size_is_refused() {
        assert_rejects(
            &edited_json(|v| v["segments"]["0"]["sector_size"] = 4096.into()),
            "sector_size",
        );
    }

    #[test]
    fn inconsistent_data_offset_is_refused() {
        // Build a region whose *layout* is consistent, then tamper only the
        // segment-0 offset in the parsed JSON: strict validation must catch
        // the divergence (parse_layout alone already rejects a mismatched
        // on-disk layout, so this covers the second line of defense).
        let region = synth_region(VALID_JSON);
        let mut json = parse_json_copy(&region.bytes[..LUKS2_METADATA_COPY_SIZE]).unwrap();
        json["segments"]["0"]["offset"] = "16777217".into();
        let err = validate_metadata_strict(&json, &region.layout).expect_err("must fail");
        assert!(
            err.to_string().contains("data_offset"),
            "expected data_offset in {err}"
        );
    }

    #[test]
    fn seal_round_trip_and_tamper_detection() {
        let mut region = synth_region(VALID_JSON);
        let mac_key = DerivedSeed([0x24u8; 32]);
        let other_key = DerivedSeed([0x42u8; 32]);

        assert_eq!(
            verify_header_seal(&region, &mac_key).expect("unsealed check"),
            HeaderSeal::Unsealed
        );

        let slot = compute_header_mac(&region.bytes, &mac_key).unwrap();
        for copy in [0, LUKS2_METADATA_COPY_SIZE] {
            let start = copy + HEADER_MAC_SLOT_OFFSET;
            region.bytes[start..start + HEADER_MAC_LEN].copy_from_slice(&slot);
        }
        assert_eq!(
            verify_header_seal(&region, &mac_key).expect("sealed check"),
            HeaderSeal::Sealed
        );

        // wrong key -> mismatch
        let err = verify_header_seal(&region, &other_key).expect_err("wrong key");
        assert!(err.to_string().contains("MAC mismatch"));

        // single-copy MAC -> copies differ
        region.bytes[HEADER_MAC_SLOT_OFFSET..HEADER_MAC_SLOT_OFFSET + HEADER_MAC_LEN].fill(0);
        let err = verify_header_seal(&region, &mac_key).expect_err("single copy");
        assert!(err.to_string().contains("copies differ"));

        // restore, tamper payload -> mismatch
        region.bytes[HEADER_MAC_SLOT_OFFSET..HEADER_MAC_SLOT_OFFSET + HEADER_MAC_LEN]
            .copy_from_slice(&slot);
        let mid = region.bytes.len() / 2;
        region.bytes[mid] ^= 0xFF;
        let err = verify_header_seal(&region, &mac_key).expect_err("tampered payload");
        assert!(err.to_string().contains("MAC mismatch"));
    }

    #[test]
    fn mac_keys_are_distinct_from_each_other_for_same_region() {
        let region = synth_region(VALID_JSON);
        let a = compute_header_mac(&region.bytes, &DerivedSeed([1u8; 32])).unwrap();
        let b = compute_header_mac(&region.bytes, &DerivedSeed([2u8; 32])).unwrap();
        assert_ne!(a.to_vec(), b.to_vec());
    }

    #[test]
    fn detached_bytes_zero_both_slots() {
        let mut region = synth_region(VALID_JSON);
        for copy in [0, LUKS2_METADATA_COPY_SIZE] {
            let start = copy + HEADER_MAC_SLOT_OFFSET;
            region.bytes[start..start + HEADER_MAC_LEN].fill(0xAB);
        }
        let det = region.detached_bytes();
        for copy in [0, LUKS2_METADATA_COPY_SIZE] {
            let start = copy + HEADER_MAC_SLOT_OFFSET;
            assert!(det[start..start + HEADER_MAC_LEN].iter().all(|&b| b == 0));
        }
        // rest of the region is preserved
        assert_eq!(det.len(), region.bytes.len());
        assert_eq!(&det[..6], b"LUKS\xba\xbe");
    }

    #[test]
    fn version_parser_handles_release_and_distro_strings() {
        assert_eq!(
            parse_cryptsetup_version("cryptsetup 2.8.8 flags: UDEV BLKID\n"),
            Some((2, 8, 8))
        );
        assert_eq!(
            parse_cryptsetup_version("cryptsetup 2.6.1-4~deb12u2\n"),
            Some((2, 6, 1))
        );
        assert_eq!(
            parse_cryptsetup_version("cryptsetup 2.9\n"),
            Some((2, 9, 0))
        );
        assert_eq!(parse_cryptsetup_version("garbage"), None);
        assert_eq!(parse_cryptsetup_version(""), None);
    }

    // Empirically the binary-header checksum occupies [0x1c0,0x1e0); the
    // MAC slot must live strictly beyond it, inside the zero padding.
    const _: () = assert!(HEADER_MAC_SLOT_OFFSET >= 0x1e0);
    const _: () = assert!(HEADER_MAC_SLOT_OFFSET + HEADER_MAC_LEN <= LUKS2_JSON_SUB_OFFSET);
}
