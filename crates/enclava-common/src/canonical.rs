//! CE-v1: canonical encoding for cryptographic bindings.
//!
//! See `SECURITY_MITIGATION_PLAN.md` D11. Every transcript hash and Ed25519
//! signing input in the platform uses this encoding. Plain `||` concatenation
//! is forbidden because a variable-length field shifting boundaries can
//! change the meaning of a hash.

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CeV1DecodeError {
    #[error("truncated CE-v1 record at byte {offset}")]
    Truncated { offset: usize },
    #[error("CE-v1 label at byte {offset} is not UTF-8")]
    InvalidLabel { offset: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub struct CeV1Record<'a> {
    pub label: &'a str,
    pub value: &'a [u8],
}

/// Returns the raw CE-v1 TLV-encoded message bytes.
///
/// Each record is encoded as `label_len:u16_be || label_bytes || value_len:u32_be || value_bytes`.
/// Records appear in the order given. The caller is responsible for choosing
/// a fixed order and including a versioned `purpose` record first.
///
/// Use this output as the input to Ed25519 signing (per RFC 8032 PureEd25519,
/// which internally hashes with SHA-512). Pre-hashing with SHA-256 would be
/// wasteful and ambiguous.
pub fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let total: usize = records.iter().map(|(l, v)| 2 + l.len() + 4 + v.len()).sum();
    let mut out = Vec::with_capacity(total);
    for (label, value) in records {
        let label_len = u16::try_from(label.len()).expect("CE-v1 label exceeds u16::MAX");
        let value_len = u32::try_from(value.len()).expect("CE-v1 value exceeds u32::MAX");
        out.extend_from_slice(&label_len.to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Strictly decodes all CE-v1 records without copying their contents.
pub fn ce_v1_decode(bytes: &[u8]) -> Result<Vec<CeV1Record<'_>>, CeV1DecodeError> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let label_len = read_len::<2>(bytes, &mut offset)?;
        let label_offset = offset;
        let label_bytes = take(bytes, &mut offset, label_len)?;
        let label =
            std::str::from_utf8(label_bytes).map_err(|_| CeV1DecodeError::InvalidLabel {
                offset: label_offset,
            })?;
        let value_len = read_len::<4>(bytes, &mut offset)?;
        let value = take(bytes, &mut offset, value_len)?;
        records.push(CeV1Record { label, value });
    }

    Ok(records)
}

fn read_len<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<usize, CeV1DecodeError> {
    let raw: [u8; N] = take(bytes, offset, N)?.try_into().expect("length checked");
    Ok(raw
        .into_iter()
        .fold(0usize, |value, byte| (value << 8) | usize::from(byte)))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], CeV1DecodeError> {
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or(CeV1DecodeError::Truncated { offset: *offset })?;
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}

/// Returns the 32-byte SHA-256 of `ce_v1_bytes(records)`.
///
/// Use this where a fixed-length identifier is needed (REPORT_DATA,
/// `descriptor_core_hash`, sub-canonicalizations embedded as values in
/// another CE-v1 record). NOT used as an Ed25519 sign input; for signing,
/// pass the raw `ce_v1_bytes` output.
pub fn ce_v1_hash(records: &[(&str, &[u8])]) -> [u8; 32] {
    Sha256::digest(ce_v1_bytes(records)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_records_encode_to_empty_bytes() {
        assert_eq!(ce_v1_bytes(&[]), Vec::<u8>::new());
    }

    #[test]
    fn single_record_layout_is_length_prefixed_tlv() {
        let bytes = ce_v1_bytes(&[("ab", b"cd")]);
        // 2 bytes label_len (BE) + label + 4 bytes value_len (BE) + value
        assert_eq!(
            bytes,
            vec![0x00, 0x02, b'a', b'b', 0x00, 0x00, 0x00, 0x02, b'c', b'd']
        );
    }

    #[test]
    fn collision_test_distinguishes_boundary_shift() {
        // Plain concat would make "a"||"bc" == "ab"||"c" == "abc".
        // CE-v1 must produce different bytes — and therefore different hashes —
        // even when the label/value byte streams are equal under concatenation.
        let bytes_a = ce_v1_bytes(&[("a", b"bc")]);
        let bytes_b = ce_v1_bytes(&[("ab", b"c")]);
        assert_ne!(bytes_a, bytes_b);

        let hash_a = ce_v1_hash(&[("a", b"bc")]);
        let hash_b = ce_v1_hash(&[("ab", b"c")]);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn order_dependent() {
        let a = ce_v1_hash(&[("x", b"1"), ("y", b"2")]);
        let b = ce_v1_hash(&[("y", b"2"), ("x", b"1")]);
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic() {
        let a = ce_v1_hash(&[("purpose", b"enclava-test-v1"), ("k", b"v")]);
        let b = ce_v1_hash(&[("purpose", b"enclava-test-v1"), ("k", b"v")]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_is_sha256_of_bytes() {
        let records: &[(&str, &[u8])] = &[("purpose", b"enclava-test-v1")];
        let bytes = ce_v1_bytes(records);
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(ce_v1_hash(records), expected);
    }

    #[test]
    fn decode_round_trips_binary_values() {
        let bytes = ce_v1_bytes(&[("purpose", b"proof-bundle-v1"), ("binary", b"\0\xff")]);
        assert_eq!(
            ce_v1_decode(&bytes).unwrap(),
            vec![
                CeV1Record {
                    label: "purpose",
                    value: b"proof-bundle-v1",
                },
                CeV1Record {
                    label: "binary",
                    value: b"\0\xff",
                },
            ]
        );
    }

    #[test]
    fn decode_rejects_every_truncation() {
        for bytes in [
            ce_v1_bytes(&[("purpose", b"proof-bundle-v1")]),
            ce_v1_bytes(&[("nonce", &[7; 32])]),
        ] {
            for end in 1..bytes.len() {
                assert!(
                    matches!(
                        ce_v1_decode(&bytes[..end]),
                        Err(CeV1DecodeError::Truncated { .. })
                    ),
                    "accepted truncation at {end}"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_invalid_utf8_labels() {
        assert_eq!(
            ce_v1_decode(&[0, 1, 0xff, 0, 0, 0, 0]),
            Err(CeV1DecodeError::InvalidLabel { offset: 2 })
        );
    }
}
