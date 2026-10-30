//! Locating the raw SNP report and AMD chain inside guest evidence JSON.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::Value;
use sev::parser::ByteParser;

/// Real ARK/ASK/VCEK certificates are under 2 KiB; anything larger is
/// rejected before X.509 parsing (same bound as the unlock transition gate).
const MAX_EVIDENCE_CERTIFICATE_DER_BYTES: usize = 16_384;

#[derive(Debug)]
pub(crate) struct SnpDerChain {
    pub(crate) ark_der: Vec<u8>,
    pub(crate) ask_der: Vec<u8>,
    pub(crate) vcek_der: Vec<u8>,
}

pub(crate) fn snp_report_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Object(map) => {
            for (key, candidate) in map {
                let is_report_key = matches!(
                    normalize_json_key(key).as_str(),
                    "snpreport"
                        | "snpreportbytes"
                        | "rawsnpreport"
                        | "rawreport"
                        | "report"
                        | "quote"
                        | "attestationreport"
                        | "attestationreportbytes"
                );
                if !is_report_key {
                    continue;
                }
                if let Some(bytes) = structured_snp_report_bytes(candidate) {
                    return Some(bytes);
                }
                if let Some(bytes) = bytes_value(candidate)
                    && bytes.len() == enclava_verifier::SNP_REPORT_BYTES
                {
                    return Some(bytes);
                }
            }
            map.values().find_map(snp_report_bytes)
        }
        Value::Array(values) => bytes_value(value)
            .filter(|bytes| bytes.len() == enclava_verifier::SNP_REPORT_BYTES)
            .or_else(|| values.iter().find_map(snp_report_bytes)),
        _ => None,
    }
}

/// CoCo guest components serialize the report as sev's structured JSON.
fn structured_snp_report_bytes(value: &Value) -> Option<Vec<u8>> {
    if !value.is_object() {
        return None;
    }
    let report: sev::firmware::guest::AttestationReport =
        serde::Deserialize::deserialize(value).ok()?;
    Some(report.to_bytes().ok()?.as_ref().to_vec())
}

pub(crate) fn snp_der_chain(value: &Value) -> Option<SnpDerChain> {
    if let Some(chain) = coco_cert_chain(value) {
        return Some(chain);
    }
    Some(SnpDerChain {
        ark_der: bounded(named_bytes(
            value,
            &["ark", "arkder", "arkcert", "arkcertificate"],
        )?)?,
        ask_der: bounded(named_bytes(
            value,
            &["ask", "askder", "askcert", "askcertificate"],
        )?)?,
        vcek_der: bounded(named_bytes(
            value,
            &["vcek", "vcekder", "vcekcert", "vcekcertificate"],
        )?)?,
    })
}

fn coco_cert_chain(value: &Value) -> Option<SnpDerChain> {
    match value {
        Value::Object(map) => {
            if let Some(entries) = map.get("cert_chain").and_then(Value::as_array) {
                let (mut ark_der, mut ask_der, mut vcek_der) = (None, None, None);
                for entry in entries {
                    let cert_type = entry
                        .get("cert_type")
                        .and_then(Value::as_str)
                        .map(normalize_json_key)?;
                    let data = entry.get("data").and_then(bytes_value)?;
                    match cert_type.as_str() {
                        "ark" => ark_der = Some(data),
                        "ask" | "asvk" => ask_der = Some(data),
                        "vcek" | "vlek" => vcek_der = Some(data),
                        _ => {}
                    }
                }
                if let (Some(ark_der), Some(ask_der), Some(vcek_der)) = (ark_der, ask_der, vcek_der)
                {
                    return Some(SnpDerChain {
                        ark_der: bounded(ark_der)?,
                        ask_der: bounded(ask_der)?,
                        vcek_der: bounded(vcek_der)?,
                    });
                }
            }
            map.values().find_map(coco_cert_chain)
        }
        Value::Array(values) => values.iter().find_map(coco_cert_chain),
        _ => None,
    }
}

fn bounded(der: Vec<u8>) -> Option<Vec<u8>> {
    (!der.is_empty() && der.len() <= MAX_EVIDENCE_CERTIFICATE_DER_BYTES).then_some(der)
}

fn named_bytes(value: &Value, normalized_names: &[&str]) -> Option<Vec<u8>> {
    match value {
        Value::Object(map) => {
            for (key, candidate) in map {
                let normalized = normalize_json_key(key);
                if normalized_names.contains(&normalized.as_str())
                    && let Some(bytes) = bytes_value(candidate)
                {
                    return Some(bytes);
                }
            }
            map.values()
                .find_map(|candidate| named_bytes(candidate, normalized_names))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|candidate| named_bytes(candidate, normalized_names)),
        _ => None,
    }
}

fn normalize_json_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn bytes_value(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(raw) => bytes_string(raw),
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_u64().and_then(|number| u8::try_from(number).ok()))
            .collect(),
        _ => None,
    }
}

/// PEM certificate, `0x`-optional hex, or any base64 alphabet.
pub(crate) fn bytes_string(raw: &str) -> Option<Vec<u8>> {
    let value = raw.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.contains("BEGIN CERTIFICATE") {
        let b64: String = value
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        return B64_STANDARD.decode(b64.as_bytes()).ok();
    }
    if value.len().is_multiple_of(2) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(value).ok();
    }
    B64_STANDARD
        .decode(value.as_bytes())
        .or_else(|_| URL_SAFE.decode(value.as_bytes()))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value.as_bytes()))
        .ok()
}
