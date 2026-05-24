import base64
import hashlib
import json
import struct
from typing import Any

from cap_hermes_proof_support import ProofError


def ce_v1_bytes(records: list[tuple[str, bytes]]) -> bytes:
    out = bytearray()
    for label, value in records:
        label_bytes = label.encode("utf-8")
        out.extend(struct.pack(">H", len(label_bytes)))
        out.extend(label_bytes)
        out.extend(struct.pack(">I", len(value)))
        out.extend(value)
    return bytes(out)


def ce_v1_hash(records: list[tuple[str, bytes]]) -> bytes:
    return hashlib.sha256(ce_v1_bytes(records)).digest()


def tee_tls_transcript_hash(domain: str, nonce: bytes, leaf_spki_sha256: bytes) -> bytes:
    return ce_v1_hash(
        [
            ("purpose", b"enclava-tee-tls-v1"),
            ("domain", domain.encode("utf-8")),
            ("nonce", nonce),
            ("leaf_spki_sha256", leaf_spki_sha256),
        ]
    )


def tee_report_data(
    domain: str,
    nonce: bytes,
    leaf_spki_sha256: bytes,
    receipt_pubkey_sha256: bytes,
) -> bytes:
    transcript_hash = tee_tls_transcript_hash(domain, nonce, leaf_spki_sha256)
    binding_hash = ce_v1_hash(
        [
            ("purpose", b"enclava-tee-report-data-v1"),
            ("transcript_hash", transcript_hash),
            ("receipt_pubkey_sha256", receipt_pubkey_sha256),
        ]
    )
    return binding_hash.hex().encode("ascii")


def parse_bytes_value(value: Any) -> bytes | None:
    if isinstance(value, str):
        raw = value.strip()
        if raw.startswith("0x"):
            raw = raw[2:]
        if raw and len(raw) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in raw):
            try:
                return bytes.fromhex(raw)
            except ValueError:
                return None
        try:
            padded = raw + ("=" * (-len(raw) % 4))
            return base64.b64decode(padded, validate=True)
        except Exception:
            return raw.encode("utf-8") if raw else None
    if isinstance(value, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
        return bytes(value)
    return None


def normalized_key(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def extract_report_data(value: Any) -> bytes | None:
    if isinstance(value, dict):
        for key, candidate in value.items():
            key_norm = normalized_key(key)
            if key_norm in {"reportdata", "snpreportdata"}:
                parsed = parse_bytes_value(candidate)
                if parsed and len(parsed) == 64:
                    return parsed
            if key_norm in {
                "snpreport",
                "snpreportbytes",
                "rawsnpreport",
                "rawreport",
                "report",
                "quote",
                "attestationreport",
                "attestationreportbytes",
            }:
                parsed = parse_bytes_value(candidate)
                if parsed and len(parsed) >= 0x90:
                    return parsed[0x50:0x90]
        for candidate in value.values():
            found = extract_report_data(candidate)
            if found:
                return found
    elif isinstance(value, list):
        parsed = parse_bytes_value(value)
        if parsed and len(parsed) == 64:
            return parsed
        for candidate in value:
            found = extract_report_data(candidate)
            if found:
                return found
    return None


def validate_attestation_response(
    response: Any,
    *,
    expected_nonce: str,
    expected_domain: str,
    leaf_spki_sha256_hex: str,
) -> tuple[str, str]:
    if not isinstance(response, dict):
        raise ProofError("attestation response is not a JSON object")
    if response.get("nonce") != expected_nonce:
        raise ProofError("attestation nonce mismatch")

    binding = response.get("runtime_data_binding")
    if not isinstance(binding, dict):
        raise ProofError("attestation response missing runtime_data_binding")
    if binding.get("domain") != expected_domain:
        raise ProofError("attestation domain mismatch")
    if binding.get("leaf_spki_sha256") != leaf_spki_sha256_hex:
        raise ProofError("attestation leaf SPKI mismatch")

    receipt_hash = binding.get("receipt_pubkey_sha256")
    try:
        receipt_pubkey_sha256 = bytes.fromhex(receipt_hash) if isinstance(receipt_hash, str) else b""
    except ValueError as err:
        raise ProofError("attestation receipt_pubkey_sha256 is not a 32-byte hex digest") from err
    if len(receipt_pubkey_sha256) != 32:
        raise ProofError("attestation receipt_pubkey_sha256 is not a 32-byte hex digest")

    evidence = response.get("evidence")
    if not isinstance(evidence, dict):
        raise ProofError("attestation response missing evidence")
    payload_b64 = evidence.get("payload_b64")
    if not isinstance(payload_b64, str):
        raise ProofError("attestation evidence missing payload_b64")
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as err:
        raise ProofError(f"attestation evidence payload_b64 is invalid: {err}") from err

    nonce_bytes = base64.urlsafe_b64decode(expected_nonce + ("=" * (-len(expected_nonce) % 4)))
    expected_report_data = tee_report_data(
        expected_domain,
        nonce_bytes,
        bytes.fromhex(leaf_spki_sha256_hex),
        receipt_pubkey_sha256,
    )

    evidence_json = evidence.get("json")
    if evidence_json is None:
        try:
            evidence_json = json.loads(payload.decode("utf-8"))
        except Exception:
            evidence_json = None

    report_data = extract_report_data(evidence_json) if evidence_json is not None else None
    if report_data is None and len(payload) >= 0x90:
        report_data = payload[0x50:0x90]
    if report_data is not None and report_data != expected_report_data:
        raise ProofError("SNP report_data does not match nonce/TLS/receipt binding")

    evidence_hash = hashlib.sha256(payload).hexdigest()
    if report_data is None:
        return evidence_hash, "nonce/domain/SPKI binding checked; report_data not exposed in parseable form"
    return evidence_hash, "nonce/domain/SPKI/report_data binding checked"
