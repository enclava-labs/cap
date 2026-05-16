#!/usr/bin/env python3
"""Demo-readable CAP/Hermes end-to-end proof verifier.

The live checks intentionally stay outside kubectl/ops-manifest territory:
CAP API state, public app health, confidential endpoint status, nonce-bound
attestation, deployment digest evidence, optional signed manifest evidence,
and one optional Hermes API probe.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import secrets
import ssl
import struct
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback is best effort.
    tomllib = None  # type: ignore[assignment]


PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclasses.dataclass
class CheckResult:
    status: str
    name: str
    detail: str


@dataclasses.dataclass
class HttpResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class ProofError(Exception):
    """Expected proof-validation failure."""


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


def normalize_digest(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if "@sha256:" in value:
        return value.rsplit("@", 1)[1]
    if value.startswith("sha256:"):
        return value
    if len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value):
        return f"sha256:{value.lower()}"
    return value


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def first_string_at_keys(value: Any, keys: set[str]) -> str | None:
    if isinstance(value, dict):
        for key, candidate in value.items():
            if key in keys and isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        for candidate in value.values():
            found = first_string_at_keys(candidate, keys)
            if found:
                return found
    elif isinstance(value, list):
        for candidate in value:
            found = first_string_at_keys(candidate, keys)
            if found:
                return found
    return None


def extract_manifest_digest(manifest: Any) -> str | None:
    digest = first_string_at_keys(
        manifest,
        {
            "image_digest",
            "image_ref",
            "workload_image",
            "digest",
            "expected_image_digest",
            "expected_workload_image",
            "container_image_digest",
        },
    )
    return normalize_digest(digest)


def manifest_has_signature(manifest: Any) -> bool:
    if isinstance(manifest, dict):
        for key, value in manifest.items():
            normalized = key.lower()
            if normalized in {"signature", "signatures", "receipt", "signed_policy_artifact"}:
                return bool(value)
            if normalized.endswith("_signature") and value:
                return True
        return any(manifest_has_signature(value) for value in manifest.values())
    if isinstance(manifest, list):
        return any(manifest_has_signature(value) for value in manifest)
    return False


def detached_manifest_signature_exists(manifest_path: Path) -> bool:
    return detached_manifest_signature_path(manifest_path) is not None


def detached_manifest_signature_path(manifest_path: Path) -> Path | None:
    for candidate in (
        Path(f"{manifest_path}.sigstore.json"),
        manifest_path.with_suffix(manifest_path.suffix + ".sigstore.json"),
        manifest_path.with_name(manifest_path.name + ".sigstore.json"),
    ):
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate
    return None


def cosign_verify_blob_args(
    manifest_path: Path,
    bundle_path: Path,
    certificate_identity: str,
    certificate_oidc_issuer: str,
) -> list[str]:
    return [
        "cosign",
        "verify-blob",
        "--bundle",
        str(bundle_path),
        "--certificate-identity",
        certificate_identity,
        "--certificate-oidc-issuer",
        certificate_oidc_issuer,
        str(manifest_path),
    ]


def verify_cosign_blob(
    manifest_path: Path,
    bundle_path: Path,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    timeout: float,
) -> str:
    result = subprocess.run(
        cosign_verify_blob_args(
            manifest_path,
            bundle_path,
            certificate_identity,
            certificate_oidc_issuer,
        ),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cosign verify-blob failed").strip()
        raise ProofError(detail[:360])
    return (result.stdout or result.stderr or "cosign verify-blob succeeded").strip()


def find_bool_key(value: Any, key_names: set[str]) -> bool | None:
    if isinstance(value, dict):
        for key, candidate in value.items():
            if key in key_names:
                if isinstance(candidate, bool):
                    return candidate
                if isinstance(candidate, str):
                    lowered = candidate.strip().lower()
                    if lowered in {"true", "yes", "1", "ready", "ok"}:
                        return True
                    if lowered in {"false", "no", "0", "not_ready", "error"}:
                        return False
        for candidate in value.values():
            found = find_bool_key(candidate, key_names)
            if found is not None:
                return found
    elif isinstance(value, list):
        for candidate in value:
            found = find_bool_key(candidate, key_names)
            if found is not None:
                return found
    return None


def health_is_ok(status_code: int, body: bytes) -> tuple[bool, str]:
    text = body.decode("utf-8", errors="replace").strip()
    if not 200 <= status_code < 300:
        return False, f"HTTP {status_code}: {text[:160]}"
    if not text:
        return True, f"HTTP {status_code}"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        if text.lower() == "ok" or "ok" in text.lower():
            return True, text[:160]
        return True, f"HTTP {status_code}: {text[:160]}"
    if parsed is True:
        return True, "JSON true"
    if isinstance(parsed, dict):
        if parsed.get("ok") is True or str(parsed.get("status", "")).lower() == "ok":
            return True, json.dumps(parsed, sort_keys=True)[:220]
        if parsed.get("healthy") is True or parsed.get("ready") is True:
            return True, json.dumps(parsed, sort_keys=True)[:220]
    return True, json.dumps(parsed, sort_keys=True)[:220]


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


def load_cli_defaults() -> tuple[str | None, str | None, str | None]:
    root = Path.home() / ".enclava"
    api_url = None
    token = None
    org = None
    if tomllib is None:
        return api_url, token, org
    config_path = root / "config.toml"
    if config_path.exists():
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        api_url = data.get("api_url")
        org = data.get("org")
    creds_path = root / "credentials.toml"
    if creds_path.exists():
        data = tomllib.loads(creds_path.read_text(encoding="utf-8"))
        token = data.get("session_token") or data.get("api_key")
    return api_url, token, org


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 20.0,
    insecure_tls: bool = False,
) -> HttpResult:
    request = urllib.request.Request(url, method=method.upper(), headers=headers or {}, data=body)
    context = ssl._create_unverified_context() if insecure_tls else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return HttpResult(
                url=url,
                status_code=response.status,
                headers=dict(response.headers.items()),
                body=response.read(),
            )
    except urllib.error.HTTPError as err:
        return HttpResult(
            url=url,
            status_code=err.code,
            headers=dict(err.headers.items()),
            body=err.read(),
        )


def join_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def bearer_headers(token: str | None, org: str | None = None) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if org:
        headers["X-Enclava-Org"] = org
    return headers


def latest_deployment(deployments: Any) -> dict[str, Any] | None:
    if not isinstance(deployments, list) or not deployments:
        return None
    return deployments[0] if isinstance(deployments[0], dict) else None


def fetch_leaf_spki_sha256(host: str, port: int, timeout: float) -> str:
    s_client = subprocess.run(
        [
            "openssl",
            "s_client",
            "-servername",
            host,
            "-connect",
            f"{host}:{port}",
        ],
        input=b"",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    output = s_client.stdout + s_client.stderr
    begin = output.find(b"-----BEGIN CERTIFICATE-----")
    end = output.find(b"-----END CERTIFICATE-----")
    if begin == -1 or end == -1:
        raise ProofError("openssl s_client did not return a leaf certificate")
    cert_pem = output[begin : end + len(b"-----END CERTIFICATE-----")]
    pubkey = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"],
        input=cert_pem,
        capture_output=True,
        timeout=timeout,
        check=True,
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pubkey,
        capture_output=True,
        timeout=timeout,
        check=True,
    ).stdout
    return hashlib.sha256(spki).hexdigest()


def render_results(results: list[CheckResult]) -> str:
    width = max([len(result.name) for result in results] + [10])
    lines = ["CAP/Hermes proof", "=" * 16]
    for result in results:
        wrapped = textwrap.wrap(result.detail, width=92 - width, subsequent_indent=" " * (width + 9))
        if not wrapped:
            wrapped = [""]
        first, *rest = wrapped
        lines.append(f"[{result.status:<4}] {result.name:<{width}} {first}")
        lines.extend(rest)
    return "\n".join(lines)


def add_http_check(
    results: list[CheckResult],
    name: str,
    func,
) -> Any | None:
    try:
        return func()
    except Exception as err:
        results.append(CheckResult(FAIL, name, str(err)))
        return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    cli_api_url, cli_token, cli_org = load_cli_defaults()
    parser = argparse.ArgumentParser(
        description="Verify a demo-readable CAP/Hermes end-to-end proof.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--api-url", default=os.getenv("CAP_API_URL") or cli_api_url)
    parser.add_argument(
        "--api-token",
        default=os.getenv("CAP_API_TOKEN") or os.getenv("ENCLAVA_API_TOKEN") or cli_token,
    )
    parser.add_argument("--org", default=os.getenv("CAP_ORG") or cli_org)
    parser.add_argument("--app", default=os.getenv("CAP_APP_NAME") or os.getenv("APP"))
    parser.add_argument("--expected-image-digest", default=os.getenv("EXPECTED_IMAGE_DIGEST"))
    parser.add_argument("--manifest", type=Path, default=os.getenv("CAP_PROOF_MANIFEST"))
    parser.add_argument("--require-signed-manifest", action="store_true")
    parser.add_argument("--require-cosign-verify", action="store_true")
    parser.add_argument("--cosign-certificate-identity", default=os.getenv("CAP_PROOF_COSIGN_IDENTITY"))
    parser.add_argument(
        "--cosign-certificate-oidc-issuer",
        default=os.getenv("CAP_PROOF_COSIGN_ISSUER"),
    )
    parser.add_argument("--public-health-url", default=os.getenv("CAP_PUBLIC_HEALTH_URL"))
    parser.add_argument("--public-health-path", default=os.getenv("CAP_PUBLIC_HEALTH_PATH", "/health"))
    parser.add_argument("--confidential-base-url", default=os.getenv("CAP_CONFIDENTIAL_BASE_URL"))
    parser.add_argument("--config-ready-optional", action="store_true")
    parser.add_argument("--allow-status", action="append", default=["running", "healthy", "deployed", "ready"])
    parser.add_argument("--skip-attestation", action="store_true")
    parser.add_argument("--insecure-tls", action="store_true")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--hermes-api-url", default=os.getenv("HERMES_API_URL"))
    parser.add_argument("--hermes-api-path", default=os.getenv("HERMES_API_PATH", "/health"))
    parser.add_argument("--hermes-method", default=os.getenv("HERMES_METHOD", "GET"))
    parser.add_argument("--hermes-auth-header", default=os.getenv("HERMES_AUTH_HEADER", "X-API-Key"))
    parser.add_argument("--hermes-body", default=os.getenv("HERMES_BODY"))
    parser.add_argument("--api-server-key", default=os.getenv("API_SERVER_KEY"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    results: list[CheckResult] = []

    if not args.api_url:
        results.append(CheckResult(FAIL, "inputs", "CAP API URL missing; pass --api-url or set CAP_API_URL."))
    if not args.app:
        results.append(CheckResult(FAIL, "inputs", "CAP app name missing; pass --app or set CAP_APP_NAME."))
    if not args.api_token:
        results.append(CheckResult(FAIL, "inputs", "CAP API token missing; pass --api-token or log in with enclava CLI."))
    if any(result.status == FAIL for result in results):
        print(render_results(results))
        return 1

    manifest_digest = None
    if args.manifest:
        manifest_path = Path(args.manifest)
        try:
            manifest = load_json_file(manifest_path)
            manifest_digest = extract_manifest_digest(manifest)
            inline_signature = manifest_has_signature(manifest)
            detached_signature = detached_manifest_signature_path(manifest_path)
            signature_present = inline_signature or detached_signature is not None
            cosign_verified = False
            if detached_signature and args.cosign_certificate_identity and args.cosign_certificate_oidc_issuer:
                verify_cosign_blob(
                    manifest_path,
                    detached_signature,
                    args.cosign_certificate_identity,
                    args.cosign_certificate_oidc_issuer,
                    args.timeout,
                )
                cosign_verified = True
            if detached_signature and cosign_verified:
                signature_text = "detached signature bundle cosign verified"
            elif detached_signature and not inline_signature:
                signature_text = "detached signature bundle present"
            elif inline_signature:
                signature_text = "signature present"
            else:
                signature_text = "signature not found"
            if args.require_cosign_verify and not cosign_verified:
                status = FAIL
                if not detached_signature:
                    signature_text = "cosign verification required but detached bundle not found"
                elif not args.cosign_certificate_identity or not args.cosign_certificate_oidc_issuer:
                    signature_text = "cosign verification required but identity/issuer missing"
            elif args.require_signed_manifest and not signature_present:
                status = FAIL
            elif signature_present:
                status = PASS
            else:
                status = WARN
            sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            detail = f"{manifest_path} sha256={sha256}; digest={manifest_digest or 'not found'}; {signature_text}"
            results.append(CheckResult(status, "signed manifest", detail))
        except Exception as err:
            results.append(CheckResult(FAIL, "signed manifest", f"{args.manifest}: {err}"))
    elif args.require_signed_manifest:
        results.append(CheckResult(FAIL, "signed manifest", "--require-signed-manifest was set but no --manifest was provided."))
    else:
        results.append(CheckResult(SKIP, "signed manifest", "No manifest file supplied."))

    expected_digest = normalize_digest(args.expected_image_digest) or manifest_digest

    cap_health = add_http_check(
        results,
        "CAP API health",
        lambda: http_request(join_url(args.api_url, "/health"), timeout=args.timeout, insecure_tls=args.insecure_tls),
    )
    if cap_health:
        ok, detail = health_is_ok(cap_health.status_code, cap_health.body)
        results.append(CheckResult(PASS if ok else FAIL, "CAP API health", detail))

    auth = bearer_headers(args.api_token, args.org)
    app_status_resp = add_http_check(
        results,
        "CAP app status",
        lambda: http_request(
            join_url(args.api_url, f"/apps/{urllib.parse.quote(args.app)}/status"),
            headers=auth,
            timeout=args.timeout,
            insecure_tls=args.insecure_tls,
        ),
    )
    app_status = None
    app_domain = None
    if app_status_resp:
        try:
            app_status = app_status_resp.json()
            app_domain = app_status.get("domain") if isinstance(app_status, dict) else None
            status = str(app_status.get("status", "")).lower() if isinstance(app_status, dict) else ""
            allowed = {item.lower() for item in args.allow_status}
            if app_status_resp.status_code != 200:
                results.append(CheckResult(FAIL, "CAP app status", f"HTTP {app_status_resp.status_code}: {app_status_resp.text[:220]}"))
            elif status in allowed:
                results.append(CheckResult(PASS, "CAP app status", f"{args.app} status={status}; domain={app_domain or 'n/a'}"))
            else:
                results.append(CheckResult(FAIL, "CAP app status", f"{args.app} status={status or 'missing'}; allowed={sorted(allowed)}"))
        except Exception as err:
            results.append(CheckResult(FAIL, "CAP app status", f"invalid JSON: {err}; body={app_status_resp.text[:220]}"))

    deployments_resp = add_http_check(
        results,
        "deployment digest",
        lambda: http_request(
            join_url(args.api_url, f"/apps/{urllib.parse.quote(args.app)}/deployments"),
            headers=auth,
            timeout=args.timeout,
            insecure_tls=args.insecure_tls,
        ),
    )
    if deployments_resp:
        try:
            deployments = deployments_resp.json()
            latest = latest_deployment(deployments)
            deployed_digest = normalize_digest(latest.get("image_digest") if latest else None)
            if deployments_resp.status_code != 200:
                results.append(CheckResult(FAIL, "deployment digest", f"HTTP {deployments_resp.status_code}: {deployments_resp.text[:220]}"))
            elif not latest:
                results.append(CheckResult(FAIL, "deployment digest", "No deployments returned for app."))
            elif not expected_digest:
                results.append(CheckResult(WARN, "deployment digest", f"latest deployment digest={deployed_digest or 'missing'}; no expected digest supplied."))
            elif deployed_digest == expected_digest:
                results.append(CheckResult(PASS, "deployment digest", f"latest deployment {latest.get('deployment_id') or latest.get('id')} matches {expected_digest}"))
            else:
                results.append(CheckResult(FAIL, "deployment digest", f"latest deployment digest={deployed_digest}; expected={expected_digest}"))
        except Exception as err:
            results.append(CheckResult(FAIL, "deployment digest", f"invalid JSON: {err}; body={deployments_resp.text[:220]}"))

    public_health_url = args.public_health_url
    if not public_health_url and app_domain:
        public_health_url = join_url(f"https://{app_domain}", args.public_health_path)
    public_health_json = None
    if public_health_url:
        public_resp = add_http_check(
            results,
            "public health",
            lambda: http_request(public_health_url, timeout=args.timeout, insecure_tls=args.insecure_tls),
        )
        if public_resp:
            ok, detail = health_is_ok(public_resp.status_code, public_resp.body)
            try:
                public_health_json = public_resp.json()
            except Exception:
                public_health_json = None
            results.append(CheckResult(PASS if ok else FAIL, "public health", f"{public_health_url}: {detail}"))
    else:
        results.append(CheckResult(FAIL, "public health", "No domain from CAP status and no --public-health-url supplied."))

    confidential_base = args.confidential_base_url
    if not confidential_base and app_domain:
        confidential_base = f"https://{app_domain}/.well-known/confidential"

    confidential_status_json = None
    if confidential_base:
        confidential_resp = add_http_check(
            results,
            "confidential status",
            lambda: http_request(join_url(confidential_base, "/status"), timeout=args.timeout, insecure_tls=args.insecure_tls),
        )
        if confidential_resp:
            try:
                confidential_status_json = confidential_resp.json()
                if confidential_resp.status_code == 200:
                    summary = json.dumps(confidential_status_json, sort_keys=True)[:260]
                    results.append(CheckResult(PASS, "confidential status", summary))
                else:
                    results.append(CheckResult(FAIL, "confidential status", f"HTTP {confidential_resp.status_code}: {confidential_resp.text[:220]}"))
            except Exception as err:
                results.append(CheckResult(FAIL, "confidential status", f"invalid JSON: {err}; body={confidential_resp.text[:220]}"))

        config_ready = find_bool_key(confidential_status_json, {"config_ready", "configReady"}) if confidential_status_json is not None else None
        if config_ready is None and public_health_json is not None:
            config_ready = find_bool_key(public_health_json, {"config_ready", "configReady"})
        if config_ready is True:
            results.append(CheckResult(PASS, "config_ready", "config_ready=true"))
        elif config_ready is False:
            results.append(CheckResult(FAIL, "config_ready", "config_ready=false"))
        elif args.config_ready_optional:
            results.append(CheckResult(WARN, "config_ready", "No config_ready field exposed by confidential status or public health."))
        else:
            results.append(CheckResult(FAIL, "config_ready", "No config_ready field exposed; pass --config-ready-optional only for apps that do not report it."))

        if args.skip_attestation:
            results.append(CheckResult(SKIP, "attestation", "--skip-attestation set."))
        else:
            try:
                parsed = urllib.parse.urlparse(confidential_base)
                host = parsed.hostname
                port = parsed.port or 443
                if not host:
                    raise ProofError("confidential URL has no host")
                leaf_hex = fetch_leaf_spki_sha256(host, port, args.timeout)
                nonce = secrets.token_bytes(32)
                nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
                attestation_url = join_url(confidential_base, "/attestation")
                query = urllib.parse.urlencode(
                    {
                        "nonce": nonce_b64,
                        "domain": host,
                        "leaf_spki_sha256": leaf_hex,
                    }
                )
                separator = "&" if "?" in attestation_url else "?"
                attestation_resp = http_request(
                    f"{attestation_url}{separator}{query}",
                    timeout=args.timeout,
                    insecure_tls=args.insecure_tls,
                )
                if attestation_resp.status_code != 200:
                    raise ProofError(f"HTTP {attestation_resp.status_code}: {attestation_resp.text[:220]}")
                evidence_hash, detail = validate_attestation_response(
                    attestation_resp.json(),
                    expected_nonce=nonce_b64,
                    expected_domain=host,
                    leaf_spki_sha256_hex=leaf_hex,
                )
                results.append(CheckResult(PASS, "attestation", f"{detail}; evidence_sha256={evidence_hash}"))
            except Exception as err:
                results.append(CheckResult(FAIL, "attestation", str(err)))
    else:
        results.append(CheckResult(FAIL, "confidential status", "No domain from CAP status and no --confidential-base-url supplied."))

    if args.api_server_key:
        hermes_base = args.hermes_api_url
        if not hermes_base and app_domain:
            hermes_base = f"https://{app_domain}"
        if not hermes_base:
            results.append(CheckResult(FAIL, "Hermes API", "API_SERVER_KEY is set but no Hermes URL or CAP app domain is available."))
        else:
            hermes_url = join_url(hermes_base, args.hermes_api_path)
            header_value = args.api_server_key
            if args.hermes_auth_header.lower() == "authorization" and not header_value.lower().startswith("bearer "):
                header_value = f"Bearer {header_value}"
            headers = {
                "Accept": "application/json",
                args.hermes_auth_header: header_value,
            }
            body = args.hermes_body.encode("utf-8") if args.hermes_body else None
            if body:
                headers["Content-Type"] = "application/json"
            hermes_resp = add_http_check(
                results,
                "Hermes API",
                lambda: http_request(
                    hermes_url,
                    method=args.hermes_method,
                    headers=headers,
                    body=body,
                    timeout=args.timeout,
                    insecure_tls=args.insecure_tls,
                ),
            )
            if hermes_resp:
                ok, detail = health_is_ok(hermes_resp.status_code, hermes_resp.body)
                results.append(CheckResult(PASS if ok else FAIL, "Hermes API", f"{args.hermes_method.upper()} {hermes_url}: {detail}"))
    else:
        results.append(CheckResult(SKIP, "Hermes API", "API_SERVER_KEY is not set."))

    print(render_results(results))
    return 1 if any(result.status == FAIL for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
