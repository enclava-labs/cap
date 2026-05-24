import dataclasses
import hashlib
import json
import ssl
import subprocess
import textwrap
import urllib.error
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


def detached_manifest_signature_path(manifest_path: Path) -> Path | None:
    for candidate in (
        Path(f"{manifest_path}.sigstore.json"),
        manifest_path.with_suffix(manifest_path.suffix + ".sigstore.json"),
        manifest_path.with_name(manifest_path.name + ".sigstore.json"),
    ):
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate
    return None


def detached_manifest_signature_exists(manifest_path: Path) -> bool:
    return detached_manifest_signature_path(manifest_path) is not None


def sigstore_bundle_looks_valid(bundle_path: Path) -> bool:
    try:
        bundle = load_json_file(bundle_path)
    except Exception:
        return False
    if not isinstance(bundle, dict):
        return False
    has_media_type = isinstance(bundle.get("mediaType"), str) and bundle["mediaType"].strip()
    has_verification_material = isinstance(bundle.get("verificationMaterial"), dict)
    has_signed_content = any(
        key in bundle for key in ("messageSignature", "dsseEnvelope")
    )
    return bool(has_media_type and has_verification_material and has_signed_content)


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
    allow_redirects: bool = True,
) -> HttpResult:
    request = urllib.request.Request(url, method=method.upper(), headers=headers or {}, data=body)
    context = ssl._create_unverified_context() if insecure_tls else None
    handlers = []
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    if not allow_redirects:
        handlers.append(NoRedirectHandler())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpResult(
                url=url,
                status_code=response.status,
                headers=dict(response.headers.items()),
                body=response.read(),
            )
    except urllib.error.HTTPError as err:
        if not allow_redirects and 300 <= err.code < 400:
            location = err.headers.get("Location", "").strip() or "missing Location"
            raise ProofError(
                f"refused authenticated redirect from {url}: HTTP {err.code} -> {location}"
            ) from err
        return HttpResult(
            url=url,
            status_code=err.code,
            headers=dict(err.headers.items()),
            body=err.read(),
        )


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


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
