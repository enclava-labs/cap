#!/usr/bin/env python3
"""Demo-readable CAP/Hermes end-to-end proof verifier."""

import argparse
import base64
import hashlib
import json
import secrets
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from cap_hermes_proof_args import parse_args
from cap_hermes_proof_attestation import validate_attestation_response
from cap_hermes_proof_support import (
    FAIL,
    PASS,
    SKIP,
    WARN,
    CheckResult,
    ProofError,
    add_http_check,
    bearer_headers,
    detached_manifest_signature_path,
    extract_manifest_digest,
    fetch_leaf_spki_sha256,
    find_bool_key,
    health_is_ok,
    http_request,
    join_url,
    latest_deployment,
    load_json_file,
    manifest_has_signature,
    normalize_digest,
    render_results,
    verify_cosign_blob,
)


def validate_inputs(args: argparse.Namespace, results: list[CheckResult]) -> bool:
    if not args.api_url:
        results.append(CheckResult(FAIL, "inputs", "CAP API URL missing; pass --api-url or set CAP_API_URL."))
    if not args.app:
        results.append(CheckResult(FAIL, "inputs", "CAP app name missing; pass --app or set CAP_APP_NAME."))
    if not args.api_token:
        detail = "CAP API token missing; pass --api-token or log in with enclava CLI."
        results.append(CheckResult(FAIL, "inputs", detail))
    return not any(result.status == FAIL for result in results)


def check_signed_manifest(args: argparse.Namespace, results: list[CheckResult]) -> str | None:
    if not args.manifest:
        if args.require_signed_manifest or args.require_cosign_verify:
            detail = "signed manifest or cosign verification was required but no --manifest was provided."
            results.append(CheckResult(FAIL, "signed manifest", detail))
        else:
            results.append(CheckResult(SKIP, "signed manifest", "No manifest file supplied."))
        return None

    manifest_path = Path(args.manifest)
    try:
        manifest = load_json_file(manifest_path)
        digest = extract_manifest_digest(manifest)
        inline_signature = manifest_has_signature(manifest)
        detached_signature = detached_manifest_signature_path(manifest_path)
        status, signature_text = signed_manifest_status(
            args, manifest_path, inline_signature, detached_signature
        )
        sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        detail = f"{manifest_path} sha256={sha256}; digest={digest or 'not found'}; {signature_text}"
        results.append(CheckResult(status, "signed manifest", detail))
        return digest
    except Exception as err:
        results.append(CheckResult(FAIL, "signed manifest", f"{args.manifest}: {err}"))
        return None


def signed_manifest_status(
    args: argparse.Namespace,
    manifest_path: Path,
    inline_signature: bool,
    detached_signature: Path | None,
) -> tuple[str, str]:
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

    if args.require_cosign_verify and not cosign_verified:
        if not detached_signature:
            return FAIL, "cosign verification required but detached bundle not found"
        return FAIL, "cosign verification required but identity/issuer missing"
    if args.require_signed_manifest and not signature_present:
        return FAIL, "signature not found"
    if detached_signature and cosign_verified:
        return PASS, "detached signature bundle cosign verified"
    if detached_signature and not inline_signature:
        return PASS, "detached signature bundle present"
    if inline_signature:
        return PASS, "signature present"
    return WARN, "signature not found"


def check_cap_api(args: argparse.Namespace, results: list[CheckResult]) -> tuple[dict[str, str], str | None]:
    cap_health = add_http_check(
        results,
        "CAP API health",
        lambda: http_request(join_url(args.api_url, "/health"), timeout=args.timeout, insecure_tls=args.insecure_tls),
    )
    if cap_health:
        ok, detail = health_is_ok(cap_health.status_code, cap_health.body)
        results.append(CheckResult(PASS if ok else FAIL, "CAP API health", detail))

    auth = bearer_headers(args.api_token, args.org)
    app_domain = check_app_status(args, results, auth)
    return auth, app_domain


def check_app_status(args: argparse.Namespace, results: list[CheckResult], auth: dict[str, str]) -> str | None:
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
    if not app_status_resp:
        return None
    try:
        app_status = app_status_resp.json()
        app_domain = app_status.get("domain") if isinstance(app_status, dict) else None
        status = str(app_status.get("status", "")).lower() if isinstance(app_status, dict) else ""
        allowed = {item.lower() for item in args.allow_status}
        if app_status_resp.status_code != 200:
            detail = f"HTTP {app_status_resp.status_code}: {app_status_resp.text[:220]}"
            results.append(CheckResult(FAIL, "CAP app status", detail))
        elif status in allowed:
            results.append(CheckResult(PASS, "CAP app status", f"{args.app} status={status}; domain={app_domain or 'n/a'}"))
        else:
            results.append(CheckResult(FAIL, "CAP app status", f"{args.app} status={status or 'missing'}; allowed={sorted(allowed)}"))
        return app_domain
    except Exception as err:
        detail = f"invalid JSON: {err}; body={app_status_resp.text[:220]}"
        results.append(CheckResult(FAIL, "CAP app status", detail))
        return None


def check_deployment_digest(
    args: argparse.Namespace,
    results: list[CheckResult],
    auth: dict[str, str],
    expected_digest: str | None,
) -> None:
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
    if not deployments_resp:
        return
    try:
        latest = latest_deployment(deployments_resp.json())
        deployed_digest = normalize_digest(latest.get("image_digest") if latest else None)
        append_deployment_result(args, results, deployments_resp, latest, deployed_digest, expected_digest)
    except Exception as err:
        detail = f"invalid JSON: {err}; body={deployments_resp.text[:220]}"
        results.append(CheckResult(FAIL, "deployment digest", detail))


def append_deployment_result(
    args: argparse.Namespace,
    results: list[CheckResult],
    response: Any,
    latest: dict[str, Any] | None,
    deployed_digest: str | None,
    expected_digest: str | None,
) -> None:
    if response.status_code != 200:
        results.append(CheckResult(FAIL, "deployment digest", f"HTTP {response.status_code}: {response.text[:220]}"))
    elif not latest:
        results.append(CheckResult(FAIL, "deployment digest", "No deployments returned for app."))
    elif not expected_digest:
        detail = f"latest deployment digest={deployed_digest or 'missing'}; no expected digest supplied."
        results.append(CheckResult(WARN, "deployment digest", detail))
    elif deployed_digest == expected_digest:
        deployment_id = latest.get("deployment_id") or latest.get("id")
        results.append(CheckResult(PASS, "deployment digest", f"latest deployment {deployment_id} matches {expected_digest}"))
    else:
        detail = f"latest deployment digest={deployed_digest}; expected={expected_digest}"
        results.append(CheckResult(FAIL, "deployment digest", detail))


def check_public_health(args: argparse.Namespace, results: list[CheckResult], app_domain: str | None) -> Any | None:
    public_health_url = args.public_health_url
    if not public_health_url and app_domain:
        public_health_url = join_url(f"https://{app_domain}", args.public_health_path)
    if not public_health_url:
        detail = "No domain from CAP status and no --public-health-url supplied."
        results.append(CheckResult(FAIL, "public health", detail))
        return None

    public_resp = add_http_check(
        results,
        "public health",
        lambda: http_request(public_health_url, timeout=args.timeout, insecure_tls=args.insecure_tls),
    )
    if not public_resp:
        return None
    ok, detail = health_is_ok(public_resp.status_code, public_resp.body)
    results.append(CheckResult(PASS if ok else FAIL, "public health", f"{public_health_url}: {detail}"))
    try:
        return public_resp.json()
    except Exception:
        return None


def check_confidential(
    args: argparse.Namespace,
    results: list[CheckResult],
    app_domain: str | None,
    public_health_json: Any | None,
) -> None:
    confidential_base = args.confidential_base_url or (f"https://{app_domain}/.well-known/confidential" if app_domain else None)
    if not confidential_base:
        detail = "No domain from CAP status and no --confidential-base-url supplied."
        results.append(CheckResult(FAIL, "confidential status", detail))
        return

    confidential_status_json = check_confidential_status(args, results, confidential_base)
    append_config_ready_result(args, results, confidential_status_json, public_health_json)
    if args.skip_attestation:
        results.append(CheckResult(SKIP, "attestation", "--skip-attestation set."))
    else:
        check_attestation(args, results, confidential_base)


def check_confidential_status(args: argparse.Namespace, results: list[CheckResult], confidential_base: str) -> Any | None:
    confidential_resp = add_http_check(
        results,
        "confidential status",
        lambda: http_request(join_url(confidential_base, "/status"), timeout=args.timeout, insecure_tls=args.insecure_tls),
    )
    if not confidential_resp:
        return None
    try:
        confidential_status_json = confidential_resp.json()
        if confidential_resp.status_code == 200:
            summary = json.dumps(confidential_status_json, sort_keys=True)[:260]
            results.append(CheckResult(PASS, "confidential status", summary))
        else:
            detail = f"HTTP {confidential_resp.status_code}: {confidential_resp.text[:220]}"
            results.append(CheckResult(FAIL, "confidential status", detail))
        return confidential_status_json
    except Exception as err:
        detail = f"invalid JSON: {err}; body={confidential_resp.text[:220]}"
        results.append(CheckResult(FAIL, "confidential status", detail))
        return None


def append_config_ready_result(
    args: argparse.Namespace,
    results: list[CheckResult],
    confidential_status_json: Any | None,
    public_health_json: Any | None,
) -> None:
    config_ready = find_bool_key(confidential_status_json, {"config_ready", "configReady"}) if confidential_status_json is not None else None
    if config_ready is None and public_health_json is not None:
        config_ready = find_bool_key(public_health_json, {"config_ready", "configReady"})
    if config_ready is True:
        results.append(CheckResult(PASS, "config_ready", "config_ready=true"))
    elif config_ready is False:
        results.append(CheckResult(FAIL, "config_ready", "config_ready=false"))
    elif args.config_ready_optional:
        detail = "No config_ready field exposed by confidential status or public health."
        results.append(CheckResult(WARN, "config_ready", detail))
    else:
        detail = "No config_ready field exposed; pass --config-ready-optional only for apps that do not report it."
        results.append(CheckResult(FAIL, "config_ready", detail))


def check_attestation(args: argparse.Namespace, results: list[CheckResult], confidential_base: str) -> None:
    try:
        parsed = urllib.parse.urlparse(confidential_base)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            raise ProofError("confidential URL has no host")
        leaf_hex = fetch_leaf_spki_sha256(host, port, args.timeout)
        nonce = secrets.token_bytes(32)
        nonce_b64 = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
        attestation_resp = fetch_attestation(args, confidential_base, host, leaf_hex, nonce_b64)
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


def fetch_attestation(args: argparse.Namespace, confidential_base: str, host: str, leaf_hex: str, nonce_b64: str) -> Any:
    attestation_url = join_url(confidential_base, "/attestation")
    query = urllib.parse.urlencode({"nonce": nonce_b64, "domain": host, "leaf_spki_sha256": leaf_hex})
    separator = "&" if "?" in attestation_url else "?"
    return http_request(
        f"{attestation_url}{separator}{query}",
        timeout=args.timeout,
        insecure_tls=args.insecure_tls,
    )


def check_hermes(args: argparse.Namespace, results: list[CheckResult], app_domain: str | None) -> None:
    if not args.api_server_key:
        results.append(CheckResult(SKIP, "Hermes API", "API_SERVER_KEY is not set."))
        return
    hermes_base = args.hermes_api_url or (f"https://{app_domain}" if app_domain else None)
    if not hermes_base:
        detail = "API_SERVER_KEY is set but no Hermes URL or CAP app domain is available."
        results.append(CheckResult(FAIL, "Hermes API", detail))
        return
    hermes_url = join_url(hermes_base, args.hermes_api_path)
    header_value = args.api_server_key
    if args.hermes_auth_header.lower() == "authorization" and not header_value.lower().startswith("bearer "):
        header_value = f"Bearer {header_value}"
    headers = {"Accept": "application/json", args.hermes_auth_header: header_value}
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
        label = f"{args.hermes_method.upper()} {hermes_url}: {detail}"
        results.append(CheckResult(PASS if ok else FAIL, "Hermes API", label))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    results: list[CheckResult] = []
    if not validate_inputs(args, results):
        print(render_results(results))
        return 1

    manifest_digest = check_signed_manifest(args, results)
    expected_digest = normalize_digest(args.expected_image_digest) or manifest_digest
    auth, app_domain = check_cap_api(args, results)
    check_deployment_digest(args, results, auth, expected_digest)
    public_health_json = check_public_health(args, results, app_domain)
    check_confidential(args, results, app_domain, public_health_json)
    check_hermes(args, results, app_domain)

    print(render_results(results))
    return 1 if any(result.status == FAIL for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
