#!/usr/bin/env python3
"""One-command public appraiser API v1 conformance check."""

import argparse
import base64
import hashlib
import json
import struct
import urllib.request


def ce(records):
    return b"".join(
        struct.pack(">H", len(label)) + label.encode() + struct.pack(">I", len(value)) + value
        for label, value in records
    )


def result_hash(result):
    checks = []
    for check in result["checks"]:
        checks.append(ce([
            ("id", check["id"].encode()),
            ("outcome", check["outcome"].encode()),
            ("observed_present", b"1" if check["observed"] is not None else b"0"),
            ("observed", (check["observed"] or "").encode()),
            ("expected_present", b"1" if check["expected"] is not None else b"0"),
            ("expected", (check["expected"] or "").encode()),
            ("reason_code", check["reason_code"].encode()),
        ]))
    records = [
        ("purpose", b"enclava-appraisal-result-v1"),
        ("verdict", result["verdict"].encode()),
        ("bundle_sha256", result["bundle_sha256"].encode()),
        ("policy_sha256", result["policy_sha256"].encode()),
        ("target_origin", result["target_origin"].encode()),
        ("challenge_nonce", result["challenge_nonce"].encode()),
        ("verified_at", str(result["verified_at"]).encode()),
        ("verifier_version", result["verifier_version"].encode()),
        *(("check", check) for check in checks),
        *(("warning", warning.encode()) for warning in result["warnings"]),
    ]
    return hashlib.sha256(ce(records)).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint", help="appraiser base URL, for example https://appraiser.example")
    parser.add_argument("--header", action="append", default=[], metavar="NAME:VALUE")
    args = parser.parse_args()
    nonce = bytes(32)
    body = json.dumps({
        "bundle_base64": "",
        "policy_base64": base64.b64encode(b"{}").decode(),
        "challenge_nonce_base64url": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
        "expected_target_origin": "https://fixture.example",
    }, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/vnd.enclava.appraisal-request.v1+json"}
    headers.update(dict(header.split(":", 1) for header in args.header))
    request = urllib.request.Request(
        args.endpoint.rstrip("/") + "/v1/appraise", body, headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200
        assert response.headers.get_content_type() == "application/vnd.enclava.appraisal-response.v1+json"
        assert response.headers.get("Cache-Control") == "no-store"
        appraisal = json.load(response)
    result = appraisal["result"]
    assert result["verdict"] == "FAIL"
    assert result["target_origin"] == "https://fixture.example"
    assert result["challenge_nonce"] == nonce.hex()
    assert any(check["reason_code"] == "MALFORMED_BUNDLE" for check in result["checks"])
    assert appraisal["result_sha256"] == result_hash(result)
    print(f"PASS {appraisal['result_sha256']}")


if __name__ == "__main__":
    main()
