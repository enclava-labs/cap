#!/usr/bin/env python3
"""Generate or check crates/enclava-cli/platform-release.json.

Production releases must pass ENCLAVA_PLATFORM_RELEASE_SIGNING_KEY_HEX as a
32-byte Ed25519 seed. The --dev-fixture-key option is only for the checked-in
development artifact verified by enclava-cli's fallback fixture root.
"""


import argparse
import copy
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


DEV_FIXTURE_SIGNING_KEY_HEX = "c0" * 32
DEFAULT_RELEASE_PATH = Path(__file__).resolve().parents[1] / "platform-release.json"
GHCR_DIGEST_RE = re.compile(
    r"^ghcr\.io/enclava-labs/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
DIGEST_PINNED_RE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


def ce_v1_bytes(records: list[tuple[str, bytes]]) -> bytes:
    out = bytearray()
    for label, value in records:
        label_bytes = label.encode()
        out.extend(len(label_bytes).to_bytes(2, "big"))
        out.extend(label_bytes)
        out.extend(len(value).to_bytes(4, "big"))
        out.extend(value)
    return bytes(out)


def hex32_bytes(field: str, value: str) -> bytes:
    value = value.strip()
    if not HEX32_RE.fullmatch(value):
        raise ValueError(f"{field} must be 32 lowercase hex bytes")
    return bytes.fromhex(value)


def canonical_platform_release_bytes(payload: dict[str, str]) -> bytes:
    return ce_v1_bytes(
        [
            ("purpose", b"enclava-platform-release-v1"),
            ("schema_version", payload["schema_version"].encode()),
            (
                "platform_release_version",
                payload["platform_release_version"].encode(),
            ),
            ("signing_service_url", payload["signing_service_url"].encode()),
            (
                "signing_service_pubkey",
                hex32_bytes(
                    "signing_service_pubkey_hex",
                    payload["signing_service_pubkey_hex"],
                ),
            ),
            ("policy_template_id", payload["policy_template_id"].encode()),
            (
                "policy_template_sha256",
                hex32_bytes(
                    "policy_template_sha256",
                    payload["policy_template_sha256"],
                ),
            ),
            ("policy_template_text", payload["policy_template_text"].encode()),
            ("attestation_proxy_image", payload["attestation_proxy_image"].encode()),
            ("caddy_ingress_image", payload["caddy_ingress_image"].encode()),
            ("trustee_kbs_url", payload["trustee_kbs_url"].encode()),
            ("trustee_kbs_ca_cert_pem", payload["trustee_kbs_ca_cert_pem"].encode()),
            ("tenant_caddy_tls_mode", payload["tenant_caddy_tls_mode"].encode()),
            ("tenant_caddy_acme_ca", payload["tenant_caddy_acme_ca"].encode()),
            (
                "expected_firmware_measurement",
                hex32_bytes(
                    "expected_firmware_measurement",
                    payload["expected_firmware_measurement"],
                ),
            ),
            ("expected_runtime_class", payload["expected_runtime_class"].encode()),
            ("genpolicy_version", payload["genpolicy_version"].encode()),
            ("created_at", payload["created_at"].encode()),
        ]
    )


def env_overlay(payload: dict[str, str]) -> dict[str, str]:
    out = copy.deepcopy(payload)
    mapping = {
        "PLATFORM_RELEASE_VERSION": "platform_release_version",
        "SIGNING_SERVICE_URL": "signing_service_url",
        "SIGNING_SERVICE_PUBKEY_HEX": "signing_service_pubkey_hex",
        "POLICY_TEMPLATE_ID": "policy_template_id",
        "ATTESTATION_PROXY_IMAGE": "attestation_proxy_image",
        "CADDY_INGRESS_IMAGE": "caddy_ingress_image",
        "TRUSTEE_KBS_URL": "trustee_kbs_url",
        "TRUSTEE_KBS_CA_CERT_PEM": "trustee_kbs_ca_cert_pem",
        "TENANT_CADDY_TLS_MODE": "tenant_caddy_tls_mode",
        "TENANT_CADDY_ACME_CA": "tenant_caddy_acme_ca",
        "EXPECTED_FIRMWARE_MEASUREMENT": "expected_firmware_measurement",
        "EXPECTED_RUNTIME_CLASS": "expected_runtime_class",
        "GENPOLICY_VERSION": "genpolicy_version",
        "CREATED_AT": "created_at",
    }
    for env_name, field in mapping.items():
        if os.environ.get(env_name):
            out[field] = os.environ[env_name]

    template_path = os.environ.get("POLICY_TEMPLATE_PATH")
    if template_path:
        out["policy_template_text"] = Path(template_path).read_text()
    elif os.environ.get("POLICY_TEMPLATE_TEXT"):
        out["policy_template_text"] = os.environ["POLICY_TEMPLATE_TEXT"]

    out["policy_template_sha256"] = hashlib.sha256(
        out["policy_template_text"].encode()
    ).hexdigest()
    return out


def validate_payload(payload: dict[str, str], *, allow_dev_internal_tls: bool = False) -> None:
    if payload["schema_version"] != "v1":
        raise ValueError("schema_version must be v1")
    for field in ["attestation_proxy_image", "caddy_ingress_image"]:
        if allow_dev_internal_tls:
            if not DIGEST_PINNED_RE.fullmatch(payload[field]):
                raise ValueError(f"{field} must be a digest-pinned ref")
        elif not GHCR_DIGEST_RE.fullmatch(payload[field]):
            raise ValueError(f"{field} must be a ghcr.io/enclava-labs digest-pinned ref")
    if not payload["trustee_kbs_url"].startswith("https://"):
        raise ValueError("trustee_kbs_url must be https")
    if payload["tenant_caddy_tls_mode"] not in ("acme", "dns01-broker", "internal"):
        raise ValueError("tenant_caddy_tls_mode must be acme, dns01-broker, or internal")
    if payload["tenant_caddy_tls_mode"] == "internal" and not allow_dev_internal_tls:
        raise ValueError(
            "tenant_caddy_tls_mode=internal is only allowed with --dev-fixture-key"
        )
    if not payload["tenant_caddy_acme_ca"].startswith(("http://", "https://")):
        raise ValueError("tenant_caddy_acme_ca must be http or https")
    hex32_bytes("signing_service_pubkey_hex", payload["signing_service_pubkey_hex"])
    hex32_bytes("policy_template_sha256", payload["policy_template_sha256"])
    hex32_bytes(
        "expected_firmware_measurement", payload["expected_firmware_measurement"]
    )
    actual = hashlib.sha256(payload["policy_template_text"].encode()).hexdigest()
    if actual != payload["policy_template_sha256"]:
        raise ValueError("policy_template_sha256 does not match policy_template_text")


def signing_seed(args: argparse.Namespace) -> str:
    if args.dev_fixture_key:
        return DEV_FIXTURE_SIGNING_KEY_HEX
    value = os.environ.get("ENCLAVA_PLATFORM_RELEASE_SIGNING_KEY_HEX")
    if value:
        return value
    raise SystemExit(
        "set ENCLAVA_PLATFORM_RELEASE_SIGNING_KEY_HEX or pass --dev-fixture-key"
    )


def generate(args: argparse.Namespace) -> str:
    base = json.loads(args.input.read_text())
    payload = env_overlay(base["payload"])
    validate_payload(payload, allow_dev_internal_tls=args.dev_fixture_key)

    seed = hex32_bytes("ENCLAVA_PLATFORM_RELEASE_SIGNING_KEY_HEX", signing_seed(args))
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(canonical_platform_release_bytes(payload))
    envelope = {
        "payload": payload,
        "signature": signature.hex(),
        "signing_pubkey": public_key.hex(),
    }
    return json.dumps(envelope, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_RELEASE_PATH)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--dev-fixture-key",
        action="store_true",
        help=(
            "sign with the checked-in non-production fixture key; also permits "
            "dev-only internal tenant Caddy TLS"
        ),
    )
    args = parser.parse_args()

    rendered = generate(args)
    if args.check:
        current = args.input.read_text()
        if current != rendered:
            sys.stderr.write(f"{args.input} is not up to date\n")
            return 1
        return 0
    if args.output:
        args.output.write_text(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
