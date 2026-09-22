#!/usr/bin/env python3
"""Generate or check crates/enclava-cli/platform-release.json.

Production releases must pass ENCLAVA_PLATFORM_RELEASE_SIGNING_KEY_HEX as a
32-byte Ed25519 seed. The --dev-fixture-key option is only for the checked-in
development artifact verified by enclava-cli's fallback fixture root.

Python dependencies (cryptography, idna) are declared in requirements.txt
next to this script: pip install -r requirements.txt
"""


import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


DEV_FIXTURE_SIGNING_KEY_HEX = "c0" * 32
DEFAULT_RELEASE_PATH = Path(__file__).resolve().parents[1] / "platform-release.json"
GHCR_DIGEST_RE = re.compile(
    r"^ghcr\.io/enclava-labs/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
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


# WHATWG forbidden domain code points that Python's urlparse does NOT treat
# as delimiters (it only splits on / ? #): everything in this set (plus
# control/0x7F chars) makes the url crate reject the host, so the generator
# must reject it too rather than sign an unloadable envelope.
_FORBIDDEN_HOST_CHARS = set(" #%<>@[\\]^|`{}")


def _label_looks_numeric(label: str) -> bool:
    # WHATWG treats a host whose last label is a (decimal or 0x-hex) number
    # as an IPv4 address and runs the full IPv4 parser on it; Python's
    # urlparse happily leaves `1.2.3.4.5` or `999.1.1.1` in .hostname.
    if label.isdigit():
        return True
    return len(label) > 2 and label.lower().startswith("0x") and all(
        ch in "0123456789abcdef" for ch in label[2:].lower()
    )


def _idna_ok(host: str) -> bool:
    # Non-ASCII hosts go through the same UTS46/IDNA2008 processing the url
    # crate performs (stdlib .encode("idna") is IDNA2003 and accepts inputs
    # like a non-breaking space that the url crate rejects, so it cannot be
    # used here). If the `idna` package is unavailable, fail closed: reject
    # every non-ASCII host rather than risk signing an unloadable envelope.
    if host.isascii():
        return True
    try:
        import idna  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        idna.encode(host, uts46=True)
    except (idna.IDNAError, UnicodeError, ValueError):
        return False
    return True


def _host_ok(host: str) -> bool:
    # Bracketed hosts (netloc `[...]`): WHATWG only allows brackets for
    # literal IPv6 addresses — IPvFuture forms like `[v1.fe80]` pass
    # urlparse (hostname `v1.fe80`) but the url crate rejects them
    # ("invalid IPv6 address"), so validate the bracket content as strict
    # IPv6. A zone index (`[fe80::1%25eth0]`) is also rejected: the url
    # crate rejects it for https, and a release URL must never carry one.
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        if "%" in inner:
            return False
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return False
        return True
    if any(
        ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _FORBIDDEN_HOST_CHARS
        for ch in host
    ):
        return False
    if not _idna_ok(host):
        return False
    # WHATWG IPv4 ending rule (see _label_looks_numeric): when the last
    # label is numeric the whole host must be a valid IPv4 address or the
    # url crate rejects it. IPv4Address is stricter than WHATWG for exotic
    # forms (pure-integer `12345`, hex/octal octets) — rejecting those is
    # generator-stricter, which is the safe direction.
    bare = host.rstrip(".")
    if bare:
        last_label = bare.rsplit(".", 1)[-1]
        if _label_looks_numeric(last_label):
            try:
                ipaddress.IPv4Address(bare)
            except ValueError:
                return False
    return True


def _authority_ok(netloc: str) -> bool:
    # Bracketed hosts: WHATWG only allows brackets for literal IPv6.
    # urlparse's `.hostname` STRIPS the brackets, so IPvFuture forms like
    # `[v1.fe80]` reach host checks as `v1.fe80` (a plausible hostname),
    # while the url crate rejects the whole URL ("invalid IPv6 address").
    # Validate the bracket content here, on the raw netloc. A zone index
    # (`[fe80::1%25eth0]`) is rejected too — the url crate rejects it for
    # special schemes, and a release URL must never carry one.
    host_part = netloc.rsplit("@", 1)[-1]
    if host_part.startswith("["):
        end = host_part.find("]")
        if end == -1:
            return False
        inner = host_part[1:end]
        if "%" in inner:
            return False
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return False
        # Nothing but an optional :port may follow the bracket.
        if host_part[end + 1 :] and not host_part[end + 1 :].startswith(":"):
            return False
    # Python's urlparse and the WHATWG parser disagree on netloc structure:
    # urlparse splits userinfo at the LAST "@" and treats "\" as an ordinary
    # character, while WHATWG ends the authority at the first "\" (special
    # schemes) and first "@". A URL like
    #   http://evil.example\@signing.release.svc
    # therefore has hostname `signing.release.svc` in Python but host
    # `evil.example` in the url crate — the cleartext-host gate would check
    # the wrong host. No legitimate release URL carries userinfo or a
    # backslash, so reject both outright in the authority.
    return "@" not in netloc and "\\" not in netloc


def _is_https(value: str) -> bool:
    # urlparse lowercases the scheme, so `HTTPS://` is accepted exactly as
    # the Rust validators (parsed-URL scheme) accept it. The authority is
    # checked with the same semantics the Rust consumers (url crate)
    # enforce, so a release ceremony cannot sign metadata the API/CLI would
    # refuse to load:
    #   * a non-empty host is required (url crate rejects hostless values
    #     like `https://` or `https:` with EmptyHost),
    #   * reading `.port` raises ValueError for non-numeric or
    #     out-of-range ports (`https://kbs.example:bad/`, `:99999`),
    #   * forbidden domain code points in the host are rejected (see
    #     _FORBIDDEN_HOST_CHARS).
    try:
        parsed = urlparse(value)
        parsed.port  # noqa: B018 — property access raises for malformed ports
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme != "https" or not host:
        return False
    if not _authority_ok(parsed.netloc):
        return False
    return _host_ok(host)


def _plain_http_host_allowed(host: str) -> bool:
    # Mirror of enclava_common::hostnames::plain_http_host_allowed: cleartext
    # is only for loopback or cluster-internal signing services.
    if host.lower() == "localhost":
        return True
    bare = host.strip("[]")
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return bare.lower().endswith((".svc", ".svc.cluster.local"))


def _is_valid_signing_service_url(value: str) -> bool:
    # Mirror of the Rust validate_release_payload rule for
    # signing_service_url: parseable URL, scheme http or https, and http is
    # only allowed for loopback/cluster-internal hosts (the bearer token
    # must not transit cleartext off-cluster).
    try:
        parsed = urlparse(value)
        parsed.port  # noqa: B018 — property access raises for malformed ports
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not host:
        return False
    if not _authority_ok(parsed.netloc):
        return False
    if not _host_ok(host):
        return False
    if parsed.scheme == "http":
        return _plain_http_host_allowed(host)
    return True


def validate_payload(payload: dict[str, str], *, allow_dev_internal_tls: bool = False) -> None:
    if payload["schema_version"] != "v1":
        raise ValueError("schema_version must be v1")
    if not _is_valid_signing_service_url(payload["signing_service_url"]):
        raise ValueError(
            "signing_service_url must be a valid http(s) URL "
            "(http only for loopback/cluster-internal hosts)"
        )
    for field in ["attestation_proxy_image", "caddy_ingress_image"]:
        if not GHCR_DIGEST_RE.fullmatch(payload[field]):
            raise ValueError(f"{field} must be a ghcr.io/enclava-labs digest-pinned ref")
    if not _is_https(payload["trustee_kbs_url"]):
        raise ValueError("trustee_kbs_url must be https")
    if payload["tenant_caddy_tls_mode"] not in ("acme", "dns01-broker", "internal"):
        raise ValueError("tenant_caddy_tls_mode must be acme, dns01-broker, or internal")
    if payload["tenant_caddy_tls_mode"] == "internal" and not allow_dev_internal_tls:
        raise ValueError(
            "tenant_caddy_tls_mode=internal is only allowed with --dev-fixture-key"
        )
    if not _is_https(payload["tenant_caddy_acme_ca"]):
        raise ValueError("tenant_caddy_acme_ca must be https")
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
