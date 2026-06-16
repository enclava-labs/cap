import copy
import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "crates/enclava-cli/scripts/generate-platform-release.py"
spec = importlib.util.spec_from_file_location("generate_platform_release", SCRIPT)
generate_platform_release = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(generate_platform_release)


def base_payload() -> dict[str, str]:
    import json

    envelope = json.loads(
        (REPO_ROOT / "crates/enclava-cli/platform-release.json").read_text()
    )
    return copy.deepcopy(envelope["payload"])


def test_release_generator_rejects_http_kbs_url():
    payload = base_payload()
    payload["trustee_kbs_url"] = "http://kbs.example.test:8080"

    with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
        generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_internal_tls_without_dev_fixture_key():
    payload = base_payload()
    payload["tenant_caddy_tls_mode"] = "internal"

    with pytest.raises(ValueError, match="only allowed with --dev-fixture-key"):
        generate_platform_release.validate_payload(payload)


def test_release_generator_allows_internal_tls_with_dev_fixture_key():
    payload = base_payload()
    payload["tenant_caddy_tls_mode"] = "internal"

    generate_platform_release.validate_payload(payload, allow_dev_internal_tls=True)


def test_release_generator_allows_pullable_dev_fixture_images():
    payload = base_payload()
    payload["attestation_proxy_image"] = (
        "docker.io/library/alpine@sha256:"
        "c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
    )
    payload["caddy_ingress_image"] = (
        "docker.io/library/busybox@sha256:"
        "b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
    )

    generate_platform_release.validate_payload(payload, allow_dev_internal_tls=True)
