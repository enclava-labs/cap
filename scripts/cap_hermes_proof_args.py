import argparse
import os
from pathlib import Path

from cap_hermes_proof_support import load_cli_defaults


def arg_supplied(argv: list[str], name: str) -> bool:
    return any(item == name or item.startswith(f"{name}=") for item in argv)


def parse_args(argv: list[str]) -> argparse.Namespace:
    cli_api_url, cli_token, cli_org = load_cli_defaults()
    env_api_url = os.getenv("CAP_API_URL")
    env_api_token = os.getenv("CAP_API_TOKEN") or os.getenv("ENCLAVA_API_TOKEN")
    api_url_default = env_api_url or cli_api_url
    api_token_default = env_api_token or cli_token
    parser = argparse.ArgumentParser(
        description="Verify a demo-readable CAP/Hermes end-to-end proof.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--api-url", default=api_url_default)
    parser.add_argument(
        "--api-token",
        default=api_token_default,
    )
    parser.add_argument("--org", default=os.getenv("CAP_ORG") or cli_org)
    parser.add_argument("--app", default=os.getenv("CAP_APP_NAME") or os.getenv("APP"))
    parser.add_argument("--expected-image-digest", default=os.getenv("EXPECTED_IMAGE_DIGEST"))
    parser.add_argument("--manifest", type=Path, default=os.getenv("CAP_PROOF_MANIFEST"))
    parser.add_argument("--require-signed-manifest", action="store_true")
    parser.add_argument("--require-cosign-verify", action="store_true")
    parser.add_argument("--cosign-certificate-identity", default=os.getenv("CAP_PROOF_COSIGN_IDENTITY"))
    parser.add_argument("--cosign-certificate-oidc-issuer", default=os.getenv("CAP_PROOF_COSIGN_ISSUER"))
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
    args = parser.parse_args(argv)
    args._cli_api_url = cli_api_url
    args._api_url_source = (
        "arg"
        if arg_supplied(argv, "--api-url")
        else "env"
        if env_api_url
        else "cli"
        if cli_api_url
        else None
    )
    args._api_token_source = (
        "arg"
        if arg_supplied(argv, "--api-token")
        else "env"
        if env_api_token
        else "cli"
        if cli_token
        else None
    )
    return args
