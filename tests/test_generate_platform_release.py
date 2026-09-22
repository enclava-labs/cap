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


def test_release_generator_scheme_check_is_case_insensitive():
    # Parity with the Rust validators (parsed-URL scheme): HTTPS:// is a
    # valid scheme, not a rejected prefix.
    payload = base_payload()
    payload["trustee_kbs_url"] = "HTTPS://kbs.example.test:8080"
    payload["tenant_caddy_acme_ca"] = "HTTPS://acme.example.test/directory"

    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_http_acme_ca():
    payload = base_payload()
    payload["tenant_caddy_acme_ca"] = "http://acme.example.test/directory"

    with pytest.raises(ValueError, match="tenant_caddy_acme_ca must be https"):
        generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_hostless_https_kbs_url():
    # `https://` and `https:` parse with scheme https but no host; the Rust
    # consumers (url crate) reject them (EmptyHost), so the generator must
    # not sign such an envelope.
    for value in ("https://", "https:", "HTTPS://"):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_hostless_https_acme_ca():
    for value in ("https://", "https:"):
        payload = base_payload()
        payload["tenant_caddy_acme_ca"] = value

        with pytest.raises(ValueError, match="tenant_caddy_acme_ca must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_malformed_port_kbs_url():
    # `https://kbs.example:bad/` and out-of-range ports parse fine in
    # urlparse (scheme https, host set), but the Rust consumers reject them
    # at reqwest::Url::parse — the generator must not sign such an envelope.
    for value in ("https://kbs.example.test:bad/", "https://kbs.example.test:99999"):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_malformed_port_acme_ca():
    for value in (
        "https://acme.example.test:bad/directory",
        "https://acme.example.test:99999/directory",
    ):
        payload = base_payload()
        payload["tenant_caddy_acme_ca"] = value

        with pytest.raises(ValueError, match="tenant_caddy_acme_ca must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_invalid_host_characters():
    # Space / percent in the host are forbidden domain code points in the
    # WHATWG URL parser (what reqwest::Url uses), so reject at sign time.
    for value in ("https://kbs.example.test /", "https://kbs%.example.test/"):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_valid_boundary_ports():
    payload = base_payload()
    payload["trustee_kbs_url"] = "https://kbs.example.test:65535"
    payload["tenant_caddy_acme_ca"] = "https://acme.example.test:1/directory"

    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_whatwg_forbidden_host_chars():
    # <, >, ^, |, `, {, } survive Python urlparse but are forbidden domain
    # code points in the WHATWG parser (reqwest::Url) — reject at sign time.
    for ch in ("<", ">", "^", "|", "`", "{", "}"):
        payload = base_payload()
        payload["trustee_kbs_url"] = f"https://kbs.example{ch}test/"

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_off_loopback_http_signing_url():
    # Mirror of the Rust rule: http is only for loopback/cluster-internal
    # signing services; cleartext off-cluster must not be signed.
    for value in (
        "http://signing.example.test:8123/",
        "http://10.0.0.1:8123/",
        "ftp://signing.example.test/",
        "https://signing.example.test:bad/",
    ):
        payload = base_payload()
        payload["signing_service_url"] = value

        with pytest.raises(ValueError, match="signing_service_url"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_loopback_and_cluster_http_signing_url():
    payload = base_payload()
    payload["signing_service_url"] = "http://signing.release.svc:8123/"
    generate_platform_release.validate_payload(payload)

    payload = base_payload()
    payload["signing_service_url"] = "http://127.0.0.1:8123/"
    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_backslash_userinfo_signing_url_bypass():
    # Devin: Python urlparse splits userinfo at the LAST "@", WHATWG at the
    # first — so `http://evil.example\@signing.release.svc` has hostname
    # `signing.release.svc` in Python but host `evil.example` in reqwest.
    # The cleartext-host gate must not check the wrong host.
    for value in (
        "http://evil.example\\@signing.release.svc",
        "http://user:pass@signing.release.svc",
        "https://kbs.example.test\\@evil.example/",
    ):
        payload = base_payload()
        payload["signing_service_url"] = value

        with pytest.raises(ValueError, match="signing_service_url"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_idna_invalid_unicode_hosts():
    # Codex: a non-breaking space (or other code point the WHATWG/UTS46
    # pipeline rejects) passes Python's urlparse and the ASCII denylist but
    # makes reqwest::Url::parse fail with "invalid international domain
    # name" — signing it would produce an unloadable envelope.
    # U+FF1C (fullwidth less-than) is a confirmed double rejection: UTS46
    # maps it to forbidden "<" and the url crate fails IDNA on it too.
    for value in (
        "https://kbs .example.test/",
        "https://kbs＜.example.test/",
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_valid_unicode_idna_host():
    # Positive control: a genuinely valid IDN that reqwest::Url::parse
    # accepts (münchen.example.test -> xn--mnchen-3ya.example.test) must
    # still be signable — the IDNA gate is not a blanket Unicode ban.
    # The idna package is a declared dependency (scripts/requirements.txt);
    # if the environment lacks it the generator fail-closed rejects all
    # non-ASCII hosts, so skip the positive control there rather than
    # depend on an incidental package.
    pytest.importorskip("idna")
    payload = base_payload()
    payload["trustee_kbs_url"] = "https://münchen.example.test/"
    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_invalid_ascii_ace_labels():
    # Codex P2 (cap#165): an ASCII but malformed ACE label like `xn--`
    # (empty Punycode payload) or `xn--mnchen-3ya-` (bad delimiter) passes
    # urlparse and the character denylist, but the url crate's IDNA
    # processing rejects it — the generator must not sign such a host.
    pytest.importorskip("idna")
    for value in (
        "https://xn--/",
        "https://xn--.example.test/",
        "https://xn--mnchen-3ya-.example.test/",
        "https://kbs.xn--/ ",
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_valid_ascii_ace_labels():
    # Positive control: a well-formed ACE label round-trips through
    # idna.encode and must remain signable.
    pytest.importorskip("idna")
    payload = base_payload()
    payload["trustee_kbs_url"] = "https://xn--mnchen-3ya.example.test/"
    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_whatwg_ipv4_ending_host_shapes():
    # WHATWG runs the IPv4 parser when the last label is numeric; Python
    # urlparse leaves `1.2.3.4.5` / `999.1.1.1` untouched in .hostname but
    # reqwest rejects them ("invalid IPv4 address").
    for value in (
        "https://1.2.3.4.5/",
        "https://999.1.1.1/",
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_idna_normalized_ipv4_overflow():
    # Codex P2: fullwidth digits (U+FF10-U+FF19) are numeric per WHATWG
    # but not recognized as decimal by _label_looks_numeric. After UTS46
    # normalization they become regular digits, triggering the IPv4 check.
    # Example: "０＆#120717; is fullwidth "x" (U+FF58), " gou" is invalid hex.
    # More direct: U+FF18 (fullwidth 8) normalizes to "8", so "０＆#120717;
    # becomes "0x100000000" (overflows IPv4).
    pytest.importorskip("idna")
    for value in (
        "https://０＆#120717;/",  # fullwidth "8" -> 8, but the hex part is invalid
        "https://０＆#120720;/",  # fullwidth "0" + "x" + hex digits
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_valid_ipv4_host():
    payload = base_payload()
    payload["trustee_kbs_url"] = "https://192.168.0.1/"
    generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_bracketed_non_ipv6_hosts():
    # Codex P2: `https://[v1.fe80]/` is an IPvFuture form — urlparse
    # reports hostname `v1.fe80` (passes the ASCII denylist, last label
    # isn't numeric), but reqwest::Url::parse rejects it ("invalid IPv6
    # address"). WHATWG allows brackets only for literal IPv6.
    for value in (
        "https://[v1.fe80]/",
        "https://[v1.fe80]:8443/",
        "https://[fe80::1%25eth0]/",
        "https://[not_ipv6]/",
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value

        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)

        payload = base_payload()
        payload["tenant_caddy_acme_ca"] = value

        with pytest.raises(ValueError, match="tenant_caddy_acme_ca must be https"):
            generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_valid_ipv6_hosts():
    # Positive control: a literal IPv6 address the url crate accepts.
    payload = base_payload()
    payload["trustee_kbs_url"] = "https://[2001:db8::1]/"
    generate_platform_release.validate_payload(payload)


def test_release_generator_accepts_ipv4_mapped_ipv6_hosts():
    # Codex P2 (cap#165 follow-up): urlparse's `.hostname` strips the
    # brackets, so `https://[::ffff:192.0.2.128]/` reaches _host_ok as
    # `::ffff:192.0.2.128`; its dotted tail previously tripped the WHATWG
    # IPv4-ending rule even though the url crate (WHATWG parser) accepts
    # and normalizes the URL. Valid IPv6 — mapped forms included — must
    # pass for KBS, ACME, and signing-service endpoints alike.
    for value in (
        "https://[::ffff:192.0.2.128]/",
        "https://[::ffff:192.0.2.128]:8443/",
        "https://[2001:db8:0:0:0:0:192.0.2.1]/",
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value
        generate_platform_release.validate_payload(payload)

        payload = base_payload()
        payload["tenant_caddy_acme_ca"] = value
        generate_platform_release.validate_payload(payload)

        # https signing-service URL lane exercises the same checks.
        payload = base_payload()
        payload["signing_service_url"] = value
        generate_platform_release.validate_payload(payload)


def test_release_generator_rejects_invalid_unbracketed_colon_hosts():
    # The `:`-bearing host branch must fail closed: anything that is not
    # a strict IPv6 literal (e.g. a port-colon leak or garbage) stays
    # rejected instead of falling through to the domain checks.
    for value in (
        "https://kbs.example:notaport/",
        "https://[::ffff:192.0.2.999]/",  # invalid embedded IPv4
    ):
        payload = base_payload()
        payload["trustee_kbs_url"] = value
        with pytest.raises(ValueError, match="trustee_kbs_url must be https"):
            generate_platform_release.validate_payload(payload)
