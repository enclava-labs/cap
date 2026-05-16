import base64
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cap_hermes_proof.py"
SPEC = importlib.util.spec_from_file_location("cap_hermes_proof", SCRIPT_PATH)
proof = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = proof
SPEC.loader.exec_module(proof)


class CapHermesProofTests(unittest.TestCase):
    def test_ce_v1_hash_uses_length_prefixed_records(self):
        expected_bytes = (
            struct.pack(">H", 7)
            + b"purpose"
            + struct.pack(">I", 4)
            + b"test"
            + struct.pack(">H", 1)
            + b"x"
            + struct.pack(">I", 1)
            + b"y"
        )

        self.assertEqual(proof.ce_v1_bytes([("purpose", b"test"), ("x", b"y")]), expected_bytes)
        self.assertEqual(
            proof.ce_v1_hash([("purpose", b"test"), ("x", b"y")]),
            hashlib.sha256(expected_bytes).digest(),
        )

    def test_manifest_digest_and_signature_are_extracted_recursively(self):
        manifest = {
            "metadata": {"signature": "abc"},
            "descriptor": {
                "image_digest": (
                    "ghcr.io/example/app@"
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            },
        }

        self.assertEqual(
            proof.extract_manifest_digest(manifest),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertTrue(proof.manifest_has_signature(manifest))

    def test_manifest_digest_accepts_hermes_policy_workload_image(self):
        manifest = {
            "expected": {
                "workload_image": (
                    "ghcr.io/enclava-ai/hermes-agent-enclava@"
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )
            }
        }

        self.assertEqual(
            proof.extract_manifest_digest(manifest),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )

    def test_detached_manifest_signature_bundle_counts_as_signed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "hermes-policy.json"
            manifest_path.write_text("{}", encoding="utf-8")
            bundle_path = Path(f"{manifest_path}.sigstore.json")
            bundle_path.write_text('{"bundle": true}', encoding="utf-8")

            self.assertTrue(proof.detached_manifest_signature_exists(manifest_path))
            self.assertEqual(proof.detached_manifest_signature_path(manifest_path), bundle_path)

    def test_cosign_verify_blob_args_include_identity_and_bundle(self):
        args = proof.cosign_verify_blob_args(
            Path("/tmp/policy.json"),
            Path("/tmp/policy.json.sigstore.json"),
            "https://github.com/example/repo/.github/workflows/build.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        )

        self.assertEqual(args[0], "cosign")
        self.assertIn("--bundle", args)
        self.assertIn("--certificate-identity", args)
        self.assertEqual(args[-1], "/tmp/policy.json")

    def test_config_ready_finds_boolean_and_string_values(self):
        self.assertTrue(proof.find_bool_key({"nested": {"config_ready": "ok"}}, {"config_ready"}))
        self.assertFalse(proof.find_bool_key({"configReady": "false"}, {"configReady"}))
        self.assertIsNone(proof.find_bool_key({"ready": True}, {"config_ready"}))

    def test_extract_report_data_from_json_hex_and_raw_snp_offset(self):
        expected = b"a" * 64
        raw = bytearray(b"\x00" * 0x90)
        raw[0x50:0x90] = expected

        self.assertEqual(
            proof.extract_report_data({"attestation_report": {"report_data": expected.hex()}}),
            expected,
        )
        self.assertEqual(proof.extract_report_data({"quote": base64.b64encode(raw).decode()}), expected)

    def test_attestation_validation_accepts_nonce_domain_spki_and_report_data(self):
        domain = "demo.example.test"
        nonce = b"\x11" * 32
        nonce_b64 = base64.urlsafe_b64encode(nonce).decode().rstrip("=")
        leaf = b"\x22" * 32
        receipt = b"\x33" * 32
        report_data = proof.tee_report_data(domain, nonce, leaf, receipt)
        evidence_json = {"attestation_report": {"report_data": report_data.hex()}}
        payload = json.dumps(evidence_json).encode()
        response = {
            "nonce": nonce_b64,
            "runtime_data_binding": {
                "domain": domain,
                "leaf_spki_sha256": leaf.hex(),
                "receipt_pubkey_sha256": receipt.hex(),
            },
            "evidence": {
                "payload_b64": base64.b64encode(payload).decode(),
                "json": evidence_json,
            },
        }

        evidence_hash, detail = proof.validate_attestation_response(
            response,
            expected_nonce=nonce_b64,
            expected_domain=domain,
            leaf_spki_sha256_hex=leaf.hex(),
        )

        self.assertEqual(evidence_hash, hashlib.sha256(payload).hexdigest())
        self.assertIn("report_data", detail)

    def test_attestation_validation_rejects_nonce_mismatch(self):
        response = {
            "nonce": "wrong",
            "runtime_data_binding": {},
            "evidence": {"payload_b64": ""},
        }

        with self.assertRaisesRegex(proof.ProofError, "nonce mismatch"):
            proof.validate_attestation_response(
                response,
                expected_nonce="expected",
                expected_domain="demo.example.test",
                leaf_spki_sha256_hex="00" * 32,
            )

    def test_attestation_validation_rejects_invalid_receipt_hash_cleanly(self):
        nonce = base64.urlsafe_b64encode(b"\x11" * 32).decode().rstrip("=")
        response = {
            "nonce": nonce,
            "runtime_data_binding": {
                "domain": "demo.example.test",
                "leaf_spki_sha256": "00" * 32,
                "receipt_pubkey_sha256": "not-hex",
            },
            "evidence": {"payload_b64": base64.b64encode(b"{}").decode()},
        }

        with self.assertRaisesRegex(proof.ProofError, "receipt_pubkey_sha256"):
            proof.validate_attestation_response(
                response,
                expected_nonce=nonce,
                expected_domain="demo.example.test",
                leaf_spki_sha256_hex="00" * 32,
            )

    def test_render_results_is_demo_readable(self):
        output = proof.render_results(
            [
                proof.CheckResult(proof.PASS, "CAP API health", "ok"),
                proof.CheckResult(proof.SKIP, "Hermes API", "API_SERVER_KEY is not set."),
            ]
        )

        self.assertIn("CAP/Hermes proof", output)
        self.assertIn("[PASS]", output)
        self.assertIn("[SKIP]", output)

    def test_load_json_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text('{"image_digest": "sha256:' + ("a" * 64) + '"}', encoding="utf-8")

            loaded = proof.load_json_file(path)

        self.assertEqual(proof.extract_manifest_digest(loaded), "sha256:" + ("a" * 64))


if __name__ == "__main__":
    unittest.main()
