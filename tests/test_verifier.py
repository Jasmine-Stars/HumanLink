import base64
import tempfile
import unittest
from pathlib import Path

import yaml

from sdk.assertion.builder import build_assertion
from sdk.types import DeviceAuthResponse
from sdk.verifier import HumanLinkVerifier


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.config_path = str(Path(self.tempdir.name) / "config.yaml")
        self.pubkey = bytes.fromhex("01" * 32 + "02" * 32)
        self.device_did = "did:key:z2oAt2GGBM5x5u1nRprDG7K6tvJtx8DbDeTzM7LAwroNmF"
        with open(self.config_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                {
                    "device": {"did": self.device_did},
                    "db": {"path": str(Path(self.tempdir.name) / "humanlink.db")},
                    "verification": {"chain_check": "skip", "min_match_score": 100},
                },
                handle,
                sort_keys=True,
            )
        self.verifier = HumanLinkVerifier(self.config_path)
        self.challenge = self.verifier.create_challenge(
            action="bash",
            action_params={"cmd": "rm -rf /tmp/demo"},
            display_title="命令执行确认",
            display_summary="删除目录 /tmp/demo",
            risk="high",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _build_assertion(self):
        response = DeviceAuthResponse(
            protocol="0.3",
            matched_id=1,
            score=188,
            sensor_serial="aa" * 32,
            nonce=self.challenge["nonce"],
            signed_hash="",
            signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
            pubkey=base64.b64encode(self.pubkey).decode("ascii"),
        )
        return build_assertion(self.challenge, response)

    def test_create_challenge_contains_origin_and_params(self):
        self.assertEqual(self.challenge["origin"], "local://openclaw")
        self.assertEqual(self.challenge["params"]["cmd"], "rm -rf /tmp/demo")

    def test_verify_rejects_device_binding_mismatch(self):
        assertion = self._build_assertion()
        result = self.verifier.verify(assertion, self.challenge)
        self.assertFalse(result.valid)
        self.assertEqual(result.failure_reason, "DEVICE_BINDING_MISMATCH")

    def test_verify_rejects_action_hash_mismatch(self):
        self.challenge["requiredIssuerDID"] = assertion_did = self._build_assertion()["device"]["id"]
        assertion = self._build_assertion()
        assertion["challenge"]["actionHash"] = "00" * 32
        result = self.verifier.verify(assertion, self.challenge)
        self.assertFalse(result.valid)
        self.assertEqual(result.failure_reason, "ACTION_HASH_MISMATCH")


if __name__ == "__main__":
    unittest.main()
