import base64
import unittest

from sdk.assertion.builder import build_assertion, build_assertion_skeleton
from sdk.identity.did_resolver import did_from_pubkey
from sdk.types import DeviceAuthResponse


class AssertionBuilderTests(unittest.TestCase):
    def setUp(self):
        self.pubkey = bytes.fromhex("01" * 32 + "02" * 32)
        self.did = did_from_pubkey(self.pubkey)
        self.challenge = {
            "origin": "local://openclaw",
            "action": "bash",
            "requiredIssuerDID": self.did,
            "actionHash": "ab" * 32,
            "nonce": "11" * 8,
            "issuedAt": "2026-04-04T10:00:00Z",
            "display": {
                "title": "命令执行确认",
                "summary": "删除目录 /tmp/demo",
                "risk": "high",
                "source": "local://openclaw",
            },
            "params": {"cmd": "rm -rf /tmp/demo"},
        }

    def test_build_skeleton(self):
        skeleton = build_assertion_skeleton(self.challenge, self.did)
        self.assertEqual(skeleton["device"]["id"], self.did)
        self.assertNotIn("proof", skeleton)

    def test_build_assertion_uses_derived_did(self):
        response = DeviceAuthResponse(
            protocol="0.3",
            matched_id=1,
            score=188,
            sensor_serial="aa" * 32,
            nonce="11" * 8,
            signed_hash="",
            signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
            pubkey=base64.b64encode(self.pubkey).decode("ascii"),
        )
        assertion = build_assertion(self.challenge, response)
        self.assertEqual(assertion["device"]["id"], self.did)
        self.assertEqual(assertion["proof"]["verificationMethod"], f"{self.did}#key-0")
        self.assertEqual(assertion["subject"]["localId"], "slot-01")


if __name__ == "__main__":
    unittest.main()
