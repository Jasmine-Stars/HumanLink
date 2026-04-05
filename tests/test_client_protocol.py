import base64
import tempfile
import unittest
from pathlib import Path

import yaml

from sdk.client import HumanLinkClient
from sdk.hardware.protocol import DeviceProtocolError
from sdk.identity.did_resolver import did_from_pubkey
from sdk.verifier import HumanLinkVerifier


class FakeBridge:
    def __init__(self, response):
        self.response = response
        self.sent = []

    def send_json(self, message):
        self.sent.append(message)

    def read_json(self, timeout_seconds=None):
        return dict(self.response)


class ClientProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.config_path = str(Path(self.tempdir.name) / "config.yaml")
        self.pubkey = bytes.fromhex(
            "1457247ffac5ba509274323a67816ca61dbbec307e92627734d7b60155ea4f8e"
            "44c56d3006191661631132679a37a673cd70a9c569229c3a44e1cc1984a757bf"
        )
        self.device_did = did_from_pubkey(self.pubkey)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                {
                    "device": {"did": self.device_did},
                    "db": {"path": str(Path(self.tempdir.name) / "humanlink.db")},
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

    def test_request_auth_rejects_nonce_mismatch(self):
        bridge = FakeBridge(
            {
                "status": "ok",
                "protocol": "0.3",
                "matched_id": 1,
                "score": 188,
                "sensor_serial": "aa" * 32,
                "nonce": "22" * 8,
                "signed_hash": "00" * 32,
                "sig": base64.b64encode(b"\x00" * 64).decode("ascii"),
                "pubkey": base64.b64encode(self.pubkey).decode("ascii"),
            }
        )
        client = HumanLinkClient(bridge=bridge)
        with self.assertRaises(DeviceProtocolError):
            client.request_auth(self.challenge)

    def test_request_auth_rejects_did_mismatch(self):
        other_pubkey = bytes.fromhex("01" * 32 + "02" * 32)
        bridge = FakeBridge(
            {
                "status": "ok",
                "protocol": "0.3",
                "matched_id": 1,
                "score": 188,
                "sensor_serial": "aa" * 32,
                "nonce": self.challenge["nonce"],
                "signed_hash": "00" * 32,
                "sig": base64.b64encode(b"\x00" * 64).decode("ascii"),
                "pubkey": base64.b64encode(other_pubkey).decode("ascii"),
            }
        )
        client = HumanLinkClient(bridge=bridge)
        with self.assertRaises(DeviceProtocolError):
            client.request_auth(self.challenge)


if __name__ == "__main__":
    unittest.main()
