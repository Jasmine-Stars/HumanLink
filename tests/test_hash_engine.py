import unittest

from sdk.crypto.hash_engine import build_action_hash, canonicalize_json, compute_h_doc, rebuild_signed_hash


class HashEngineTests(unittest.TestCase):
    def test_action_hash_uses_sorted_params(self):
        a = build_action_hash(
            action="transfer",
            params={"currency": "USD", "amount": 500, "recipient": "Alice"},
            nonce="a1f3b7c2d4e56789",
            required_issuer_did="did:key:zExample",
        )
        b = build_action_hash(
            action="transfer",
            params={"recipient": "Alice", "amount": 500, "currency": "USD"},
            nonce="a1f3b7c2d4e56789",
            required_issuer_did="did:key:zExample",
        )
        self.assertEqual(a, b)

    def test_action_hash_changes_with_nonce_and_did(self):
        base = build_action_hash("bash", {"cmd": "rm -rf /tmp/x"}, "0011223344556677", "did:key:z1")
        changed_nonce = build_action_hash("bash", {"cmd": "rm -rf /tmp/x"}, "1111223344556677", "did:key:z1")
        changed_did = build_action_hash("bash", {"cmd": "rm -rf /tmp/x"}, "0011223344556677", "did:key:z2")
        self.assertNotEqual(base, changed_nonce)
        self.assertNotEqual(base, changed_did)

    def test_h_doc_ignores_field_order(self):
        first = {"b": 2, "a": {"z": 1, "x": 2}}
        second = {"a": {"x": 2, "z": 1}, "b": 2}
        self.assertEqual(canonicalize_json(first), canonicalize_json(second))
        self.assertEqual(compute_h_doc(first), compute_h_doc(second))

    def test_signed_hash_rebuild(self):
        sensor_serial = bytes.fromhex("aa" * 32)
        nonce = bytes.fromhex("11" * 8)
        h_doc = bytes.fromhex("22" * 32)
        signed_hash = rebuild_signed_hash(1, 188, sensor_serial, nonce, h_doc)
        self.assertEqual(len(signed_hash), 32)


if __name__ == "__main__":
    unittest.main()
