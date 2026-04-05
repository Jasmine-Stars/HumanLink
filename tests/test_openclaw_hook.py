import unittest

from apps.openclaw.openclaw_humanlink_hook import humanlink_approval


class FakeVerifier:
    def __init__(self):
        self.store = type("Store", (), {"write_audit": lambda *args, **kwargs: None})()

    def create_challenge(self, **kwargs):
        return {
            "origin": "local://openclaw",
            "action": kwargs["action"],
            "requiredIssuerDID": "did:key:zDevice",
            "actionHash": "aa" * 32,
            "nonce": "11" * 8,
            "issuedAt": "2026-04-04T10:00:00Z",
            "display": {
                "title": "命令执行确认",
                "summary": kwargs["display_summary"],
                "risk": kwargs["risk"],
                "source": "local://openclaw",
            },
            "params": kwargs["action_params"],
        }

    def verify(self, assertion, challenge):
        return type(
            "Result",
            (),
            {
                "valid": assertion["ok"],
                "failure_step": None if assertion["ok"] else 9,
                "failure_reason": None if assertion["ok"] else "SIGNATURE_INVALID",
                "assertion_id": "urn:uuid:test",
                "device_did": "did:key:zDevice",
                "chain_checked": False,
                "to_dict": lambda self: {"verified_at": "2026-04-04T10:00:01Z"},
            },
        )()


class FakeClient:
    def __init__(self, ok=True, error=None):
        self.ok = ok
        self.error = error

    def request_auth(self, challenge, timeout_seconds=30):
        if self.error:
            raise self.error
        return {"ok": self.ok}


class OpenClawHookTests(unittest.TestCase):
    def test_hook_returns_true_on_success(self):
        allowed = humanlink_approval(
            "rm -rf /tmp/demo",
            {"tool": "bash", "params": {"cmd": "rm -rf /tmp/demo"}, "risk_level": "high"},
            verifier=FakeVerifier(),
            client=FakeClient(ok=True),
        )
        self.assertTrue(allowed)

    def test_hook_returns_false_on_failed_verification(self):
        allowed = humanlink_approval(
            "rm -rf /tmp/demo",
            {"tool": "bash", "params": {"cmd": "rm -rf /tmp/demo"}, "risk_level": "high"},
            verifier=FakeVerifier(),
            client=FakeClient(ok=False),
        )
        self.assertFalse(allowed)


if __name__ == "__main__":
    unittest.main()
