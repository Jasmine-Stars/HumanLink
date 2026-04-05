from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict
from urllib import error, request

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sdk.api.server import humanlink_approval
from sdk.client import DeviceNotConnected


@dataclass
class CaseResult:
    name: str
    passed: bool
    detail: str


class FakeStore:
    def __init__(self) -> None:
        self.audit_calls = 0
        self.last_audit: Dict[str, Any] = {}

    def write_audit(self, **kwargs: Any) -> None:
        self.audit_calls += 1
        self.last_audit = dict(kwargs)


class FakeVerifier:
    def __init__(self) -> None:
        self.config = SimpleNamespace(hardware={"serial_port": "COM1", "usb_baud": 115200})
        self.store = FakeStore()

    def get_device_attestation(self) -> Dict[str, Any]:
        return {"attested": True}

    def create_challenge(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "nonce": "nonce-1234",
            "action": kwargs["action"],
            "params": kwargs["action_params"],
            "display": {
                "title": kwargs["display_title"],
                "summary": kwargs["display_summary"],
                "risk": kwargs["risk"],
            },
            "origin": kwargs.get("origin", "local://openclaw"),
        }

    def verify(self, assertion: Dict[str, Any], challenge: Dict[str, Any]) -> Any:
        valid = bool(assertion.get("ok", False))
        return SimpleNamespace(
            valid=valid,
            device_did="did:key:zFakeDevice",
            failure_step=None if valid else 9,
            failure_reason=None if valid else "SIGNATURE_INVALID",
            chain_checked=False,
        )


class SuccessClient:
    def request_auth(self, challenge: Dict[str, Any], timeout_seconds: int = 30) -> Dict[str, Any]:
        return {"ok": True, "id": "assertion-001"}


class RejectClient:
    def request_auth(self, challenge: Dict[str, Any], timeout_seconds: int = 30) -> Dict[str, Any]:
        return {"ok": False, "id": "assertion-bad"}


class OfflineClient:
    def request_auth(self, challenge: Dict[str, Any], timeout_seconds: int = 30) -> Dict[str, Any]:
        raise DeviceNotConnected("offline")


def run_direct() -> list[CaseResult]:
    command = "rm -rf /tmp/important"
    context = {
        "tool": "bash",
        "params": {"cmd": command},
        "risk_level": "high",
        "display_summary": "Delete /tmp/important",
        "origin": "local://openclaw",
        "timeout_seconds": 30,
    }

    results: list[CaseResult] = []

    verifier_ok = FakeVerifier()
    approved = humanlink_approval(
        command=command,
        context=context,
        verifier=verifier_ok,
        client=SuccessClient(),
        fallback="deny",
    )
    results.append(
        CaseResult(
            name="direct_success",
            passed=approved is True and verifier_ok.store.audit_calls == 1,
            detail=f"approved={approved}, audit_calls={verifier_ok.store.audit_calls}",
        )
    )

    verifier_reject = FakeVerifier()
    rejected = humanlink_approval(
        command=command,
        context=context,
        verifier=verifier_reject,
        client=RejectClient(),
        fallback="deny",
    )
    results.append(
        CaseResult(
            name="direct_reject",
            passed=rejected is False,
            detail=f"approved={rejected}",
        )
    )

    verifier_offline = FakeVerifier()
    deny_when_offline = humanlink_approval(
        command=command,
        context=context,
        verifier=verifier_offline,
        client=OfflineClient(),
        fallback="deny",
    )
    allow_when_offline = humanlink_approval(
        command=command,
        context=context,
        verifier=verifier_offline,
        client=OfflineClient(),
        fallback="allow",
    )
    results.append(
        CaseResult(
            name="direct_fallback",
            passed=(deny_when_offline is False and allow_when_offline is True),
            detail=f"offline_deny={deny_when_offline}, offline_allow={allow_when_offline}",
        )
    )

    return results


def run_http(base_url: str) -> CaseResult:
    payload = {
        "command": "rm -rf /tmp/important",
        "context": {
            "tool": "bash",
            "params": {"cmd": "rm -rf /tmp/important"},
            "risk_level": "high",
            "display_summary": "Delete /tmp/important",
            "origin": "local://openclaw",
            "timeout_seconds": 30,
        },
        "fallback": "deny",
    }
    raw = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url=f"{base_url.rstrip('/')}/auth/approval",
        data=raw,
        headers={"content-type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8")
            parsed = json.loads(body)
            passed = resp.status == 200 and isinstance(parsed.get("approved"), bool)
            return CaseResult(
                name="http_live",
                passed=passed,
                detail=f"status={resp.status}, body={body}",
            )
    except error.URLError as exc:
        return CaseResult(
            name="http_live",
            passed=False,
            detail=f"request failed: {exc}",
        )
    except Exception as exc:  # pylint: disable=broad-except
        return CaseResult(
            name="http_live",
            passed=False,
            detail=f"unexpected error: {exc}",
        )


def print_results(results: list[CaseResult]) -> int:
    failed = 0
    for item in results:
        status = "PASS" if item.passed else "FAIL"
        print(f"[{status}] {item.name} -> {item.detail}")
        if not item.passed:
            failed += 1
    return failed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test HumanLink approval flow: direct function path and optional live HTTP path."
    )
    parser.add_argument(
        "--mode",
        choices=("direct", "http", "both"),
        default="both",
        help="direct: call humanlink_approval directly; http: call running /auth/approval; both: run both.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8765",
        help="Base URL for live HTTP mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    all_results: list[CaseResult] = []

    if args.mode in ("direct", "both"):
        all_results.extend(run_direct())

    if args.mode in ("http", "both"):
        all_results.append(run_http(args.base_url))

    failed = print_results(all_results)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
