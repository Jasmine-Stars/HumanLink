from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sdk import HumanLinkClient, HumanLinkVerifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local hardware smoke test with SQLite-backed fake DID binding."
    )
    parser.add_argument("--config", default="config.local-test.yaml")
    parser.add_argument("--port", default=None)
    parser.add_argument("--user-id", default="local-user")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    verifier = HumanLinkVerifier(config_path=args.config)
    client = HumanLinkClient(
        port=args.port or verifier.config.hardware.get("serial_port"),
        baud=int(verifier.config.hardware.get("usb_baud", 115200)),
        attestation=verifier.get_device_attestation(),
    )

    status = client.get_device_status()
    print("STATUS")
    print(json.dumps(status, indent=2, ensure_ascii=False))

    device_did = client.get_device_did()
    verifier.register_local_device(device_did, user_id=args.user_id)
    print("\nBOUND DEVICE DID")
    print(device_did)
    print(f"sqlite={Path(verifier.store.path).expanduser()}")

    challenge = verifier.create_challenge(
        action="local_hardware_smoke_test",
        action_params={"step": "auth", "mode": "fake_did"},
        display_title="本地硬件联调测试",
        display_summary="测试 status/getDID/auth/verify 全链路",
        risk="high",
        user_id=args.user_id,
    )
    print("\nCHALLENGE")
    print(json.dumps(challenge, indent=2, ensure_ascii=False))

    assertion = client.request_auth(challenge=challenge, timeout_seconds=30)
    print("\nASSERTION")
    print(json.dumps(assertion, indent=2, ensure_ascii=False))

    result = verifier.verify(assertion=assertion, challenge=challenge)
    print("\nVERIFY RESULT")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
