from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sdk.api.server import _build_challenge_from_command_context
from sdk.assertion.builder import build_assertion_skeleton
from sdk.client import HumanLinkClient
from sdk.crypto.hash_engine import compute_h_doc
from sdk.verifier import HumanLinkVerifier


def main() -> None:
    # OpenClaw approval_hook input example
    command = "rm -rf /home/user/important"
    context = {
        "tool": "bash",
        "params": {"cmd": "rm -rf /home/user/important"},
        "risk_level": "high",
        "display_summary": "删除目录 /home/user/important",
    }

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        config_path = tmp_path / "config.yaml"
        config = {
            "device": {"did": "did:key:z2oAt2GGBM5x5u1nRprDG7K6tvJtx8DbDeTzM7LAwroNmF"},
            "db": {"path": ":memory:"},
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=True)

        verifier = HumanLinkVerifier(str(config_path))
        challenge, normalized_context = _build_challenge_from_command_context(
            verifier=verifier,
            command=command,
            context=context,
        )

        # This is exactly how sdk/client.py builds the payload sent to firmware.
        client = HumanLinkClient(attestation=verifier.get_device_attestation())
        skeleton = build_assertion_skeleton(
            challenge=challenge,
            device_did=challenge["requiredIssuerDID"],
            attestation=client.attestation,
        )
        h_doc = compute_h_doc(skeleton).hex()
        device_request = {
            "cmd": "auth",
            "h_doc": h_doc,
            "nonce": challenge["nonce"],
            "display": {
                "title": challenge["display"]["title"],
                "risk": challenge["display"]["risk"],
            },
        }

    print("=== openclaw_input ===")
    print(json.dumps({"command": command, "context": context}, ensure_ascii=False, indent=2))
    print()
    print("=== normalized_context ===")
    print(json.dumps(normalized_context, ensure_ascii=False, indent=2))
    print()
    print("=== challenge_generated_by_sdk ===")
    print(json.dumps(challenge, ensure_ascii=False, indent=2))
    print()
    print("=== assertion_skeleton ===")
    print(json.dumps(skeleton, ensure_ascii=False, indent=2))
    print()
    print("=== json_sent_to_firmware (USB) ===")
    print(json.dumps(device_request, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
