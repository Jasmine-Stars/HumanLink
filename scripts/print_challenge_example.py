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
from sdk.verifier import HumanLinkVerifier


def main() -> None:
    command = "rm -rf /home/user/important"
    context = {
        "tool": "bash",
        "params": {"cmd": command},
        "risk_level": "high",
        "display_summary": "删除目录 /home/user/important",
    }

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        config_path = tmp_path / "config.yaml"
        config = {
            "device": {
                "did": "did:key:z2oAt2GGBM5x5u1nRprDG7K6tvJtx8DbDeTzM7LAwroNmF",
            },
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

    print("=== normalized_context ===")
    print(json.dumps(normalized_context, ensure_ascii=False, indent=2))
    print()
    print("=== challenge ===")
    print(json.dumps(challenge, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
