from __future__ import annotations

import os
from typing import Any, Dict, Optional

from sdk.client import DeviceNotConnected, HumanLinkClient, USBTimeoutError
from sdk.verifier import HumanLinkVerifier


DEFAULT_CONFIG_PATH = os.path.expanduser("~/.humanlink/config.yaml")


def _format_summary(command: str, context: Dict[str, Any]) -> str:
    return context.get("display_summary") or f"{context.get('tool', 'unknown')}: {command[:100]}"


def _fallback_decision(context: Dict[str, Any]) -> bool:
    fallback = context.get("fallback", "deny")
    if fallback == "allow":
        return True
    return False


def humanlink_approval(
    command: str,
    context: Dict[str, Any],
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    verifier: Optional[HumanLinkVerifier] = None,
    client: Optional[HumanLinkClient] = None,
) -> bool:
    active_verifier = verifier or HumanLinkVerifier(config_path=config_path)
    active_client = client or HumanLinkClient(
        port=active_verifier.config.hardware.get("serial_port"),
        baud=int(active_verifier.config.hardware.get("usb_baud", 115200)),
        attestation=active_verifier.get_device_attestation(),
    )

    challenge = active_verifier.create_challenge(
        action=context["tool"],
        action_params=context["params"],
        display_title="命令执行确认",
        display_summary=_format_summary(command, context),
        risk=context.get("risk_level", "high"),
        origin=context.get("origin", "local://openclaw"),
    )
    try:
        assertion = active_client.request_auth(challenge=challenge, timeout_seconds=int(context.get("timeout_seconds", 30)))
    except (TimeoutError, USBTimeoutError):
        return False
    except DeviceNotConnected:
        return _fallback_decision(context)

    result = active_verifier.verify(assertion=assertion, challenge=challenge)
    active_verifier.store.write_audit(
        logged_at=result.to_dict()["verified_at"],
        command=command,
        context=context,
        challenge_nonce=challenge["nonce"],
        assertion_id=result.assertion_id,
        device_did=result.device_did,
        valid=result.valid,
        failure_step=result.failure_step,
        failure_reason=result.failure_reason,
        chain_checked=result.chain_checked,
    )
    return result.valid
