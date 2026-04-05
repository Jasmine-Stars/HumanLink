from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from sdk.client import DeviceNotConnected, HumanLinkClient, USBTimeoutError
from sdk.types import isoformat_z, utc_now
from sdk.verifier import HumanLinkVerifier

_REQUIRED_CONTEXT_FIELDS = ("tool", "params", "risk_level")
_VALID_RISK_LEVELS = {"low", "medium", "high"}
_VALID_FALLBACKS = {"deny", "ui", "allow"}
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.humanlink/config.yaml")


def _normalize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("context must be a dict")

    missing = [field for field in _REQUIRED_CONTEXT_FIELDS if field not in context]
    if missing:
        raise ValueError(f"context missing fields: {missing}")

    tool = context["tool"]
    params = context["params"]
    risk_level = str(context["risk_level"]).lower()

    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("context.tool must be a non-empty string")
    if not isinstance(params, dict):
        raise ValueError("context.params must be a dict")
    if risk_level not in _VALID_RISK_LEVELS:
        raise ValueError("context.risk_level must be one of: low, medium, high")

    normalized = dict(context)
    normalized["tool"] = tool
    normalized["params"] = dict(params)
    normalized["risk_level"] = risk_level
    return normalized


def _format_summary(command: str, context: Dict[str, Any]) -> str:
    summary = context.get("display_summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()[:256]

    raw = command.strip() if isinstance(command, str) else ""
    if raw:
        return raw[:256]

    return f'{context["tool"]}: {context["params"]}'[:256]


def _build_challenge_from_command_context(
    verifier: HumanLinkVerifier,
    command: str,
    context: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    normalized = _normalize_context(context)

    challenge = verifier.create_challenge(
        action=normalized["tool"],
        action_params=normalized["params"],
        display_title="Command Approval",
        display_summary=_format_summary(command, normalized),
        risk=normalized["risk_level"],
        origin=str(normalized.get("origin", "local://openclaw")),
    )
    return challenge, normalized


def _fallback_decision(fallback: str) -> bool:
    fallback_value = str(fallback).lower()
    if fallback_value not in _VALID_FALLBACKS:
        return False
    if fallback_value == "allow":
        return True
    # "deny" and "ui": SDK returns False; caller may trigger UI path.
    return False
# 功能：OpenClaw approval_hook 实现，基于命令字符串和上下文构建认证挑战，并通过 HumanLinkClient 与设备交互获取认证断言，最后使用 HumanLinkVerifier 验证断言的有效性，并记录审计日志。支持 USB 超时和设备未连接的异常处理，以及可配置的 fallback 策略。
# 参数说明：
# - command: 原始命令字符串，供日志记录和展示摘要使用
# - context: 包含 tool、params、risk_level 等字段的上下文信息，用于构建认证挑战
# - config_path: 可选的配置文件路径，默认为 ~/.humanlink/config.yaml
# - verifier: 可选的 HumanLinkVerifier 实例，如果未提供则会根据 config_path 创建一个新的实例
# - client: 可选的 HumanLinkClient 实例，如果未提供则会根据 verifier 的配置创建一个新的实例
# - fallback: 当设备未连接时的处理策略，默认为 "deny"，可选值包括 "deny"、"ui" 和 "allow"
def humanlink_approval(
    command: str, # 原始命令字符串，供日志记录和展示摘要使用
    context: Dict[str, Any],
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    verifier: Optional[HumanLinkVerifier] = None,
    client: Optional[HumanLinkClient] = None,
    fallback: str = "deny",
) -> bool:
    """
    OpenClaw approval_hook implementation.

    Returns:
        True:  approved
        False: rejected/timeout/error
    """
    local_verifier = verifier or HumanLinkVerifier(config_path=config_path)
    active_client = client or HumanLinkClient(
        port=local_verifier.config.hardware.get("serial_port"),
        baud=int(local_verifier.config.hardware.get("usb_baud", 115200)),
        attestation=local_verifier.get_device_attestation(),
    )

    try:
        challenge, normalized_context = _build_challenge_from_command_context(local_verifier, command, context)
        timeout_seconds = int(context.get("timeout_seconds", 30))
        assertion = active_client.request_auth(challenge=challenge, timeout_seconds=timeout_seconds)
    except USBTimeoutError:
        return False
    except DeviceNotConnected:
        return _fallback_decision(fallback)
    except Exception:
        return False

    result = local_verifier.verify(assertion=assertion, challenge=challenge)
    local_verifier.store.write_audit(
        logged_at=isoformat_z(utc_now()),
        command=command,
        context=normalized_context,
        challenge_nonce=challenge["nonce"],
        assertion_id=str(assertion.get("id", "")),
        device_did=result.device_did,
        valid=result.valid,
        failure_step=result.failure_step,
        failure_reason=result.failure_reason,
        chain_checked=result.chain_checked,
    )
    return bool(result.valid)


def build_app(config_path: str = DEFAULT_CONFIG_PATH, client: Optional[HumanLinkClient] = None):
    try:
        from fastapi import FastAPI, HTTPException
    except ModuleNotFoundError as exc:
        raise RuntimeError("fastapi is required to run the HumanLink API server") from exc

    verifier = HumanLinkVerifier(config_path=config_path)
    active_client = client or HumanLinkClient(
        port=verifier.config.hardware.get("serial_port"),
        baud=int(verifier.config.hardware.get("usb_baud", 115200)),
        attestation=verifier.get_device_attestation(),
    )

    app = FastAPI(title="HumanLink Local SDK", version="0.3")
    app.state.last_result = None

    @app.post("/auth/challenge")
    def auth_challenge(payload: Dict[str, Any]):
        if "context" in payload:
            if "command" not in payload:
                raise HTTPException(status_code=400, detail={"missing": ["command"]})
            try:
                challenge, _ = _build_challenge_from_command_context(
                    verifier=verifier,
                    command=str(payload["command"]),
                    context=payload["context"],
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            required = ["action", "action_params", "display_title", "display_summary", "risk"]
            missing = [field for field in required if field not in payload]
            if missing:
                raise HTTPException(status_code=400, detail={"missing": missing})

            challenge = verifier.create_challenge(
                action=payload["action"],
                action_params=payload["action_params"],
                display_title=payload["display_title"],
                display_summary=payload["display_summary"],
                risk=payload["risk"],
                origin=payload.get("origin", "local://openclaw"),
            )

        try:
            assertion = active_client.request_auth(
                challenge=challenge,
                timeout_seconds=int(payload.get("timeout_seconds", 30)),
            )
        except USBTimeoutError as exc:
            raise HTTPException(status_code=408, detail="auth timeout") from exc
        except DeviceNotConnected as exc:
            raise HTTPException(status_code=503, detail="device not connected") from exc

        result = verifier.verify(assertion=assertion, challenge=challenge)
        app.state.last_result = result.to_dict()
        return {"challenge": challenge, "assertion": assertion, "verification": result.to_dict()}
    
    @app.post("/auth/approval")
    def auth_approval(payload: Dict[str, Any]):
        required = ["command", "context"]
        missing = [field for field in required if field not in payload]
        if missing:
            raise HTTPException(status_code=400, detail={"missing": missing})

        try:
            approved = humanlink_approval(
                command=str(payload["command"]),
                context=payload["context"],
                config_path=config_path,
                verifier=verifier,
                client=active_client,
                fallback=str(payload.get("fallback", "deny")),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        app.state.last_result = {"approved": approved}
        return {"approved": approved}

    @app.get("/auth/status")
    def auth_status():
        return {"last_result": app.state.last_result}

    @app.get("/device/did")
    def device_did():
        return verifier.get_device_did_document()

    @app.get("/device/attestation")
    def device_attestation():
        return verifier.get_device_attestation()

    return app

