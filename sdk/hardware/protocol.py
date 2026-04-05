from __future__ import annotations

import json
from typing import Any, Dict


class DeviceProtocolError(RuntimeError):
    pass


DEVICE_ERROR_CODES = {
    1: "TIMEOUT",
    2: "NO_MATCH",
    3: "SENSOR_ERROR",
    4: "SE_ERROR",
    5: "BAD_INPUT",
    6: "NOT_ENROLLED",
    7: "SIGN_FAIL",
}


def encode_message(message: Dict[str, Any]) -> bytes:
    return (json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def decode_message(payload: bytes) -> Dict[str, Any]:
    try:
        return json.loads(payload.decode("utf-8").strip())
    except json.JSONDecodeError as exc:
        raise DeviceProtocolError("device returned invalid JSON") from exc


def raise_for_error_response(message: Dict[str, Any]) -> None:
    if message.get("status") == "err":
        code = int(message.get("code", 0))
        reason = DEVICE_ERROR_CODES.get(code, "UNKNOWN_DEVICE_ERROR")
        raise DeviceProtocolError(f"{reason}: {message.get('msg', '')}".strip())
