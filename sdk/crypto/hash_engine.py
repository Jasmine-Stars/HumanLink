from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Dict


SEPARATOR = b"\x1f"


def _stringify_param_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(value)


def build_action_hash(action: str, params: Dict[str, Any], nonce: str, required_issuer_did: str) -> str:
    fields = [action.encode("utf-8")]
    for key in sorted(params):
        field = f"{key}={_stringify_param_value(params[key])}"
        fields.append(field.encode("utf-8"))
    fields.append(nonce.encode("utf-8"))
    fields.append(required_issuer_did.encode("utf-8"))
    return hashlib.sha256(SEPARATOR.join(fields)).hexdigest()


def canonicalize_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_h_doc(assertion_without_proof: Dict[str, Any]) -> bytes:
    return hashlib.sha256(canonicalize_json(assertion_without_proof).encode("utf-8")).digest()


def rebuild_signed_hash(
    matched_id: int,
    score: int,
    sensor_serial: bytes,
    nonce: bytes,
    h_doc: bytes,
) -> bytes:
    if len(sensor_serial) != 32:
        raise ValueError("sensor_serial must be 32 bytes")
    if len(nonce) != 8:
        raise ValueError("nonce must be 8 bytes")
    if len(h_doc) != 32:
        raise ValueError("h_doc must be 32 bytes")
    raw = struct.pack(">HH", matched_id, score) + sensor_serial + nonce + h_doc
    return hashlib.sha256(raw).digest()
