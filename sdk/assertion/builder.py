from __future__ import annotations

import base64
import uuid
from typing import Any, Dict

from sdk.crypto.hash_engine import compute_h_doc, rebuild_signed_hash
from sdk.identity.did_resolver import did_from_pubkey
from sdk.types import DEFAULT_ATTESTATION, DeviceAuthResponse, Challenge, isoformat_z, utc_now


def build_assertion_skeleton(
    challenge: Dict[str, Any],
    device_did: str,
    attestation: Dict[str, Any] | None = None,
    *,
    assertion_id: str | None = None,
    created: str | None = None,
    matched_id: int = 0,
    score: int = 0,
    sensor_serial: str = "00" * 32,
) -> Dict[str, Any]:
    attestation_data = dict(DEFAULT_ATTESTATION if attestation is None else attestation)
    return {
        "@context": "https://humanlink.dev/protocol/v0-3",
        "type": "HumanPresenceAssertion",
        "id": assertion_id or f"urn:uuid:{uuid.uuid4()}",
        "version": "0.3",
        "created": created or isoformat_z(utc_now()),
        "device": {
            "id": device_did,
            "attestation": attestation_data,
        },
        "subject": {
            "localId": f"slot-{matched_id:02d}",
            "isRegistered": matched_id >= 0,
        },
        "challenge": {
            "origin": challenge["origin"],
            "action": challenge["action"],
            "requiredIssuerDID": challenge["requiredIssuerDID"],
            "actionHash": challenge["actionHash"],
            "nonce": challenge["nonce"],
            "issuedAt": challenge["issuedAt"],
            "display": dict(challenge["display"]),
        },
        "evidence": {
            "matchScore": score,
            "sensorSerial": sensor_serial,
        },
    }


def build_assertion(
    challenge: Dict[str, Any],
    response: DeviceAuthResponse,
    attestation: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    pubkey_bytes = base64.b64decode(response.pubkey)
    derived_did = did_from_pubkey(pubkey_bytes)
    skeleton = build_assertion_skeleton(
        challenge=challenge,
        device_did=derived_did,
        attestation=attestation,
        matched_id=response.matched_id,
        score=response.score,
        sensor_serial=response.sensor_serial,
    )
    h_doc = compute_h_doc(skeleton)
    rebuilt = rebuild_signed_hash(
        matched_id=response.matched_id,
        score=response.score,
        sensor_serial=bytes.fromhex(response.sensor_serial),
        nonce=bytes.fromhex(response.nonce),
        h_doc=h_doc,
    )
    proof = {
        "type": "ECDSA-P256",
        "signedHash": rebuilt.hex(),
        "signature": response.signature,
        "verificationMethod": f"{derived_did}#key-0",
    }
    assertion = dict(skeleton)
    assertion["proof"] = proof
    return assertion
