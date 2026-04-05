from __future__ import annotations

from typing import Any, Dict, Optional

from sdk.assertion.builder import build_assertion_skeleton, build_assertion
from sdk.crypto.hash_engine import compute_h_doc
from sdk.hardware.protocol import DeviceProtocolError, raise_for_error_response
from sdk.hardware.usb_bridge import DeviceNotConnected, USBSerialBridge, USBTimeoutError
from sdk.identity.did_resolver import did_from_pubkey
from sdk.types import DEFAULT_ATTESTATION, DeviceAuthResponse


class HumanLinkClient:
    def __init__(
        self,
        transport: str = "usb",
        port: str | None = None,
        baud: int = 115200,
        bridge: Optional[USBSerialBridge] = None,
        attestation: Optional[Dict[str, Any]] = None,
    ):
        if transport != "usb":
            raise ValueError("Only USB transport is supported in v1")
        self.transport = transport
        self.bridge = bridge or USBSerialBridge(port=port, baud=baud)
        self.attestation = dict(DEFAULT_ATTESTATION if attestation is None else attestation)

    def connect(self) -> None:
        self.bridge.connect()

    def get_device_status(self) -> Dict[str, Any]:
        self.bridge.send_json({"cmd": "status"})
        message = self.bridge.read_json()
        raise_for_error_response(message)
        return message

    def get_device_did(self) -> str:
        self.bridge.send_json({"cmd": "getDID"})
        message = self.bridge.read_json()
        raise_for_error_response(message)
        if "device_did" in message:
            return str(message["device_did"])
        if "pubkey" in message:
            import base64

            return did_from_pubkey(base64.b64decode(message["pubkey"]))
        raise DeviceProtocolError("device DID not present in response")

    def request_auth(self, challenge: Dict[str, Any], timeout_seconds: int = 30) -> Dict[str, Any]:
        skeleton = build_assertion_skeleton(
            challenge=challenge,
            device_did=challenge["requiredIssuerDID"],
            attestation=self.attestation,
        )
        h_doc = compute_h_doc(skeleton).hex()
        request = {
            "cmd": "auth",
            "h_doc": h_doc,
            "nonce": challenge["nonce"],
            "display": {
                "title": challenge["display"]["title"],
                "risk": challenge["display"]["risk"],
            },
        }
        self.bridge.send_json(request)
        message = self.bridge.read_json(timeout_seconds=timeout_seconds)
        raise_for_error_response(message)

        response = DeviceAuthResponse(
            protocol=str(message.get("protocol", "0.3")),
            matched_id=int(message["matched_id"]),
            score=int(message["score"]),
            sensor_serial=str(message["sensor_serial"]),
            nonce=str(message["nonce"]),
            signed_hash=str(message["signed_hash"]),
            signature=str(message["sig"]),
            pubkey=str(message["pubkey"]),
        )
        import base64

        if response.nonce != challenge["nonce"]:
            raise DeviceProtocolError("device nonce echo mismatch")

        derived_did = did_from_pubkey(base64.b64decode(response.pubkey))
        if derived_did != challenge["requiredIssuerDID"]:
            raise DeviceProtocolError("device DID mismatch")

        assertion = build_assertion(challenge=challenge, response=response, attestation=self.attestation)
        if assertion["proof"]["signedHash"] != response.signed_hash:
            raise DeviceProtocolError("device signed_hash mismatch")
        return assertion


__all__ = [
    "HumanLinkClient",
    "DeviceNotConnected",
    "USBTimeoutError",
    "DeviceProtocolError",
]
