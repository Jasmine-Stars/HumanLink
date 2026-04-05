from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


DEFAULT_ATTESTATION = {
    "sensorType": "optical_fingerprint",
    "sensorFAR": 0.00001,
    "sensorFRR": 0.01,
    "secureElement": "ATECC608A",
    "livenessDetection": False,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Config:
    hardware: Dict[str, Any] = field(default_factory=dict)
    protocol: Dict[str, Any] = field(default_factory=dict)
    verification: Dict[str, Any] = field(default_factory=dict)
    gateway: Dict[str, Any] = field(default_factory=dict)
    api: Dict[str, Any] = field(default_factory=dict)
    device: Dict[str, Any] = field(default_factory=dict)
    audit: Dict[str, Any] = field(default_factory=dict)
    db: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Challenge:
    origin: str
    action: str
    requiredIssuerDID: str
    actionHash: str
    nonce: str
    issuedAt: str
    display: Dict[str, Any]
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "action": self.action,
            "requiredIssuerDID": self.requiredIssuerDID,
            "actionHash": self.actionHash,
            "nonce": self.nonce,
            "issuedAt": self.issuedAt,
            "display": dict(self.display),
            "params": dict(self.params),
        }


@dataclass
class DeviceAuthResponse:
    protocol: str
    matched_id: int
    score: int
    sensor_serial: str
    nonce: str
    signed_hash: str
    signature: str
    pubkey: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "matched_id": self.matched_id,
            "score": self.score,
            "sensor_serial": self.sensor_serial,
            "nonce": self.nonce,
            "signed_hash": self.signed_hash,
            "signature": self.signature,
            "pubkey": self.pubkey,
        }


@dataclass
class VerificationResult:
    valid: bool
    failure_step: Optional[int]
    failure_reason: Optional[str]
    device_did: str
    assertion_id: str
    chain_checked: bool
    chain_check_reason: Optional[str]
    verified_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "failure_step": self.failure_step,
            "failure_reason": self.failure_reason,
            "device_did": self.device_did,
            "assertion_id": self.assertion_id,
            "chain_checked": self.chain_checked,
            "chain_check_reason": self.chain_check_reason,
            "verified_at": isoformat_z(self.verified_at),
        }
