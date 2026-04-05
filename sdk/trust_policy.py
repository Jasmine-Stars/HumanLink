from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


ACCEPTED_SECURE_ELEMENTS = {"ATECC608A"}


@dataclass(frozen=True)
class TrustPolicy:
    name: str

    DEFAULT = "default"
    STRICT = "strict"
    PERMISSIVE = "permissive"


def evaluate_attestation(attestation: Dict[str, Any], policy_name: str) -> bool:
    secure_element = attestation.get("secureElement")
    sensor_far = float(attestation.get("sensorFAR", 1))
    liveness = bool(attestation.get("livenessDetection", False))

    if policy_name == TrustPolicy.DEFAULT:
        return secure_element in ACCEPTED_SECURE_ELEMENTS and sensor_far <= 0.001
    if policy_name == TrustPolicy.STRICT:
        return (
            secure_element in ACCEPTED_SECURE_ELEMENTS
            and sensor_far <= 0.0001
            and liveness is True
        )
    if policy_name == TrustPolicy.PERMISSIVE:
        return secure_element is not None
    return False
