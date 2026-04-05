from __future__ import annotations

from typing import Any, Dict


REQUIRED_ASSERTION_FIELDS = [
    "@context",
    "type",
    "id",
    "version",
    "created",
    "device",
    "subject",
    "challenge",
    "evidence",
    "proof",
]


def validate_assertion_structure(assertion: Dict[str, Any]) -> bool:
    for field in REQUIRED_ASSERTION_FIELDS:
        if field not in assertion:
            return False

    if assertion.get("@context") != "https://humanlink.dev/protocol/v0-3":
        return False
    if assertion.get("type") != "HumanPresenceAssertion":
        return False
    if assertion.get("version") != "0.3":
        return False

    challenge = assertion.get("challenge", {})
    display = challenge.get("display", {})
    proof = assertion.get("proof", {})
    evidence = assertion.get("evidence", {})
    device = assertion.get("device", {})
    subject = assertion.get("subject", {})

    required_paths = [
        device.get("id"),
        device.get("attestation"),
        subject.get("localId"),
        subject.get("isRegistered"),
        challenge.get("origin"),
        challenge.get("action"),
        challenge.get("requiredIssuerDID"),
        challenge.get("actionHash"),
        challenge.get("nonce"),
        challenge.get("issuedAt"),
        display.get("title"),
        display.get("summary"),
        display.get("risk"),
        display.get("source"),
        evidence.get("matchScore"),
        evidence.get("sensorSerial"),
        proof.get("type"),
        proof.get("signedHash"),
        proof.get("signature"),
        proof.get("verificationMethod"),
    ]
    if any(value in (None, "") for value in required_paths):
        return False
    return proof.get("type") == "ECDSA-P256"
