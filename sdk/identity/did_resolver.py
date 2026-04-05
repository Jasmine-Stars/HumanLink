from __future__ import annotations

from typing import Dict


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}
P256_MULTICODEC_PREFIX = bytes.fromhex("1200")


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + (encoded or "1")


def b58decode(data: str) -> bytes:
    number = 0
    for char in data:
        if char not in BASE58_INDEX:
            raise ValueError(f"invalid base58 character: {char}")
        number = number * 58 + BASE58_INDEX[char]
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    pad = 0
    for char in data:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + decoded


def did_from_pubkey(pubkey_bytes: bytes) -> str:
    if len(pubkey_bytes) != 64:
        raise ValueError("P-256 public key must be 64 bytes without the 0x04 prefix")
    return "did:key:z" + b58encode(P256_MULTICODEC_PREFIX + pubkey_bytes)


def decode_did_key(verification_method: str) -> bytes:
    did = verification_method.split("#", 1)[0]
    if not did.startswith("did:key:z"):
        raise ValueError("verificationMethod must be a did:key")
    payload = b58decode(did[len("did:key:z"):])
    if not payload.startswith(P256_MULTICODEC_PREFIX):
        raise ValueError("unsupported multicodec prefix")
    pubkey_bytes = payload[len(P256_MULTICODEC_PREFIX):]
    if len(pubkey_bytes) != 64:
        raise ValueError("decoded pubkey must be 64 bytes")
    return pubkey_bytes


def build_did_document(device_did: str) -> Dict[str, object]:
    return {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": device_did,
        "verificationMethod": [
            {
                "id": f"{device_did}#key-0",
                "type": "JsonWebKey2020",
                "controller": device_did,
                "publicKeyMultibase": device_did.split("did:key:", 1)[1],
            }
        ],
        "authentication": [f"{device_did}#key-0"],
    }
