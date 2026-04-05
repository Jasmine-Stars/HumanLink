from __future__ import annotations

import base64


class SignatureVerificationUnavailable(RuntimeError):
    pass


def verify_assertion_signature(pubkey_bytes: bytes, signed_hash: bytes, signature_b64: str) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ModuleNotFoundError as exc:
        raise SignatureVerificationUnavailable(
            "cryptography is required for ECDSA verification"
        ) from exc

    signature_bytes = base64.b64decode(signature_b64)
    if len(signature_bytes) != 64:
        raise ValueError("signature must be 64-byte raw r||s, base64 encoded")

    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")
    x = int.from_bytes(pubkey_bytes[:32], "big")
    y = int.from_bytes(pubkey_bytes[32:], "big")

    signature_der = encode_dss_signature(r, s)
    public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    try:
        public_key.verify(signature_der, signed_hash, ec.ECDSA(hashes.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return False
    return True
