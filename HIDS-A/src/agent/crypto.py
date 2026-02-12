from __future__ import annotations
import hmac
import hashlib

def sign_hmac_sha256(psk: bytes, msg: bytes) -> str:
    """Sign a message with PSK using HMAC-SHA256."""
    return hmac.new(psk, msg, hashlib.sha256).hexdigest()

def verify_hmac_sha256(psk: bytes, msg: bytes, sig_hex: str) -> bool:
    """Verify HMAC signature using constant-time comparison."""
    expected = sign_hmac_sha256(psk, msg)
    return hmac.compare_digest(expected, sig_hex)