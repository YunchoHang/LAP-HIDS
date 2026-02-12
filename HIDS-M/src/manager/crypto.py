from __future__ import annotations
import hmac, hashlib

def sign_hmac_sha256(psk: bytes, msg: bytes) -> str:
    return hmac.new(psk, msg, hashlib.sha256).hexdigest()

def verify_hmac_sha256(psk: bytes, msg: bytes, sig_hex: str) -> bool:
    expected = sign_hmac_sha256(psk, msg)
    return hmac.compare_digest(expected, sig_hex)