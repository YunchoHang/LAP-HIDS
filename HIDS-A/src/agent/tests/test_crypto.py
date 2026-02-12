from agent.crypto import sign_hmac_sha256, verify_hmac_sha256

def test_hmac_sign_verify_ok():
    psk = b"secret"
    msg = b"hello"
    sig = sign_hmac_sha256(psk, msg)
    assert verify_hmac_sha256(psk, msg, sig) is True

def test_hmac_verify_fail_wrong_sig():
    psk = b"secret"
    msg = b"hello"
    assert verify_hmac_sha256(psk, msg, "00"*32) is False
