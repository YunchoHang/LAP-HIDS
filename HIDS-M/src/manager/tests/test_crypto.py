from manager.crypto import sign_hmac_sha256, verify_hmac_sha256

def test_manager_hmac_ok():
    psk = b"k"
    msg = b"m"
    sig = sign_hmac_sha256(psk, msg)
    assert verify_hmac_sha256(psk, msg, sig)

def test_manager_hmac_fail():
    assert not verify_hmac_sha256(b"k", b"m", "ff"*32)
