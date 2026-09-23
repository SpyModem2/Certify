from certify.security import (
    hash_password,
    sign_token,
    totp,
    verify_password,
    verify_token,
    verify_totp,
)


def test_password_round_trip() -> None:
    encoded = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("incorrect password", encoded)


def test_rfc6238_totp_vector() -> None:
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp(secret, 59) == "287082"
    assert verify_totp(secret, "287082", 59)


def test_signed_token_round_trip() -> None:
    token = sign_token({"sub": 1, "exp": 4_000_000_000}, "x" * 32)
    assert verify_token(token, "x" * 32) == {"sub": 1, "exp": 4_000_000_000}
    assert verify_token(token + "broken", "x" * 32) is None
