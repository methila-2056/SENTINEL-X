"""Tests for password hashing and JWT token primitives."""

import jwt as pyjwt
import pytest

from sentinel_x.api.security import (
    ITERATIONS,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_hash_roundtrip() -> None:
    stored = hash_password("S3cret-pass!")
    assert stored.startswith(f"pbkdf2_sha256${ITERATIONS}$")
    assert verify_password("S3cret-pass!", stored) is True


def test_wrong_password_rejected() -> None:
    stored = hash_password("correct-horse")
    assert verify_password("wrong-battery", stored) is False


def test_salts_are_unique_per_call() -> None:
    assert hash_password("same") != hash_password("same")


def test_malformed_stored_hash_rejected_safely() -> None:
    assert verify_password("x", "not-a-valid-hash") is False
    assert verify_password("x", "pbkdf2_sha256$abc$zz$$") is False
    assert verify_password("x", "") is False


def test_unknown_algorithm_rejected() -> None:
    stored = hash_password("pw").replace("pbkdf2_sha256", "scrypt", 1)
    assert verify_password("pw", stored) is False


def test_token_roundtrip_carries_claims() -> None:
    token = create_access_token("alice", "analyst")
    claims = decode_token(token)
    assert claims["sub"] == "alice"
    assert claims["role"] == "analyst"
    assert claims["exp"] > claims["iat"]


def test_expired_token_rejected() -> None:
    token = create_access_token("alice", "viewer", expires_minutes=-1)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_token(token)


def test_tampered_token_rejected() -> None:
    token = create_access_token("alice", "viewer")
    header, payload, signature = token.split(".")
    forged_payload = payload[:-2] + ("AA" if not payload.endswith("AA") else "BB")
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token(f"{header}.{forged_payload}.{signature}")
