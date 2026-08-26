"""Tests for password hashing primitives."""

from sentinel_x.api.security import ITERATIONS, hash_password, verify_password


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
