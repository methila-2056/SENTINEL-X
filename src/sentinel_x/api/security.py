"""Password hashing and JWT token issuance/verification for the API.

Passwords: PBKDF2-HMAC-SHA256 (see hash_password).
Tokens:    HS256 JWTs signed with settings.secret_key.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from sentinel_x.common.settings import get_settings

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 390_000
SALT_BYTES = 16

JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"{ALGORITHM}${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash; safe against malformed input."""
    try:
        algorithm, iterations_s, salt_hex, hash_hex = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        expected = bytes.fromhex(hash_hex)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, int(iterations_s)
    )
    return hmac.compare_digest(candidate, expected)


def create_access_token(username: str, role: str, expires_minutes: int | None = None) -> str:
    """Issue a signed JWT carrying the subject and role claims."""
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(
        minutes=settings.access_token_expire_minutes
        if expires_minutes is None
        else expires_minutes
    )
    payload = {"sub": username, "role": role, "iat": now, "exp": expire}
    return jwt.encode(payload, settings.secret_key.get_secret_value(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT. Raises jwt.InvalidTokenError on any problem."""
    settings = get_settings()
    return jwt.decode(
        token, settings.secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
    )
