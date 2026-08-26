"""Password hashing with PBKDF2-HMAC-SHA256.

Stored format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
Uses only the standard library; comparison is constant-time.
"""

import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 390_000
SALT_BYTES = 16


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
