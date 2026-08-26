"""FastAPI dependencies for JWT authentication and role-based authorization."""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from sqlalchemy import select

from sentinel_x.api.security import decode_token
from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import UserRow

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
KNOWN_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str


def _user_exists(username: str) -> bool:
    with get_sync_session() as session:
        found = session.scalar(select(UserRow.username).where(UserRow.username == username))
        return found is not None


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> AuthUser:
    """Resolve the caller from a bearer JWT; the account must still exist."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise unauthorized
    try:
        claims = decode_token(token)
    except InvalidTokenError as exc:
        raise unauthorized from exc
    username = str(claims.get("sub", ""))
    role = str(claims.get("role", ""))
    if not username or role not in KNOWN_ROLES:
        raise unauthorized
    if not _user_exists(username):
        # Deleted/disabled accounts must not keep working with old tokens.
        raise unauthorized
    return AuthUser(username=username, role=role)


def require_roles(*allowed: str):
    """Dependency factory enforcing that the caller has one of `allowed` roles."""

    def checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed)}",
            )
        return user

    return checker


# Module-level singletons so routers can use `Depends(require_admin)` without
# constructing a new dependency per request.
require_admin = require_roles(ROLE_ADMIN)
require_analyst_or_admin = require_roles(ROLE_ANALYST, ROLE_ADMIN)
