"""Authentication endpoints: token issuance, current user, user management."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from sentinel_x.api.deps import KNOWN_ROLES, ROLE_ADMIN, AuthUser, get_current_user, require_roles
from sentinel_x.api.security import create_access_token, hash_password, verify_password
from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import UserRow

logger = structlog.get_logger(__name__)

router = APIRouter()


class TokenRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str = "viewer"


@router.post("/token", response_model=TokenResponse)
def issue_token(body: TokenRequest) -> TokenResponse:
    """Exchange credentials for a bearer JWT."""
    with get_sync_session() as session:
        row = session.scalar(select(UserRow).where(UserRow.username == body.username))
        if row is None or not verify_password(body.password, row.password_hash):
            logger.warning("auth_failed", username=body.username)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        return TokenResponse(
            access_token=create_access_token(row.username, row.role), role=row.role
        )


@router.get("/me")
def whoami(user: AuthUser = Depends(get_current_user)) -> dict[str, str]:
    return {"username": user.username, "role": user.role}


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest, admin: AuthUser = Depends(require_roles(ROLE_ADMIN))
) -> dict[str, str]:
    """Admin-only account creation."""
    if body.role not in KNOWN_ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {', '.join(KNOWN_ROLES)}")
    with get_sync_session() as session:
        exists = session.scalar(select(UserRow.username).where(UserRow.username == body.username))
        if exists is not None:
            raise HTTPException(status_code=409, detail="username already exists")
        session.add(
            UserRow(
                username=body.username,
                password_hash=hash_password(body.password),
                role=body.role,
            )
        )
        session.commit()
    logger.info("user_created", by=admin.username, username=body.username, role=body.role)
    return {"username": body.username, "role": body.role}


@router.get("/users")
def list_users(admin: AuthUser = Depends(require_roles(ROLE_ADMIN))) -> list[dict[str, str]]:
    with get_sync_session() as session:
        rows = session.scalars(select(UserRow).order_by(UserRow.username)).all()
        return [{"username": r.username, "role": r.role} for r in rows]
