"""Full authentication lifecycle against the database (beyond unit-level 401s)."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from sentinel_x.api.security import hash_password
from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import UserRow


def _mkuser(role: str) -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:10]
    username, password = f"auth-{role}-{suffix}", "Auth-Test-Pass-1"
    with get_sync_session() as session:
        session.add(UserRow(username=username, password_hash=hash_password(password), role=role))
        session.commit()
    return username, password


def test_login_returns_working_token(client: TestClient) -> None:
    username, password = _mkuser("viewer")
    res = client.post("/api/auth/token", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json() == {"username": username, "role": "viewer"}


def test_deleted_account_cannot_use_old_token(client: TestClient) -> None:
    username, password = _mkuser("viewer")
    res = client.post("/api/auth/token", json={"username": username, "password": password})
    headers = {"Authorization": f"Bearer {res.json()['access_token']}"}
    assert client.get("/api/events", params={"limit": 1}, headers=headers).status_code == 200

    with get_sync_session() as session:
        row = session.query(UserRow).filter_by(username=username).one()
        session.delete(row)
        session.commit()

    # Token is still cryptographically valid but the account is gone.
    assert client.get("/api/events", params={"limit": 1}, headers=headers).status_code == 401
