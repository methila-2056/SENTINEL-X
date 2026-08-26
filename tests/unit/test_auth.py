"""Authentication and RBAC behavior tests.

These run without a database: the token/user dependency short-circuits with
401 before any handler body executes, and DB-backed flows are covered by the
integration suite.
"""

import pytest
from fastapi.testclient import TestClient

from sentinel_x.api.app import create_app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/api/events",
        "/api/incidents",
        "/api/knowledge/search?q=test",
        "/api/graph/neighborhood?entity_id=host:x",
    ],
)
def test_read_endpoints_require_token(client: TestClient, path: str) -> None:
    resp = client.get(path)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_investigation_trigger_requires_token(client: TestClient) -> None:
    resp = client.post("/api/investigations", json={"incident_id": "det-0000"})
    assert resp.status_code == 401


def test_token_endpoint_rejects_short_password(client: TestClient) -> None:
    resp = client.post("/api/auth/token", json={"username": "abc", "password": "short"})
    assert resp.status_code == 422


def test_me_requires_token(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401
