"""Tests for the admin audit log viewer endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel_x.api.app import create_app
from sentinel_x.api.deps import AuthUser, get_current_user


def _fake_admin() -> AuthUser:
    return AuthUser(username="admin", role="admin")


def _fake_viewer() -> AuthUser:
    return AuthUser(username="viewer", role="viewer")


@pytest.fixture()
def admin_client() -> TestClient:
    app = create_app()
    app.dependency_overrides[get_current_user] = _fake_admin
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def viewer_client() -> TestClient:
    app = create_app()
    app.dependency_overrides[get_current_user] = _fake_viewer
    return TestClient(app, raise_server_exceptions=False)


def test_audit_log_requires_auth() -> None:
    c = TestClient(create_app(), raise_server_exceptions=False)
    assert c.get("/api/admin/audit-log").status_code == 401


def test_audit_log_requires_admin(viewer_client: TestClient) -> None:
    resp = viewer_client.get("/api/admin/audit-log")
    assert resp.status_code == 403


def test_audit_log_returns_entries(admin_client: TestClient) -> None:
    resp = admin_client.get("/api/admin/audit-log")
    assert resp.status_code == 200
    body = resp.json()
    assert "entries" in body
    assert "total_in_buffer" in body
    assert "filtered_count" in body
    assert isinstance(body["entries"], list)


def test_audit_log_filter_by_method(admin_client: TestClient) -> None:
    resp = admin_client.get("/api/admin/audit-log", params={"method": "POST"})
    assert resp.status_code == 200
    for entry in resp.json()["entries"]:
        assert entry["method"] == "POST"


def test_audit_log_filter_by_status(admin_client: TestClient) -> None:
    resp = admin_client.get(
        "/api/admin/audit-log",
        params={"status_min": 200, "status_max": 299},
    )
    assert resp.status_code == 200
    for entry in resp.json()["entries"]:
        assert 200 <= entry["status_code"] <= 299


def test_audit_log_filter_by_path_prefix(admin_client: TestClient) -> None:
    resp = admin_client.get(
        "/api/admin/audit-log",
        params={"path_prefix": "/api/admin"},
    )
    assert resp.status_code == 200
    for entry in resp.json()["entries"]:
        assert entry["path"].startswith("/api/admin")
