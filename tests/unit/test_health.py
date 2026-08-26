"""Tests for the deep health check endpoint."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from sentinel_x.api.app import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_shallow_health_returns_ok() -> None:
    res = _client().get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


@patch("sentinel_x.api.routers.health._check_postgres")
@patch("sentinel_x.api.routers.health._check_redis")
def test_deep_health_ok_when_all_healthy(mock_redis, mock_pg) -> None:
    mock_pg.return_value = {"status": "ok", "latency_ms": 1.2}
    mock_redis.return_value = {"status": "ok", "latency_ms": 0.5}
    res = _client().get("/api/health/deep")
    body = res.json()
    assert body["status"] == "ok"
    assert body["components"]["postgres"]["status"] == "ok"
    assert body["components"]["redis"]["status"] == "ok"


@patch("sentinel_x.api.routers.health._check_postgres")
@patch("sentinel_x.api.routers.health._check_redis")
def test_deep_health_degraded_when_pg_down(mock_redis, mock_pg) -> None:
    mock_pg.return_value = {"status": "error", "error": "connection refused", "latency_ms": 0.1}
    mock_redis.return_value = {"status": "ok", "latency_ms": 0.5}
    res = _client().get("/api/health/deep")
    body = res.json()
    assert body["status"] == "degraded"
    assert body["components"]["postgres"]["status"] == "error"
    assert body["components"]["redis"]["status"] == "ok"


@patch("sentinel_x.api.routers.health._check_postgres")
@patch("sentinel_x.api.routers.health._check_redis")
def test_deep_health_response_structure(mock_redis, mock_pg) -> None:
    mock_pg.return_value = {"status": "ok", "latency_ms": 2.0}
    mock_redis.return_value = {"status": "ok", "latency_ms": 0.8}
    res = _client().get("/api/health/deep")
    body = res.json()
    assert body["status"] in ("ok", "degraded")
    assert "postgres" in body["components"]
    assert "redis" in body["components"]
    for comp in body["components"].values():
        assert "status" in comp
        assert "latency_ms" in comp
