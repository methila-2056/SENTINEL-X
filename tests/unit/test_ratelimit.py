"""Tests for the sliding-window rate limit middleware."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinel_x.api.ratelimit import RateLimitMiddleware


def _app_with_limiter(limit: int = 3, window: int = 60) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, extra_limits={"/test": (limit, window)})

    @app.get("/test")
    def test_route() -> dict[str, str]:
        return {"ok": "true"}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def test_requests_within_limit_succeed() -> None:
    client = TestClient(_app_with_limiter(limit=3))
    for _i in range(3):
        res = client.get("/test")
        assert res.status_code == 200
    # After 3 requests with limit 3, remaining should be 0
    assert res.headers["X-RateLimit-Limit"] == "3"
    assert res.headers["X-RateLimit-Remaining"] == "0"


def test_request_over_limit_returns_429() -> None:
    client = TestClient(_app_with_limiter(limit=2))
    client.get("/test")
    client.get("/test")
    res = client.get("/test")
    assert res.status_code == 429
    body = res.json()
    assert body["error"] == "rate_limit_exceeded"
    assert "retry_after_s" in body
    assert int(res.headers["Retry-After"]) >= 1


def test_health_endpoint_bypasses_rate_limit() -> None:
    client = TestClient(_app_with_limiter(limit=1))
    client.get("/test")
    # /health should not count toward any limit
    for _ in range(5):
        res = client.get("/health")
        assert res.status_code == 200


def test_different_paths_have_independent_limits() -> None:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        extra_limits={"/a": (1, 60), "/b": (3, 60)},
    )

    @app.get("/a")
    def route_a() -> dict[str, str]:
        return {"a": "1"}

    @app.get("/b")
    def route_b() -> dict[str, str]:
        return {"b": "1"}

    client = TestClient(app)
    # /a: limit=1, /b: limit=3
    assert client.get("/a").status_code == 200  # a: 1/1
    assert client.get("/b").status_code == 200  # b: 1/3
    assert client.get("/b").status_code == 200  # b: 2/3
    assert client.get("/b").status_code == 200  # b: 3/3
    # /a exhausted, /b still has room from its independent limit
    assert client.get("/a").status_code == 429
    assert client.get("/b").status_code == 429  # b also exhausted now
