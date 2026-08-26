"""Sliding-window rate limiting middleware for FastAPI.

Tracks request counts per client IP using an in-memory dict with automatic
expiry. Lightweight — no external dependencies (Redis, memcached). Suitable
for single-worker dev; for multi-worker production, swap the backing store.
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Default limits: (max_requests, window_seconds)
DEFAULT_LIMITS: dict[str, tuple[int, int]] = {
    "/api/auth/token": (10, 60),       # brute-force protection
    "/api/investigations": (5, 60),    # LLM-heavy, expensive
}
GLOBAL_LIMIT: tuple[int, int] = (120, 60)  # catch-all for all other routes


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter."""

    def __init__(self, app, *, extra_limits: dict[str, tuple[int, int]] | None = None):
        super().__init__(app)
        self._limits = {**DEFAULT_LIMITS, **(extra_limits or {})}
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._last_prune = time.monotonic()

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _matching_limit(self, path: str) -> tuple[int, int]:
        # Exact match first, then prefix match
        if path in self._limits:
            return self._limits[path]
        for prefix, limit in self._limits.items():
            if prefix != "/" and path.startswith(prefix + "/"):
                return limit
        return GLOBAL_LIMIT

    def _prune(self, now: float) -> None:
        """Evict expired entries periodically to bound memory."""
        if now - self._last_prune < 120:
            return
        self._last_prune = now
        empty_keys = [
            key for key, stamps in self._hits.items()
            if not stamps or stamps[-1] < now - 300
        ]
        for key in empty_keys:
            del self._hits[key]

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for health checks and docs
        if request.url.path in ("/api/health", "/docs", "/openapi.json"):
            return await call_next(request)

        now = time.monotonic()
        self._prune(now)

        ip = self._client_ip(request)
        max_requests, window = self._matching_limit(request.url.path)
        key = f"{ip}:{request.url.path}"

        stamps = self._hits[key]
        cutoff = now - window
        self._hits[key] = stamps = [t for t in stamps if t > cutoff]

        if len(stamps) >= max_requests:
            retry_after = int(stamps[0] + window - now) + 1
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "retry_after_s": retry_after},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(stamps[0] + window)),
                },
            )

        stamps.append(now)
        response = await call_next(request)
        remaining = max(0, max_requests - len(stamps))
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(stamps[0] + window))
        return response
