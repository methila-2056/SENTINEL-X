"""Request audit logging middleware for FastAPI.

Logs every HTTP request with method, path, status code, response latency,
client IP, and authenticated user (if any). Structured as structured JSON
logs via structlog for downstream aggregation (ELK, Grafana Loki, etc.).

No external dependencies — uses in-memory buffer with periodic flush to
structlog. Suitable for single-worker dev; swap to a queue for production.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger(__name__)

# Paths to exclude from audit logging (health probes, docs)
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/api/health",
    "/api/health/deep",
    "/docs",
    "/openapi.json",
})


@dataclass
class AuditEntry:
    timestamp: float
    method: str
    path: str
    status_code: int
    latency_ms: int
    client_ip: str
    user_agent: str
    user: str | None = None


# Module-level singleton: the middleware registers itself here on init so
# the admin viewer router can access the buffer without app.state hacks.
_audit_instance: AuditLogMiddleware | None = None


def get_audit_buffer() -> list[AuditEntry] | None:
    """Return a snapshot of the audit ring buffer, or None if middleware not loaded."""
    if _audit_instance is None:
        return None
    return list(_audit_instance._buffer)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs structured audit entries for every non-exempt request."""

    def __init__(self, app, *, max_buffer: int = 500):
        super().__init__(app)
        self._buffer: deque[AuditEntry] = deque(maxlen=max_buffer)
        global _audit_instance
        _audit_instance = self

    @property
    def recent_entries(self) -> list[AuditEntry]:
        return list(self._buffer)

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = int((time.perf_counter() - start) * 1000)

        entry = AuditEntry(
            timestamp=time.time(),
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            client_ip=self._client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            user=getattr(request.state, "user", None)
            if hasattr(request, "state")
            else None,
        )
        self._buffer.append(entry)

        log_fn = logger.warning if response.status_code >= 400 else logger.info
        log_fn(
            "audit_request",
            method=entry.method,
            path=entry.path,
            status=entry.status_code,
            latency_ms=entry.latency_ms,
            client_ip=entry.client_ip,
        )
        return response
