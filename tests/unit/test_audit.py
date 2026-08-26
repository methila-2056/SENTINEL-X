"""Tests for the audit log middleware."""

from __future__ import annotations

from sentinel_x.api.audit import _EXEMPT_PATHS, AuditEntry


def test_exempt_paths_excluded() -> None:
    assert "/api/health" in _EXEMPT_PATHS
    assert "/docs" in _EXEMPT_PATHS
    assert "/openapi.json" in _EXEMPT_PATHS


def test_audit_entry_fields() -> None:
    entry = AuditEntry(
        timestamp=1700000000.0,
        method="GET",
        path="/api/incidents",
        status_code=200,
        latency_ms=12,
        client_ip="127.0.0.1",
        user_agent="test",
        user="admin",
    )
    assert entry.method == "GET"
    assert entry.latency_ms == 12
    assert entry.user == "admin"


def test_audit_entry_no_user() -> None:
    entry = AuditEntry(
        timestamp=1700000000.0,
        method="POST",
        path="/api/auth/token",
        status_code=200,
        latency_ms=45,
        client_ip="10.0.0.1",
        user_agent="curl",
    )
    assert entry.user is None


def test_buffer_maxlen() -> None:
    from sentinel_x.api.audit import AuditLogMiddleware as M

    m = M.__new__(M)
    from collections import deque

    m._buffer = deque(maxlen=3)
    for i in range(5):
        m._buffer.append(
            AuditEntry(
                timestamp=float(i),
                method="GET",
                path="/test",
                status_code=200,
                latency_ms=0,
                client_ip="127.0.0.1",
                user_agent="test",
            )
        )
    assert len(m._buffer) == 3
    assert m._buffer[0].timestamp == 2.0
