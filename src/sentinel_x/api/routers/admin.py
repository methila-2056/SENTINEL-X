"""Audit log viewer: admin-only endpoint to query recent request audit entries.

GET /api/admin/audit-log returns recent audit entries from the in-memory
ring buffer, with optional filtering by method, path prefix, and status
code range. Restricted to admin role.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, Query

from sentinel_x.api.audit import get_audit_buffer
from sentinel_x.api.deps import AuthUser, require_admin

router = APIRouter()


@router.get("/audit-log")
def get_audit_log(
    _user: AuthUser = Depends(require_admin),
    method: str | None = Query(None, description="Filter by HTTP method (GET, POST, etc.)"),
    path_prefix: str | None = Query(None, description="Filter by path prefix"),
    status_min: int = Query(0, ge=0, description="Minimum status code"),
    status_max: int = Query(599, le=599, description="Maximum status code"),
    limit: int = Query(100, ge=1, le=500, description="Max entries to return"),
) -> dict[str, Any]:
    entries = get_audit_buffer()
    if entries is None:
        return {"entries": [], "total_in_buffer": 0, "filtered_count": 0}

    filtered = entries
    if method:
        filtered = [e for e in filtered if e.method.upper() == method.upper()]
    if path_prefix:
        filtered = [e for e in filtered if e.path.startswith(path_prefix)]
    filtered = [e for e in filtered if status_min <= e.status_code <= status_max]

    recent = filtered[-limit:]
    return {
        "entries": [asdict(e) for e in recent],
        "total_in_buffer": len(entries),
        "filtered_count": len(filtered),
    }
