"""Raw telemetry query endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import select

from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import SecurityEventRow

router = APIRouter()


@router.get("")
def query_events(
    host: str | None = None,
    user: str | None = None,
    event_type: str | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[dict[str, Any]]:
    stmt = select(SecurityEventRow).order_by(SecurityEventRow.timestamp.desc()).limit(limit * 4)
    with get_sync_session() as session:
        rows = session.scalars(stmt).all()
        filtered = [
            r
            for r in rows
            if (host is None or (r.host or "").lower() == host.lower())
            and (user is None or (r.user or "").lower() == user.lower())
            and (event_type is None or r.event_type == event_type)
        ]
        return [
            {
                "event_id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "source": r.source,
                "event_type": r.event_type,
                "action": r.action,
                "user": r.user,
                "host": r.host,
                "process": r.process,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "dst_port": r.dst_port,
                "file_path": r.file_path,
                "bytes_transferred": r.bytes_transferred,
                "severity": r.severity,
                "label": r.label,
                "technique_id": r.technique_id,
                "incident_id": r.incident_id,
            }
            for r in filtered[:limit]
        ]
