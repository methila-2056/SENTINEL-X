"""Incident endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import IncidentRow

router = APIRouter()


class IncidentOut(BaseModel):
    id: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str | None = None
    severity_label: str | None = None
    risk_score: float | None = None
    anomaly_score: float | None = None
    attack_probability: float | None = None
    n_events: int = 0


@router.get("")
def list_incidents(
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
) -> list[IncidentOut]:
    with get_sync_session() as session:
        rows = session.scalars(
            select(IncidentRow).order_by(IncidentRow.risk_score.desc()).limit(limit * 2)
        ).all()
        out = [
            IncidentOut(
                id=row.id,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                status=row.status,
                severity_label=row.severity_label,
                risk_score=row.risk_score,
                anomaly_score=row.anomaly_score,
                attack_probability=row.attack_probability,
                n_events=len(row.correlated_event_ids or []),
            )
            for row in rows
            if (row.risk_score or 0) >= min_risk
        ]
        return out[:limit]


@router.get("/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    with get_sync_session() as session:
        row = session.get(IncidentRow, incident_id)
        if row is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return {
            "id": row.id,
            "first_seen": row.first_seen.isoformat(),
            "last_seen": row.last_seen.isoformat(),
            "status": row.status,
            "severity_label": row.severity_label,
            "risk_score": row.risk_score,
            "anomaly_score": row.anomaly_score,
            "attack_probability": row.attack_probability,
            "signals": row.signals or {},
            "correlated_event_ids": (row.correlated_event_ids or [])[:100],
            "entities": row.entities,
            "ground_truth_incident_id": row.ground_truth_incident_id,
        }
