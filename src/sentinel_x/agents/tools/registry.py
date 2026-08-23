"""Agent tools: allow-listed, read-only investigation capabilities."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinel_x.common.logging import get_logger
from sentinel_x.graph.traversal.walk import neighborhood
from sentinel_x.incidents.risk import score_incident
from sentinel_x.retrieval.hybrid.fusion import hybrid_search

logger = get_logger(__name__)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, str]
    fn: Callable[..., Any]
    max_results: int = 10


@dataclass
class ToolResult:
    tool: str
    args: dict[str, Any]
    ok: bool
    payload: Any = None
    error: str | None = None
    evidence_ids: list[str] = field(default_factory=list)

    def to_json(self, limit_chars: int = 6000) -> str:
        body = json.dumps(
            {"ok": self.ok, "evidence_ids": self.evidence_ids[:20], "data": self.payload},
            default=str,
        )
        if len(body) > limit_chars:
            body = body[:limit_chars] + "...(truncated)"
        return body


def _events_to_dicts(rows) -> list[dict]:
    out = []
    for row in rows:
        out.append(
            {
                "event_id": row.event_id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "event_type": row.event_type,
                "action": row.action,
                "user": row.user,
                "host": row.host,
                "src_ip": row.src_ip,
                "dst_ip": row.dst_ip,
                "dst_port": row.dst_port,
                "file_path": row.file_path,
                "bytes_transferred": row.bytes_transferred,
                "technique_id": row.technique_id,
                "label": row.label,
            }
        )
    return out


def build_default_tools() -> dict[str, Tool]:
    """Construct the read-only investigation toolbox bound to live services."""
    from sqlalchemy import select

    from sentinel_x.common.db import get_sync_session
    from sentinel_x.data.db.models import IncidentRow, SecurityEventRow

    def get_incident(incident_id: str):
        with get_sync_session() as session:
            row = session.get(IncidentRow, incident_id)
            if row is None:
                return None
            return {
                "id": row.id,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
                "severity_label": row.severity_label,
                "risk_score": row.risk_score,
                "attack_probability": row.attack_probability,
                "n_events": len(row.correlated_event_ids or []),
                "entities": row.entities,
            }

    def get_incident_events(incident_id: str, limit: int = 40):
        with get_sync_session() as session:
            incident = session.get(IncidentRow, incident_id)
            if incident is None:
                return {"error": f"unknown incident {incident_id}"}
            ids = (incident.correlated_event_ids or [])[: max(limit, 1)]
            rows = session.scalars(
                select(SecurityEventRow).where(SecurityEventRow.event_id.in_(ids))
            ).all()
            return _events_to_dicts(rows)

    def query_events(
        host: str | None = None,
        user: str | None = None,
        event_type: str | None = None,
        limit: int = 25,
    ):
        stmt = (
            select(SecurityEventRow)
            .order_by(SecurityEventRow.timestamp.desc())
            .limit(max(limit, 1) * 3)
        )
        with get_sync_session() as session:
            rows = session.scalars(stmt).all()
            filtered = [
                r
                for r in rows
                if (host is None or (r.host or "").lower() == host.lower())
                and (user is None or (r.user or "").lower() == user.lower())
                and (event_type is None or r.event_type == event_type)
            ]
            return _events_to_dicts(filtered[: max(limit, 1)])

    def search_threat_intelligence(query: str, top_k: int = 6):
        docs = hybrid_search(query, top_k=max(top_k, 1))
        return [
            {
                "external_id": doc.external_id,
                "title": doc.title,
                "source": doc.source,
                "snippet": doc.content[:500],
            }
            for doc in docs
        ]

    def query_knowledge_graph(entity_id: str, max_hops: int = 2):
        return neighborhood(entity_id, max_hops=max(min(max_hops, 3), 1))

    def calculate_risk(incident_id: str):
        events = get_incident_events(incident_id, limit=400)
        if isinstance(events, dict):
            return events
        import pandas as pd

        frame = pd.DataFrame(events)
        risk = float(get_incident(incident_id)["risk_score"])  # type: ignore[index]
        scored = score_incident(frame, attack_probability=risk)
        return scored

    tools = {
        "get_incident": Tool(
            name="get_incident",
            description="Fetch summary metadata for one correlated security incident by id.",
            parameters={"incident_id": "str"},
            fn=get_incident,
        ),
        "get_incident_events": Tool(
            name="get_incident_events",
            description="List the raw security events that belong to an incident.",
            parameters={"incident_id": "str", "limit": "int=40"},
            fn=get_incident_events,
            max_results=60,
        ),
        "query_events": Tool(
            name="query_events",
            description="Search raw telemetry by host, user, and/or event_type.",
            parameters={"host": "str?", "user": "str?", "event_type": "str?", "limit": "int=25"},
            fn=query_events,
            max_results=30,
        ),
        "search_threat_intelligence": Tool(
            name="search_threat_intelligence",
            description="Hybrid semantic+keyword search over MITRE ATT&CK and Sigma knowledge base.",
            parameters={"query": "str", "top_k": "int=6"},
            fn=search_threat_intelligence,
        ),
        "query_knowledge_graph": Tool(
            name="query_knowledge_graph",
            description="Explore entity relationships around a user/host/ip entity id.",
            parameters={"entity_id": "str", "max_hops": "int=2"},
            fn=query_knowledge_graph,
        ),
        "calculate_risk": Tool(
            name="calculate_risk",
            description="Recompute behavioral risk signals for an incident.",
            parameters={"incident_id": "str"},
            fn=calculate_risk,
        ),
    }
    return tools
