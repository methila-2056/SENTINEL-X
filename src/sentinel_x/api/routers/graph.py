"""Knowledge-graph endpoints: incident subgraph and entity neighborhood."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import IncidentRow, SecurityEventRow
from sentinel_x.graph.traversal.walk import GraphNeighborhood, related_entities_for_incident

router = APIRouter()


def _entity_id(kind: str, name: str | None) -> str | None:
    return f"{kind}:{name}" if name else None


def _neighborhood_to_dict(nbhd: GraphNeighborhood) -> dict[str, Any]:
    return {
        "nodes": [
            {
                "id": n["id"],
                "type": n["entity_type"],
                "name": n["name"],
                "malicious": bool(n.get("is_malicious")),
            }
            for n in nbhd.nodes
        ],
        "edges": [
            {
                "source": e["src_id"],
                "target": e["dst_id"],
                "relation": e["relation"],
                "weight": float(e.get("weight", 1.0)),
            }
            for e in nbhd.edges
        ],
    }


@router.get("/incidents/{incident_id}/graph")
def incident_graph(incident_id: str, max_hops: int = Query(2, ge=1, le=3)) -> dict[str, Any]:
    """Entity-relationship subgraph around the entities of an incident."""
    with get_sync_session() as session:
        incident = session.get(IncidentRow, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        event_ids = (incident.correlated_event_ids or [])[:200]
        rows = session.scalars(
            select(SecurityEventRow).where(SecurityEventRow.id.in_(event_ids))
        ).all()

    # Seed order matters: external destination IOCs carry the highest signal
    # and must survive the traversal seed cap, so they go first.
    seed_ids: list[str] = []
    seen: set[str] = set()

    def _add_seed(eid: str | None) -> None:
        if eid and eid not in seen:
            seen.add(eid)
            seed_ids.append(eid)

    for row in rows:
        _add_seed(_entity_id("ioc", row.dst_ip))
    for row in rows:
        for kind, value in (
            ("user", row.user),
            ("host", row.host),
            ("ip", row.src_ip),
            ("process", row.process),
        ):
            _add_seed(_entity_id(kind, value))

    nbhd = related_entities_for_incident(seed_ids[:24], max_hops=max_hops)
    result = _neighborhood_to_dict(nbhd)
    result["incident_id"] = incident_id
    return result


@router.get("/graph/neighborhood")
def graph_neighborhood(entity_id: str, max_hops: int = Query(2, ge=1, le=4)) -> dict[str, Any]:
    """Neighborhood around one entity id, e.g. 'host:WS-118'."""
    from sentinel_x.graph.traversal.walk import neighborhood

    nbhd = neighborhood(entity_id, max_hops=max_hops)
    if not nbhd.nodes:
        raise HTTPException(status_code=404, detail="unknown entity")
    return _neighborhood_to_dict(nbhd)


@router.get("/incidents/{incident_id}/events")
def incident_events(incident_id: str, limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    """Chronological event timeline for one incident."""
    with get_sync_session() as session:
        incident = session.get(IncidentRow, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        ids = (incident.correlated_event_ids or [])[:limit]
        rows = session.scalars(
            select(SecurityEventRow)
            .where(SecurityEventRow.id.in_(ids))
            .order_by(SecurityEventRow.timestamp)
        ).all()
        return [
            {
                "event_id": r.id,
                "timestamp": r.timestamp.isoformat(),
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
                "attack_category": r.attack_category,
            }
            for r in rows
        ]
