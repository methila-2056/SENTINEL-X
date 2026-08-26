"""Entity extraction and knowledge-graph construction from event streams."""

import zlib
from typing import Any

import structlog
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from sentinel_x.data.db.models import EdgeRow, EntityRow

logger = structlog.get_logger(__name__)

EXTERNAL_PREFIXES = ("10.", "192.168.", "172.")


def _entity_id(entity_type: str, name: str) -> str:
    return f"{entity_type}:{name}"


def _stable_edge_id(src: str, relation: str, dst: str) -> str:
    return f"{zlib.crc32(f'{src}|{relation}|{dst}'.encode()):08x}"


def extract_entities_and_edges(events, session: Session) -> tuple[int, int]:
    """Build graph nodes/edges from canonical event dicts (or SecurityEvent models).

    Node types: user, host, ip, process, file
    Relations:  authenticated_to, executed_on, connected_to, accessed,
                originated_from, targeted_by
    Returns (n_entities_upserted, n_edges_upserted).
    """
    entities: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_entity(etype: str, name: str | None, seen_at) -> str | None:
        if not name or not isinstance(name, str):
            return None
        eid = _entity_id(etype, name)
        ent = entities.get(eid)
        if ent is None:
            entities[eid] = {
                "id": eid,
                "entity_type": etype,
                "name": name,
                "first_seen": seen_at,
                "last_seen": seen_at,
            }
        else:
            if seen_at < ent["first_seen"]:
                ent["first_seen"] = seen_at
            if seen_at > ent["last_seen"]:
                ent["last_seen"] = seen_at
        return eid

    def add_edge(src_id: str | None, relation: str, dst_id: str | None, seen_at, props=None):
        if src_id is None or dst_id is None or src_id == dst_id:
            return
        key = (src_id, relation, dst_id)
        edge = edges.get(key)
        if edge is None:
            edges[key] = {
                "id": _stable_edge_id(*key),
                "src_id": src_id,
                "relation": relation,
                "dst_id": dst_id,
                "weight": 1.0,
                "first_seen": seen_at,
                "last_seen": seen_at,
                "properties": props or {},
            }
        else:
            edge["weight"] += 1.0
            if seen_at > edge["last_seen"]:
                edge["last_seen"] = seen_at

    for ev in events:
        ts = ev["timestamp"]
        user = ev.get("user")
        host = ev.get("host")
        process = ev.get("process")
        src_ip = ev.get("src_ip")
        dst_ip = ev.get("dst_ip")
        file_path = ev.get("file_path")

        uid = add_entity("user", user, ts)
        hid = add_entity("host", host, ts)
        pid = add_entity("process", process, ts) if process else None
        sid = add_entity("ip", src_ip, ts) if src_ip else None
        did = (
            add_entity("ip", dst_ip, ts)
            if dst_ip and not dst_ip.startswith(EXTERNAL_PREFIXES)
            else None
        )
        ioc_id = (
            add_entity("ioc", dst_ip, ts)
            if dst_ip and dst_ip.startswith(("185.", "45.155.", "91.219."))
            else None
        )
        fid = add_entity("file", file_path, ts) if file_path else None

        if uid and hid:
            add_edge(
                uid,
                "authenticated_to" if ev.get("event_type") == "authentication" else "acted_on",
                hid,
                ts,
            )
        if uid and pid:
            add_edge(uid, "executed", pid, ts, {"host": host})
        if pid and hid:
            add_edge(pid, "ran_on", hid, ts)
        if hid and sid and sid != did:
            add_edge(hid, "originated_from", sid, ts)
        if sid and did:
            add_edge(sid, "connected_to", did, ts)
        if sid and ioc_id and sid != ioc_id:
            add_edge(sid, "contacted", ioc_id, ts)
        if uid and fid:
            add_edge(uid, "accessed", fid, ts, {"action": ev.get("action")})

    # Upsert entities
    for ent in entities.values():
        stmt = (
            pg_insert(EntityRow)
            .values(**ent)
            .on_conflict_do_update(
                index_elements=[EntityRow.id],
                set_={
                    "last_seen": ent["last_seen"],
                    "first_seen": func.least(EntityRow.first_seen, ent["first_seen"]),
                },
            )
        )
        session.execute(stmt)

    # Upsert edges (stable ids make this idempotent)
    for edge in edges.values():
        stmt = (
            pg_insert(EdgeRow)
            .values(**edge)
            .on_conflict_do_update(
                index_elements=[EdgeRow.id],
                set_={
                    "weight": EdgeRow.__table__.c.weight + 1.0,
                    "last_seen": edge["last_seen"],
                },
            )
        )
        session.execute(stmt)

    session.commit()
    logger.info(
        "graph_updated",
        entities=len(entities),
        edges=len(edges),
    )
    return len(entities), len(edges)
