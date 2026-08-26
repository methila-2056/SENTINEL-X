"""Multi-hop graph traversal over entity/edge tables using recursive CTEs."""

from dataclasses import dataclass, field

from sqlalchemy import text

from sentinel_x.common.db import get_sync_session


@dataclass
class GraphNeighborhood:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    paths: list[dict] = field(default_factory=list)


def neighborhood(
    entity_id: str,
    max_hops: int = 3,
    limit_nodes: int = 100,
) -> GraphNeighborhood:
    """Undirected BFS neighborhood of an entity within max_hops."""
    session = get_sync_session()
    try:
        sql = text(
            """
            WITH RECURSIVE walk AS (
                SELECT e.id, e.entity_type, e.name, e.is_malicious, 0 AS depth
                FROM entities e WHERE e.id = :start
                UNION
                SELECT n.id, n.entity_type, n.name, n.is_malicious, w.depth + 1
                FROM walk w
                JOIN edges ed ON ed.src_id = w.id OR ed.dst_id = w.id
                JOIN entities n ON n.id = CASE WHEN ed.src_id = w.id THEN ed.dst_id ELSE ed.src_id END
                WHERE w.depth < :hops
            )
            SELECT id, entity_type, name, is_malicious
            FROM (
                SELECT id, entity_type, name, is_malicious, min(depth) AS d
                FROM walk
                GROUP BY id, entity_type, name, is_malicious
            ) t
            ORDER BY d
            LIMIT :limit
            """
        )
        node_rows = session.execute(
            sql, {"start": entity_id, "hops": max_hops, "limit": limit_nodes}
        ).mappings()
        nodes = [dict(r) for r in node_rows]
        if not nodes:
            return GraphNeighborhood()

        ids = [n["id"] for n in nodes]
        edge_sql = text(
            """
            SELECT src_id, dst_id, relation, weight
            FROM edges
            WHERE src_id = ANY(:ids) AND dst_id = ANY(:ids)
            """
        )
        edge_rows = session.execute(edge_sql, {"ids": ids}).mappings()
        edges = [dict(r) for r in edge_rows]
        return GraphNeighborhood(nodes=nodes, edges=edges)
    finally:
        session.close()


def paths_to_iocs(entity_id: str, max_hops: int = 4, limit: int = 20) -> list[dict]:
    """Find paths from an entity to any IOC node (known-bad infrastructure)."""
    session = get_sync_session()
    try:
        sql = text(
            """
            WITH RECURSIVE walk AS (
                SELECT id, ARRAY[id]::varchar[] AS path, 0 AS depth
                FROM entities WHERE id = :start
                UNION
                SELECT n.id, w.path || n.id, w.depth + 1
                FROM walk w
                JOIN edges ed ON ed.src_id = w.id OR ed.dst_id = w.id
                JOIN entities n ON n.id = CASE WHEN ed.src_id = w.id THEN ed.dst_id ELSE ed.src_id END
                WHERE w.depth < :hops AND NOT n.id = ANY(w.path)
            )
            SELECT w.path
            FROM walk w
            JOIN entities last ON last.id = (w.path)[array_length(w.path, 1)]
            WHERE last.is_malicious OR last.entity_type = 'ioc'
            LIMIT :limit
            """
        )
        rows = session.execute(
            sql, {"start": entity_id, "hops": max_hops, "limit": limit}
        ).mappings()
        return [{"path": r["path"]} for r in rows]
    finally:
        session.close()


def related_entities_for_incident(
    event_entity_ids: list[str], max_hops: int = 2
) -> GraphNeighborhood:
    """Union of neighborhoods around the entities involved in an incident."""
    combined = GraphNeighborhood()
    seen = set()
    for eid in event_entity_ids:
        nbhd = neighborhood(eid, max_hops=max_hops)
        for node in nbhd.nodes:
            if node["id"] not in seen:
                seen.add(node["id"])
                combined.nodes.append(node)
        for edge in nbhd.edges:
            key = (edge["src_id"], edge["relation"], edge["dst_id"])
            if key not in {(e["src_id"], e["relation"], e["dst_id"]) for e in combined.edges}:
                combined.edges.append(edge)
    return combined
