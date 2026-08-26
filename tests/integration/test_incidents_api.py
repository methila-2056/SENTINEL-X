"""Incident endpoint integration tests against live PostgreSQL."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_contains_seeded_incident(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    res = client.get("/api/incidents", params={"limit": 200}, headers=admin_headers)
    assert res.status_code == 200
    ids = [row["id"] for row in res.json()]
    assert seeded_incident["incident_id"] in ids


def test_incident_detail_shape(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    iid = seeded_incident["incident_id"]
    res = client.get(f"/api/incidents/{iid}", headers=admin_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == iid
    assert body["status"] == "open"
    assert len(body["correlated_event_ids"]) == 3
    assert "signals" in body and "entities" in body


def test_missing_incident_404(client: TestClient, admin_headers: dict[str, str]) -> None:
    assert client.get("/api/incidents/does-not-exist", headers=admin_headers).status_code == 404


def test_event_timeline_chronological(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    iid = seeded_incident["incident_id"]
    res = client.get(f"/api/incidents/{iid}/events", headers=admin_headers)
    assert res.status_code == 200
    events = res.json()
    assert len(events) == 3
    stamps = [e["timestamp"] for e in events]
    assert stamps == sorted(stamps)


def test_subgraph_returns_connected_nodes(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    iid = seeded_incident["incident_id"]
    res = client.get(f"/api/incidents/{iid}/graph", headers=admin_headers)
    assert res.status_code == 200
    graph = res.json()
    node_ids = {n["id"] for n in graph["nodes"]}
    # The seeded host entity must appear in the neighborhood.
    assert any(nid.startswith("host:seed-host-") for nid in node_ids)
