"""Event query endpoint integration tests (SQL-side filter correctness)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_host_filter_matches_seeded_events_only(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    res = client.get(
        "/api/events",
        params={"host": seeded_incident["host"], "limit": 500},
        headers=admin_headers,
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 3
    assert all(r["host"] == seeded_incident["host"] for r in rows)


def test_user_filter_case_insensitive(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    res = client.get(
        "/api/events",
        params={"user": seeded_incident["user"].upper(), "limit": 500},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert len(res.json()) == 3


def test_combined_filters_narrow_results(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    res = client.get(
        "/api/events",
        params={
            "host": seeded_incident["host"],
            "event_type": "authentication",
            "limit": 500,
        },
        headers=admin_headers,
    )
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["action"] == "login_failure"


def test_limit_is_respected(
    client: TestClient, admin_headers: dict[str, str], seeded_incident: dict
) -> None:
    res = client.get(
        "/api/events",
        params={"host": seeded_incident["host"], "limit": 2},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert len(res.json()) == 2
