"""Shared fixtures for API integration tests (live PostgreSQL required).

Skips cleanly when DATABASE_URL_SYNC is unreachable so the unit suite
still runs on machines without infrastructure.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from sentinel_x.api.app import create_app
from sentinel_x.common.db import create_all, get_sync_session


def _postgres_reachable() -> bool:
    try:
        with get_sync_session() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - probe boundary
        return False


pytestmark = pytest.mark.integration

if not _postgres_reachable():
    pytest.skip("PostgreSQL unreachable; skipping integration suite", allow_module_level=True)


@pytest.fixture(scope="session")
def client() -> TestClient:
    create_all()  # idempotent schema bootstrap (adds users table on old DBs)
    return TestClient(create_app())


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="session")
def admin_headers(client: TestClient) -> dict[str, str]:
    from sentinel_x.api.security import hash_password
    from sentinel_x.data.db.models import UserRow

    username, password = _unique("it-admin"), "Int-Test-Pass-1"
    with get_sync_session() as session:
        session.add(UserRow(username=username, password_hash=hash_password(password), role="admin"))
        session.commit()
    res = client.post("/api/auth/token", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


@pytest.fixture()
def seeded_incident(client: TestClient, admin_headers: dict[str, str]) -> dict:
    """One incident + three correlated events + their knowledge-graph nodes.

    Mirrors seed_database's flow (events -> incident stamping -> entity
    extraction) so graph endpoints have real traversable data.
    """
    from sentinel_x.data.db.models import EdgeRow, EntityRow, IncidentRow, SecurityEventRow
    from sentinel_x.graph.entities.extract import extract_entities_and_edges

    tag = uuid.uuid4().hex[:10]
    host = f"seed-host-{tag}"
    user = f"seed-user-{tag}"
    process = f"suspicious-{tag}.exe"
    base = datetime.now(UTC).replace(tzinfo=None)
    event_ids = [f"seed-{tag}-{i}" for i in range(3)]
    src_ips = {f"172.20.{i}.{int(tag[:2], 16) + 10}" for i in range(3)}  # RFC1918 internal

    records = [
        {
            "id": eid,
            "timestamp": base + timedelta(minutes=i),
            "source": "integration-test",
            "event_type": "authentication" if i == 0 else "process_execution",
            "action": "login_failure" if i == 0 else "process_create",
            "user": user,
            "host": host,
            "process": None if i == 0 else process,
            "src_ip": sorted(src_ips)[i],
            "dst_ip": None,
            "dst_port": None,
            "file_path": None,
            "bytes_transferred": None,
            "severity": 2,
            "label": "benign",
            "attack_category": None,
            "technique_id": None,
            "metadata_": {},
        }
        for i, eid in enumerate(event_ids)
    ]
    rows = [SecurityEventRow(**r) for r in records]
    incident = IncidentRow(
        id=f"seed-det-{tag}",
        first_seen=base,
        last_seen=base + timedelta(minutes=2),
        status="open",
        severity_label="medium",
        risk_score=0.42,
        correlated_event_ids=event_ids,
        entities={"users": [user], "hosts": [host], "src_ips": sorted(src_ips), "external_ips": []},
        signals={"failed_login_ratio": 1 / 3},
    )

    entity_ids = [
        f"user:{user}",
        f"host:{host}",
        f"process:{process}",
        *(f"ip:{ip}" for ip in src_ips),
    ]

    with get_sync_session() as session:
        session.add_all(rows)
        session.add(incident)
        session.execute(
            text("UPDATE security_events SET incident_id = :iid WHERE id = ANY(:eids)").bindparams(
                iid=incident.id, eids=event_ids
            )
        )
        extract_entities_and_edges(records, session)
        session.commit()

    yield {"incident_id": incident.id, "host": host, "user": user, "event_ids": event_ids}

    with get_sync_session() as session:
        session.query(SecurityEventRow).filter(SecurityEventRow.id.in_(event_ids)).delete(
            synchronize_session=False
        )
        session.query(IncidentRow).filter(IncidentRow.id == incident.id).delete(
            synchronize_session=False
        )
        session.query(EdgeRow).filter(
            EdgeRow.src_id.in_(entity_ids) | EdgeRow.dst_id.in_(entity_ids)
        ).delete(synchronize_session=False)
        session.query(EntityRow).filter(EntityRow.id.in_(entity_ids)).delete(
            synchronize_session=False
        )
        session.commit()
