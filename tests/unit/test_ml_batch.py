"""Tests for the ML batch scoring endpoint.

Tests auth requirements and request validation via dependency override.
Actual scoring logic is covered by the scoring module tests.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel_x.api.app import create_app
from sentinel_x.api.deps import AuthUser, get_current_user


def _fake_admin() -> AuthUser:
    return AuthUser(username="testadmin", role="admin")


@pytest.fixture()
def client() -> TestClient:
    app = create_app()
    app.dependency_overrides[get_current_user] = _fake_admin
    return TestClient(app, raise_server_exceptions=False)


def test_score_requires_auth() -> None:
    app = create_app()
    c = TestClient(app, raise_server_exceptions=False)
    resp = c.post("/api/ml/score", json={"events": [{"event_id": "e1"}]})
    assert resp.status_code == 401


def test_score_empty_batch_rejected(client: TestClient) -> None:
    resp = client.post("/api/ml/score", json={"events": []})
    assert resp.status_code == 422


def test_score_exceeds_max_rejected(client: TestClient) -> None:
    events = [{"event_id": f"evt_{i}"} for i in range(501)]
    resp = client.post("/api/ml/score", json={"events": events})
    assert resp.status_code == 422


def test_score_missing_events_field_rejected(client: TestClient) -> None:
    resp = client.post("/api/ml/score", json={})
    assert resp.status_code == 422


def test_score_valid_single_event(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import pandas as pd

    def _fake_score(events: pd.DataFrame) -> pd.DataFrame:
        return events.assign(attack_probability=0.75, anomaly_score=0.3)

    monkeypatch.setattr(
        "sentinel_x.api.routers.ml.score_host_minutes", _fake_score
    )
    resp = client.post(
        "/api/ml/score",
        json={"events": [{"event_id": "evt_001", "host": "WS-001"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["n_events"] == 1
    assert len(body["scored"]) == 1
    assert body["scored"][0]["event_id"] == "evt_001"
    assert body["scored"][0]["attack_probability"] == 0.75
