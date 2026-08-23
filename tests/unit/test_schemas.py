"""Unit tests for the canonical event schema."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel_x.data.schemas.event import (
    Action,
    EventType,
    IncidentGroundTruth,
    Label,
    SecurityEvent,
)


def _make_event(**overrides):
    base = dict(
        event_id="syn-1",
        timestamp=datetime(2026, 8, 1, 9, 0, tzinfo=UTC),
        source="auth_log",
        event_type=EventType.AUTHENTICATION,
        action=Action.LOGIN_SUCCESS,
        user="alice",
        host="WS-100",
        src_ip="10.0.1.10",
        label=Label.BENIGN,
    )
    base.update(overrides)
    return SecurityEvent(**base)


class TestSecurityEvent:
    def test_valid_event(self) -> None:
        ev = _make_event()
        assert ev.event_type == EventType.AUTHENTICATION
        assert ev.label == Label.BENIGN
        assert ev.metadata == {}

    def test_missing_required_field(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(event_id=None)

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(dst_port=70000)

    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_event(severity=11)

    def test_frozen_model(self) -> None:
        ev = _make_event()
        with pytest.raises(ValidationError):
            ev.user = "bob"

    def test_roundtrip_serialization(self) -> None:
        ev = _make_event()
        payload = ev.model_dump(mode="json")
        restored = SecurityEvent.model_validate(payload)
        assert restored == ev


class TestIncidentGroundTruth:
    def test_valid_incident(self) -> None:
        gt = IncidentGroundTruth(
            incident_id="INC-1000",
            scenario="ransomware_encryption",
            technique_ids=["T1059", "T1486"],
            start_time=datetime(2026, 8, 1, 9, 0, tzinfo=UTC),
            end_time=datetime(2026, 8, 1, 9, 30, tzinfo=UTC),
            compromised_users=["alice"],
            compromised_hosts=["WS-100"],
            description="test",
        )
        assert len(gt.technique_ids) == 2
