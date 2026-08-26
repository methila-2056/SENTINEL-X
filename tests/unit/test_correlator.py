"""Unit tests for event correlation and risk scoring."""

from datetime import UTC, datetime, timedelta

import pandas as pd
import pytest

from sentinel_x.incidents.correlator import correlate_events
from sentinel_x.incidents.risk import score_incident


def _df() -> pd.DataFrame:
    t0 = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    rows = []

    def ev(ts, **kw):
        base = dict(
            event_id=f"e{len(rows)}",
            timestamp=ts,
            source="test",
            event_type="authentication",
            action="login_failure",
            user="alice",
            host="WS-1",
            process=None,
            src_ip="185.1.1.1",
            dst_ip=None,
            dst_port=3389,
            file_path=None,
            bytes_transferred=None,
            severity=3,
            label="attack",
            attack_category="brute_force",
            technique_id="T1110",
            incident_id="INC-1000",
            metadata={},
        )
        base.update(kw)
        rows.append(base)

    for i in range(10):  # burst on WS-1
        ev(t0 + timedelta(seconds=i * 5))
    # Unrelated benign host far away in time
    ev(
        t0 + timedelta(hours=4),
        host="WS-9",
        user="bob",
        src_ip="10.0.0.9",
        label="benign",
        action="login_success",
    )
    return pd.DataFrame(rows)


class TestCorrelator:
    def test_burst_forms_single_incident(self) -> None:
        candidates = correlate_events(_df(), entity_link_window="15min")
        big = candidates[0]
        assert (
            len(big.member_event_ids) == 10
        )  # the burst; the benign event shares no entity with it
        assert "WS-1" in big.hosts

    def test_unrelated_events_separate(self) -> None:
        candidates = correlate_events(_df(), entity_link_window="15min")
        assert len(candidates) >= 2

    def test_time_window_respected(self) -> None:
        df = _df()
        # Push last benign event to overlap window -> still separate by host/user/ip
        candidates = correlate_events(df, entity_link_window="1s")
        sizes = [len(c.member_event_ids) for c in candidates]
        assert max(sizes) < len(df)


class TestRiskScoring:
    @pytest.fixture
    def attack_events(self) -> pd.DataFrame:
        return _df().iloc[:10]

    def test_attack_scores_high(self, attack_events: pd.DataFrame) -> None:
        scored = score_incident(attack_events, attack_probability=0.95)
        assert scored["risk_score"] > 0.6
        assert scored["severity_label"] in ("high", "critical")

    def test_benign_scores_low(self) -> None:
        events = pd.DataFrame(
            [
                {
                    "event_type": "process_execution",
                    "action": "execute",
                    "user": "alice",
                    "host": "WS-1",
                    "process": "chrome.exe",
                    "dst_ip": None,
                    "file_path": None,
                    "bytes_transferred": 100.0,
                    "severity": 0,
                }
            ]
        )
        scored = score_incident(events, attack_probability=0.02)
        assert scored["risk_score"] < 0.2
        assert scored["severity_label"] == "low"

    def test_signals_populated(self, attack_events: pd.DataFrame) -> None:
        signals = score_incident(attack_events, attack_probability=0.5)["signals"]
        assert signals["failed_login_ratio"] == 1.0
        assert signals["n_events"] == 10
