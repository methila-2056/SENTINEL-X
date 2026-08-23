"""Unit tests for windowed feature engineering."""

from datetime import UTC, datetime, timedelta

import pandas as pd
import pytest

from sentinel_x.ml.features.window_features import (
    FEATURE_COLUMNS,
    build_host_minute_features,
)


def _events_df() -> pd.DataFrame:
    t0 = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    rows = []

    def ev(ts, **kw):
        base = dict(
            event_id=f"e{len(rows)}",
            timestamp=ts,
            source="test",
            event_type="process_execution",
            action="execute",
            user="alice",
            host="WS-1",
            process="chrome.exe",
            src_ip="10.0.1.10",
            dst_ip=None,
            dst_port=None,
            file_path=None,
            bytes_transferred=None,
            severity=0,
            label="benign",
            attack_category=None,
            technique_id=None,
            incident_id=None,
            metadata={},
        )
        base.update(kw)
        rows.append(base)

    # Normal login + app
    ev(t0, event_type="authentication", action="login_success")
    for i in range(5):
        ev(t0 + timedelta(seconds=60 * i), process="excel.exe")
    # Attack burst: failed logins from a bad IP
    bad = t0 + timedelta(minutes=10)
    for i in range(20):
        ev(
            bad + timedelta(seconds=i),
            event_type="authentication",
            action="login_failure",
            src_ip="185.220.101.7",
            label="attack",
            attack_category="brute_force",
            severity=3,
        )
    return pd.DataFrame(rows)


class TestBuildHostMinuteFeatures:
    @pytest.fixture
    def features(self) -> pd.DataFrame:
        return build_host_minute_features(_events_df())

    def test_output_shape_and_columns(self, features: pd.DataFrame) -> None:
        assert len(features) > 0
        missing = [c for c in FEATURE_COLUMNS if c not in features.columns]
        assert not missing, f"Missing columns: {missing}"
        assert "label_attack" in features.columns
        assert list(features.columns[:2]) == ["host", "minute"]

    def test_attack_bucket_flagged(self, features: pd.DataFrame) -> None:
        attacks = features[features["label_attack"] == 1]
        assert len(attacks) >= 1
        assert (attacks["n_auth_fail"] > 0).all()

    def test_rolling_columns_present(self, features: pd.DataFrame) -> None:
        roll = [c for c in features.columns if c.endswith("_prev5m")]
        assert len(roll) >= 10

    def test_no_nulls_in_features(self, features: pd.DataFrame) -> None:
        assert features[FEATURE_COLUMNS].isna().sum().sum() == 0

    def test_benign_buckets_have_no_auth_fails_from_attack_window(self, features) -> None:
        benign = features[(features["label_attack"] == 0)]
        assert (benign["n_unique_src_ips"] <= 2).all()

    def test_handles_empty_stream(self) -> None:
        empty = _events_df().iloc[0:0]
        out = build_host_minute_features(empty)
        assert isinstance(out, pd.DataFrame)

    def test_deterministic(self) -> None:
        a = build_host_minute_features(_events_df())
        b = build_host_minute_features(_events_df())
        pd.testing.assert_frame_equal(a, b)
