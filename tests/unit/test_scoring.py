"""Tests for ML inference scoring helpers."""

import numpy as np
import pandas as pd

import sentinel_x.ml.inference.scoring as scoring


def _events(n=30, host="WS-1", label="benign"):
    t0 = pd.Timestamp("2026-08-16 10:00:00", tz="UTC")
    return pd.DataFrame(
        {
            "event_id": [f"e{i}" for i in range(n)],
            "timestamp": [t0 + pd.Timedelta(seconds=20 * i) for i in range(n)],
            "source": "auth_log",
            "event_type": "authentication",
            "action": "login_failure",
            "user": ["alice"] * n,
            "host": host,
            "process": None,
            "src_ip": ["10.0.0.9"] * n,
            "dst_ip": None,
            "dst_port": None,
            "file_path": None,
            "bytes_transferred": np.nan,
            "severity": 0,
            "label": label,
        }
    )


class TestScoreHostMinutes:
    def test_returns_scores_per_window(self, monkeypatch):
        # Force fallback path by hiding artifacts
        import pathlib

        monkeypatch.setattr(scoring, "MODELS_DIR", pathlib.Path("definitely/missing"))
        scoring.load_model.cache_clear()
        out = scoring.score_host_minutes(_events())
        assert not out.empty
        assert "attack_probability" in out.columns
        assert "anomaly_score" in out.columns
        assert (out["attack_probability"] == 0.5).all()

    def test_empty_input(self):
        empty = pd.DataFrame(
            columns=[
                "event_id",
                "timestamp",
                "event_type",
                "action",
                "user",
                "host",
                "src_ip",
                "dst_ip",
                "process",
                "file_path",
                "bytes_transferred",
                "severity",
                "label",
            ]
        )
        out = scoring.score_host_minutes(empty)
        assert out.empty

    def test_real_model_scores_in_range(self):
        scoring.load_model.cache_clear()
        out = scoring.score_host_minutes(_events())
        if "attack_probability" in out.columns:
            assert ((out["attack_probability"] >= 0) & (out["attack_probability"] <= 1)).all()


class TestScoreIncidentEvents:
    def test_window_filtering(self):
        scoring.load_model.cache_clear()
        events = _events(n=60)
        features = scoring.score_host_minutes(events)
        first = events["timestamp"].min()
        last = events["timestamp"].max()
        scores = scoring.score_incident_events(events, first, last, {"WS-1"})
        assert set(scores) == {"attack_probability", "anomaly_score"}
        for value in scores.values():
            if value is not None:
                assert 0.0 <= value <= 1.0
        _ = features
