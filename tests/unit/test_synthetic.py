"""Unit tests for the synthetic scenario generator."""

import numpy as np
import pandas as pd

from sentinel_x.data.ingestion.synthetic import (
    build_world,
    generate_benign_events,
    generate_dataset,
)


class TestWorld:
    def test_build_world_deterministic(self) -> None:
        users_a, hosts_a = build_world(42)
        users_b, hosts_b = build_world(42)
        assert users_a == users_b
        assert hosts_a == hosts_b
        assert all("workstation" in u for u in users_a)
        assert len(hosts_a) > len(users_a)  # includes servers


class TestBenignGeneration:
    def test_generates_events_and_all_benign(self) -> None:
        rng = np.random.default_rng(7)
        users, _ = build_world(42)
        from datetime import UTC, datetime

        day_start = datetime(2026, 8, 3, tzinfo=UTC)
        events = generate_benign_events(
            users[:5], [u["workstation"] for u in users[:5]], 2, rng, day_start
        )
        assert len(events) > 50
        df = pd.DataFrame(events)
        assert (df["label"] == "benign").all()
        # Timestamps must fall within the generated window
        ts = pd.to_datetime(df["timestamp"])
        assert ts.min() >= pd.Timestamp(day_start)
        assert ts.max() < pd.Timestamp(day_start) + pd.Timedelta(days=2)

    def test_no_weekend_traffic_for_employees(self) -> None:
        rng = np.random.default_rng(1)
        users, _ = build_world(42)
        employees = [u for u in users if u["role"] != "it_admin"]
        from datetime import UTC, datetime

        saturday = datetime(2026, 8, 8, tzinfo=UTC)  # a Saturday
        events = generate_benign_events(
            employees, [u["workstation"] for u in employees], 2, rng, saturday
        )
        df = pd.DataFrame(events)
        if len(df):
            days = pd.to_datetime(df["timestamp"]).dt.weekday
            assert (days >= 5).all()  # only weekend-day events


class TestDatasetGeneration:
    def test_full_dataset_with_ground_truth(self, tmp_path) -> None:
        df, incidents = generate_dataset(tmp_path / "syn", seed=99, days=2, n_attacks=4)
        assert len(incidents) == 4
        attack_rows = df[df["label"] == "attack"]
        assert len(attack_rows) > 0
        # Every attack event maps to a known incident id
        gt_ids = {i["incident_id"] for i in incidents}
        assert set(attack_rows["incident_id"].dropna().unique()) <= gt_ids
        # Technique ids populated on attack rows and valid MITRE format
        tech = attack_rows["technique_id"].dropna()
        assert tech.str.match(r"^T\d{4}$").all()
        # Incidents reference real scenario names
        assert all(i["scenario"] for i in incidents)
        # Artifacts written
        assert (tmp_path / "syn" / "events.parquet").exists()
        assert (tmp_path / "syn" / "incidents_ground_truth.json").exists()

    def test_seed_reproducibility(self, tmp_path) -> None:
        df_a, inc_a = generate_dataset(tmp_path / "a", seed=5, days=1, n_attacks=2)
        df_b, inc_b = generate_dataset(tmp_path / "b", seed=5, days=1, n_attacks=2)
        pd.testing.assert_frame_equal(df_a.reset_index(drop=True), df_b.reset_index(drop=True))
        assert len(inc_a) == len(inc_b)
