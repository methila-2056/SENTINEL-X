"""Experiment: end-to-end detection -> correlation -> incident formation.

Loads synthetic events, scores host-minute buckets with the trained XGBoost
model, correlates flagged events into incidents, scores risk and compares
formed incident membership against ground truth.

Usage:
    python experiments/incidents/run_correlation.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.common.db import get_sync_session  # noqa: E402
from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.data.db.models import IncidentRow  # noqa: E402
from sentinel_x.incidents.correlator import correlate_events  # noqa: E402
from sentinel_x.incidents.risk import score_incident  # noqa: E402
from sentinel_x.ml.features.window_features import (  # noqa: E402
    FEATURE_COLUMNS,
    build_host_minute_features,
)


def correlation_quality(formed: list[set[str]], ground_truth: dict[str, set[str]]) -> dict:
    """Score formed incident boundaries against ground-truth groupings.

    For each ground-truth incident, find the formed incident with best overlap;
    compute precision/recall/F1 over event membership.
    """
    precisions, recalls, f1s = [], [], []
    matched = 0
    for gt_ids in ground_truth.values():
        if not formed:
            break
        gt_set = set(gt_ids)
        best = max(formed, key=lambda f: len(f & gt_set))
        overlap = len(best & gt_set)
        precision = overlap / len(best) if best else 0.0
        recall = overlap / len(gt_set) if gt_set else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)
        matched += int(recall >= 0.8)
    return {
        "incidents_recovered": matched,
        "incidents_total": len(ground_truth),
        "recovery_rate": round(matched / max(len(ground_truth), 1), 3),
        "mean_boundary_precision": round(float(np.mean(precisions or [0])), 3),
        "mean_boundary_recall": round(float(np.mean(recalls or [0])), 3),
        "mean_boundary_f1": round(float(np.mean(f1s or [0])), 3),
    }


def main() -> int:
    configure_logging()
    events = pd.read_parquet(ROOT / "data/processed/synthetic/events.parquet")
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)

    # --- ML scoring on host-minute buckets -----------------------------------
    model_bundle = joblib.load(ROOT / "models/xgboost.joblib")
    model = model_bundle["model"]
    features = build_host_minute_features(events)
    probs = model.predict_proba(features[FEATURE_COLUMNS].to_numpy(dtype=np.float64))[:, 1]
    features["attack_probability"] = probs

    flagged_buckets = set(
        map(
            tuple, features.loc[features["attack_probability"] > 0.5, ["host", "minute"]].to_numpy()
        )
    )
    bucket_lookup = {(r.host, r.minute): r.attack_probability for r in features.itertuples()}

    def event_bucket_prob(row) -> float:
        minute = row["timestamp"].floor("min")
        return float(bucket_lookup.get((row.get("host") or "unknown", minute), 0.0))

    events["ml_attack_probability"] = events.apply(event_bucket_prob, axis=1)

    # --- Correlation over flagged + neighboring events ------------------------
    # Correlate only events in flagged buckets (plus small padding) to keep
    # incident boundaries tight rather than clustering the entire stream.
    flagged_events = events[
        events.apply(
            lambda r: (r.get("host") or "unknown", r["timestamp"].floor("min")) in flagged_buckets,
            axis=1,
        )
    ]
    print(f"Flagged events for correlation: {len(flagged_events)}")

    candidates = correlate_events(flagged_events, entity_link_window="30min")

    with open(ROOT / "data/processed/synthetic/incidents_ground_truth.json") as fh:
        gt_incidents = json.load(fh)

    session = get_sync_session()
    formed_sets: list[set[str]] = []
    try:
        for idx, cand in enumerate(candidates[:50]):
            member_rows = events[events["event_id"].isin(cand.member_event_ids)]
            prob = float(member_rows["ml_attack_probability"].max())
            scored = score_incident(member_rows, attack_probability=prob)
            if scored["risk_score"] < 0.4:
                continue
            incident_id = f"FORMED-{idx:04d}"
            formed_sets.append(set(cand.member_event_ids))
            session.merge(
                IncidentRow(
                    id=incident_id,
                    first_seen=cand.first_seen.to_pydatetime(),
                    last_seen=cand.last_seen.to_pydatetime(),
                    status="open",
                    severity_label=scored["severity_label"],
                    risk_score=scored["risk_score"],
                    attack_probability=prob,
                    correlated_event_ids=cand.member_event_ids[:500],
                    entities={
                        "users": sorted(cand.users)[:20],
                        "hosts": sorted(cand.hosts)[:20],
                        "external_ips": sorted(cand.dst_ips_external)[:20],
                    },
                )
            )
        session.commit()
    finally:
        session.close()

    quality = correlation_quality(
        formed_sets,
        {
            g["incident_id"]: set(events.loc[events["incident_id"] == g["incident_id"], "event_id"])
            for g in gt_incidents
        },
    )

    out_dir = ROOT / "experiments/ml"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "correlation_quality.json", "w") as fh:
        json.dump(quality, fh, indent=2)
    print("Correlation quality:", quality)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
