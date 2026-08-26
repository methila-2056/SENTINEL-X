"""Live scoring: load trained detection models and score event groups.

Used by the incident engine to attach ML-derived attack probability and
anomaly scores to correlated incidents at ingestion time.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sentinel_x.common.logging import get_logger
from sentinel_x.ml.features.window_features import FEATURE_COLUMNS, build_host_minute_features

logger = get_logger(__name__)

MODELS_DIR = Path("models")


@lru_cache(maxsize=4)
def load_model(name: str):
    """Load a joblib model artifact from the models directory (cached).

    Artifacts are stored as {"model": estimator, "feature_names": [...]}.
    """
    path = MODELS_DIR / f"{name}.joblib"
    if not path.exists():
        logger.warning("model_artifact_missing", model=name, path=str(path))
        return None
    bundle = joblib.load(path)
    if isinstance(bundle, dict) and "model" in bundle:
        feature_names = bundle.get("feature_names") or []
        if feature_names and list(feature_names) != list(FEATURE_COLUMNS):
            logger.warning(
                "model_feature_mismatch",
                model=name,
                n_expected=len(FEATURE_COLUMNS),
                n_saved=len(feature_names),
            )
        return bundle["model"]
    return bundle


def score_host_minutes(events: pd.DataFrame) -> pd.DataFrame:
    """Build host-minute features and append ML scores for each window.

    Adds:
      attack_probability - XGBoost probability that the window is malicious
      anomaly_score      - Isolation Forest abnormality in [0, 1]
    Falls back to neutral scores when artifacts are unavailable.
    """
    features = build_host_minute_features(events)
    if features.empty:
        return features.assign(attack_probability=[], anomaly_score=[])

    X = features[FEATURE_COLUMNS].to_numpy(dtype=np.float64)

    clf = load_model("xgboost")
    proba = clf.predict_proba(X)[:, 1] if clf is not None else np.full(len(X), 0.5)

    iso = load_model("isolation_forest")
    if iso is not None:
        raw = -iso.decision_function(X)  # higher = more anomalous
        lo, hi = float(raw.min()), float(raw.max())
        anomaly = (raw - lo) / (hi - lo) if hi > lo else np.zeros_like(raw)
    else:
        anomaly = np.full(len(X), 0.5)

    features["attack_probability"] = np.round(proba, 4)
    features["anomaly_score"] = np.round(anomaly, 4)
    return features


def score_incident_events(
    events: pd.DataFrame,
    first_seen: pd.Timestamp,
    last_seen: pd.Timestamp,
    hosts: set[str],
) -> dict[str, float | None]:
    """ML scores for one incident: max window scores overlapping its span.

    Only windows whose host participates in the incident and whose minute
    falls within [first_seen, last_seen] are considered.
    """
    features = score_host_minutes(events)
    if features.empty:
        return {"attack_probability": None, "anomaly_score": None}

    mask = (
        (features["minute"] >= first_seen.floor("min"))
        & (features["minute"] <= last_seen.ceil("min"))
        & (features["host"].isin(hosts) if hosts else True)
    )
    subset = features.loc[mask]
    if subset.empty:
        return {"attack_probability": None, "anomaly_score": None}
    return {
        "attack_probability": float(subset["attack_probability"].max()),
        "anomaly_score": float(subset["anomaly_score"].max()),
    }
