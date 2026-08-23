"""Experiment: classical baseline detection models on synthetic telemetry.

Usage:
    python experiments/ml/run_baseline.py [--source synthetic] [--seed 42]
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.evaluation.ml.metrics import save_metrics_report  # noqa: E402
from sentinel_x.ml.features.window_features import (  # noqa: E402
    FEATURE_COLUMNS,
    build_host_minute_features,
)
from sentinel_x.ml.training.classical import run_model_suite  # noqa: E402


def load_events(source: str) -> pd.DataFrame:
    if source == "synthetic":
        path = ROOT / "data/processed/synthetic/events.parquet"
    elif source == "cicids2017":
        path = ROOT / "data/processed/cicids2017/events.parquet"
    else:
        raise ValueError(f"Unknown source: {source}")
    return pd.read_parquet(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="synthetic", choices=["synthetic", "cicids2017"])
    parser.add_argument("--split-quantile", type=float, default=0.75)
    args = parser.parse_args()

    events = load_events(args.source)
    print(f"Loaded {len(events)} events")

    features = build_host_minute_features(events)
    print(f"Built {len(features)} host-minute feature rows")
    print(f"Attack rate: {features['label_attack'].mean():.4f}")

    # Temporal split to avoid leakage from the future
    cutoff = features["minute"].quantile(args.split_quantile)
    train_mask = features["minute"] < cutoff
    X_train = features.loc[train_mask, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    y_train = features.loc[train_mask, "label_attack"].to_numpy()
    X_test = features.loc[~train_mask, FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    y_test = features.loc[~train_mask, "label_attack"].to_numpy()

    print(
        f"Train: {len(X_train)} rows ({y_train.sum()} attacks) | "
        f"Test: {len(X_test)} rows ({y_test.sum()} attacks)"
    )

    out_dir = ROOT / f"experiments/ml/baseline_{args.source}"
    metrics = run_model_suite(
        experiment_name=f"sentinel-x-baseline-{args.source}",
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_names=FEATURE_COLUMNS,
        artifacts_dir=out_dir,
        models_dir=ROOT / "models",
    )
    json_path = save_metrics_report(metrics, out_dir)
    print(f"Metrics saved -> {json_path}")
    for name, m in metrics.items():
        print(f"  {name:20s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
