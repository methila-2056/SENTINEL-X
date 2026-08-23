"""Experiment: Transformer sequence model vs classical baselines on synthetic data.

Usage:
    python experiments/ml/run_deep_model.py [--epochs 12]
"""

import argparse
import sys
from pathlib import Path

import mlflow
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_x.evaluation.ml.metrics import save_metrics_report  # noqa: E402
from sentinel_x.ml.models.sequence_dataset import (  # noqa: E402
    EventVocab,
    build_sequences,
)
from sentinel_x.ml.training.deep import train_event_transformer  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=12)
    args = parser.parse_args()

    events = pd.read_parquet(ROOT / "data/processed/synthetic/events.parquet")
    tokens, numerics, labels = build_sequences(events)
    vocab = EventVocab.from_events(events)
    print(f"Sequences: {len(labels)} | attack windows: {int(labels.sum())} | vocab: {vocab.size}")

    # Temporal split at the sequence level using window start timestamps is complex;
    # use a deterministic random split with fixed seed for this experiment.
    rng = np.random.default_rng(42)
    idx = rng.permutation(len(labels))
    split = int(len(idx) * 0.8)
    tr, te = idx[:split], idx[split:]

    mlflow.set_experiment("sentinel-x-deep-synthetic")
    with mlflow.start_run(run_name="event_transformer"):
        model, metrics = train_event_transformer(
            tokens[tr],
            numerics[tr],
            labels[tr],
            tokens[te],
            numerics[te],
            labels[te],
            vocab_size=vocab.size,
            artifacts_dir=ROOT / "experiments/ml/deep_synthetic",
            model_path=ROOT / "models/event_transformer.pt",
            epochs=args.epochs,
        )
        mlflow.log_params(
            {
                "model": "event_transformer",
                "params": model.num_parameters(),
                "seq_len": tokens.shape[1],
                "vocab_size": vocab.size,
                "n_train": len(tr),
                "n_test": len(te),
            }
        )
        mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
        mlflow.log_artifact(str(ROOT / "models/event_transformer.pt"))

    save_metrics_report({"event_transformer": metrics}, ROOT / "experiments/ml/deep_synthetic")
    print(
        f"event_transformer     P={metrics['precision']:.3f} R={metrics['recall']:.3f} F1={metrics['f1']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
