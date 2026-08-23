"""Unit tests for detection metrics computation."""

import numpy as np

from sentinel_x.evaluation.ml.metrics import compute_detection_metrics


def test_perfect_predictions() -> None:
    y = np.array([0, 0, 1, 1])
    p = np.array([0.1, 0.2, 0.9, 0.8])
    m = compute_detection_metrics(y, p, threshold=0.5)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["roc_auc"] == 1.0
    assert m["false_positives"] == 0


def test_all_wrong() -> None:
    y = np.array([0, 0, 1, 1])
    p = np.array([0.9, 0.8, 0.1, 0.2])
    m = compute_detection_metrics(y, p)
    assert m["recall"] == 0.0
    assert m["false_negatives"] == 2
    assert m["false_positives"] == 2


def test_single_class_returns_none_aucs() -> None:
    y = np.array([1, 1, 1])
    p = np.array([0.4, 0.6, 0.5])
    m = compute_detection_metrics(y, p)
    assert m["roc_auc"] is None
    assert m["pr_auc"] is None


def test_counts_sum_to_total() -> None:
    rng = np.random.default_rng(3)
    y = (rng.random(200) > 0.7).astype(int)
    p = rng.random(200)
    m = compute_detection_metrics(y, p)
    total = m["true_positives"] + m["false_positives"] + m["true_negatives"] + m["false_negatives"]
    assert total == 200
