"""ML evaluation metrics for detection models."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def compute_detection_metrics(
    y_true: np.ndarray, y_proba: np.ndarray, threshold: float = 0.5
) -> dict:
    """Binary detection metrics at a fixed decision threshold + threshold-free AUCs."""
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "threshold": threshold,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None,
        "pr_auc": float(average_precision_score(y_true, y_proba))
        if len(np.unique(y_true)) > 1
        else None,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
    }


def save_evaluation_charts(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    model_name: str,
    out_dir: Path,
) -> dict[str, str]:
    """Save ROC curve, PR curve and confusion matrix charts. Returns file paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots(figsize=(5, 4))
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        ax.plot(fpr, tpr, label=f"ROC AUC={roc_auc_score(y_true, y_proba):.3f}")
        ax.plot([0, 1], [0, 1], "k--", linewidth=0.7)
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title(f"ROC — {model_name}")
        ax.legend()
        roc_path = out_dir / f"{model_name}_roc.png"
        fig.tight_layout()
        fig.savefig(roc_path, dpi=120)
        plt.close(fig)
        paths["roc"] = str(roc_path)

        fig, ax = plt.subplots(figsize=(5, 4))
        prec, rec, _ = precision_recall_curve(y_true, y_proba)
        ax.plot(rec, prec, label=f"PR AUC={average_precision_score(y_true, y_proba):.3f}")
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.set_title(f"Precision-Recall — {model_name}")
        ax.legend()
        pr_path = out_dir / f"{model_name}_pr.png"
        fig.tight_layout()
        fig.savefig(pr_path, dpi=120)
        plt.close(fig)
        paths["pr"] = str(pr_path)

    return paths


def save_metrics_report(all_metrics: dict[str, dict], out_dir: Path) -> Path:
    """Persist a JSON metrics report and a Markdown summary table."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "metrics.json"
    with open(json_path, "w") as fh:
        json.dump(all_metrics, fh, indent=2)

    header = "| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | FP | FN |"
    sep = "|---|---|---|---|---|---|---|---|"
    lines = [header, sep]
    for name, m in all_metrics.items():
        lines.append(
            f"| {name} "
            f"| {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} "
            f"| {m['roc_auc'] if m['roc_auc'] is not None else 'n/a'} "
            f"| {m['pr_auc'] if m['pr_auc'] is not None else 'n/a'} "
            f"| {m['false_positives']} | {m['false_negatives']} |"
        )
    md_path = out_dir / "metrics_summary.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path
