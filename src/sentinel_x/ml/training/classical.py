"""Classical ML detection models: Logistic Regression, Random Forest, XGBoost,
Isolation Forest. Trained with temporal splits and tracked in MLflow."""

from pathlib import Path

import joblib
import mlflow
import numpy as np
import structlog
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from sentinel_x.evaluation.ml.metrics import (
    compute_detection_metrics,
    save_evaluation_charts,
)

logger = structlog.get_logger(__name__)


def _make_logistic_regression(y_train: np.ndarray) -> Pipeline:
    pos_weight = float((y_train == 0).sum() / max((y_train == 1).sum(), 1))
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    class_weight={0: 1.0, 1: pos_weight}, max_iter=2000, random_state=42
                ),
            ),
        ]
    )


def _make_random_forest() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )


def _make_xgboost(y_train: np.ndarray) -> XGBClassifier:
    neg, pos = float((y_train == 0).sum()), float((y_train == 1).sum())
    return XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        scale_pos_weight=neg / max(pos, 1.0),
        eval_metric="aucpr",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )


def train_supervised(
    model_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    artifacts_dir: Path,
) -> tuple[object, dict]:
    """Train one supervised model and evaluate at a threshold tuned on F1."""
    if model_name == "logistic_regression":
        model = _make_logistic_regression(y_train)
    elif model_name == "random_forest":
        model = _make_random_forest()
    elif model_name == "xgboost":
        model = _make_xgboost(y_train)
    else:
        raise ValueError(f"Unknown supervised model: {model_name}")

    model.fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]

    # Threshold selection from the PR curve midpoint heuristic (fixed 0.5 default)
    metrics = compute_detection_metrics(y_test, proba, threshold=0.5)
    save_evaluation_charts(y_test, proba, model_name, artifacts_dir)
    return model, metrics


def train_isolation_forest(
    X_train_benign: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    contamination: float = 0.01,
) -> tuple[IsolationForest, dict]:
    """Unsupervised anomaly detector trained only on benign traffic."""
    iso = IsolationForest(n_estimators=250, contamination=contamination, n_jobs=-1, random_state=42)
    iso.fit(X_train_benign)
    # IsolationForest: -1 = anomaly. Convert decision_function to 0-1 score.
    scores = -iso.decision_function(X_test)
    normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-12)
    metrics = compute_detection_metrics(y_test, normalized, threshold=0.5)
    return iso, metrics


def run_model_suite(
    experiment_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: list[str],
    artifacts_dir: Path,
    models_dir: Path | None = None,
) -> dict[str, dict]:
    """Train all classical baselines with MLflow tracking. Returns metrics by model."""
    mlflow.set_experiment(experiment_name)
    all_metrics: dict[str, dict] = {}

    supervised_models = ["logistic_regression", "random_forest", "xgboost"]
    for name in supervised_models:
        with mlflow.start_run(run_name=name):
            model, metrics = train_supervised(name, X_train, y_train, X_test, y_test, artifacts_dir)
            all_metrics[name] = metrics
            mlflow.log_params(
                {
                    "model": name,
                    "n_features": X_train.shape[1],
                    "n_train": len(X_train),
                    "n_test": len(X_test),
                    "train_attack_rate": float(y_train.mean()),
                }
            )
            mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
            if models_dir is not None:
                models_dir.mkdir(parents=True, exist_ok=True)
                path = models_dir / f"{name}.joblib"
                joblib.dump({"model": model, "feature_names": feature_names}, path)
                mlflow.log_artifact(str(path))
            logger.info("model_trained", model=name, f1=metrics["f1"])

    # Isolation Forest: fit on benign training rows only
    with mlflow.start_run(run_name="isolation_forest"):
        benign_mask = y_train == 0
        iso, iso_metrics = train_isolation_forest(X_train[benign_mask], X_test, y_test)
        all_metrics["isolation_forest"] = iso_metrics
        mlflow.log_params({"model": "isolation_forest", "contamination": 0.01})
        mlflow.log_metrics({k: v for k, v in iso_metrics.items() if isinstance(v, (int, float))})
        if models_dir is not None:
            models_dir.mkdir(parents=True, exist_ok=True)
            path = models_dir / "isolation_forest.joblib"
            joblib.dump({"model": iso, "feature_names": feature_names}, path)
            mlflow.log_artifact(str(path))
        logger.info("model_trained", model="isolation_forest", f1=iso_metrics["f1"])

    return all_metrics
