"""Training loop for the Transformer event-sequence model."""

from pathlib import Path

import numpy as np
import structlog
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from sentinel_x.evaluation.ml.metrics import (
    compute_detection_metrics,
    save_evaluation_charts,
)
from sentinel_x.ml.models.transformer import EventTransformer

logger = structlog.get_logger(__name__)


def _pos_weight(y: np.ndarray) -> float:
    neg = float((y == 0).sum())
    pos = max(float((y == 1).sum()), 1.0)
    return neg / pos


def train_event_transformer(
    train_tokens: np.ndarray,
    train_numerics: np.ndarray,
    train_labels: np.ndarray,
    test_tokens: np.ndarray,
    test_numerics: np.ndarray,
    test_labels: np.ndarray,
    vocab_size: int,
    artifacts_dir: Path,
    model_path: Path | None = None,
    epochs: int = 12,
    batch_size: int = 128,
    lr: float = 1e-3,
    device: str | None = None,
) -> tuple[EventTransformer, dict]:
    """Train with class-weighted BCE, early stopping on val F1. Returns (model, metrics)."""
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(42)

    # Validation split from the tail of training data (already temporal upstream)
    n_val = max(int(len(train_tokens) * 0.15), 8)
    t_all = torch.from_numpy(train_tokens.astype(np.int64))
    n_all = torch.from_numpy(train_numerics.astype(np.float32))
    y_all = torch.from_numpy(train_labels.astype(np.float32))
    ds_train = TensorDataset(t_all[:-n_val], n_all[:-n_val], y_all[:-n_val])
    ds_val = TensorDataset(t_all[-n_val:], n_all[-n_val:], y_all[-n_val:])
    dl_train = DataLoader(ds_train, batch_size=batch_size, shuffle=True)
    dl_val = DataLoader(ds_val, batch_size=batch_size)

    model = EventTransformer(vocab_size=vocab_size).to(device)
    criterion = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor(_pos_weight(train_labels), dtype=torch.float32, device=device)
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    best_f1 = -1.0
    best_state = None
    patience = 3
    stale = 0

    def run_epoch(dl: DataLoader, train_mode: bool) -> float:
        model.train(train_mode)
        total_loss = 0.0
        count = 0
        with torch.set_grad_enabled(train_mode):
            for toks, nums, ys in dl:
                toks, nums, ys = toks.to(device), nums.to(device), ys.to(device)
                logits = model(toks, nums)
                loss = criterion(logits, ys)
                if train_mode:
                    optimizer.zero_grad()
                    loss.backward()
                    nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                total_loss += float(loss.item()) * len(ys)
                count += len(ys)
        return total_loss / max(count, 1)

    for epoch in range(epochs):
        train_loss = run_epoch(dl_train, True)
        val_loss = run_epoch(dl_val, False)
        logger.info(
            "epoch", epoch=epoch + 1, train_loss=round(train_loss, 4), val_loss=round(val_loss, 4)
        )
        # Track val F1 using the current model
        model.eval()
        probs = []
        with torch.no_grad():
            for toks, nums, _ys in dl_val:
                logits = model(toks.to(device), nums.to(device))
                probs.append(torch.sigmoid(logits).cpu().numpy())
        val_p = np.concatenate(probs)
        val_y = ds_val.tensors[2].numpy()
        m = compute_detection_metrics(val_y, val_p)
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                logger.info("early_stop", epoch=epoch + 1, best_f1=best_f1)
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Final evaluation on the held-out test split
    ds_test = TensorDataset(
        torch.from_numpy(test_tokens.astype(np.int64)),
        torch.from_numpy(test_numerics.astype(np.float32)),
    )
    dl_test = DataLoader(ds_test, batch_size=batch_size)
    model.eval()
    test_probs: list[np.ndarray] = []
    with torch.no_grad():
        for toks, nums in dl_test:
            logits = model(toks.to(device), nums.to(device))
            test_probs.append(torch.sigmoid(logits).cpu().numpy())
    test_proba = np.concatenate(test_probs)
    metrics = compute_detection_metrics(test_labels, test_proba)
    save_evaluation_charts(test_labels, test_proba, "event_transformer", artifacts_dir)

    if model_path is not None:
        model_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), model_path)

    return model, metrics
