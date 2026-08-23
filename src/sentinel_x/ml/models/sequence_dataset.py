"""Sequence dataset construction for the Transformer event encoder.

Each host's ordered event stream is cut into fixed-length windows. Events are
encoded as tokens combining event type + action, with auxiliary numeric
features appended after the embedding layer.
"""

import json
from dataclasses import dataclass

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

SEQ_LEN = 32


@dataclass
class EventVocab:
    token_to_idx: dict[str, int]

    @classmethod
    def from_events(cls, events: pd.DataFrame, min_freq: int = 1) -> "EventVocab":
        tokens = events["event_type"].astype(str) + ":" + events["action"].astype(str)
        counts = tokens.value_counts()
        vocab = {"<pad>": 0, "<unk>": 1}
        for token, count in counts.items():
            if count >= min_freq:
                vocab[token] = len(vocab)
        return cls(token_to_idx=vocab)

    def encode_token(self, token: str) -> int:
        return self.token_to_idx.get(token, 1)

    @property
    def size(self) -> int:
        return len(self.token_to_idx)

    def save(self, path) -> None:
        with open(path, "w") as fh:
            json.dump(self.token_to_idx, fh, indent=2)


def numeric_event_features(events: pd.DataFrame) -> np.ndarray:
    """Per-event numeric features aligned with rows of `events`."""
    df = events.copy()
    bytes_col = pd.to_numeric(df.get("bytes_transferred"), errors="coerce").fillna(0.0)
    log_bytes = np.log1p(bytes_col.to_numpy(dtype=np.float64))
    severity = pd.to_numeric(df["severity"], errors="coerce").fillna(0.0).to_numpy(np.float64)
    dst_ip = df.get("dst_ip", pd.Series([None] * len(df))).fillna("").astype(str)
    external = (~dst_ip.str.startswith(("10.", "192.168.", "172.")) & (dst_ip != "")).to_numpy(
        np.float64
    )
    port = pd.to_numeric(df.get("dst_port"), errors="coerce").fillna(0.0).to_numpy(np.float64)
    port_norm = np.clip(port / 65535.0, 0.0, 1.0)
    return np.column_stack([log_bytes, severity / 10.0, external, port_norm]).astype(np.float32)


def build_sequences(
    events: pd.DataFrame,
    seq_len: int = SEQ_LEN,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Cut each host's event stream into fixed-length windows.

    Returns:
        tokens:   (N, seq_len) int32 padded token ids
        numerics: (N, seq_len, 4) float32 per-step numeric features
        labels:   (N,) int8 — 1 if any event in the window is an attack
    """
    vocab = EventVocab.from_events(events)
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values(["host", "timestamp"])
    df["_token"] = df["event_type"].astype(str) + ":" + df["action"].astype(str)
    numerics_all = numeric_event_features(df)

    pad_id = vocab.encode_token("<pad>")
    unk_id = vocab.encode_token("<unk>")

    token_rows: list[np.ndarray] = []
    numeric_rows: list[np.ndarray] = []
    labels: list[int] = []

    for _host, group in df.groupby("host", sort=False):
        idx = group.index.to_numpy()
        toks = np.array(
            [vocab.token_to_idx.get(t, unk_id) for t in group["_token"]], dtype=np.int64
        )
        nums = numerics_all[idx]
        is_attack = (group["label"] == "attack").to_numpy()
        n = len(toks)
        if n == 0:
            continue
        # Non-overlapping trailing windows; last window padded if short
        for start in range(0, n, seq_len):
            end = min(start + seq_len, n)
            window_toks = toks[start:end]
            window_nums = nums[start:end]
            tok_row = np.full(seq_len, pad_id, dtype=np.int64)
            num_row = np.zeros((seq_len, 4), dtype=np.float32)
            tok_row[: len(window_toks)] = window_toks
            num_row[: len(window_nums)] = window_nums
            token_rows.append(tok_row)
            numeric_rows.append(num_row)
            labels.append(int(is_attack[start:end].any()))

    return (
        np.stack(token_rows),
        np.stack(numeric_rows),
        np.asarray(labels, dtype=np.int8),
    )


class EventSequenceDataset(Dataset):
    def __init__(self, tokens: np.ndarray, numerics: np.ndarray, labels: np.ndarray):
        self.tokens = torch.from_numpy(tokens.astype(np.int64))
        self.numerics = torch.from_numpy(numerics.astype(np.float32))
        self.labels = torch.from_numpy(labels.astype(np.float32))

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int):
        return self.tokens[idx], self.numerics[idx], self.labels[idx]
