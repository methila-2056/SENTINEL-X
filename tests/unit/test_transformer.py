"""Unit tests for sequence dataset construction and the Transformer model."""

import numpy as np
import pandas as pd
import pytest

try:
    import torch
except ImportError:  # pragma: no cover - host may block/omit the torch runtime
    pytest.skip("torch runtime unavailable on this host", allow_module_level=True)

from torch import nn  # noqa: E402

from sentinel_x.ml.models.sequence_dataset import (  # noqa: E402
    SEQ_LEN,
    EventVocab,
    build_sequences,
)
from sentinel_x.ml.models.transformer import EventTransformer  # noqa: E402


def _events_df(n_hosts: int = 3, n_events: int = 80) -> pd.DataFrame:
    rows = []
    rng = np.random.default_rng(0)
    t0 = pd.Timestamp("2026-08-03T09:00:00Z")
    for h in range(n_hosts):
        for i in range(n_events):
            attack = i > n_events - 12
            rows.append(
                {
                    "event_id": f"h{h}-{i}",
                    "timestamp": t0 + pd.Timedelta(seconds=int(i * 30 + rng.integers(0, 10))),
                    "source": "test",
                    "event_type": "authentication" if attack and i % 2 else "process_execution",
                    "action": "login_failure" if attack and i % 2 else "execute",
                    "user": f"user{h}",
                    "host": f"WS-{h}",
                    "process": "chrome.exe",
                    "src_ip": "10.0.0.1" if not attack else "185.1.1.1",
                    "dst_ip": None,
                    "dst_port": None,
                    "file_path": None,
                    "bytes_transferred": float(rng.integers(100, 5000)),
                    "severity": 3 if attack else 0,
                    "label": "attack" if attack else "benign",
                    "attack_category": None,
                    "technique_id": None,
                    "incident_id": None,
                    "metadata": {},
                }
            )
    return pd.DataFrame(rows)


class TestEventVocab:
    def test_vocab_contains_special_tokens(self) -> None:
        v = EventVocab.from_events(_events_df())
        assert "<pad>" in v.token_to_idx
        assert "<unk>" in v.token_to_idx
        assert v.encode_token("<pad>") == 0

    def test_unknown_token_maps_to_unk(self) -> None:
        v = EventVocab.from_events(_events_df())
        assert v.encode_token("never_seen:action") == v.token_to_idx["<unk>"]


class TestBuildSequences:
    def test_shapes_and_labels(self) -> None:
        events = _events_df()
        tokens, numerics, labels = build_sequences(events)
        assert tokens.shape[1] == SEQ_LEN
        assert numerics.shape == (*tokens.shape, 4)
        assert len(labels) == len(tokens)
        # Each host's tail is an attack window
        assert labels.sum() >= 1

    def test_padding_is_zero(self) -> None:
        tokens, _, _ = build_sequences(_events_df())
        # Windows shorter than SEQ_LEN have a padded suffix
        padded_rows = tokens[:, -1] == 0
        assert padded_rows.any()
        row = tokens[padded_rows][0]
        first_pad = int(np.argmax(row == 0))
        assert (row[first_pad:] == 0).all()


class TestEventTransformer:
    def test_forward_shape(self) -> None:
        model = EventTransformer(vocab_size=20)
        tokens = torch.randint(0, 20, (4, SEQ_LEN))
        numerics = torch.rand(4, SEQ_LEN, 4)
        out = model(tokens, numerics)
        assert out.shape == (4,)

    def test_parameters_finite_after_step(self) -> None:
        model = EventTransformer(vocab_size=20)
        opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
        tokens = torch.randint(0, 20, (8, SEQ_LEN))
        numerics = torch.rand(8, SEQ_LEN, 4)
        ys = torch.rand(8)
        loss = nn.functional.binary_cross_entropy_with_logits(model(tokens, numerics), ys)
        loss.backward()
        opt.step()
        for p in model.parameters():
            assert torch.isfinite(p).all()

    def test_small_model_size(self) -> None:
        model = EventTransformer(vocab_size=20)
        assert model.num_parameters() < 500_000
