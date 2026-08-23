"""Transformer encoder over security-event sequences."""

import math

import torch
from torch import nn


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 512):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1)]


class EventTransformer(nn.Module):
    """Binary classifier over fixed-length event windows.

    Token embeddings (event_type:action) are combined with per-step numeric
    features, passed through a Transformer encoder and mean-pooled.
    """

    def __init__(
        self,
        vocab_size: int,
        n_numeric: int = 4,
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_ff: int = 128,
        dropout: float = 0.1,
        pad_idx: int = 0,
    ):
        super().__init__()
        self.pad_idx = pad_idx
        self.token_emb = nn.Embedding(vocab_size, d_model, padding_idx=pad_idx)
        self.numeric_proj = nn.Linear(n_numeric, d_model)
        self.pos = PositionalEncoding(d_model)
        layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_ff,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.head = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, 32),
            nn.GELU(),
            nn.Linear(32, 1),
        )

    def forward(self, tokens: torch.Tensor, numerics: torch.Tensor) -> torch.Tensor:
        mask = tokens == self.pad_idx  # (B, L) True where padded
        x = self.token_emb(tokens) + self.numeric_proj(numerics)
        x = self.pos(x)
        x = self.encoder(x, src_key_padding_mask=mask)
        # Mean-pool over non-padded positions
        keep = (~mask).unsqueeze(-1).float()
        pooled = (x * keep).sum(dim=1) / keep.sum(dim=1).clamp(min=1.0)
        return self.head(pooled).squeeze(-1)

    def num_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters())
