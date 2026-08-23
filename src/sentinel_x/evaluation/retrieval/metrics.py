"""Retrieval evaluation metrics: Recall@K, MRR, NDCG@K."""

import math

import numpy as np


def recall_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    top = retrieved[:k]
    if not relevant:
        return 0.0
    return float(len(set(top) & relevant)) / len(relevant)


def reciprocal_rank(retrieved: list[str], relevant: set[str]) -> float:
    for rank, doc_id in enumerate(retrieved, start=1):
        if doc_id in relevant:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(retrieved: list[str], relevant: set[str], k: int) -> float:
    """Binary-gain NDCG."""
    dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank, doc_id in enumerate(retrieved[:k], start=1)
        if doc_id in relevant
    )
    ideal_hits = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_hits + 1))
    return float(dcg / idcg) if idcg > 0 else 0.0


def evaluate_retrieval(
    queries_relevant: dict[str, set[str]],
    retrieval_fn,
    ks: tuple[int, ...] = (5, 10),
) -> dict:
    """Run a retrieval function over a golden query set and aggregate metrics.

    Args:
        queries_relevant: mapping query text -> set of relevant external_ids
        retrieval_fn: callable(query) -> ordered list of document ids
    """
    recalls = {f"recall@{k}": [] for k in ks}
    mrrs: list[float] = []
    ndcgs = {f"ndcg@{k}": [] for k in ks}
    per_query: list[dict] = []

    for query, relevant in queries_relevant.items():
        retrieved = retrieval_fn(query)
        row = {"query": query}
        for k in ks:
            r = recall_at_k(retrieved, relevant, k)
            recalls[f"recall@{k}"].append(r)
            row[f"recall@{k}"] = round(r, 3)
        rr = reciprocal_rank(retrieved, relevant)
        mrrs.append(rr)
        row["mrr"] = round(rr, 3)
        for k in ks:
            n = ndcg_at_k(retrieved, relevant, k)
            ndcgs[f"ndcg@{k}"].append(n)
            row[f"ndcg@{k}"] = round(n, 3)
        per_query.append(row)

    summary = {
        **{name: float(np.mean(vals or [0.0])) for name, vals in recalls.items()},
        "mrr": float(np.mean(mrrs or [0.0])),
        **{name: float(np.mean(vals or [0.0])) for name, vals in ndcgs.items()},
        "n_queries": len(queries_relevant),
    }
    return {"summary": summary, "per_query": per_query}
