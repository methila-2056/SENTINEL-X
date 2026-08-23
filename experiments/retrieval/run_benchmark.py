"""Experiment: retrieval benchmark - BM25 vs Vector vs Hybrid vs Hybrid+Reranker.

Usage:
    python experiments/retrieval/run_benchmark.py [--queries 25]
"""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from golden_set import GOLDEN_QUERIES  # noqa: E402

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.evaluation.retrieval.metrics import evaluate_retrieval  # noqa: E402
from sentinel_x.retrieval.bm25.fts_search import fts_search  # noqa: E402
from sentinel_x.retrieval.embeddings.vector_search import vector_search  # noqa: E402
from sentinel_x.retrieval.hybrid.fusion import hybrid_search  # noqa: E402
from sentinel_x.retrieval.reranking.rerank import rerank  # noqa: E402


def make_ids_retriever(fn):
    """Wrap a doc-returning retriever into an id-list-returning function."""

    def wrapped(query: str) -> list[str]:
        docs = fn(query, top_k=20)
        return [d.id for d in docs]

    return wrapped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", type=int, default=25)
    args = parser.parse_args()
    configure_logging()

    queries = dict(list(GOLDEN_QUERIES.items())[: args.queries])

    def hybrid_reranked(query: str) -> list[str]:
        candidates = hybrid_search(query, top_k=20)
        top = rerank(query, candidates, top_k=10)
        seen = {d.id for d in top}
        rest = [d.id for d in candidates if d.id not in seen]
        return [d.id for d in top] + rest

    methods = {
        "bm25": make_ids_retriever(fts_search),
        "vector": make_ids_retriever(vector_search),
        "hybrid_rrf": make_ids_retriever(hybrid_search),
        "hybrid_reranked": lambda q: hybrid_reranked(q),
    }

    all_results = {}
    timings = {}
    for name, fn in methods.items():
        start = time.perf_counter()
        result = evaluate_retrieval(queries, fn)
        elapsed = time.perf_counter() - start
        timings[name] = round(elapsed / len(queries) * 1000, 1)
        all_results[name] = result["summary"]
        print(
            f"{name:18s} "
            + " ".join(f"{k}={v:.3f}" for k, v in result["summary"].items() if k != "n_queries")
        )

    out_dir = ROOT / "experiments/retrieval"
    out_dir.mkdir(parents=True, exist_ok=True)

    header = "| Method | Recall@5 | Recall@10 | MRR | NDCG@5 | NDCG@10 | Avg latency (ms) |"
    sep = "|---|---|---|---|---|---|---|"
    lines = [header, sep]
    for name, s in all_results.items():
        lines.append(
            f"| {name} | {s['recall@5']:.3f} | {s['recall@10']:.3f} | {s['mrr']:.3f} "
            f"| {s['ndcg@5']:.3f} | {s['ndcg@10']:.3f} | {timings[name]} |"
        )
    (out_dir / "benchmark.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(out_dir / "benchmark.json", "w") as fh:
        json.dump({"summary": all_results, "latency_ms_per_query": timings}, fh, indent=2)
    print(f"\nBenchmark saved -> {out_dir / 'benchmark.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
