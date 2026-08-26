"""Ablation: RAG answer quality across retrieval configurations.

Measures context precision/recall plus faithfulness of the generated answer
for: vector-only, bm25-only, hybrid RRF, hybrid+reranker (full system).

Faithfulness/answer-relevance require Ollama; when unavailable the run
degrades to retrieval-context metrics only (flagged in output).

Usage:
    python experiments/ablations/run_rag_ablation.py [--queries 25] [--top-k 5]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments/retrieval"))

from golden_set import GOLDEN_QUERIES  # noqa: E402

from sentinel_x.common.logging import configure_logging  # noqa: E402
from sentinel_x.evaluation.rag.metrics import (  # noqa: E402
    answer_relevance,
    context_precision,
    context_recall,
    faithfulness,
)
from sentinel_x.llm.client import OllamaClient  # noqa: E402
from sentinel_x.retrieval.bm25.fts_search import fts_search  # noqa: E402
from sentinel_x.retrieval.embeddings.vector_search import vector_search  # noqa: E402
from sentinel_x.retrieval.hybrid.fusion import hybrid_search  # noqa: E402
from sentinel_x.retrieval.reranking.rerank import rerank  # noqa: E402

ANSWER_SYSTEM = """You are a security analyst assistant. Answer the question using ONLY the
provided evidence excerpts. If the evidence is insufficient, reply exactly:
"Insufficient evidence". Keep the answer to 1-2 sentences."""


def retrieve_config(name: str, query: str, top_k: int):
    """Return ordered (external_id, snippet) pairs for one ablation config."""
    if name == "vector":
        docs = vector_search(query, top_k=top_k)
    elif name == "bm25":
        docs = fts_search(query, top_k=top_k)
    elif name == "hybrid":
        docs = hybrid_search(query, top_k=top_k)[:top_k]
    elif name == "full":
        candidates = hybrid_search(query, top_k=20)
        docs = rerank(query, candidates, top_k=top_k)
    else:
        raise ValueError(name)
    return [(d.external_id or d.id, d.content) for d in docs]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", type=int, default=25)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--skip-generation", action="store_true")
    args = parser.parse_args()
    configure_logging()

    client = OllamaClient()
    use_llm = (not args.skip_generation) and client.is_available()
    embedder = None
    if use_llm:
        try:
            from sentence_transformers import SentenceTransformer

            from sentinel_x.common.settings import get_settings

            embedder = SentenceTransformer(get_settings().embedding_model)
        except Exception:
            embedder = None

    configs = ["vector", "bm25", "hybrid", "full"]
    queries = dict(list(GOLDEN_QUERIES.items())[: args.queries])
    per_config: dict[str, dict] = {
        c: {
            "context_precision": [],
            "context_recall": [],
            "faithfulness": [],
            "answer_relevance": [],
            "n_answers": 0,
        }
        for c in configs
    }

    for qi, (query, relevant) in enumerate(queries.items(), start=1):
        for config in configs:
            retrieved = retrieve_config(config, query, args.top_k)
            ids = [rid for rid, _ in retrieved]
            snippets = [text for _, text in retrieved]

            row = per_config[config]
            row["context_precision"].append(context_precision(ids, relevant, args.top_k))
            row["context_recall"].append(context_recall(ids, relevant))

            if not use_llm:
                continue
            context_block = "\n\n".join(
                f"[{i + 1}] {snippet[:800]}" for i, (_, snippet) in enumerate(retrieved)
            )
            try:
                answer = client.generate(
                    ANSWER_SYSTEM,
                    f"Evidence:\n{context_block}\n\nQuestion: {query}",
                    num_predict=200,
                )
            except Exception:
                continue
            row["faithfulness"].append(faithfulness(answer, snippets)["faithfulness"])
            rel = answer_relevance(query, answer, embedder)
            if rel is not None:
                row["answer_relevance"].append(rel)
            row["n_answers"] += 1
        print(f"[{qi}/{len(queries)}] {query[:60]}")

    summary = {}
    for config, vals in per_config.items():
        n = len(queries)
        summary[config] = {
            "context_precision@k": round(sum(vals["context_precision"]) / n, 4),
            "context_recall": round(sum(vals["context_recall"]) / n, 4),
            "faithfulness": round(sum(vals["faithfulness"]) / max(vals["n_answers"], 1), 4)
            if vals["n_answers"]
            else None,
            "answer_relevance": round(
                sum(vals["answer_relevance"]) / max(len(vals["answer_relevance"]), 1), 4
            )
            if vals["answer_relevance"]
            else None,
            "n_queries": n,
            "n_generated_answers": vals["n_answers"],
            "generation_used": use_llm,
        }

    out_dir = ROOT / "experiments/ablations"
    out_dir.mkdir(parents=True, exist_ok=True)

    header = (
        "| Configuration | Context P@" + str(args.top_k) + " | Context Recall | Faithfulness "
        "| Answer Relevance |"
    )
    lines = [header, "|---|---|---|---|---|"]

    def fmt(v: float | str | None) -> str:
        if isinstance(v, float):
            return f"{v:.3f}"
        return "n/a" if v is None else str(v)

    for config, s in summary.items():
        lines.append(
            f"| {config} | {fmt(s['context_precision@k'])} | {fmt(s['context_recall'])} "
            f"| {fmt(s['faithfulness'])} | {fmt(s['answer_relevance'])} |"
        )
    if not use_llm:
        lines.append("\n_Generation metrics unavailable: Ollama was not reachable._")
    (out_dir / "rag_ablation.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(out_dir / "rag_ablation.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nSaved -> {out_dir / 'rag_ablation.md'}")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
