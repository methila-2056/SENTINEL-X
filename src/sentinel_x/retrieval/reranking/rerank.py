"""Cross-encoder reranking of retrieved candidates."""

import structlog

from sentinel_x.rag.ingestion.embedder import get_reranker
from sentinel_x.retrieval.bm25.fts_search import RetrievedDoc

logger = structlog.get_logger(__name__)


def rerank(query: str, docs: list[RetrievedDoc], top_k: int = 5) -> list[RetrievedDoc]:
    """Score query-document pairs with a cross-encoder, return top_k."""
    if not docs:
        return []
    reranker = get_reranker()
    pairs = [(query, d.content[:1500]) for d in docs]
    scores = reranker.predict(pairs, show_progress_bar=False)
    ranked = sorted(zip(scores, docs, strict=True), key=lambda pair: float(pair[0]), reverse=True)
    return [doc for _score, doc in ranked[:top_k]]
