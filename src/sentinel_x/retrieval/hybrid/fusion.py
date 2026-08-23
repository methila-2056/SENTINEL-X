"""Reciprocal Rank Fusion of BM25 + vector search results."""

from sentinel_x.retrieval.bm25.fts_search import RetrievedDoc, fts_search
from sentinel_x.retrieval.embeddings.vector_search import vector_search

DEFAULT_RRF_K = 60


def rrf_fuse(
    result_lists: list[list[RetrievedDoc]],
    k: int = DEFAULT_RRF_K,
) -> list[RetrievedDoc]:
    """Fuse ranked lists with Reciprocal Rank Fusion.

    score(d) = sum over lists of 1 / (k + rank(d))
    """
    fused_scores: dict[str, float] = {}
    doc_by_id: dict[str, RetrievedDoc] = {}
    for results in result_lists:
        for rank, doc in enumerate(results):
            fused_scores[doc.id] = fused_scores.get(doc.id, 0.0) + 1.0 / (k + rank + 1)
            doc_by_id.setdefault(doc.id, doc)
    ordered_ids = sorted(fused_scores, key=lambda d: fused_scores[d], reverse=True)
    return [doc_by_id[d] for d in ordered_ids]


def hybrid_search(
    query: str,
    top_k: int = 20,
    source_filter: str | None = None,
    rrf_k: int = DEFAULT_RRF_K,
) -> list[RetrievedDoc]:
    """BM25 + vector retrieval fused via RRF."""
    fts_results = fts_search(query, top_k=top_k, source_filter=source_filter)
    vec_results = vector_search(query, top_k=top_k, source_filter=source_filter)
    return rrf_fuse([fts_results, vec_results], k=rrf_k)[:top_k]
