"""Unit tests for retrieval fusion and evaluation metrics."""

from sentinel_x.evaluation.retrieval.metrics import (
    evaluate_retrieval,
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank,
)
from sentinel_x.retrieval.bm25.fts_search import RetrievedDoc
from sentinel_x.retrieval.hybrid.fusion import rrf_fuse


def _doc(doc_id: str, score: float = 0.5) -> RetrievedDoc:
    return RetrievedDoc(
        id=doc_id,
        source="s",
        document_type="t",
        external_id=doc_id,
        title=doc_id,
        content="content",
        score=score,
    )


class TestMetrics:
    def test_recall_at_k(self) -> None:
        retrieved = ["a", "b", "c"]
        assert recall_at_k(retrieved, {"a"}, 1) == 1.0
        assert recall_at_k(retrieved, {"a", "d"}, 3) == 0.5
        assert recall_at_k(retrieved, set(), 3) == 0.0

    def test_mrr(self) -> None:
        assert reciprocal_rank(["x", "hit"], {"hit"}) == 0.5
        assert reciprocal_rank(["x"], {"hit"}) == 0.0

    def test_ndcg_perfect(self) -> None:
        assert abs(ndcg_at_k(["a", "b"], {"a", "b"}, 2) - 1.0) < 1e-9

    def test_evaluate_aggregates(self) -> None:
        queries = {
            "q1": {"a"},
            "q2": {"b"},
        }
        result = evaluate_retrieval(queries, lambda q: ["a"] if q == "q1" else ["x", "b"])
        s = result["summary"]
        assert s["recall@5"] == 1.0
        assert s["mrr"] == 0.75


class TestRRF:
    def test_fusion_prefers_docs_in_both_lists(self) -> None:
        list_a = [_doc("top-a"), _doc("shared"), _doc("tail-a")]
        list_b = [_doc("top-b"), _doc("shared")]
        fused = rrf_fuse([list_a, list_b])
        ids = [d.id for d in fused]
        # "shared" appears in both lists so should outrank single-list docs
        assert ids.index("shared") < ids.index("top-a")

    def test_empty_input(self) -> None:
        assert rrf_fuse([[], []]) == []
