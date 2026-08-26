"""Tests for RAG evaluation metrics."""

from sentinel_x.evaluation.rag.metrics import (
    answer_relevance,
    claim_supported,
    context_precision,
    context_recall,
    evaluate_rag_response,
    faithfulness,
)


class TestContextMetrics:
    def test_precision_counts_relevant_fraction(self):
        retrieved = ["a", "b", "c", "d"]
        assert context_precision(retrieved, {"a", "c"}, k=4) == 0.5

    def test_precision_respects_k(self):
        retrieved = ["a", "x", "y", "z"]
        assert context_precision(retrieved, {"a"}, k=1) == 1.0

    def test_recall_full_when_all_retrieved(self):
        assert context_recall(["a", "b"], {"a", "b"}) == 1.0

    def test_recall_partial(self):
        assert context_recall(["a"], {"a", "b"}) == 0.5

    def test_empty_inputs_are_zero(self):
        assert context_precision([], {"a"}) == 0.0
        assert context_recall([], {"a"}) == 0.0
        assert context_recall([], set()) == 0.0


class TestFaithfulness:
    def test_supported_claim_detected(self):
        evidence = ["Ransomware encrypted files and modified registry run keys for persistence."]
        assert claim_supported(
            "The ransomware encrypted files.",
            set().union(*[set(e.lower().split()) for e in evidence]),
        )

    def test_unsupported_claim_rejected(self):
        from sentinel_x.evaluation.rag.metrics import TOKEN_PATTERN

        tokens = {t for t in TOKEN_PATTERN.findall("the sky is blue") if len(t) > 2}
        assert not claim_supported("The attacker deployed mimikatz credential dumping.", tokens)

    def test_faithfulness_scores_sentences(self):
        evidence = ["Attacker used powershell encoded command to download malware."]
        result = faithfulness(
            "The attacker used powershell. The moon is made of cheese.",
            evidence,
        )
        assert 0.0 < result["faithfulness"] < 1.0
        assert result["n_claims"] == 2

    def test_empty_answer_zero(self):
        assert faithfulness("", ["evidence"])["faithfulness"] == 0.0


class TestAnswerRelevance:
    def test_none_without_embedder(self):
        assert answer_relevance("q", "a", embedder=None) is None


class TestEvaluateRagResponse:
    def test_end_to_end(self):
        result = evaluate_rag_response(
            query="how did ransomware persist",
            answer="Ransomware added registry run keys for persistence.",
            retrieved_ids=["T1486", "T1547.001"],
            relevant_ids={"T1486"},
            evidence_texts=["Ransomware added registry run keys for persistence."],
            k=2,
        )
        assert result["context_precision"] == 0.5
        assert result["context_recall"] == 1.0
        assert 0.0 <= result["faithfulness"] <= 1.0
