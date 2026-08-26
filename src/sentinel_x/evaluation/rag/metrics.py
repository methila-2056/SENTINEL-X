"""RAG evaluation metrics: context quality and answer grounding.

Deterministic, computed metrics (no LLM-judge unless one is supplied):
  - context_precision / context_recall vs a golden relevant set
  - faithfulness      : share of answer claims supported by retrieved evidence
                        (lexical grounding with content-word overlap)
  - answer_relevance  : semantic similarity between query and answer
                        (embedding cosine, optional)
"""

from __future__ import annotations

import re

import numpy as np

TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "to",
    "in",
    "on",
    "for",
    "with",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "by",
    "at",
    "as",
    "it",
    "this",
    "that",
    "which",
    "from",
    "not",
    "no",
    "but",
    "has",
    "have",
    "had",
    "can",
    "may",
    "will",
    "would",
    "should",
    "could",
    "do",
    "does",
    "did",
    "its",
    "their",
}
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")

# A claim is "supported" when this fraction of its content words appears in the
# evidence pool (union of retrieved snippets).
SUPPORT_THRESHOLD = 0.5


def _content_tokens(text: str) -> set[str]:
    return {t for t in TOKEN_PATTERN.findall(text.lower()) if t not in STOPWORDS and len(t) > 2}


def context_precision(retrieved: list[str], relevant: set[str], k: int | None = None) -> float:
    top = retrieved[:k] if k else retrieved
    if not top:
        return 0.0
    return len(set(top) & relevant) / len(top)


def context_recall(retrieved: list[str], relevant: set[str]) -> float:
    if not relevant:
        return 0.0
    return len(set(retrieved) & relevant) / len(relevant)


def claim_supported(claim: str, evidence_tokens: set[str]) -> bool:
    words = _content_tokens(claim)
    if not words:
        return True  # no factual content to verify
    overlap = len(words & evidence_tokens) / len(words)
    return overlap >= SUPPORT_THRESHOLD


def faithfulness(answer: str, evidence_texts: list[str]) -> dict:
    """Fraction of answer sentences grounded in retrieved evidence.

    Returns per-sentence verdicts plus aggregate score.
    """
    evidence_tokens: set[str] = set()
    for text in evidence_texts:
        evidence_tokens |= _content_tokens(text)

    sentences = [s.strip() for s in SENTENCE_SPLIT.split(answer or "") if s.strip()]
    verdicts = []
    for sentence in sentences:
        verdicts.append(
            {"claim": sentence[:200], "supported": claim_supported(sentence, evidence_tokens)}
        )
    supported_count = sum(1 for v in verdicts if v["supported"])
    score = supported_count / len(verdicts) if verdicts else 0.0
    return {"faithfulness": round(score, 4), "n_claims": len(verdicts), "verdicts": verdicts}


def answer_relevance(query: str, answer: str, embedder=None) -> float | None:
    """Cosine similarity between query and answer embeddings.

    Args:
        embedder: object exposing `.encode(texts) -> np.ndarray`
                  (e.g. SentenceTransformer). Returns None when unavailable.
    """
    if embedder is None or not answer.strip():
        return None
    qv, av = embedder.encode([query, answer])
    denom = float(np.linalg.norm(qv) * np.linalg.norm(av))
    if denom == 0.0:
        return 0.0
    return round(float(np.dot(qv, av) / denom), 4)


def evaluate_rag_response(
    query: str,
    answer: str,
    retrieved_ids: list[str],
    relevant_ids: set[str],
    evidence_texts: list[str],
    k: int = 10,
    embedder=None,
) -> dict:
    """One-stop evaluation for a single RAG exchange."""
    relevance = answer_relevance(query, answer, embedder)
    return {
        "query": query,
        "context_precision": round(context_precision(retrieved_ids, relevant_ids, k), 4),
        "context_recall": round(context_recall(retrieved_ids, relevant_ids), 4),
        "faithfulness": faithfulness(answer, evidence_texts)["faithfulness"],
        "answer_relevance": relevance,
        "n_retrieved": len(retrieved_ids),
    }
