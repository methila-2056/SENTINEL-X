"""Knowledge search endpoint (hybrid retrieval over ATT&CK/Sigma/playbooks)."""

from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel

from sentinel_x.retrieval.hybrid.fusion import hybrid_search

router = APIRouter()


class KnowledgeHit(BaseModel):
    external_id: str | None = None
    title: str | None = None
    source: str | None = None
    document_type: str | None = None
    score: float | None = None
    snippet: str


@router.get("/search", response_model=list[KnowledgeHit])
def search_knowledge(
    q: str = Query(..., min_length=2),
    top_k: int = Query(6, ge=1, le=20),
) -> list[KnowledgeHit]:
    docs = hybrid_search(q, top_k=top_k)
    return [
        KnowledgeHit(
            external_id=doc.external_id,
            title=doc.title,
            source=doc.source,
            document_type=doc.document_type,
            score=doc.score,
            snippet=doc.content[:600],
        )
        for doc in docs
    ]
