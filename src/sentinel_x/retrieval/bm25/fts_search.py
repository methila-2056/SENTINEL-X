"""PostgreSQL full-text search over knowledge documents."""

from dataclasses import dataclass

from sqlalchemy import text

from sentinel_x.common.db import get_sync_session


@dataclass
class RetrievedDoc:
    id: str
    source: str
    document_type: str
    external_id: str | None
    title: str
    content: str
    score: float


def fts_search(query: str, top_k: int = 20, source_filter: str | None = None) -> list[RetrievedDoc]:
    """BM25-style ranked full-text search using ts_rank_cd."""
    session = get_sync_session()
    try:
        sql = text(
            """
            SELECT id, source, document_type, external_id, title,
                   left(content, 1200) AS content,
                   ts_rank_cd(content_tsv, websearch_to_tsquery('english', :q)) AS score
            FROM documents
            WHERE content_tsv @@ websearch_to_tsquery('english', :q)
              AND (:source IS NULL OR source = :source)
            ORDER BY score DESC
            LIMIT :k
            """
        )
        rows = session.execute(sql, {"q": query, "k": top_k, "source": source_filter}).mappings()
        return [
            RetrievedDoc(
                id=str(r["id"]),
                source=r["source"],
                document_type=r["document_type"],
                external_id=r["external_id"],
                title=r["title"],
                content=r["content"],
                score=float(r["score"]),
            )
            for r in rows
        ]
    finally:
        session.close()
