"""Dense vector search over knowledge documents using pgvector."""

from sqlalchemy import text

from sentinel_x.common.db import get_sync_session
from sentinel_x.rag.ingestion.embedder import embed_query
from sentinel_x.retrieval.bm25.fts_search import RetrievedDoc


def vector_search(
    query: str,
    top_k: int = 20,
    source_filter: str | None = None,
) -> list[RetrievedDoc]:
    """Cosine-distance ANN search with the HNSW index."""
    query_vector = embed_query(query)
    session = get_sync_session()
    try:
        sql = text(
            """
            SELECT id, source, document_type, external_id, title,
                   left(content, 1200) AS content,
                   1 - (embedding <=> :vec) AS score
            FROM documents
            WHERE (:source IS NULL OR source = :source)
            ORDER BY embedding <=> :vec
            LIMIT :k
            """
        )
        rows = session.execute(
            sql, {"vec": query_vector, "k": top_k, "source": source_filter}
        ).mappings()
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
