"""RAG ingestion pipeline: sources -> chunks -> embeddings -> PostgreSQL."""

import structlog
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinel_x.common.db import get_sync_session
from sentinel_x.data.db.models import Document
from sentinel_x.rag.ingestion.chunker import chunk_text
from sentinel_x.rag.ingestion.embedder import embed_texts
from sentinel_x.rag.ingestion.sources import (
    DocumentDict,
    load_playbooks,
    load_sigma_rules,
    parse_mitre_stix,
)

logger = structlog.get_logger(__name__)


def document_to_rows(doc: DocumentDict, max_chars: int = 900) -> list[dict]:
    """Chunk a source document into row dicts ready for embedding."""
    chunks = chunk_text(doc["content"], max_chars=max_chars)
    rows = []
    for i, chunk in enumerate(chunks):
        meta = dict(doc.get("metadata") or {})
        meta["chunk_index"] = i
        meta["chunk_count"] = len(chunks)
        rows.append(
            {
                "source": doc["source"],
                "document_type": doc["document_type"],
                "external_id": doc.get("external_id"),
                "title": doc["title"] if i == 0 else f"{doc['title']} (part {i + 1})",
                "content": chunk,
                "metadata_": meta,
            }
        )
    return rows


def upsert_documents(session, rows: list[dict]) -> int:
    """Embed and upsert document chunks keyed on (source, external_id, title)."""
    if not rows:
        return 0
    embeddings = embed_texts([r["content"] for r in rows])
    written = 0
    for row, vector in zip(rows, embeddings, strict=True):
        stmt = pg_insert(Document).values(
            source=row["source"],
            document_type=row["document_type"],
            external_id=row["external_id"],
            title=row["title"],
            content=row["content"],
            metadata_=row["metadata_"],
            embedding=vector,
        )
        # Re-ingestion of the same source+external id replaces older chunks
        stmt = stmt.on_conflict_do_update(
            index_elements=["source", "external_id", "title"],
            set_={
                "content": stmt.excluded.content,
                "metadata_": stmt.excluded.metadata_,
                "embedding": stmt.excluded.embedding,
            },
        )
        session.execute(stmt)
        written += 1
    session.commit()
    return written


def ingest_all(
    mitre_path=None,
    sigma_dir=None,
    playbook_dir=None,
    sigma_limit=3000,
) -> dict[str, int]:
    """Full knowledge-base ingestion. Returns counts per source."""
    session = get_sync_session()
    try:
        stats: dict[str, int] = {}

        if playbook_dir is not None:
            docs = load_playbooks(playbook_dir)
            rows = [r for d in docs for r in document_to_rows(d)]
            stats["playbook"] = upsert_documents(session, rows)
            logger.info("ingested", source="playbook", chunks=stats["playbook"])

        if sigma_dir is not None:
            docs = load_sigma_rules(sigma_dir, limit=sigma_limit)
            rows = [r for d in docs for r in document_to_rows(d)]
            stats["sigma"] = upsert_documents(session, rows)
            logger.info("ingested", source="sigma", chunks=stats["sigma"])

        if mitre_path is not None:
            docs = parse_mitre_stix(mitre_path)
            rows = [r for d in docs for r in document_to_rows(d)]
            stats["mitre_attack"] = upsert_documents(session, rows)
            logger.info("ingested", source="mitre_attack", chunks=stats["mitre_attack"])

        return stats
    finally:
        session.close()
