"""Embedding + reranking model wrappers (lazy singletons)."""

from functools import lru_cache

import structlog

from sentinel_x.common.settings import get_settings

logger = structlog.get_logger(__name__)

# sentence_transformers pulls torch; imported lazily so the retrieval stack
# stays usable on hosts without a working torch runtime.


@lru_cache
def get_embedder():
    from sentence_transformers import SentenceTransformer

    settings = get_settings()
    logger.info("loading_embedder", model=settings.embedding_model)
    return SentenceTransformer(settings.embedding_model)


@lru_cache
def get_reranker():
    from sentence_transformers import CrossEncoder

    settings = get_settings()
    logger.info("loading_reranker", model=settings.reranker_model)
    return CrossEncoder(settings.reranker_model)


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts; returns normalized vectors."""
    model = get_embedder()
    vectors = model.encode(
        texts,
        batch_size=64,
        normalize_embeddings=True,
        show_progress_bar=False,
    )
    return [v.tolist() for v in vectors]


def embed_query(query: str) -> list[float]:
    model = get_embedder()
    vector = model.encode([query], normalize_embeddings=True)[0]
    return vector.tolist()
