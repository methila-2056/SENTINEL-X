# SENTINEL-X API image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install -e .

# Pre-download embedding + reranker models into the image layer cache
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); \
    SentenceTransformer('cross-encoder/ms-marco-MiniLM-L-6-v2')" || echo "model warmup skipped"

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "sentinel_x.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
