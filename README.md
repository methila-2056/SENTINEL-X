# SENTINEL-X

![CI](https://github.com/methila-2056/SENTINEL-X/actions/workflows/ci.yml/badge.svg) ![CodeQL](https://github.com/methila-2056/SENTINEL-X/actions/workflows/codeql.yml/badge.svg)

**AI-Powered Security Incident Intelligence & Autonomous Investigation Platform**

SENTINEL-X detects abnormal enterprise activity with ML, correlates related security events into incidents, retrieves evidence from a threat-intelligence knowledge base via hybrid RAG, reasons over an entity knowledge graph, and runs a tool-using investigation agent that produces **evidence-grounded incident reports with measurable confidence**.

## Architecture

```text
Security Telemetry          Threat Intelligence
      ¦                            ¦
      ?                            ?
Data Pipeline               Document Pipeline
      ¦                            ¦
      ?                            ?
Feature Engineering          Embeddings
      ¦                            ¦
      ?                            ?
ML Detection                PostgreSQL + pgvector
      ¦                            ¦
      +----------------------------+
                 ?
          Incident Engine
                 ¦
         +---------------+
         ?               ?
    Knowledge        Hybrid RAG
      Graph              ¦
         ¦               ?
         +--------?  Reranker
                         ¦
                         ?
                 Investigation Agent
                         ¦
                   Tool Calling ? Verification
                         ¦
                         ?
                Evidence-Grounded Report
                         ¦
            +-------------------------+
            ?                         ?
         FastAPI                  React UI
```

## Technology stack

| Layer | Technology |
|---|---|
| Language | Python 3.12, TypeScript |
| ML | scikit-learn, XGBoost, PyTorch (Transformer encoder), Isolation Forest |
| Retrieval | PostgreSQL FTS (BM25-style) + pgvector HNSW + RRF fusion + cross-encoder reranking |
| LLM | Ollama + Qwen2.5 3B (local) |
| Backend | FastAPI, SQLAlchemy 2 (async), JWT auth, RBAC |
| Database | PostgreSQL 16 + pgvector |
| MLOps | MLflow, GitHub Actions CI, Docker Compose |
| Observability | structlog structured logging |

## Quickstart

```powershell
# 1. Create environment and install
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 2. Start infrastructure (PostgreSQL+pgvector, Redis)
docker compose up -d

# 3. Configure environment
Copy-Item .env.example .env
```

## Repository layout

```text
apps/api          FastAPI application
apps/web          React + TypeScript dashboard
src/sentinel_x/   Core Python package
  data/           Ingestion, normalization, canonical schemas
  ml/             Features, training, models, inference
  retrieval/      BM25, vector, hybrid fusion, reranking
  rag/            Document ingestion, context building, generation
  graph/          Entity extraction, relationships, traversal
  incidents/      Correlation engine and risk scoring
  agents/         Planner, tools, workflows, verification
  evaluation/     ML / retrieval / RAG / agent metrics
experiments/      Reproducible experiment entry points
configs/          Configuration files
infrastructure/   Docker and deployment assets
docs/             Architecture notes, experiment reports, research
```

## Status

Active development. See `docs/architecture/` for design decisions and `docs/experiments/` for measured results.

## License

MIT

