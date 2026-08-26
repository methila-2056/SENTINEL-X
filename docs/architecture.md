# Architecture

This document describes the internal structure of SENTINEL-X, how data moves through the system, and the key abstractions that hold it together.

## System overview

SENTINEL-X is a security-operations platform that combines traditional SIEM log ingestion with ML-based anomaly detection, knowledge-graph correlation, and a tool-using LLM investigation agent. The goal is to reduce an analyst's time-to-understanding from hours to minutes by automatically surfacing evidence-grounded incident reports.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL-X                                     │
│                                                                         │
│  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────────────┐   │
│  │ Ingest   │──▶│ Detect    │──▶│ Correlate│──▶│ Investigate (LLM)│   │
│  │ (raw)    │   │ (ML)      │   │ (graph)  │   │ + verify tools   │   │
│  └──────────┘   └───────────┘   └──────────┘   └──────┬───────────┘   │
│       │                                  │              │               │
│       ▼                                  ▼              ▼               │
│  ┌──────────┐                   ┌────────────┐  ┌──────────────┐      │
│  │ Parquet  │                   │ PostgreSQL │  │ Report (JSON)│      │
│  └──────────┘                   │ + pgvector │  └──────────────┘      │
│                                 └────────────┘          │               │
│                                                    ┌────▼────┐         │
│                                                    │  API    │         │
│                                                    │ (FastAPI)│        │
│                                                    └────┬────┘         │
│                                                    ┌────▼────┐         │
│                                                    │  Web UI │         │
│                                                    │ (React) │         │
│                                                    └─────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Package map

```
src/sentinel_x/
├── agents/          # Tool-using investigation agent (Ollama function-calling)
├── api/
│   ├── app.py       # FastAPI factory, lifespan, CORS
│   ├── deps.py      # Dependency injection: DB sessions, auth, singletons
│   ├── security.py  # PBKDF2 hashing, JWT issuance/verification
│   ├── jobstore.py  # InMemoryJobStore / RedisJobStore abstraction
│   └── routers/
│       ├── auth.py       # /api/auth/token, /me, /users
│       ├── incidents.py  # /api/incidents, /{id}/events, /{id}/graph
│       ├── events.py     # /api/events (SQL-side filtered)
│       ├── agent.py      # POST /api/agent/investigate (async job)
│       ├── search.py     # GET /api/knowledge/search
│       └── ingest.py     # POST /api/ingest (CSV upload)
├── common/
│   ├── settings.py  # pydantic-settings env config
│   ├── db.py        # Async + sync engine factories, get_session, create_all
│   ├── logging.py   # structlog configuration
│   ├── netutil.py   # RFC 1918 detection for src_ip classification
│   └── redis_client.py  # Shared Redis client factory
├── data/
│   ├── db/models.py     # SQLAlchemy ORM: SecurityEvent, Incident, Document, Entity, Edge, User
│   └── ingestion/       # CSV download, synthetic generator, Parquet writers
├── evaluation/          # Ground-truth matching, precision/recall extraction
├── graph/
│   ├── entities/extract.py   # Regex NER (user, host, process, IP) → EntityRow + EdgeRow
│   └── traversal.py          # BFS over knowledge graph (entity → edges → neighbors)
├── incidents/
│   ├── pipeline.py     # seed_database(): ingest → detect → correlate → graph
│   ├── correlator.py   # Temporal + entity-based incident grouping
│   └── risk.py         # Risk scoring (0-1) with signal weights
├── llm/
│   └── ollama_client.py   # Ollama chat completion wrapper
├── ml/
│   ├── feature_engineering.py   # Feature matrix construction
│   ├── inference/scoring.py     # XGBoost host-minute scoring
│   └── training/                # IsolationForest, XGBoost training loops
├── rag/                  # Hybrid RAG pipeline
├── retrieval/
│   └── hybrid/fusion.py  # BM25 (pg FTS) + vector (pgvector) + RRF + rerank
├── scripts/              # CLI entry points (sentinelx-seed, etc.)
└── verification/         # Tool-call verification (domain recon, DNS, CVE lookup)
```

## Data flow

### 1. Ingestion

Raw CSV or synthetic events land in `data/raw/` or `data/processed/synthetic/`. The ingestion module normalises schemas and writes canonical Parquet files with the columns:

```
event_id | timestamp | source | event_type | action | user | host |
process | src_ip | dst_ip | dst_port | file_path | bytes_transferred | severity
```

### 2. Detection

The ML pipeline (`ml/`) builds a feature matrix per (host, 5-minute window):
- Event-type counts (auth failure, process create, network out, file write)
- Entropy features (unique users, IPs, ports, processes)
- Temporal features (hour-of-day, is_weekend)

An XGBoost classifier scores each window 0-1. Windows above a threshold are emitted as anomalous candidates.

### 3. Correlation

`incidents/correlator.py` groups anomalous events into incidents using:
- **Temporal proximity**: events within a configurable window (default 5 minutes)
- **Entity overlap**: events sharing the same user, host, or source IP

Each incident gets a risk score (weighted sum of anomaly score, event count, entity diversity).

### 4. Knowledge graph extraction

`graph/entities/extract.py` runs regex-based NER on every event:
- Users → `user:<name>`
- Hosts → `host:<hostname>`
- Processes → `process:<binary_name>`
- IPs → `ip:<address>` (classified as internal/external via `netutil.is_internal_ip`)

Entity and edge rows are persisted to the `entities` / `edges` tables, forming a traversable graph.

### 5. Knowledge base

Threat intelligence documents (MITRE ATT&CK techniques, Sigma rules) are embedded with `sentence-transformers/all-MiniLM-L6-v2` and stored in the `documents` table alongside a tsvector column for BM25-style FTS.

Hybrid retrieval (`retrieval/hybrid/fusion.py`) combines:
1. PostgreSQL full-text search (BM25) → top-k candidates
2. pgvector HNSW cosine search → top-k candidates
3. Reciprocal Rank Fusion to merge result sets
4. Cross-encoder reranking (`cross-encoder/ms-marco-MiniLM-L-6-v2`)

### 6. Investigation agent

`agents/` implements a tool-using loop over Ollama + Qwen2.5:

```
┌─────────────┐     ┌────────────┐     ┌──────────────┐
│  LLM prompt │────▶│  Ollama    │────▶│  Tool call?  │
│  + context  │     │  response  │     │              │
└─────────────┘     └────────────┘     └──────┬───────┘
                            ▲                  │ yes
                            │                  ▼
                            │         ┌────────────────┐
                            │         │ Execute tool   │
                            │         │ (graph search, │
                            │         │  web lookup,   │
                            │         │  CVE check)    │
                            │         └───────┬────────┘
                            │                 │
                            └─────────────────┘
                                     (loop)
```

Available tools:
- `graph_neighbors(entity_id, hops)` — traverse the knowledge graph
- `domain_whois(domain)` — passive DNS / registration lookup
- `cve_lookup(cve_id)` — NVD CVE details

After a bounded number of tool rounds, the agent produces a structured report:

```json
{
  "summary": "...",
  "confidence": 0.82,
  "evidence_refs": ["event:abc-123", "doc:T1059"],
  "recommendations": ["..."]
}
```

### 7. Serving

FastAPI serves everything through a REST API with JWT auth and RBAC:

| Role | Access |
|---|---|
| `admin` | Full read/write + user management |
| `analyst` | Incidents, events, investigations |
| `viewer` | Read-only dashboards |

The React web app (`apps/web/`) consumes the API and renders incident lists, detail pages with timelines, knowledge-graph visualisations, and the investigation report viewer.

## Request lifecycle (investigate endpoint)

```
POST /api/agent/investigate  {"incident_id": "det-abc"}

1. Auth middleware validates JWT → AuthUser(role=analyst)
2. require_roles(["admin","analyst"]) gate passes
3. IncidentRow fetched from Postgres (404 if missing)
4. Job created via choose_job_store() → RedisJobStore in prod, InMemoryJobStore in dev
5. Job ID returned immediately (HTTP 202 Accepted)
6. Background thread starts _run_investigation():
   a. Fetch correlated events + graph neighborhood
   b. Build LLM prompt with evidence context
   c. Agent loop: LLM → tool calls → execute → LLM ...
   d. Structured report written to job store
7. Client polls GET /api/agent/jobs/{job_id}
8. On completion: report JSON in job.report
```

## Deployment topology

### Local development (Docker Compose)

```
localhost
├── :5173  ──▶  web (nginx, 127.0.0.1 only)
├── :8001  ──▶  API (uvicorn, non-root)
├── :5000  ──▶  MLflow
├── :5432  ──▶  PostgreSQL + pgvector (127.0.0.1 only)
└── :6380  ──▶  Redis (requirepass, 127.0.0.1 only)
```

All services bind to `127.0.0.1` only. Redis requires authentication (`REDIS_PASSWORD`). Containers run as non-root where possible. The `frontend` and `backend` Docker networks provide isolation (web cannot reach Postgres/Redis directly).

### CI (GitHub Actions)

```
lint job    → ruff check + ruff format --check + mypy
test job    → pytest -m "not evaluation" (postgres/redis service containers)
web job     → tsc --noEmit + vite build
CodeQL      → GitHub code scanning
```

## Key abstractions

| Abstraction | Location | Purpose |
|---|---|---|
| `get_sync_session()` | `common/db.py` | Context-managed SQLAlchemy session (sync driver) |
| `get_async_session()` | `common/db.py` | Async session for FastAPI DI |
| `get_redis()` | `common/redis_client.py` | Process-wide Redis client (AUTH-aware) |
| `InMemoryJobStore` | `api/jobstore.py` | Bounded in-process job state (dev) |
| `RedisJobStore` | `api/jobstore.py` | Redis-backed job state with 24h TTL |
| `choose_job_store()` | `api/jobstore.py` | Factory: Redis if reachable, else memory |
| `is_internal_ip()` | `common/netutil.py` | RFC 1918 / RFC 4193 classification |
| `build_label_map()` | `data/ingestion/parquet.py` | Immutable LABEL_MAP factory |
| `extract_entities_and_edges()` | `graph/entities/extract.py` | Regex NER → Entity + Edge rows |
| `hybrid_search()` | `retrieval/hybrid/fusion.py` | BM25 + vector + RRF + rerank |
| `investigate_incident()` | `agents/` | Tool-using agent loop |
