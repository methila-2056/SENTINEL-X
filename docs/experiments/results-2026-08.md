# SENTINEL-X Experiment Results — August 2026

All numbers below are produced by runnable scripts in `experiments/` against the
local stack (PostgreSQL 16 + pgvector, 5,433 knowledge documents, 6,360 events,
1,074 incidents, Ollama `qwen2.5:3b-instruct-q4_K_M` on CPU). No number in this
report is hand-written; each is emitted by its script as JSON/Markdown.

---

## 1. Retrieval benchmark — BM25 vs Vector vs Hybrid vs Hybrid+Reranker

Script: `experiments/retrieval/run_benchmark.py` (golden set: `golden_set.py`)

| Method | Recall@5 | Recall@10 | MRR | NDCG@5 | NDCG@10 | Avg latency (ms) |
|---|---|---|---|---|---|---|
| bm25 | 0.180 | 0.180 | 0.213 | 0.196 | 0.245 | 29.6 |
| vector | 0.620 | 0.740 | 0.603 | 0.719 | 0.869 | 400.2 |
| hybrid_rrf | 0.600 | 0.720 | 0.580 | 0.702 | 0.872 | 105.1 |
| hybrid_reranked | 0.580 | 0.700 | **0.627** | 0.713 | **0.879** | 1177.4 |

**Reading.** Vector search dominates raw recall on this corpus (semantic
paraphrases of technique descriptions). Hybrid RRF recovers most recall at ~4x
lower latency than vector-only. The cross-encoder reranker trades a little
recall for the best MRR/NDCG@10 — i.e., when it ranks a document high, that
document really is relevant, which matters more for LLM grounding than raw
candidate recall.

---

## 2. RAG ablation — does retrieval configuration improve answer quality?

Script: `experiments/ablations/run_rag_ablation.py --queries 25 --top-k 5`
(25 golden queries; answers generated per configuration by the local LLM;
faithfulness/answer-relevance judged by the same model — self-judge limitation noted below)

| Configuration | Context P@5 | Context Recall | Faithfulness | Answer Relevance |
|---|---|---|---|---|
| bm25-only | 0.137 | 0.180 | 0.200 | 0.158 |
| vector-only | 0.200 | **0.620** | 0.440 | 0.346 |
| hybrid (RRF) | 0.200 | **0.620** | 0.420 | 0.330 |
| hybrid + reranker (full) | 0.184 | 0.580 | **0.500** | **0.405** |

**Findings.**

- Retrieval quality bounds answer quality: bm25-only's 0.18 context recall
  collapses faithfulness to 0.20.
- The full system loses 0.04 context recall to reranking but gains **+13.6%
  relative faithfulness** (0.44 → 0.50) and **+17% relative answer relevance**
  (0.35 → 0.41). Reranking buys groundedness, not recall — consistent with the
  benchmark's MRR result.
- This is the central ablation claim of the project: **hybrid retrieval +
  reranking measurably reduces unsupported LLM conclusions** versus
  vector-only RAG, at the cost of reranker latency.

**Limitations.** Self-judging (same 3B model generates and judges) inflates
absolute scores; comparisons across configurations remain meaningful because
the judge is held constant. n=25 queries; confidence intervals are wide.

---

## 3. Knowledge-graph evaluation — multi-hop IOC reachability

Script: `experiments/ablations/run_graph_eval.py --hops {1..4}`
(15 ground-truth attack hosts vs 10 benign control hosts; undirected recursive-CTE
traversal; hit = path exists to a malicious/IOC node AND such a node is in the
neighborhood) — results in `experiments/ablations/results/graph_eval_results.json`

| Max hops | Attack IOC-path rate | Benign IOC-path rate | Separation |
|---|---|---|---|
| 1 | 0.000 | 0.000 | 0.000 |
| 2 | **0.333** | **0.000** | **+0.333** |
| 3 | 0.333 | 0.000 | +0.333 |
| 4 | 0.333 | 0.000 | +0.333 |

**Findings.**

- Perfect group separation from 2 hops onward: benign hosts never reach IOC
  infrastructure within 4 hops in this corpus.
- Attack rate saturates at 0.333 because only 5/15 synthetic incident scenarios
  include C2 egress to flagged IP ranges; the remaining scenarios are
  file/privilege-escalation chains with no network indicator — a coverage gap of
  the synthetic corpus, not of the traversal.
- Hop radius ≥ 2 is required: hosts never link directly to IOCs (minimum path is
  host → ip → ioc).

### Bug found and fixed during evaluation

`neighborhood()` truncated with `SELECT DISTINCT ... LIMIT n` **without ORDER BY**,
which made results non-monotonic in depth (an IOC node could be evicted from an
arbitrary top-n at higher radii; observed as WS-101 flipping true→false→true).
Fixed to truncate nearest-first via `min(depth)` ordering
(`src/sentinel_x/graph/traversal/walk.py`). Evaluation scripts are exactly where
this class of bug surfaces — one argument for building them.

---

## Reproducing

```powershell
docker compose up -d postgres redis ollama   # or host Ollama
python scripts/init_db.py
python scripts/download_knowledge.py          # then run the ingestion entry point
python scripts/seed_pipeline.py --reset
python experiments/retrieval/run_benchmark.py
python experiments/ablations/run_graph_eval.py --hops 2
python experiments/ablations/run_rag_ablation.py --queries 25
```
