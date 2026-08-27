import { useState } from 'react'
import { api } from '../api'
import type { KnowledgeDoc } from '../types'

const EXAMPLES = [
  'ransomware file encryption shadow copies',
  'pass the hash ntlm',
  'dns tunneling covert channel',
  'kerberoasting service tickets',
]

export function KnowledgeSearch() {
  const [query, setQuery] = useState('')
  const [hits, setHits] = useState<KnowledgeDoc[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run(q: string) {
    if (q.trim().length < 2) return
    setLoading(true)
    setError(null)
    try {
      setHits(await api.searchKnowledge(q, 10))
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <h1>Threat Intelligence Search</h1>
      <p className="page-subtitle">
        Hybrid retrieval: BM25 full-text + pgvector semantic search fused with RRF.
      </p>
      <form
        className="search-row"
        onSubmit={(e) => {
          e.preventDefault()
          void run(query)
        }}
      >
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search MITRE ATT&CK techniques, Sigma rules, playbooks…"
        />
        <button className="btn" disabled={loading}>
          {loading ? 'Searching…' : 'Search'}
        </button>
      </form>

      <div style={{ marginBottom: 16 }}>
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            className="badge info"
            style={{ cursor: 'pointer', border: 'none', marginRight: 8 }}
            onClick={() => {
              setQuery(ex)
              void run(ex)
            }}
          >
            {ex}
          </button>
        ))}
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        {hits === null ? (
          <div className="muted">Enter a query to search the knowledge base.</div>
        ) : hits.length === 0 ? (
          <div className="muted">No results.</div>
        ) : (
          hits.map((hit, i) => (
            <div key={i} className="knowledge-hit">
              <div className="hit-title">
                {hit.external_id && <span className="mono" style={{ color: 'var(--accent)' }}>{hit.external_id} · </span>}
                {hit.title}
              </div>
              <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
                source: {hit.source ?? '—'} · type: {hit.document_type ?? '—'}
                {hit.score != null && ` · score ${hit.score.toFixed(3)}`}
              </div>
              <div className="hit-snippet">{hit.snippet}</div>
            </div>
          ))
        )}
      </div>
    </>
  )
}
