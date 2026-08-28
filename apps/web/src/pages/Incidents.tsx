import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { IncidentSummary } from '../types'
import { Meter, RiskBadge, severityColor } from '../components/RiskBadge'
import { Spinner } from '../components/Spinner'

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listIncidents()
      .then((rows) =>
        setIncidents(rows.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))),
      )
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <>
      <h1>Incidents</h1>
      <p className="page-subtitle">ML-scored abnormal activity, correlated into incidents.</p>
      <div className="card">
        {loading && <Spinner label="Loading incidents…" />}
        {error && (
          <div className="error-banner">
            API error: {error}{' '}
            <button className="btn-retry" onClick={load} style={{ marginLeft: 8 }}>
              Retry
            </button>
          </div>
        )}
        {!loading && !error && incidents.length === 0 && (
          <div className="muted">
            No incidents found. Seed the database with:{' '}
            <code className="mono">sentinelx seed</code>
          </div>
        )}
        {!loading && !error && incidents.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Risk</th>
                <th style={{ width: '15%' }}></th>
                <th>ML prob.</th>
                <th>Anomaly</th>
                <th>Events</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((row) => (
                <tr
                  key={row.id}
                  className="clickable"
                  onClick={() => navigate(`/incidents/${row.id}`)}
                >
                  <td className="mono">{row.id}</td>
                  <td><StatusBadge status={row.status} /></td>
                  <td>
                    <RiskBadge label={row.severity_label} />
                  </td>
                  <td>{(row.risk_score ?? 0).toFixed(2)}</td>
                  <td>
                    <Meter value={row.risk_score} color={severityColor(row.severity_label)} />
                  </td>
                  <td>{row.attack_probability != null ? row.attack_probability.toFixed(2) : '—'}</td>
                  <td>{row.anomaly_score != null ? row.anomaly_score.toFixed(2) : '—'}</td>
                  <td>{row.n_events}</td>
                  <td className="muted" title={fmtFull(row.first_seen)}>{fmtRelative(row.first_seen)}</td>
                  <td className="muted" title={fmtFull(row.last_seen)}>{fmtRelative(row.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

const STATUS_STYLES: Record<string, string> = {
  open: 'badge critical',
  investigating: 'badge high',
  closed: 'badge low',
}

function StatusBadge({ status }: { status: string | null }) {
  if (!status) return <span className="muted">—</span>
  return <span className={STATUS_STYLES[status] ?? 'badge info'}>{status}</span>
}

function fmtRelative(iso: string | null): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const sec = Math.round(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  const min = Math.round(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.round(min / 60)
  if (hr < 24) return `${hr}h ago`
  const d = Math.round(hr / 24)
  return `${d}d ago`
}

function fmtFull(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}
