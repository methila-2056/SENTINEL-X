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
      <h1>Open Incidents</h1>
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
                <th>Severity</th>
                <th>Risk score</th>
                <th style={{ width: '18%' }}></th>
                <th>ML attack prob.</th>
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
                  <td className="muted">{fmtTime(row.first_seen)}</td>
                  <td className="muted">{fmtTime(row.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

function fmtTime(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}
