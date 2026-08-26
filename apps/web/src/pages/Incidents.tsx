import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { IncidentSummary } from '../types'
import { Meter, RiskBadge, severityColor } from '../components/RiskBadge'

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    api
      .listIncidents()
      .then((rows) =>
        setIncidents(
          rows.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)),
        ),
      )
      .catch((e) => setError(String(e)))
  }, [])

  if (error) return <div className="error-banner">API error: {error}</div>

  return (
    <>
      <h1>Open Incidents</h1>
      <div className="card">
        {incidents.length === 0 ? (
          <div className="muted">
            No incidents found. Seed the database first:{' '}
            <code className="mono">python scripts/seed_pipeline.py</code>
          </div>
        ) : (
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
