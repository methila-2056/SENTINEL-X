import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { JobStatus } from '../types'
import { Spinner } from '../components/Spinner'

export function Investigations() {
  const [jobs, setJobs] = useState<JobStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listInvestigations()
      .then(setJobs)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <>
      <h1>Investigation History</h1>
      <p className="page-subtitle">Agent-driven investigations and their outcomes.</p>
      <div className="card">
        {loading && <Spinner label="Loading investigations…" />}
        {error && (
          <div className="error-banner">
            API error: {error}{' '}
            <button className="btn-retry" onClick={load} style={{ marginLeft: 8 }}>
              Retry
            </button>
          </div>
        )}
        {!loading && !error && jobs.length === 0 && (
          <div className="muted">
            No investigations yet. Start one from an incident detail page.
          </div>
        )}
        {!loading && !error && jobs.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Incident</th>
                <th>State</th>
                <th>Elapsed</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr
                  key={job.job_id}
                  className="clickable"
                  onClick={() => navigate(`/incidents/${job.incident_id}`)}
                >
                  <td className="mono">{job.job_id}</td>
                  <td className="mono">{job.incident_id}</td>
                  <td><StateBadge state={job.state} /></td>
                  <td className="muted">
                    {job.elapsed_s != null ? `${job.elapsed_s.toFixed(1)}s` : '—'}
                  </td>
                  <td className="muted">
                    {job.report && 'summary' in job.report
                      ? String(job.report.summary).slice(0, 80)
                      : job.state === 'failed' && job.report && 'error' in job.report
                        ? <span className="badge critical">failed</span>
                        : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

const STATE_STYLES: Record<string, string> = {
  running: 'badge info',
  completed: 'badge low',
  failed: 'badge critical',
}

function StateBadge({ state }: { state: string }) {
  return <span className={STATE_STYLES[state] ?? 'badge info'}>{state}</span>
}
