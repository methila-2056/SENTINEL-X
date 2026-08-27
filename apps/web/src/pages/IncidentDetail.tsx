import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api'
import type {
  GraphData,
  IncidentDetail as IncidentDetailType,
  InvestigationReport,
  JobStatus,
  SecurityEvent,
} from '../types'
import { GraphView } from '../components/GraphView'
import { Meter, RiskBadge, severityColor } from '../components/RiskBadge'
import { Spinner } from '../components/Spinner'

const POLL_INTERVAL_MS = 2000

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const [incident, setIncident] = useState<IncidentDetailType | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [job, setJob] = useState<JobStatus | null>(null)
  const [running, setRunning] = useState(false)

  const load = useCallback(() => {
    if (!id) return
    setLoading(true)
    setError(null)
    Promise.all([
      api.getIncident(id),
      api.getIncidentEvents(id).catch(() => [] as SecurityEvent[]),
      api.getIncidentGraph(id).catch(() => null),
    ])
      .then(([inc, evs, gr]) => {
        setIncident(inc)
        setEvents(evs)
        setGraph(gr)
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!job || job.state !== 'running') return
    const timer = setInterval(async () => {
      try {
        const status = await api.getJob(job.job_id)
        setJob(status)
        if (status.state !== 'running') setRunning(false)
      } catch {
        /* transient */
      }
    }, POLL_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [job])

  const startInvestigation = useCallback(async () => {
    if (!id) return
    setRunning(true)
    try {
      setJob(await api.startInvestigation(id))
    } catch (e) {
      setError(String(e))
      setRunning(false)
    }
  }, [id])

  if (loading) return <Spinner label="Loading incident…" />
  if (error)
    return (
      <div className="error-banner">
        API error: {error}{' '}
        <button className="btn-retry" onClick={load} style={{ marginLeft: 8 }}>
          Retry
        </button>
      </div>
    )
  if (!incident) return <div className="muted">Incident not found.</div>

  const report = job?.report && !('error' in job.report) ? job.report : null

  return (
    <>
      <h1>
        Incident <span className="mono">{incident.id}</span>{' '}
        <RiskBadge label={incident.severity_label} />
        {incident.ground_truth_incident_id && (
          <span className="badge info" style={{ marginLeft: 8 }}>
            GT: {incident.ground_truth_incident_id}
          </span>
        )}
      </h1>

      <div className="grid-4">
        <Stat label="Risk score" value={(incident.risk_score ?? 0).toFixed(2)}>
          <Meter value={incident.risk_score} color={severityColor(incident.severity_label)} />
        </Stat>
        <Stat
          label="ML attack probability"
          value={incident.attack_probability != null ? incident.attack_probability.toFixed(2) : '—'}
        >
          <Meter value={incident.attack_probability ?? 0} />
        </Stat>
        <Stat
          label="Anomaly score"
          value={incident.anomaly_score != null ? incident.anomaly_score.toFixed(2) : '—'}
        >
          <Meter value={incident.anomaly_score ?? 0} color="#a78bfa" />
        </Stat>
        <Stat label="Correlated events" value={String(events.length)} />
      </div>

      <div className="card">
        <h2>Behavioral signals</h2>
        <div className="grid-4">
          {Object.entries(incident.signals ?? {}).map(([key, val]) => (
            <div key={key}>
              <div className="stat-label">{snakeToWords(key)}</div>
              <div className="stat-value" style={{ fontSize: 16 }}>
                {typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(2) : String(val)}
              </div>
            </div>
          ))}
        </div>
      </div>

      <button className="btn btn-primary" onClick={startInvestigation} disabled={running}>
        {running ? 'Agent investigating…' : 'Run AI investigation'}
      </button>
      {job && (
        <span style={{ marginLeft: 12 }} className="muted">
          job {job.job_id} — state: <b>{job.state}</b>
          {job.elapsed_s != null ? ` (${job.elapsed_s}s)` : ''}
        </span>
      )}

      {report && <ReportPanel report={report} />}

      <div className="grid-2" style={{ marginTop: 16 }}>
        <div className="card">
          <h2>Attack chain timeline</h2>
          <ul className="timeline">
            {events.map((ev) => (
              <li key={ev.event_id}>
                <time>{new Date(ev.timestamp).toLocaleTimeString()}</time>
                <span className="ev-type">{ev.event_type} / {ev.action}</span>
                <span className="ev-detail">{describe(ev)}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <h2>Entity knowledge graph</h2>
          <GraphView data={graph} />
        </div>
      </div>
    </>
  )
}

function ReportPanel({ report }: { report: InvestigationReport }) {
  const v = report.verification
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>AI investigation report</h2>
      <p style={{ marginTop: 0 }}>{report.summary}</p>
      {report.root_cause_technique && (
        <p>
          <b>Root cause technique:</b>{' '}
          <span className="mono" style={{ color: 'var(--accent)' }}>
            {report.root_cause_technique}
          </span>
        </p>
      )}
      <div className="grid-4">
        <Stat label="Verdict" value={v.verdict} />
        <Stat label="Confidence" value={`${Math.round(v.confidence * 100)}%`}>
          <Meter value={v.confidence} color="#4ade80" />
        </Stat>
        <Stat label="Evidence coverage" value={`${Math.round(v.evidence_coverage * 100)}%`} />
        <Stat
          label="Citation precision"
          value={
            v.citation_precision != null ? `${Math.round(v.citation_precision * 100)}%` : '—'
          }
        />
      </div>
      <h2 style={{ marginTop: 14 }}>Key findings</h2>
      {(v.claim_verdicts ?? []).length > 0
        ? v.claim_verdicts.map((c, i) => (
            <div key={i} className={`finding ${c.grounded ? 'grounded' : 'ungrounded'}`}>
              {c.claim}
              {c.citations.length > 0 && (
                <>
                  {' '}
                  {c.citations.map((cite) => (
                    <span key={cite} className="cite">
                      [{cite}]{' '}
                    </span>
                  ))}
                </>
              )}
              {!c.grounded && <span className="badge critical">ungrounded</span>}
            </div>
          ))
        : report.key_findings.map((f, i) => (
            <div key={i} className="finding grounded">
              {f}
            </div>
          ))}
      {v.hallucinated_citations?.length > 0 && (
        <p className="muted" style={{ fontSize: 12.5 }}>
          Hallucinated citations rejected:{' '}
          <span className="mono">{v.hallucinated_citations.join(', ')}</span>
        </p>
      )}
      <h2 style={{ marginTop: 14 }}>Recommended actions</h2>
      <ul style={{ margin: 0, paddingLeft: 20 }}>
        {report.recommended_actions.map((a, i) => (
          <li key={i} style={{ marginBottom: 4, fontSize: 13.5 }}>
            {a}
          </li>
        ))}
      </ul>
      <h2 style={{ marginTop: 14 }}>Agent tool calls ({report.steps.length})</h2>
      <table className="data">
        <thead>
          <tr>
            <th>#</th>
            <th>Tool</th>
            <th>Args</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {report.steps.map((s) => (
            <tr key={s.step_index}>
              <td>{s.step_index}</td>
              <td className="mono">{s.tool}</td>
              <td className="mono muted" style={{ fontSize: 12 }}>
                {JSON.stringify(s.args)}
              </td>
              <td>{s.ok ? '✓' : '✗'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted" style={{ fontSize: 12.5, marginBottom: 0 }}>
        {report.llm_calls} LLM calls · wall time {report.wall_time_s}s
      </p>
    </div>
  )
}

function Stat({
  label,
  value,
  children,
}: {
  label: string
  value: string
  children?: React.ReactNode
}) {
  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {children}
    </div>
  )
}

function describe(ev: SecurityEvent): string {
  const parts: string[] = []
  if (ev.user) parts.push(`user=${ev.user}`)
  if (ev.host) parts.push(`host=${ev.host}`)
  if (ev.process) parts.push(`proc=${ev.process}`)
  if (ev.src_ip) parts.push(`src=${ev.src_ip}`)
  if (ev.dst_ip) parts.push(`dst=${ev.dst_ip}${ev.dst_port ? `:${ev.dst_port}` : ''}`)
  if (ev.file_path) parts.push(`file=${ev.file_path}`)
  if (ev.bytes_transferred) parts.push(`bytes=${ev.bytes_transferred}`)
  if (ev.technique_id) parts.push(`[${ev.technique_id}]`)
  return parts.join('  ')
}

function snakeToWords(s: string): string {
  return s.replace(/_/g, ' ')
}
