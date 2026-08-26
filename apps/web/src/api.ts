import { clearToken, getToken } from './auth'
import type {
  GraphData,
  IncidentDetail,
  IncidentSummary,
  JobStatus,
  KnowledgeDoc,
  SecurityEvent,
} from './types'

const BASE = import.meta.env.VITE_API_BASE ?? ''

function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function handle<T>(path: string, method: string, res: Response): Promise<T> {
  if (res.status === 401) {
    // Expired/invalid token: evict and let the login screen take over.
    clearToken()
    throw new Error('Session expired')
  }
  if (!res.ok) throw new Error(`${method} ${path} failed: ${res.status}`)
  return res.json() as Promise<T>
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() })
  return handle(path, 'GET', res)
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  })
  return handle(path, 'POST', res)
}

export const api = {
  listIncidents: (minRisk = 0, limit = 100) =>
    get<IncidentSummary[]>(`/api/incidents?min_risk=${minRisk}&limit=${limit}`),

  getIncident: (id: string) => get<IncidentDetail>(`/api/incidents/${id}`),

  getIncidentEvents: (id: string) =>
    get<SecurityEvent[]>(`/api/incidents/${id}/events?limit=200`),

  getIncidentGraph: (id: string, maxHops = 2) =>
    get<GraphData>(`/api/incidents/${id}/graph?max_hops=${maxHops}`),

  queryEvents: (params: { host?: string; user?: string; eventType?: string }) => {
    const q = new URLSearchParams()
    if (params.host) q.set('host', params.host)
    if (params.user) q.set('user', params.user)
    if (params.eventType) q.set('event_type', params.eventType)
    return get<SecurityEvent[]>(`/api/events?${q.toString()}`)
  },

  searchKnowledge: (query: string, topK = 8) =>
    get<KnowledgeDoc[]>(`/api/knowledge/search?q=${encodeURIComponent(query)}&top_k=${topK}`),

  startInvestigation: (incidentId: string) =>
    post<JobStatus>('/api/investigations', { incident_id: incidentId }),

  listInvestigations: () => get<JobStatus[]>('/api/investigations'),

  getJob: (jobId: string) => get<JobStatus>(`/api/investigations/${jobId}`),
}
