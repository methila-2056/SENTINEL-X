// Shared API types mirroring the FastAPI schemas.

export interface IncidentSummary {
  id: string
  first_seen: string | null
  last_seen: string | null
  status: string | null
  severity_label: string | null
  risk_score: number | null
  anomaly_score?: number | null
  attack_probability: number | null
  n_events: number
}

export interface IncidentDetail extends IncidentSummary {
  signals: Record<string, number>
  correlated_event_ids: string[]
  entities: {
    users?: string[]
    hosts?: string[]
    src_ips?: string[]
    external_ips?: string[]
  }
  ground_truth_incident_id: string | null
}

export interface SecurityEvent {
  event_id: string
  timestamp: string
  event_type: string
  action: string
  user: string | null
  host: string | null
  process: string | null
  src_ip: string | null
  dst_ip: string | null
  dst_port: number | null
  file_path: string | null
  bytes_transferred: number | null
  severity: number
  label: string
  technique_id: string | null
  attack_category?: string | null
}

export interface GraphNode {
  id: string
  type: string
  name: string
  malicious: boolean
}

export interface GraphEdge {
  source: string
  target: string
  relation: string
  weight: number
}

export interface GraphData {
  incident_id?: string
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface ClaimVerdict {
  claim: string
  grounded: boolean
  citations: string[]
}

export interface Verification {
  verdict: string
  confidence: number
  evidence_coverage: number
  citation_precision: number
  cited_evidence_count: number
  hallucinated_citations: string[]
  technique_identified_supported: boolean
  claim_verdicts: ClaimVerdict[]
}

export interface InvestigationStep {
  step_index: number
  thought: string
  tool: string | null
  args: Record<string, unknown>
  ok: boolean
  duration_ms: number
}

export interface InvestigationReport {
  incident_id: string
  summary: string
  root_cause_technique: string | null
  key_findings: string[]
  recommended_actions: string[]
  evidence_ids: string[]
  verification: Verification
  steps: InvestigationStep[]
  llm_calls: number
  wall_time_s: number
}

export interface JobStatus {
  job_id: string
  incident_id: string
  state: 'running' | 'completed' | 'failed'
  elapsed_s: number | null
  report: InvestigationReport | { error: string } | null
}

export interface KnowledgeDoc {
  external_id: string | null
  title: string | null
  source: string | null
  document_type?: string | null
  score?: number | null
  snippet: string
}
