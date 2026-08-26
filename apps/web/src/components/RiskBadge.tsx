const RISK_COLORS: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#4ade80',
}

export function severityColor(label: string | null | undefined): string {
  return RISK_COLORS[(label ?? 'low').toLowerCase()] ?? RISK_COLORS.low
}

export function RiskBadge({ label }: { label: string | null | undefined }) {
  const key = (label ?? 'low').toLowerCase()
  return <span className={`badge ${key}`}>{key}</span>
}

export function Meter({
  value,
  color,
}: {
  value: number | null | undefined
  color?: string
}) {
  const pct = Math.round(Math.min(Math.max(value ?? 0, 0), 1) * 100)
  return (
    <div className="meter">
      <div style={{ width: `${pct}%`, background: color ?? 'var(--accent)' }} />
    </div>
  )
}
