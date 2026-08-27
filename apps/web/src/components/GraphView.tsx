import type { GraphData } from '../types'

interface Props {
  data: GraphData | null
  width?: number
  height?: number
}

const TYPE_COLORS: Record<string, string> = {
  user: '#38bdf8',
  host: '#a78bfa',
  ip: '#facc15',
  ioc: '#f43f5e',
  process: '#4ade80',
  file: '#fb923c',
}

/** Deterministic radial layout — seeds at center, others on concentric rings. */
function computeLayout(data: GraphData, width: number, height: number) {
  const positions = new Map<string, { x: number; y: number }>()
  const nodes = data.nodes
  if (!nodes.length) return positions

  const degree = new Map<string, number>()
  for (const e of data.edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1)
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1)
  }
  const sorted = [...nodes].sort(
    (a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0),
  )
  const cx = width / 2
  const cy = height / 2
  sorted.forEach((n, i) => {
    if (i === 0) {
      positions.set(n.id, { x: cx, y: cy })
    } else {
      const ring = Math.ceil(i / 8)
      const ringIndex = (i - 1) % 8
      const countInRing = Math.min(8, sorted.length - 1 - (ring - 1) * 8)
      const angle = (2 * Math.PI * ringIndex) / Math.max(countInRing, 1)
      const radius = 70 + ring * 62
      positions.set(n.id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle) * 0.82,
      })
    }
  })
  return positions
}

export function GraphView({ data, width = 720, height = 430 }: Props) {
  if (!data || !data.nodes.length) {
    return <div className="muted">No graph data available for this incident.</div>
  }
  const positions = computeLayout(data, width, height)

  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto' }}>
      {data.edges.map((e, i) => {
        const a = positions.get(e.source)
        const b = positions.get(e.target)
        if (!a || !b) return null
        return (
          <g key={`e${i}`}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#cbd5e1" strokeWidth={1.4} />
            <text
              x={(a.x + b.x) / 2}
              y={(a.y + b.y) / 2 - 3}
              fill="#64748b"
              fontSize="9.5"
              textAnchor="middle"
            >
              {e.relation}
            </text>
          </g>
        )
      })}
      {data.nodes.map((n) => {
        const p = positions.get(n.id)
        if (!p) return null
        const color = n.malicious ? '#f43f5e' : (TYPE_COLORS[n.type] ?? '#8aa0bd')
        const r = n.malicious ? 13 : 10
        return (
          <g key={n.id}>
            <circle cx={p.x} cy={p.y} r={r} fill={color} opacity={0.92}>
              <title>{`${n.type}: ${n.name}${n.malicious ? ' (malicious)' : ''}`}</title>
            </circle>
            <text x={p.x} y={p.y + r + 12} fill="#334155" fontSize="10" textAnchor="middle">
              {n.name.length > 18 ? `${n.name.slice(0, 17)}…` : n.name}
            </text>
            <text x={p.x} y={p.y - r - 6} fill="#64748b" fontSize="9" textAnchor="middle">
              {n.type}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
