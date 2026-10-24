// SPDX-License-Identifier: Apache-2.0
// Small SVG data-viz primitives in the Mission style: mini histogram, stippled area
// chart with a glowing current-point marker, segmented progress. Value changes animate
// through transform transitions only, which the motion level can switch off.
import { useMemo } from 'react'
import { useElementWidth } from '../../hooks/useElementWidth'
import { cn } from '../../lib/utils'
import { PulsingHalo } from './Decor'

const TONE_VAR = {
  primary: 'var(--accent-primary)',
  pro: 'var(--accent-pro)',
  success: 'var(--accent-success)',
  warning: 'var(--accent-warning)',
  danger: 'var(--accent-danger)',
  neutral: 'var(--text-tertiary)',
}
const toneColor = (t) => TONE_VAR[t] || t || TONE_VAR.primary

function scale(values) {
  const nums = values.map((v) => (Number.isFinite(Number(v)) ? Number(v) : 0))
  const max = Math.max(0, ...nums)
  return nums.map((v) => (max > 0 ? Math.max(0, v) / max : 0))
}

// Bars scaled to the largest value; each bar is a full-height rect scaled on Y.
export function MiniHistogram({ data = [], tone = 'primary', height = 22, barWidth = 2, gap = 1, className, label }) {
  const ratios = useMemo(() => scale(data.map((d) => (typeof d === 'object' ? d?.value : d))), [data])
  const width = Math.max(1, ratios.length * (barWidth + gap) - gap)
  if (ratios.length === 0) return null
  return (
    <svg
      className={cn('fx-histogram', className)}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : 'true'}
      data-testid="mini-histogram"
    >
      {ratios.map((r, i) => (
        <rect
          key={i}
          className="fx-bar"
          x={i * (barWidth + gap)}
          y={0}
          width={barWidth}
          height={height}
          rx={barWidth / 2}
          fill={toneColor(tone)}
          opacity={i === ratios.length - 1 ? 1 : 0.55 + 0.35 * r}
          style={{ transform: `scaleY(${Math.max(0.04, r)})` }}
        />
      ))}
    </svg>
  )
}

// points: numbers or { value, label }. The stipple is a grid of dots under the curve.
export function StippledAreaChart({ points = [], tone = 'primary', height = 140, step = 7, current, labels, className, label }) {
  const [ref, width] = useElementWidth()
  const values = useMemo(() => points.map((p) => (typeof p === 'object' ? Number(p?.value) || 0 : Number(p) || 0)), [points])
  const geometry = useMemo(() => {
    if (values.length < 2) return null
    const pad = 6
    const max = Math.max(...values, 0) || 1
    const min = Math.min(...values, 0)
    const span = max - min || 1
    const innerH = height - pad * 2
    const xAt = (i) => pad + (i / (values.length - 1)) * (width - pad * 2)
    const yAt = (v) => pad + innerH - ((v - min) / span) * innerH
    const coords = values.map((v, i) => [xAt(i), yAt(v)])
    const line = coords.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join('')
    const curveY = (x) => {
      const f = ((x - pad) / (width - pad * 2)) * (values.length - 1)
      const i = Math.min(values.length - 2, Math.max(0, Math.floor(f)))
      const tt = f - i
      return coords[i][1] + (coords[i + 1][1] - coords[i][1]) * tt
    }
    const dots = []
    for (let x = pad; x <= width - pad; x += step) {
      const top = curveY(x)
      for (let y = height - pad; y >= top; y -= step) dots.push(`M${x.toFixed(1)} ${y.toFixed(1)}h0`)
    }
    const idx = current === undefined ? values.length - 1 : Math.min(values.length - 1, Math.max(0, current))
    return { line, dots: dots.join(''), marker: coords[idx] }
  }, [values, width, height, step, current])

  const color = toneColor(tone)
  return (
    <div ref={ref} className={cn('fx-stipple relative w-full', className)} style={{ height }} data-testid="stippled-area-chart">
      {geometry && (
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : 'true'} className="fx-enter-fade block max-w-full">
          <path d={geometry.dots} stroke={color} strokeWidth="2.2" strokeLinecap="round" opacity="0.7" />
          <path d={geometry.line} stroke={color} strokeWidth="1.2" fill="none" strokeLinejoin="round" />
        </svg>
      )}
      {geometry && (
        <span className="absolute pointer-events-none" style={{ left: geometry.marker[0], top: geometry.marker[1], transform: 'translate(-50%, -50%)' }}>
          <PulsingHalo tone={tone} size={22} rings={1} flat={false} />
        </span>
      )}
      {labels?.length > 0 && (
        <div className="absolute left-0 right-0 bottom-0 translate-y-full flex justify-between pt-1 text-3xs text-text-tertiary">
          {labels.map((l, i) => <span key={`${i}-${l}`}>{l}</span>)}
        </div>
      )}
    </div>
  )
}

// segments: [{ key, state: 'done' | 'current' | 'next', weight }] laid out left to right.
export function SegmentedProgress({ segments = [], height = 3, className, label }) {
  const total = segments.reduce((n, s) => n + (Number(s.weight) || 1), 0) || 1
  const done = segments.filter((s) => s.state === 'done').length
  return (
    <div
      className={cn('fx-segments flex w-full gap-1', className)}
      style={{ height }}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={segments.length}
      aria-valuenow={done}
      data-testid="segmented-progress"
    >
      {segments.map((s, i) => (
        <span key={s.key ?? i} className={cn('fx-segment rounded-full', `fx-segment-${s.state || 'next'}`)} style={{ flexGrow: (Number(s.weight) || 1) / total }} />
      ))}
    </div>
  )
}
