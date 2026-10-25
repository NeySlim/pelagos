// SPDX-License-Identifier: Apache-2.0
// Mini strip chart (SVG): the series is redrawn on each sample, then the paper slides one
// slot to the left at constant speed over the sample interval (transform, linear). A value
// ruler on the right glides to round ticks when the maximum changes, a "+" pen settles on
// the newest point, and a crosshair reads the exact sample under the pointer.
import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { useElementWidth } from '../../hooks/useElementWidth'
import { cn } from '../../lib/utils'
import { Readout, Ruler } from './Instrument'
import { stripGeometry } from './primitives'

const TONE = { dns: 'var(--accent-primary)', dhcp: 'var(--accent-pro)', ok: 'var(--accent-success)', warn: 'var(--accent-warning-fill)' }
const PAD = 8
const BOTTOM = 14
const MAX_SLIDE_MS = 8000

export function StripChart({
  points = [],
  kind = 'line',
  tone = 'dns',
  slots = 45,
  height = 92,
  channel,
  unit,
  rate,
  count,
  format = String,
  formatTime,
  label,
  className,
  testId = 'strip-chart',
}) {
  const level = useMotionLevel()
  const [ref, width] = useElementWidth()
  const paper = useRef(null)
  const [hover, setHover] = useState(null)
  const g = useMemo(() => stripGeometry(points, { width, height, slots, kind }), [points, width, height, slots, kind])
  const { series, step, max, x, y } = g
  const last = series[series.length - 1]
  const prev = series[series.length - 2]
  const lastT = last?.t
  const seen = useRef(lastT)

  // A new sample: the paper starts one slot to the right and slides into place over the
  // real sample interval, linear. Below full it simply jumps.
  useLayoutEffect(() => {
    const el = paper.current
    const before = seen.current
    seen.current = lastT
    if (!el || before === undefined || before === lastT || !prev) return
    if (level !== 'full') {
      el.style.transition = 'none'
      el.style.transform = ''
      return
    }
    const ms = Math.min(MAX_SLIDE_MS, Math.max(500, lastT - prev.t))
    el.style.transition = 'none'
    el.style.transform = `translateX(${step.toFixed(2)}px)`
    el.getBoundingClientRect()
    el.style.transition = `transform ${ms}ms linear`
    el.style.transform = 'translateX(0)'
  }, [lastT, prev, step, level])

  const color = TONE[tone] || tone
  const line = kind === 'line' && series.length > 1 ? series.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join('') : ''
  const base = height - BOTTOM
  const bw = Math.max(2, step * 0.55)

  const onMove = (e) => {
    if (!series.length) return
    const px = e.clientX - e.currentTarget.getBoundingClientRect().left
    const i = Math.round((px - PAD) / step) - g.offset
    setHover(Math.min(series.length - 1, Math.max(0, i)))
  }
  const hovered = hover !== null && series[hover] ? { p: series[hover], x: x(hover), y: y(series[hover].v) } : null

  return (
    <div
      ref={ref}
      className={cn('fx-strip', `is-${kind}`, className)}
      style={{ height, '--fx-strip-c': color }}
      data-testid={testId}
      data-count={series.length}
      role={label ? 'img' : undefined}
      aria-label={label}
      onPointerMove={onMove}
      onPointerLeave={() => setHover(null)}
    >
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        <line className="fx-strip-grid" x1="0" x2={width} y1={y(max / 2).toFixed(1)} y2={y(max / 2).toFixed(1)} />
        <g ref={paper} className="fx-strip-paper">
          {kind === 'line' && line && (
            <>
              <path className="fx-strip-area" d={`${line}L${x(series.length - 1).toFixed(1)},${base}L${x(0).toFixed(1)},${base}Z`} />
              <path className="fx-strip-line" d={line} />
              <circle key={lastT} className="fx-strip-pt" cx={x(series.length - 1).toFixed(1)} cy={y(last.v).toFixed(1)} r="2.2" />
            </>
          )}
          {kind === 'bars' &&
            series.map((p, i) => (
              <rect
                key={i === series.length - 1 ? `new-${p.t}` : i}
                className={cn('fx-strip-bar', i === series.length - 1 && 'is-new')}
                x={(x(i) - bw / 2).toFixed(1)}
                y={y(p.v).toFixed(1)}
                width={bw.toFixed(1)}
                height={Math.max(0, base - y(p.v)).toFixed(1)}
                rx="1"
              />
            ))}
        </g>
      </svg>
      <span className="fx-strip-head" aria-hidden="true" />
      {kind === 'line' && (
        <span className="fx-strip-ruler" aria-hidden="true">
          <Ruler max={max} count={3} format={(v) => (v >= 1000 ? `${+(v / 1000).toFixed(1)}k` : String(v))} />
        </span>
      )}
      {last && <span className="fx-strip-pen" style={{ transform: `translate(${x(series.length - 1).toFixed(1)}px, ${y(last.v).toFixed(1)}px)` }} aria-hidden="true" />}
      {(channel || unit) && <Readout channel={channel} unit={unit} rate={rate} count={count} className="fx-strip-readout" />}
      {hovered && (
        <>
          <span className="fx-strip-xh" style={{ transform: `translateX(${hovered.x.toFixed(1)}px)`, '--fx-y': `${hovered.y.toFixed(1)}px` }} aria-hidden="true" />
          <span className={cn('fx-strip-xro', hovered.x < 120 && 'is-right')} style={{ left: hovered.x }} data-testid={`${testId}-readout`}>
            {formatTime ? `${formatTime(hovered.p.t)}  ` : ''}
            {format(hovered.p.v)}
          </span>
        </>
      )}
    </div>
  )
}
