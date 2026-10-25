// SPDX-License-Identifier: Apache-2.0
// Ambient layers sit under the data, below the hairline in contrast, and exist only for the
// Instrument family with the ambient preference on. The screen layer is a graticule that
// drifts at the trace paper speed (two compositor animations, no script). Tile layers are
// canvases driven by real rates (wave, spectrum, dot matrix), plus registration marks and
// a refresh sweep. At full motion on a visible page they redraw at about 30 fps from the
// one shared loop; below full they hold one static frame, redrawn when the data changes.
import { useEffect, useRef, useState } from 'react'
import { useMotion } from '../../contexts/MotionContext'
import { addAnimator, removeAnimator } from '../../hooks/useAnimationLoop'
import { useAmbientLayers } from '../../hooks/useAmbientLayers'
import { useCanvas, MAX_DPR } from '../../hooks/useCanvas'
import { cn } from '../../lib/utils'
import { FRAME_MS, RIPPLE_MS, drawDots, drawSpectrum, drawWave } from './ambientDraw'

export function AmbientScreen({ className }) {
  const { ambient } = useMotion()
  if (ambient !== 'on') return null
  return (
    <div className={cn('fx-ambient', className)} aria-hidden="true" data-testid="ambient-screen">
      <div className="fx-ambient-grid fx-loop" />
      <div className="fx-ambient-contour fx-loop" />
    </div>
  )
}

// One animator on the shared loop serves every ambient canvas on screen.
const canvases = new Set()
const LOOP_ID = {}
let acc = 0

function tick(t, dt) {
  acc += dt
  if (acc < FRAME_MS) return
  const step = acc
  acc = 0
  for (const item of canvases) item.frame(t, step)
}

function join(item) {
  canvases.add(item)
  if (canvases.size === 1) addAnimator(LOOP_ID, tick)
}

function leave(item) {
  canvases.delete(item)
  if (canvases.size === 0) removeAnimator(LOOP_ID)
}

// Ink of a canvas (its CSS color), re-read only when the theme attributes change.
const inks = new WeakMap()
function inkOf(canvas) {
  const root = document.documentElement
  const key = `${root.className}|${root.dataset.theme}|${root.dataset.themeFamily}|${root.dataset.effects}`
  const hit = inks.get(canvas)
  if (hit && hit.key === key) return hit.color
  const color = getComputedStyle(canvas).color
  inks.set(canvas, { key, color })
  return color
}

// Counts changes of `token` after the first render: the events a layer reacts to.
function useEventCount(token) {
  const prev = useRef(token)
  const [count, setCount] = useState(0)
  useEffect(() => {
    if (prev.current === token) return
    prev.current = token
    setCount((n) => n + 1)
  }, [token])
  return count
}

function CanvasLayer({ draw, needsFrame = () => true, className, testId, kind }) {
  const { ambientRunning } = useMotion()
  const phase = useRef(0)
  const { ref, redraw } = useCanvas(({ ctx, width, height }) => {
    const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1)
    draw(ctx, width, height, { phase: phase.current, now: performance.now(), dpr, color: inkOf(ctx.canvas) })
  })
  const frameRef = useRef(null)
  useEffect(() => {
    frameRef.current = (t, step) => {
      phase.current += step
      if (needsFrame(t)) redraw()
    }
  })
  // Static frame: any render with new data repaints once, whatever the level.
  useEffect(() => {
    redraw()
  })
  useEffect(() => {
    if (!ambientRunning) return undefined
    const item = { frame: (t, step) => frameRef.current?.(t, step) }
    join(item)
    return () => leave(item)
  }, [ambientRunning])
  return <canvas ref={ref} className={cn('fx-amb-canvas', className)} aria-hidden="true" data-testid={testId} data-kind={kind} />
}

// DNS: three sines whose amplitude is the query rate against the series peak.
export function AmbientWave({ rate = 0, peak = 0, tone = 'primary' }) {
  const show = useAmbientLayers()
  if (!show) return null
  return (
    <CanvasLayer
      kind="wave"
      testId="ambient-wave"
      className={`fx-tone-${tone}`}
      draw={(ctx, w, h, o) => drawWave(ctx, w, h, { rate, peak, phase: o.phase, color: o.color })}
    />
  )
}

// DHCP: the latest lease samples as faint bars along the bottom.
export function AmbientSpectrum({ values = [], tone = 'pro' }) {
  const show = useAmbientLayers()
  if (!show) return null
  return (
    <CanvasLayer
      kind="spectrum"
      testId="ambient-spectrum"
      className={`fx-tone-${tone}`}
      draw={(ctx, w, h, o) => drawSpectrum(ctx, w, h, { values, phase: o.phase, color: o.color })}
    />
  )
}

// Topology: dot matrix and hairline mesh; an event (a change of `pulse`) ripples once from
// the centre at full motion. Idle, the layer costs no frames.
export function AmbientDots({ pulse }) {
  const show = useAmbientLayers()
  const { level } = useMotion()
  const started = useRef(null)
  const count = useEventCount(pulse)
  useEffect(() => {
    if (count > 0 && level === 'full') started.current = performance.now()
  }, [count, level])
  if (!show) return null
  const elapsed = (now) => (started.current === null ? null : now - started.current)
  return (
    <CanvasLayer
      kind="dots"
      testId="ambient-dots"
      className="fx-amb-ink"
      needsFrame={(t) => started.current !== null && t - started.current < RIPPLE_MS + 2 * FRAME_MS}
      draw={(ctx, w, h, o) => drawDots(ctx, w, h, { color: o.color, dpr: o.dpr, elapsed: elapsed(o.now) })}
    />
  )
}

// Layer under a tile body: the canvases above sit in it, below the data.
export function AmbientTile({ children, className }) {
  const show = useAmbientLayers()
  if (!show || !children) return null
  return (
    <div className={cn('fx-amb-tile', className)} aria-hidden="true" data-testid="ambient-tile">
      {children}
    </div>
  )
}

// Corner brackets of a tile or panel; they pulse once when `pulse` changes (an event).
export function RegMarks({ pulse }) {
  const show = useAmbientLayers()
  const { ambientRunning } = useMotion()
  const count = useEventCount(pulse)
  if (!show) return null
  return (
    <span key={count} className={cn('fx-regs', count > 0 && ambientRunning && 'is-ping')} aria-hidden="true" data-testid="reg-marks">
      <i className="fx-reg fx-reg-tl" />
      <i className="fx-reg fx-reg-tr" />
      <i className="fx-reg fx-reg-bl" />
      <i className="fx-reg fx-reg-br" />
    </span>
  )
}

// Calibration sweep: one vertical hairline with a trail crosses the tile when `trigger`
// changes (a refresh), after `delay` ms to stagger tiles. Nothing moves below full motion.
export function Sweep({ trigger, delay = 0 }) {
  const show = useAmbientLayers()
  const { ambientRunning } = useMotion()
  const count = useEventCount(trigger)
  if (!show) return null
  return (
    <span className="fx-amb-sweep" aria-hidden="true" data-testid="tile-sweep">
      {count > 0 && ambientRunning && <i key={count} className="fx-sweep is-go" style={delay ? { animationDelay: `${delay}ms` } : undefined} />}
    </span>
  )
}
