// SPDX-License-Identifier: Apache-2.0
// Canvas traces for procedures. SerialTrace: one step lane per node over a 5 min window of
// paper that scrolls at constant speed; a plan is a marker, a serial change is a step, and
// scrubTo()/release() move a playhead back to an instant (the rollback rewind) and return.
// ThresholdTrace: a value against fixed threshold lines, with latches that close where the
// signal crossed a line (alert opened) and where it came back (resolved). Both draw once
// per event below full motion, and their readouts are DOM text.
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMotionLevel } from '../../contexts/MotionContext'
import { useAnimationLoop } from '../../hooks/useAnimationLoop'
import { useCanvas } from '../../hooks/useCanvas'
import { easeInOut, spring } from '../../lib/motion'
import { cn } from '../../lib/utils'
import { clipPoints, levelOf, rulerTicks, snapMarker, stepLevels, timeToX, valueAt, xToTime } from './traceMath'

const INKS = {
  dns: '--accent-primary',
  dhcp: '--accent-pro',
  success: '--accent-success',
  warning: '--accent-warning-fill',
  danger: '--accent-danger',
  text: '--text-primary',
  text2: '--text-secondary',
  faint: '--text-tertiary',
  bg: '--bg-secondary',
}
const FONT = '10px "IBM Plex Mono", ui-monospace, monospace'
const REVEAL_MS = 600
const LAND_MS = 600
const FRAME_MS = 33 // the paper moves a fraction of a pixel per frame: 30 fps is enough

function readInks() {
  const style = getComputedStyle(document.documentElement)
  const out = {}
  for (const [k, name] of Object.entries(INKS)) out[k] = style.getPropertyValue(name).trim() || '#888'
  return out
}

// Token colors for a canvas, re-read when the theme changes (then `onChange` repaints).
function useInks(onChange) {
  const inks = useRef(null)
  useEffect(() => {
    const mo = new MutationObserver(() => {
      inks.current = null
      onChange()
    })
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme', 'data-effects'] })
    return () => mo.disconnect()
  }, [onChange])
  return () => inks.current || (inks.current = readInks())
}

const hhmmss = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })

// ---------------------------------------------------------------- serial trace

export const SerialTrace = forwardRef(function SerialTrace(
  { lanes = [], markers = [], windowMs = 300000, className, testId = 'serial-trace', now: nowProp },
  ref,
) {
  const { t } = useTranslation()
  const level = useMotionLevel()
  const full = level === 'full'
  const clock = useRef(nowProp || (() => Date.now()))
  clock.current = nowProp || (() => Date.now())
  const scrub = useRef({ at: null, glide: null }) // glide: { from, to, start, dur, resolve, clear }
  const hover = useRef(null)
  const reveal = useRef(null) // perf start of the pen, first draw at full
  const lastValues = useRef(new Map()) // lane id -> { value, at: perf time it changed }
  const readoutRef = useRef(null)
  const lastFrame = useRef(0)
  const [held, setHeld] = useState(false) // the playhead is away from the present
  const [onScreen, setOnScreen] = useState(true)
  const box = useRef(null)
  // Off screen the paper stops; a glide in progress still finishes.
  useEffect(() => {
    if (!box.current || typeof IntersectionObserver === 'undefined') return undefined
    const io = new IntersectionObserver(([entry]) => setOnScreen(entry.isIntersecting))
    io.observe(box.current)
    return () => io.disconnect()
  }, [])
  const repaint = useRef(() => {})
  const getInks = useInks(useCallback(() => repaint.current(), []))

  const draw = useCallback(
    ({ ctx, width, height }) => {
      const c = getInks()
      const now = clock.current()
      const perf = performance.now()
      const left = 0
      const right = Math.max(40, width - 92)
      const top = 4
      const bottom = height - 16
      const from = now - windowMs
      const toX = (tt) => timeToX(tt, now, windowMs, left, right)
      const levels = stepLevels(lanes, from)
      const max = levels.length ? levels[levels.length - 1] : null
      const laneH = (bottom - top) / Math.max(1, lanes.length)
      ctx.font = FONT
      ctx.textBaseline = 'middle'

      // Pen: on the first draw at full the history is written left to right.
      let penX = right
      if (reveal.current !== null) {
        const p = Math.min(1, (perf - reveal.current) / REVEAL_MS)
        penX = left + (right - left) * p
        if (p >= 1) reveal.current = null
      }

      // Ruler and grid.
      ctx.fillStyle = c.faint
      ctx.textAlign = 'center'
      ctx.globalAlpha = 0.85
      // About one labelled tick per 80 px, so a phone keeps a readable ruler.
      for (const tick of rulerTicks(now, windowMs, Math.max(2, Math.floor((right - left) / 80)))) {
        const x = Math.round(toX(tick.t)) + 0.5
        ctx.fillRect(x, bottom, 1, 3)
        ctx.globalAlpha = 0.12
        ctx.fillRect(x, top, 1, bottom - top)
        ctx.globalAlpha = 0.85
        const text = tick.ago === 0 ? t('live.now') : t('live.agoSeconds', { seconds: Math.round(tick.ago / 1000) })
        ctx.textAlign = tick.ago === 0 ? 'right' : x < 24 ? 'left' : 'center'
        ctx.fillText(text, x, height - 5)
      }
      ctx.globalAlpha = 1

      lanes.forEach((lane, i) => {
        const y0 = top + i * laneH
        const yOf = (v) => y0 + laneH - 5 - levelOf(levels, v) * Math.max(2, laneH - 12)
        const pts = clipPoints(lane.points, from, now)
        const last = lane.points.length ? lane.points[lane.points.length - 1][1] : null
        const behind = max !== null && last !== null && Number(last) < max
        ctx.globalAlpha = 0.18
        ctx.fillStyle = c.faint
        if (i > 0) ctx.fillRect(left, Math.round(y0) + 0.5, right - left, 1)
        ctx.globalAlpha = 1
        if (pts.length) {
          ctx.save()
          ctx.beginPath()
          ctx.rect(left, y0, penX - left, laneH)
          ctx.clip()
          ctx.strokeStyle = behind ? c.warning : c.dns
          ctx.lineWidth = 1.5
          ctx.beginPath()
          let y = yOf(pts[0][1])
          ctx.moveTo(Math.max(left, toX(pts[0][0])), y)
          for (let k = 1; k < pts.length; k += 1) {
            const x = toX(pts[k][0])
            ctx.lineTo(x, y)
            y = yOf(pts[k][1])
            ctx.lineTo(x, y)
          }
          ctx.lineTo(right, y)
          ctx.stroke()
          ctx.restore()
          // A new step lands: a dot at the step that fades on the settle curve.
          const seen = lastValues.current.get(lane.id)
          if (seen && seen.value === last && full && perf - seen.at < LAND_MS && pts.length > 1) {
            const k = (perf - seen.at) / LAND_MS
            const sx = toX(pts[pts.length - 1][0])
            ctx.globalAlpha = 1 - k
            ctx.fillStyle = behind ? c.warning : c.dns
            ctx.beginPath()
            ctx.arc(sx, yOf(last), 2 + 2 * (1 - k), 0, Math.PI * 2)
            ctx.fill()
            ctx.globalAlpha = 1
          }
        }
        // Readings on the right edge: the node and the serial it serves.
        const at = scrub.current.at
        const shown = at !== null ? valueAt(lane.points, at) : last
        ctx.textAlign = 'left'
        ctx.fillStyle = c.faint
        ctx.fillText(lane.label, right + 8, y0 + laneH / 2 - 6)
        ctx.fillStyle = behind && at === null ? c.warning : c.text2
        ctx.fillText(shown === undefined || shown === null ? '-' : String(shown), right + 8, y0 + laneH / 2 + 6)
      })

      // Plan markers on the ruler: a square for an apply, a crossed square for a rollback.
      for (const m of markers) {
        const x = toX(m.t)
        if (x < left - 4 || x > right + 4) continue
        const y = bottom - 6
        if (m.kind === 'rollback') {
          ctx.strokeStyle = c.warning
          ctx.lineWidth = 1.2
          ctx.strokeRect(x - 3, y - 3, 6, 6)
          ctx.beginPath()
          ctx.moveTo(x - 3, y + 3)
          ctx.lineTo(x + 3, y - 3)
          ctx.stroke()
        } else {
          ctx.fillStyle = c.dns
          ctx.fillRect(x - 3, y - 3, 6, 6)
        }
      }

      // Playhead: the rewind position, else the pointer (magnetic near a marker).
      const at = scrub.current.at
      let headX = null
      let headT = null
      let snapped = null
      if (at !== null) {
        headT = Math.max(from, at)
        headX = toX(headT)
        ctx.globalAlpha = 0.55
        ctx.fillStyle = c.bg
        ctx.fillRect(headX, top, right - headX, bottom - top)
        ctx.globalAlpha = 1
      } else if (hover.current !== null) {
        snapped = snapMarker(markers, hover.current, toX)
        headX = snapped ? toX(snapped.t) : Math.min(right, Math.max(left, hover.current))
        headT = snapped ? snapped.t : xToTime(headX, now, windowMs, left, right)
      }
      if (headX !== null) {
        ctx.fillStyle = at !== null ? c.warning : c.text
        ctx.fillRect(Math.round(headX), top, 1, bottom - top)
      }
      const box = readoutRef.current
      if (box) {
        if (headT === null) {
          box.hidden = true
        } else {
          const marker = snapped || markers.find((m) => Math.abs(m.t - headT) < 1000)
          const values = lanes.map((l) => `${l.label} ${valueAt(l.points, headT) ?? '-'}`).join('  ')
          box.textContent = `${hhmmss(headT)}  ${values}${marker?.label ? `  ${marker.label}` : ''}`
          box.hidden = false
          // Width estimated from the text: no layout read inside a frame.
          const boxW = box.textContent.length * 6.1 + 14
          const bx = headX + 8 + boxW > width ? headX - 8 - boxW : headX + 8
          box.style.transform = `translateX(${Math.round(Math.max(0, bx))}px)`
        }
      }
    },
    [lanes, markers, windowMs, full, t], // eslint-disable-line react-hooks/exhaustive-deps
  )
  const { ref: canvasRef, redraw } = useCanvas(draw)
  repaint.current = redraw

  // Steps that changed since the last render land; the first draw at full writes the pen.
  useEffect(() => {
    const perf = performance.now()
    for (const lane of lanes) {
      const last = lane.points.length ? lane.points[lane.points.length - 1][1] : null
      const seen = lastValues.current.get(lane.id)
      if (!seen) lastValues.current.set(lane.id, { value: last, at: -Infinity })
      else if (seen.value !== last) lastValues.current.set(lane.id, { value: last, at: perf })
    }
    redraw()
  }, [lanes, markers, redraw])
  useEffect(() => {
    if (full) reveal.current = performance.now()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    redraw()
  }, [level, redraw])
  // Below full the paper jumps: a redraw every few seconds keeps "now" honest.
  useEffect(() => {
    if (full) return undefined
    const timer = setInterval(redraw, 5000)
    return () => clearInterval(timer)
  }, [full, redraw])

  useAnimationLoop(
    (time) => {
      const g = scrub.current.glide
      if (g) {
        const k = Math.min(1, (performance.now() - g.start) / g.dur)
        const target = typeof g.to === 'function' ? g.to() : g.to
        scrub.current.at = g.from + (target - g.from) * easeInOut(k)
        if (k >= 1) {
          scrub.current.glide = null
          if (g.clear) {
            scrub.current.at = null
            setHeld(false)
          }
          g.resolve()
        }
      } else if (time - lastFrame.current < FRAME_MS) return
      lastFrame.current = time
      redraw()
    },
    { enabled: onScreen || held },
  )

  useImperativeHandle(
    ref,
    () => ({
      // Moves the playhead to instant `at`, gliding on ease-in-out at full motion.
      scrubTo(at, { durationMs = 700 } = {}) {
        return new Promise((resolve) => {
          scrub.current.glide?.resolve()
          setHeld(true)
          if (!full) {
            scrub.current = { at, glide: null }
            redraw()
            resolve()
            return
          }
          const fromT = scrub.current.at ?? clock.current()
          scrub.current.glide = { from: fromT, to: at, start: performance.now(), dur: durationMs, resolve }
        })
      },
      // Lets the playhead return to the present, then the trace is live again.
      release({ durationMs = 350 } = {}) {
        return new Promise((resolve) => {
          scrub.current.glide?.resolve()
          if (!full || scrub.current.at === null) {
            scrub.current = { at: null, glide: null }
            setHeld(false)
            redraw()
            resolve()
            return
          }
          scrub.current.glide = { from: scrub.current.at, to: () => clock.current(), start: performance.now(), dur: durationMs, resolve, clear: true }
        })
      },
      get scrubbed() {
        return scrub.current.at
      },
    }),
    [full, redraw],
  )

  return (
    <div
      ref={box}
      className={cn('fx-trace', className)}
      data-testid={testId}
      data-scrubbing={held ? 'true' : undefined}
      onPointerMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect()
        hover.current = e.clientX - rect.left
        redraw()
      }}
      onPointerLeave={() => {
        hover.current = null
        redraw()
      }}
    >
      <canvas ref={canvasRef} aria-hidden="true" />
      <div ref={readoutRef} className="fx-trace-readout" data-testid={`${testId}-readout`} hidden />
    </div>
  )
})

// ---------------------------------------------------------------- threshold trace

export function ThresholdTrace({ points = [], thresholds = [], latches = [], from, to, min = 0, max = 100, format = (v) => `${Math.round(v)}%`, tone = 'dhcp', className, testId = 'threshold-trace' }) {
  const level = useMotionLevel()
  const full = level === 'full'
  const reveal = useRef(full ? performance.now() : null)
  const landed = useRef(new Map()) // latch key -> perf time it landed
  const [busy, setBusy] = useState(full)
  const repaint = useRef(() => {})
  const getInks = useInks(useCallback(() => repaint.current(), []))
  const keyOf = (l) => `${l.state}@${l.t}`

  const draw = useCallback(
    ({ ctx, width, height }) => {
      const c = getInks()
      const perf = performance.now()
      const left = 0
      const right = Math.max(40, width - 34)
      const top = 6
      const bottom = height - 4
      const end = to ?? Date.now()
      const start = from ?? end - 3600000
      const span = Math.max(1, end - start)
      const toX = (tt) => left + ((tt - start) / span) * (right - left)
      const toY = (v) => bottom - ((Math.min(max, Math.max(min, v)) - min) / (max - min)) * (bottom - top)
      ctx.font = FONT
      ctx.textBaseline = 'middle'
      ctx.textAlign = 'left'

      // Labels closer than one line of text to a label already drawn are left out.
      const labelled = []
      for (const th of thresholds) {
        const y = Math.round(toY(th.value)) + 0.5
        ctx.strokeStyle = c[th.tone] || c.faint
        ctx.globalAlpha = 0.55
        ctx.setLineDash([3, 3])
        ctx.beginPath()
        ctx.moveTo(left, y)
        ctx.lineTo(right, y)
        ctx.stroke()
        ctx.setLineDash([])
        if (labelled.every((ly) => Math.abs(ly - y) >= 10)) {
          ctx.globalAlpha = 0.9
          ctx.fillStyle = c.faint
          ctx.fillText(th.label ?? format(th.value), right + 6, y)
          labelled.push(y)
        }
      }
      ctx.globalAlpha = 1

      let penX = right
      if (reveal.current !== null) {
        const p = Math.min(1, (perf - reveal.current) / REVEAL_MS)
        penX = left + (right - left) * p
        if (p >= 1) reveal.current = null
      }
      const pts = clipPoints(points, start, end)
      if (pts.length) {
        ctx.save()
        ctx.beginPath()
        ctx.rect(left, 0, penX - left, height)
        ctx.clip()
        ctx.strokeStyle = c[tone] || c.dhcp
        ctx.lineWidth = 1.5
        ctx.beginPath()
        pts.forEach(([tt, v], i) => (i ? ctx.lineTo(toX(tt), toY(v)) : ctx.moveTo(Math.max(left, toX(tt)), toY(v))))
        ctx.stroke()
        ctx.restore()
      }

      // Latches close where the signal crossed: a dot and a hairline down to the axis.
      for (const l of latches) {
        const x = toX(l.t)
        if (x < left - 6 || x > right + 6 || x > penX + 1) continue
        const y = toY(l.value)
        const key = keyOf(l)
        if (!landed.current.has(key)) landed.current.set(key, full ? perf : -Infinity)
        const age = (perf - landed.current.get(key)) / LAND_MS
        const s = full && age < 1 ? 0.5 + 0.5 * spring(age) : 1
        const color = l.state === 'released' ? c.success : c.danger
        ctx.globalAlpha = 0.6
        ctx.fillStyle = color
        ctx.fillRect(Math.round(x), y, 1, bottom - y)
        ctx.globalAlpha = 1
        ctx.beginPath()
        ctx.arc(x, y, 3.5 * s, 0, Math.PI * 2)
        if (l.state === 'held') {
          ctx.fillStyle = c.bg
          ctx.fill()
          ctx.strokeStyle = color
          ctx.lineWidth = 1.2
          ctx.stroke()
        } else {
          ctx.fillStyle = color
          ctx.fill()
        }
      }
    },
    [points, thresholds, latches, from, to, min, max, format, tone, full], // eslint-disable-line react-hooks/exhaustive-deps
  )
  const { ref: canvasRef, redraw } = useCanvas(draw)
  repaint.current = redraw

  const pending = () => reveal.current !== null || [...landed.current.values()].some((at) => performance.now() - at < LAND_MS)
  useEffect(() => {
    redraw()
    if (full) setBusy(true)
  }, [points, latches, thresholds, level, redraw, full])
  useAnimationLoop(
    () => {
      redraw()
      if (!pending()) setBusy(false)
    },
    { enabled: busy },
  )

  return (
    <div className={cn('fx-trace fx-trace-threshold', className)} data-testid={testId} data-latches={latches.map((l) => l.state).join(' ')}>
      <canvas ref={canvasRef} aria-hidden="true" />
    </div>
  )
}
