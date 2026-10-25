// SPDX-License-Identifier: Apache-2.0
// The link between two nodes, drawn on a canvas. Transport is linear: a pulse (14 px)
// crosses in 600 ms, a transfer bar has a head and a tail 300 ms behind, and HA lease
// updates cross as 1 x 6 px ticks with Poisson spacing at the measured rate (at most 4
// visible). A lost partner turns the line into red dashes and stops every tick, which
// is the signal. Below full motion nothing travels: the line is redrawn on change only.
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { useAnimationLoop } from '../../hooks/useAnimationLoop'
import { useCanvas } from '../../hooks/useCanvas'
import { cn } from '../../lib/utils'
import { MAX_TICKS, PULSE_MS, poissonGap } from './primitives'

const TAIL_MS = 300
const TONES = { neutral: '--text-primary', dns: '--accent-primary', dhcp: '--accent-pro', success: '--accent-success', danger: '--accent-danger', warning: '--accent-warning-fill' }

function readColors() {
  const style = getComputedStyle(document.documentElement)
  const out = {}
  for (const [tone, name] of Object.entries(TONES)) out[tone] = style.getPropertyValue(name).trim() || '#888'
  out.line = style.getPropertyValue('--text-tertiary').trim() || '#888'
  return out
}

export const SignalLink = forwardRef(function SignalLink(
  { state = 'ok', rate = 0, tickTone = 'dhcp', direction = 'forward', labelTop, labelBottom, className, testId = 'signal-link' },
  ref,
) {
  const level = useMotionLevel()
  const events = useRef([]) // { kind, tone, dir, start, duration, label }
  const ticks = useRef([]) // start times
  const nextTick = useRef(0)
  const colors = useRef(null)
  const [busy, setBusy] = useState(0)
  const live = level === 'full'
  const down = state === 'down'

  const draw = useCallback(
    ({ ctx, width, height }) => {
      const c = colors.current || (colors.current = readColors())
      const y = Math.round(height / 2) + 0.5
      const now = performance.now()
      ctx.lineWidth = 1
      ctx.strokeStyle = down ? c.danger : c.line
      ctx.globalAlpha = down ? 0.9 : 0.45
      ctx.setLineDash(down ? [3, 3] : [])
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(width, y)
      ctx.stroke()
      ctx.setLineDash([])
      ctx.globalAlpha = 1
      if (!live) return
      for (const t of ticks.current) {
        const p = (now - t.start) / PULSE_MS
        const x = (t.dir === 'back' ? 1 - p : p) * width
        ctx.fillStyle = c[tickTone] || c.dhcp
        ctx.globalAlpha = 0.85
        ctx.fillRect(Math.round(x), y - 3, 1, 6)
      }
      for (const e of events.current) {
        const p = Math.min(1, (now - e.start) / e.duration)
        const color = c[e.tone] || c.neutral
        if (e.kind === 'pulse') {
          const head = (e.dir === 'back' ? 1 - p : p) * width
          const tail = e.dir === 'back' ? head + 14 : head - 14
          const g = ctx.createLinearGradient(tail, 0, head, 0)
          g.addColorStop(0, 'transparent')
          g.addColorStop(1, color)
          ctx.strokeStyle = g
          ctx.lineWidth = 2
          ctx.beginPath()
          ctx.moveTo(tail, y)
          ctx.lineTo(head, y)
          ctx.stroke()
        } else {
          // Transfer: the tail leaves 300 ms after the head; both move at the same speed.
          const span = e.duration - TAIL_MS
          const hp = Math.min(1, (now - e.start) / span)
          const tp = Math.max(0, Math.min(1, (now - e.start - TAIL_MS) / span))
          const [a, b] = e.dir === 'back' ? [1 - hp, 1 - tp] : [tp, hp]
          ctx.fillStyle = color
          ctx.globalAlpha = 0.8
          ctx.fillRect(a * width, y - 1, Math.max(1, (b - a) * width), 2)
          if (e.label) {
            ctx.globalAlpha = 0.9
            ctx.fillStyle = c.line
            ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace'
            ctx.textAlign = 'center'
            ctx.fillText(e.label, width / 2, y - 6)
          }
        }
        ctx.globalAlpha = 1
        ctx.lineWidth = 1
      }
    },
    [down, live, tickTone],
  )
  const { ref: canvasRef, redraw } = useCanvas(draw)

  // Theme changes repaint with the new tokens.
  useEffect(() => {
    const mo = new MutationObserver(() => {
      colors.current = null
      redraw()
    })
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme', 'data-effects'] })
    return () => mo.disconnect()
  }, [redraw])
  useEffect(() => {
    redraw()
  }, [redraw, state, level])

  const ticking = live && !down && rate > 0
  useAnimationLoop(
    () => {
      const now = performance.now()
      if (ticking) {
        if (!nextTick.current) nextTick.current = now + poissonGap(rate)
        if (now >= nextTick.current) {
          if (ticks.current.length < MAX_TICKS) ticks.current.push({ start: now, dir: direction })
          nextTick.current = now + poissonGap(rate)
        }
      }
      ticks.current = ticks.current.filter((t) => now - t.start < PULSE_MS)
      const before = events.current.length
      events.current = events.current.filter((e) => now - e.start < e.duration)
      redraw()
      if (before && !events.current.length) setBusy(0)
    },
    { enabled: ticking || busy > 0 },
  )

  useImperativeHandle(
    ref,
    () => ({
      // Something leaves one node for the other (replication, HA recovery).
      pulse({ tone = 'neutral', dir = direction } = {}) {
        if (!live || down) return false
        events.current.push({ kind: 'pulse', tone, dir, start: performance.now(), duration: PULSE_MS })
        setBusy((n) => n + 1)
        return true
      },
      // A measured transport: how much and how long (zone transfer).
      transfer({ tone = 'dns', dir = direction, label, durationMs = 900 } = {}) {
        if (!live || down) return false
        events.current.push({ kind: 'transfer', tone, dir, label, start: performance.now(), duration: Math.max(TAIL_MS + 300, durationMs) })
        setBusy((n) => n + 1)
        return true
      },
    }),
    [direction, live, down],
  )

  return (
    <div className={cn('fx-link', className)} data-testid={testId} data-state={state} aria-hidden="true">
      <canvas ref={canvasRef} />
      {labelTop && <span className="fx-link-label is-top">{labelTop}</span>}
      {labelBottom && <span className="fx-link-label is-bottom">{labelBottom}</span>}
    </div>
  )
})
