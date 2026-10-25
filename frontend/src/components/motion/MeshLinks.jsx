// SPDX-License-Identifier: Apache-2.0
// The links of a cluster of more than two nodes, drawn on one canvas over the node cards
// (`[data-mesh-node]` children of the container): replication arcs above the row between
// every pair of nodes, HA links straight between the two HA servers, lease update feeds as
// dashed arcs below the row from the active server to each backup. Card positions are read
// when the container resizes, never in a frame. Transport is linear as on SignalLink: a
// pulse crosses an arc in 600 ms, a transfer has its tail 300 ms behind the head, an HA
// heartbeat is a 1 x 6 px tick. Below full motion nothing travels.
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { useAnimationLoop } from '../../hooks/useAnimationLoop'
import { useCanvas } from '../../hooks/useCanvas'
import { PULSE_MS } from './primitives'
import { linkCurve, pointOn } from './meshGeometry'

const TAIL_MS = 300
const TONES = { neutral: '--text-primary', dns: '--accent-primary', dhcp: '--accent-pro', success: '--accent-success', danger: '--accent-danger' }

function readColors() {
  const style = getComputedStyle(document.documentElement)
  const out = {}
  for (const [tone, name] of Object.entries(TONES)) out[tone] = style.getPropertyValue(name).trim() || '#888'
  out.line = style.getPropertyValue('--text-tertiary').trim() || '#888'
  return out
}

const keyOf = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`)

export const MeshLinks = forwardRef(function MeshLinks({ containerRef, nodes, links, testId = 'mesh-links' }, ref) {
  const level = useMotionLevel()
  const live = level === 'full'
  const boxes = useRef({}) // node id -> { x, y, w, h, i }
  const signals = useRef([]) // { link, kind, tone, dir, label, start, duration }
  const colors = useRef(null)
  const [busy, setBusy] = useState(0)
  const [carried, setCarried] = useState(0)

  const curveOf = useCallback(
    (link) => {
      const a = boxes.current[link.a]
      const b = boxes.current[link.b]
      if (!a || !b) return null
      return linkCurve(link.kind, a, b, Math.abs(a.i - b.i))
    },
    [],
  )

  const draw = useCallback(
    ({ ctx }) => {
      const c = colors.current || (colors.current = readColors())
      for (const link of links) {
        const curve = curveOf(link)
        if (!curve) continue
        const down = link.state === 'down'
        ctx.lineWidth = link.kind === 'ha' ? 1.5 : 1
        ctx.strokeStyle = down ? c.danger : link.kind === 'repl' ? c.line : c.dhcp
        ctx.globalAlpha = down ? 0.9 : link.kind === 'repl' ? 0.32 : 0.7
        ctx.setLineDash(down ? [3, 3] : link.kind === 'feed' ? [2, 3] : [])
        ctx.beginPath()
        ctx.moveTo(...curve[0])
        ctx.quadraticCurveTo(...curve[1], ...curve[2])
        ctx.stroke()
      }
      ctx.setLineDash([])
      ctx.globalAlpha = 1
      if (!live) return
      const now = performance.now()
      for (const s of signals.current) {
        const curve = curveOf(s.link)
        if (!curve) continue
        const color = c[s.tone] || c.neutral
        const at = (p) => pointOn(curve, s.dir === 'back' ? 1 - p : p)
        const p = Math.min(1, (now - s.start) / s.duration)
        ctx.fillStyle = color
        ctx.strokeStyle = color
        if (s.kind === 'tick') {
          const [x, y] = at(p)
          ctx.globalAlpha = 0.85
          ctx.fillRect(Math.round(x), y - 3, 1, 6)
        } else if (s.kind === 'pulse') {
          ctx.lineWidth = 2
          ctx.beginPath()
          for (let k = 0; k <= 6; k += 1) {
            const q = Math.max(0, p - 0.12 + (0.12 * k) / 6)
            const [x, y] = at(q)
            if (k === 0) ctx.moveTo(x, y)
            else ctx.lineTo(x, y)
          }
          ctx.globalAlpha = 0.9
          ctx.stroke()
        } else {
          const span = s.duration - TAIL_MS
          const hp = Math.min(1, (now - s.start) / span)
          const tp = Math.max(0, Math.min(1, (now - s.start - TAIL_MS) / span))
          ctx.lineWidth = 2
          ctx.globalAlpha = 0.8
          ctx.beginPath()
          for (let k = 0; k <= 8; k += 1) {
            const [x, y] = at(tp + ((hp - tp) * k) / 8)
            if (k === 0) ctx.moveTo(x, y)
            else ctx.lineTo(x, y)
          }
          ctx.stroke()
          if (s.label) {
            const [x, y] = at(0.5)
            ctx.globalAlpha = 0.9
            ctx.fillStyle = c.line
            ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace'
            ctx.textAlign = 'center'
            ctx.fillText(s.label, x, y - 5)
          }
        }
        ctx.globalAlpha = 1
        ctx.lineWidth = 1
      }
    },
    [links, live, curveOf],
  )
  const { ref: canvasRef, redraw } = useCanvas(draw)

  // Card boxes relative to the container, read when it resizes or the cards change.
  const nodeKey = nodes.join(',')
  useEffect(() => {
    const host = containerRef?.current
    if (!host) return undefined
    const measure = () => {
      const out = {}
      host.querySelectorAll('[data-mesh-node]').forEach((el, i) => {
        out[el.getAttribute('data-mesh-node')] = { x: el.offsetLeft, y: el.offsetTop, w: el.offsetWidth, h: el.offsetHeight, i }
      })
      boxes.current = out
      redraw()
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver(measure)
    ro.observe(host)
    return () => ro.disconnect()
  }, [containerRef, nodeKey, redraw])

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
  }, [redraw, links, level])

  useAnimationLoop(
    () => {
      const now = performance.now()
      signals.current = signals.current.filter((s) => now - s.start < s.duration)
      redraw()
      if (busy > 0 && !signals.current.length) setBusy(0)
    },
    { enabled: busy > 0 },
  )

  useImperativeHandle(
    ref,
    () => ({
      // Something travels from node `from` to node `to` on their link of `kind` (repl first).
      signal(from, to, { kind = 'pulse', tone = 'neutral', link: linkKind, label, durationMs } = {}) {
        if (!live || !from || !to || from === to) return false
        const wanted = linkKind || (kind === 'tick' ? 'ha' : 'repl')
        const link = links.find((l) => l.kind === wanted && keyOf(l.a, l.b) === keyOf(from, to))
        if (!link || link.state === 'down') return false
        const duration = kind === 'transfer' ? Math.max(TAIL_MS + 300, durationMs || 900) : durationMs || (kind === 'tick' ? 500 : PULSE_MS)
        signals.current.push({ link, kind, tone, label, dir: link.a === from ? 'fwd' : 'back', start: performance.now(), duration })
        setBusy((n) => n + 1)
        setCarried((n) => n + 1)
        return true
      },
    }),
    [links, live],
  )

  return (
    <div className="fx-mesh" data-testid={testId} data-signals={carried} data-links={links.length} aria-hidden="true">
      <canvas ref={canvasRef} />
    </div>
  )
})
