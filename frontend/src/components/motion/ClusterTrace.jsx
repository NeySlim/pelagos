// SPDX-License-Identifier: Apache-2.0
// The strip-chart recorder: a canvas whose paper moves at the real clock (x is a
// function of time, sub-pixel, no jump), lanes of lines, bars, heartbeat ECG rows,
// event markers and steps, a time ruler, an animated window, a magnetic playhead with
// the exact sample under it, and a pen that reveals the history once. At full motion it
// draws on the shared loop while visible; below full it redraws on data, window or
// pointer changes only, so the paper jumps one sample at a time.
import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { useAnimationLoop } from '../../hooks/useAnimationLoop'
import { useCanvas } from '../../hooks/useCanvas'
import { cn } from '../../lib/utils'
import { easeOut, settle, spring } from '../../lib/motion'
import {
  REVEAL_MS, beatIntervalAt, followPlayhead, laneMax, nearestSample, rulerLabel, rulerLevels, smoothTowards, snapToEvent,
  tAt, visibleFrom, windowAt, xAt,
} from '../../lib/trace'
import { ink, onThemeChange, readInks } from './canvasInk'

const MONO = (px) => `${px}px "IBM Plex Mono", ui-monospace, monospace`
const RULER_H = 14
const EVENT_INK = { alert: 'bad', fail: 'bad', plan: 'dns', axfr: 'dns', ha: 'dhcp', ok: 'ok', repl: 't2', rb: 'warn' }
const clamp = (v, a, b) => Math.min(b, Math.max(a, v))

function marker(ctx, kind) {
  ctx.beginPath()
  if (kind === 'alert' || kind === 'ok') ctx.arc(0, 0, 3.5, 0, Math.PI * 2)
  else if (kind === 'plan' || kind === 'rb' || kind === 'fail') ctx.rect(-3.5, -3.5, 7, 7)
  else if (kind === 'axfr') {
    ctx.moveTo(0, -4)
    ctx.lineTo(4, 3)
    ctx.lineTo(-4, 3)
    ctx.closePath()
  } else {
    ctx.moveTo(0, -4.5)
    ctx.lineTo(4.5, 0)
    ctx.lineTo(0, 4.5)
    ctx.lineTo(-4.5, 0)
    ctx.closePath()
  }
}

// Sample spacing of a series (median of the last gaps), for the bar width.
function spacingOf(data, fallback = 4000) {
  const gaps = []
  for (let i = Math.max(1, data.length - 8); i < data.length; i += 1) gaps.push(data[i].t - data[i - 1].t)
  if (!gaps.length) return fallback
  return gaps.sort((a, b) => a - b)[gaps.length >> 1] || fallback
}

export const ClusterTrace = forwardRef(function ClusterTrace(
  {
    lanes = [],
    windowMs = 90000,
    ruler = true,
    names = true,
    pad = 8,
    rightPad = 8,
    readout = true,
    reveal = false,
    clockOffset = 0,
    locale,
    labels = {},
    eventLabel,
    className,
    testId = 'cluster-trace',
    ariaLabel,
    children,
  },
  ref,
) {
  const level = useMotionLevel()
  const full = level === 'full'
  const props = useRef({})
  props.current = { lanes, ruler, names, pad, rightPad, readout, clockOffset, locale, labels, eventLabel, full }
  const hostRef = useRef(null)
  const readoutRef = useRef(null)
  const inks = useRef(null)
  const win = useRef({ from: windowMs, to: windowMs, t0: 0, cur: windowMs })
  const pointer = useRef(null)
  const drawn = useRef({ hx: null, snapped: null, key: '' })
  const scrub = useRef(null)
  const scales = useRef({})
  const arrivals = useRef({ samples: {}, beats: {}, events: new WeakMap(), seenEvents: 0 })
  const revealRef = useRef({ t0: reveal && full ? -1 : 0 })
  const lastPt = useRef(0)
  const [visible, setVisible] = useState(true)

  const draw = useCallback(({ ctx, width: w, height: H }) => {
    const p = props.current
    const c = inks.current || (inks.current = readInks(hostRef.current || undefined))
    const pt = performance.now()
    const dt = lastPt.current ? Math.min(100, pt - lastPt.current) : 16
    lastPt.current = pt
    const tnow = Date.now() + p.clockOffset
    const isFull = p.full
    // Window: interpolated while a zoom runs.
    const wa = win.current
    if (wa.t0) {
      const { win: cur, done } = windowAt(wa, pt)
      wa.cur = cur
      if (done) wa.t0 = 0
    } else wa.cur = wa.to
    const rulerH = p.ruler ? RULER_H : 0
    const plotW = Math.max(1, w - p.pad - p.rightPad)
    const geo = { pad: p.pad, plotW, win: wa.cur }
    const x = (t) => xAt(t, tnow, geo)
    const tmin = tnow - wa.cur - 8000
    const lanesList = p.lanes.filter(Boolean)
    const laneH = (H - rulerH) / Math.max(1, lanesList.length)
    // Reveal: the pen draws the history from left to right once, 600 ms linear.
    const rv = revealRef.current
    if (rv.t0 === -1) rv.t0 = pt
    const revealK = rv.t0 > 0 && isFull ? clamp((pt - rv.t0) / REVEAL_MS, 0, 1) : 1
    if (revealK >= 1) rv.t0 = 0
    if (revealK < 1) {
      ctx.save()
      ctx.beginPath()
      ctx.rect(0, 0, p.pad + plotW * revealK, H)
      ctx.clip()
    }
    const values = {}
    let pen = null
    lanesList.forEach((ln, li) => {
      const y0 = li * laneH
      const y1 = y0 + laneH
      if (li) {
        ctx.strokeStyle = ink(c.hair)
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(0, Math.round(y0) + 0.5)
        ctx.lineTo(w, Math.round(y0) + 0.5)
        ctx.stroke()
      }
      if (p.names && ln.label && ln.type !== 'step') {
        ctx.fillStyle = ink(c.t4)
        ctx.font = MONO(10)
        ctx.textAlign = 'left'
        ctx.textBaseline = 'alphabetic'
        ctx.fillText(ln.label, p.pad, y0 + 12)
      }
      const col = c[ln.color] || c.t2
      if (ln.type === 'line' || ln.type === 'bars') {
        const data = ln.data || []
        const top = y0 + laneH * (ln.topPad ?? 0.26)
        const bot = y1 - laneH * (ln.botPad ?? 0.1)
        const mn = ln.min ?? 0
        const vis = data.length ? data.slice(visibleFrom(data, tmin)) : []
        const target = ln.max ?? laneMax(vis)
        const ymax = (scales.current[ln.key] = isFull ? smoothTowards(scales.current[ln.key], target, dt) : target)
        const y = (v) => bot - (bot - top) * clamp((v - mn) / (ymax - mn || 1), 0, 1.05)
        for (const th of ln.thresholds || []) {
          const yy = Math.round(y(th.v)) + 0.5
          ctx.strokeStyle = th.bad ? ink(c.bad, 0.45) : ink(c.hair3)
          ctx.setLineDash(th.bad ? [] : [2, 3])
          ctx.beginPath()
          ctx.moveTo(p.pad, yy)
          ctx.lineTo(p.pad + plotW, yy)
          ctx.stroke()
          ctx.setLineDash([])
          ctx.fillStyle = th.bad ? ink(c.bad, 0.8) : ink(c.t4)
          ctx.font = MONO(9)
          ctx.textAlign = 'right'
          ctx.fillText(th.label, p.pad + plotW - 2, yy - 3)
        }
        if (!vis.length) return
        const last = vis[vis.length - 1]
        const seen = arrivals.current.samples[ln.key]
        if (!seen || seen.t !== last.t) arrivals.current.samples[ln.key] = { t: last.t, at: seen ? pt : -1e9 }
        const age = pt - arrivals.current.samples[ln.key].at
        if (ln.type === 'line') {
          // The pen catches up with the newest sample over 300 ms.
          const k = isFull ? easeOut(age / 300) : 1
          ctx.beginPath()
          let px = 0
          let py = 0
          vis.forEach((s, i) => {
            let xx = x(s.t)
            let yy = y(s.v)
            if (i === vis.length - 1 && i > 0) {
              xx = px + (xx - px) * k
              yy = py + (yy - py) * k
            }
            if (i) ctx.lineTo(xx, yy)
            else ctx.moveTo(xx, yy)
            px = xx
            py = yy
          })
          ctx.strokeStyle = ink(col)
          ctx.lineWidth = 1.5
          ctx.lineJoin = 'round'
          ctx.stroke()
          ctx.lineTo(px, bot)
          ctx.lineTo(x(vis[0].t), bot)
          ctx.closePath()
          ctx.fillStyle = ink(col, 0.08)
          ctx.fill()
          ctx.lineWidth = 1
          // The newest point lights up, then rests at 40 %.
          ctx.fillStyle = ink(col, isFull ? 0.4 + 0.6 * (1 - easeOut(age / 600)) : 0.7)
          ctx.beginPath()
          ctx.arc(px, py, 2.2, 0, Math.PI * 2)
          ctx.fill()
          if (!pen) pen = px
          for (const L of ln.latches || []) {
            const inWindow = L.t >= tnow - wa.cur
            const lx = inWindow ? x(L.t) : p.pad + 3
            const lv = inWindow ? L.v ?? nearestSample(vis, L.t)?.v : vis[0].v
            if (lv === null || lv === undefined) continue
            const ly = y(lv)
            const sc = isFull && inWindow ? 0.6 + 0.4 * spring((tnow - L.t) / 600) : 1
            const open = L.state === 'open'
            const tone = L.state === 'released' ? c.ok : c.bad
            ctx.strokeStyle = ink(tone)
            ctx.lineWidth = 1.5
            ctx.fillStyle = open ? ink(c.bad) : ink(c.panel)
            ctx.beginPath()
            ctx.arc(lx, ly, 3.5 * sc, 0, Math.PI * 2)
            ctx.fill()
            ctx.stroke()
            ctx.strokeStyle = ink(tone, 0.5)
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.moveTo(lx, ly + 4)
            ctx.lineTo(lx, bot + 2)
            ctx.stroke()
          }
        } else {
          const bw = Math.max(2, ((plotW * spacingOf(data)) / wa.cur) * 0.5)
          ctx.fillStyle = ink(col, 0.75)
          vis.forEach((s, i) => {
            const xx = x(s.t)
            let yy = y(s.v)
            // The newest bar grows from the baseline and settles.
            if (i === vis.length - 1 && isFull) yy = bot - (bot - yy) * settle(age / 300)
            ctx.fillRect(xx - bw / 2, yy, bw, Math.max(0, bot - yy))
          })
          if (!pen) pen = x(last.t)
        }
        values[ln.key] = (t) => {
          const s = nearestSample(vis, t)
          return s && { v: s.v, t: s.t, y: y(s.v) }
        }
      } else if (ln.type === 'ecg') {
        const rows = ln.rows || []
        const rh = (laneH - 14) / Math.max(1, rows.length)
        rows.forEach((row, ri) => {
          const yb = Math.round(y0 + 14 + rh * ri + rh * 0.68)
          ctx.strokeStyle = ink(c.hair)
          ctx.beginPath()
          ctx.moveTo(p.pad, yb + 0.5)
          ctx.lineTo(p.pad + plotW, yb + 0.5)
          ctx.stroke()
          const out = row.outage
          if (out) {
            const xa = Math.max(p.pad, x(out.from))
            const xb = out.to ? x(out.to) : p.pad + plotW
            if (xb > p.pad) {
              ctx.strokeStyle = ink(c.bad, 0.7)
              ctx.setLineDash([3, 4])
              ctx.beginPath()
              ctx.moveTo(xa, yb + 0.5)
              ctx.lineTo(xb, yb + 0.5)
              ctx.stroke()
              ctx.setLineDash([])
            }
          }
          ctx.fillStyle = ink(c.t4)
          ctx.font = MONO(10)
          ctx.textAlign = 'right'
          ctx.fillText(row.label, p.pad + plotW - 4, yb - 10)
          const beats = row.beats || []
          const id = `${ln.key}:${ri}`
          const head = beats[0]
          const seen = arrivals.current.beats[id]
          if (head && (!seen || Math.abs(seen.t - head.t) > 1000)) arrivals.current.beats[id] = { t: head.t, at: seen ? pt : -1e9 }
          const headAge = head ? pt - arrivals.current.beats[id].at : Infinity
          ctx.strokeStyle = ink(c.ok)
          ctx.lineWidth = 1.3
          ctx.lineJoin = 'round'
          // Newest first: stop at the left edge.
          for (let i = 0; i < beats.length; i += 1) {
            const xx = x(beats[i].t)
            if (xx < p.pad - 6) break
            // A QRS lands on an underdamped spring (zeta 0.6, 450 ms) when it arrives.
            const a = isFull && i === 0 ? spring(headAge / 450, 0.6, 9) : 1
            ctx.beginPath()
            ctx.moveTo(xx - 4.5, yb)
            ctx.lineTo(xx - 2.6, yb)
            ctx.lineTo(xx - 1.8, yb + 1.6 * a)
            ctx.lineTo(xx - 0.6, yb - 9 * a)
            ctx.lineTo(xx + 0.8, yb + 3 * a)
            ctx.lineTo(xx + 1.8, yb)
            ctx.lineTo(xx + 4.5, yb)
            ctx.stroke()
          }
          ctx.strokeStyle = ink(c.bad)
          ctx.lineWidth = 1.2
          for (const ts of row.lost || []) {
            const xx = x(ts)
            if (xx < p.pad) continue
            ctx.beginPath()
            ctx.moveTo(xx - 2.5, yb - 6.5)
            ctx.lineTo(xx + 2.5, yb - 1.5)
            ctx.moveTo(xx + 2.5, yb - 6.5)
            ctx.lineTo(xx - 2.5, yb - 1.5)
            ctx.stroke()
          }
          ctx.lineWidth = 1
        })
        if (rows[0]) values.hb = (t) => beatIntervalAt(rows[0].beats || [], t)
      } else if (ln.type === 'events') {
        const ye = y0 + laneH * 0.6
        const events = ln.data || []
        const arr = arrivals.current
        // Events that arrive after the first draw land on the spring.
        if (!arr.primed || events.length !== arr.seenEvents) {
          for (const e of events) if (!arr.events.has(e)) arr.events.set(e, arr.primed ? pt : -1e9)
          arr.seenEvents = events.length
          arr.primed = true
        }
        for (const e of events) {
          const xx = x(e.t)
          if (xx < p.pad - 5 || xx > w) continue
          const at = arr.events.get(e) ?? -1e9
          const sc = isFull ? 0.5 + 0.5 * spring((pt - at) / 600) : 1
          const big = drawn.current.snapped === e ? 1.25 : 1
          ctx.save()
          ctx.translate(xx, ye)
          ctx.scale(sc * big, sc * big)
          ctx.lineWidth = 1.5
          ctx.fillStyle = ink(c.panel)
          ctx.strokeStyle = ink(c[EVENT_INK[e.kind]] || c.t2)
          marker(ctx, e.kind)
          ctx.fill()
          ctx.stroke()
          if (e.kind === 'rb') {
            ctx.beginPath()
            ctx.moveTo(-2, -2)
            ctx.lineTo(2, 2)
            ctx.moveTo(2, -2)
            ctx.lineTo(-2, 2)
            ctx.stroke()
          }
          ctx.restore()
        }
        values.events = events
      } else if (ln.type === 'step') {
        const data = ln.data || []
        if (!data.length) return
        const top = y0 + laneH * 0.3
        const bot = y1 - laneH * 0.22
        const vals = [...new Set(data.map((d) => d.v))].sort((a, b) => a - b)
        const ymap = (v) => (vals.length < 2 ? bot : bot - (bot - top) * (vals.indexOf(v) / (vals.length - 1)))
        ctx.strokeStyle = ink(col)
        ctx.lineWidth = 1.5
        ctx.beginPath()
        let yp = ymap(data[0].v)
        ctx.moveTo(p.pad, yp)
        for (let i = 1; i < data.length; i += 1) {
          const xx = Math.max(p.pad, x(data[i].t))
          const k = isFull ? easeOut((tnow - data[i].t) / 300) : 1
          const yy = yp + (ymap(data[i].v) - yp) * k
          ctx.lineTo(xx, yp)
          ctx.lineTo(xx, yy)
          yp = yy
        }
        ctx.lineTo(p.pad + plotW, yp)
        ctx.stroke()
        ctx.lineWidth = 1
        ctx.font = MONO(10)
        ctx.textAlign = 'right'
        ctx.fillStyle = ink(c.t4)
        if (ln.label) ctx.fillText(ln.label, p.pad + plotW - 4, y0 + 11)
        ctx.fillStyle = ink(col)
        ctx.fillText(String(ln.format ? ln.format(data[data.length - 1].v) : data[data.length - 1].v), p.pad + plotW - 26, yp - 3)
        values[ln.key] = (t) => {
          let v = data[0].v
          for (const d of data) if (d.t <= t) v = d.v
          return { v }
        }
      }
    })
    // Ruler: tick sets fade with their spacing; the cursor triangle follows the newest sample.
    if (p.ruler) {
      const yr = H - rulerH
      ctx.strokeStyle = ink(c.hair)
      ctx.beginPath()
      ctx.moveTo(0, yr + 0.5)
      ctx.lineTo(w, yr + 0.5)
      ctx.stroke()
      ctx.font = MONO(9)
      ctx.textAlign = 'center'
      ctx.textBaseline = 'alphabetic'
      let texts = 0
      for (const lv of rulerLevels(plotW, wa.cur)) {
        for (let tt = Math.floor(tnow / lv.step) * lv.step; tt > tnow - wa.cur - lv.step; tt -= lv.step) {
          const xx = x(tt)
          if (xx < p.pad || xx > p.pad + plotW) continue
          ctx.strokeStyle = ink(c.t1, (lv.major ? 0.32 : 0.14) * lv.tick)
          ctx.beginPath()
          ctx.moveTo(Math.round(xx) + 0.5, yr + 1)
          ctx.lineTo(Math.round(xx) + 0.5, yr + (lv.major ? 5 : 3))
          ctx.stroke()
          // Labels sit on round ages so they read "-10 s", not the wall clock.
          const ageLbl = Math.round((tnow - tt) / lv.step) * lv.step
          if (lv.label > 0.02 && ageLbl > 0 && xx > p.pad + 18 && xx < p.pad + plotW - 24 && texts < 14) {
            ctx.fillStyle = ink(c.t1, 0.42 * lv.label)
            ctx.fillText(rulerLabel(ageLbl), xx, H - 2)
            texts += 1
          }
        }
      }
      if (pen !== null) {
        ctx.fillStyle = ink(c.t2)
        ctx.beginPath()
        ctx.moveTo(pen, yr + 1)
        ctx.lineTo(pen - 3, yr + 6)
        ctx.lineTo(pen + 3, yr + 6)
        ctx.closePath()
        ctx.fill()
      }
      ctx.fillStyle = ink(c.t3)
      ctx.textAlign = 'right'
      ctx.fillText(p.labels.now || 'now', p.pad + plotW, H - 2)
    }
    // The writing head.
    const head = Math.round(p.pad + plotW) + 0.5
    ctx.strokeStyle = ink(c.hair3)
    ctx.beginPath()
    ctx.moveTo(head, 0)
    ctx.lineTo(head, H - rulerH)
    ctx.stroke()
    if (revealK < 1) {
      ctx.restore()
      const rx = p.pad + plotW * revealK
      ctx.strokeStyle = ink(c.t2)
      ctx.beginPath()
      ctx.moveTo(rx + 0.5, 0)
      ctx.lineTo(rx + 0.5, H)
      ctx.stroke()
    }
    // Playhead: the pointer, or a programmatic scrub; magnetic to event markers.
    let tx = scrub.current !== null ? x(scrub.current) : pointer.current
    const d = drawn.current
    if (tx !== null && tx !== undefined && tx >= p.pad && tx <= p.pad + plotW) {
      const snap = values.events ? snapToEvent(values.events, tx, tnow, geo) : null
      d.snapped = snap?.event || null
      if (snap) tx = snap.x
      d.hx = followPlayhead(d.hx, tx, dt, isFull)
      const hx = d.hx
      const t = tAt(hx, tnow, geo)
      ctx.strokeStyle = ink(c.t1, 0.5)
      ctx.beginPath()
      ctx.moveTo(Math.round(hx) + 0.5, 0)
      ctx.lineTo(Math.round(hx) + 0.5, H - rulerH + 6)
      ctx.stroke()
      const rows = []
      for (const ln of lanesList) {
        const fn = values[ln.key]
        if (!fn || !['line', 'bars', 'step'].includes(ln.type)) continue
        const r = fn(t)
        if (!r) continue
        rows.push([ln.readoutLabel || ln.label, ln.format ? ln.format(r.v) : String(r.v), ln.color])
        if (r.y !== undefined) {
          ctx.fillStyle = ink(c[ln.color] || c.t1)
          ctx.strokeStyle = ink(c.canvas)
          ctx.lineWidth = 1.5
          ctx.beginPath()
          ctx.arc(x(r.t), r.y, 3, 0, Math.PI * 2)
          ctx.fill()
          ctx.stroke()
          ctx.lineWidth = 1
        }
      }
      if (values.hb) {
        const iv = values.hb(t)
        if (iv) rows.push([p.labels.hbInterval || 'hb interval', `${(iv / 1000).toFixed(2)} s`, null])
      }
      writeReadout(readoutRef.current, d, { t, tnow, rows, event: d.snapped, hx, width: w, locale: p.locale, eventLabel: p.eventLabel })
    } else {
      d.snapped = null
      d.hx = null
      if (readoutRef.current && d.key) {
        readoutRef.current.classList.remove('is-on')
        d.key = ''
      }
    }
  }, [])

  const { ref: canvasRef, redraw } = useCanvas(draw)

  // Paint again with new tokens when the theme changes.
  useEffect(
    () =>
      onThemeChange(() => {
        inks.current = null
        redraw()
      }),
    [redraw],
  )

  // Draw only while the trace is on screen.
  useEffect(() => {
    const el = hostRef.current
    if (!el || typeof IntersectionObserver === 'undefined') return undefined
    const io = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting))
    io.observe(el)
    return () => io.disconnect()
  }, [])

  const running = useAnimationLoop(() => redraw(), { enabled: visible })

  // A new window animates at full motion, else applies at once.
  useEffect(() => {
    const wa = win.current
    if (wa.to === windowMs) return
    if (full) Object.assign(wa, { from: wa.cur, to: windowMs, t0: performance.now() })
    else Object.assign(wa, { from: windowMs, to: windowMs, t0: 0, cur: windowMs })
    if (!running) redraw()
  }, [windowMs, full, running, redraw])

  // Below full: redraw on every data change (the paper jumps a sample at a time).
  useEffect(() => {
    if (!running) redraw()
  }, [lanes, level, running, redraw, clockOffset])

  useImperativeHandle(
    ref,
    () => ({
      // Holds the playhead at an instant (rewind), until release().
      scrubTo(t) {
        scrub.current = t
        if (!running) redraw()
      },
      release() {
        scrub.current = null
        drawn.current.hx = null
        if (!running) redraw()
      },
      redraw,
    }),
    [running, redraw],
  )

  const onMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect()
    pointer.current = e.clientX - r.left
    if (!running) redraw()
  }
  const onLeave = () => {
    pointer.current = null
    if (!running) redraw()
  }

  return (
    <div
      ref={hostRef}
      className={cn('fx-trace', className)}
      data-testid={testId}
      data-window={windowMs}
      data-running={running ? 'true' : 'false'}
      role={ariaLabel ? 'img' : undefined}
      aria-label={ariaLabel}
      onPointerMove={onMove}
      onPointerLeave={onLeave}
    >
      <canvas ref={canvasRef} data-testid={`${testId}-canvas`} aria-hidden="true" />
      {readout && <div ref={readoutRef} className="fx-trace-readout" data-testid={`${testId}-readout`} aria-hidden="true" />}
      {children}
    </div>
  )
})

// The playhead readout: rebuilt only when its text changes, positioned by transform.
function writeReadout(el, d, { t, tnow, rows, event, hx, width, locale, eventLabel }) {
  if (!el) return
  const date = new Date(t)
  const time = `${date.toLocaleTimeString(locale || undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}.${Math.floor(date.getMilliseconds() / 100)}`
  const ago = `-${((tnow - t) / 1000).toFixed(1)} s`
  const evText = event ? (eventLabel ? eventLabel(event) : event.kind) : ''
  const key = [time, ago, ...rows.map((r) => r.join('|')), evText].join('\n')
  if (key !== d.key) {
    d.key = key
    el.replaceChildren()
    const head = document.createElement('div')
    head.className = 'fx-trace-readout-time'
    head.textContent = `${time} `
    const sub = document.createElement('span')
    sub.textContent = ago
    head.appendChild(sub)
    el.appendChild(head)
    for (const [label, value, color] of rows) {
      const row = document.createElement('div')
      row.className = 'fx-trace-readout-row'
      if (color) row.dataset.ink = color
      const l = document.createElement('span')
      l.textContent = label
      const v = document.createElement('b')
      v.textContent = value
      row.append(l, v)
      el.appendChild(row)
    }
    if (evText) {
      const ev = document.createElement('div')
      ev.className = 'fx-trace-readout-event'
      ev.textContent = evText
      el.appendChild(ev)
    }
    // Width from the mono advance (0.6 em at 10.5 px), so no frame reads layout.
    const chars = Math.max(`${time} ${ago}`.length, ...rows.map(([l, v]) => l.length + v.length + 2), Math.min(36, evText.length))
    d.rw = Math.min(236, Math.max(150, chars * 6.3 + 18))
  }
  const rw = d.rw || 160
  const left = hx + 12 + rw > width ? hx - 12 - rw : hx + 12
  el.style.transform = `translateX(${Math.max(0, left).toFixed(1)}px)`
  el.classList.add('is-on')
}
