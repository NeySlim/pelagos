// SPDX-License-Identifier: Apache-2.0
// Pure geometry and measures behind the cluster trace: time to x on the paper, the
// animated window, the smoothed Y scale, the time ruler and scale bar, the magnetic
// playhead, heartbeat instants measured from Kea partner ages, and the events lane.
import { easeInOut } from './motion'

export const TRACE_WINDOWS = [30000, 90000, 300000]
export const DEFAULT_WINDOW = 90000
export const ZOOM_MS = 400
export const SCALE_TAU_MS = 220
export const SNAP_PX = 7
export const PLAYHEAD_TAU_MS = 40
export const REVEAL_MS = 600
export const MAX_BEATS = 120

const clamp = (v, a, b) => Math.min(b, Math.max(a, v))

// x on the canvas of an instant: the right edge of the plot is `now`, the left edge
// `now - win`. tAt is its inverse.
export function xAt(t, now, { pad, plotW, win }) {
  return pad + plotW * (1 - (now - t) / win)
}

export function tAt(x, now, { pad, plotW, win }) {
  return now - (1 - (x - pad) / plotW) * win
}

// Window shown at `pt` while a zoom runs from `from` to `to` (started at `t0`, 400 ms
// ease-in-out). Returns { win, done }.
export function windowAt({ from, to, t0 }, pt, duration = ZOOM_MS) {
  if (!t0 || from === to) return { win: to, done: true }
  const k = easeInOut((pt - t0) / duration)
  return { win: from + (to - from) * k, done: k >= 1 }
}

// Exponential approach of a scale towards its target (time constant `tau`), so a burst
// dilates the lane instead of snapping it. `undefined` starts at the target.
export function smoothTowards(current, target, dt, tau = SCALE_TAU_MS) {
  if (current === undefined || current === null || !Number.isFinite(current)) return target
  return current + (target - current) * (1 - Math.exp(-dt / tau))
}

// Maximum of a lane: 15 % of headroom over the largest visible value, 1 when empty.
export function laneMax(samples) {
  let max = 0
  for (const s of samples) if (s.v > max) max = s.v
  return max > 0 ? max * 1.15 : 1
}

// Index of the first sample to draw: the one just before `tmin`, so the line enters
// from the left edge. Samples are sorted by time.
export function visibleFrom(samples, tmin) {
  let i = samples.length - 1
  while (i > 0 && samples[i].t > tmin) i -= 1
  return Math.max(0, i)
}

// Sample nearest to `t` (binary search on sorted samples), or null.
export function nearestSample(samples, t) {
  if (!samples?.length) return null
  let lo = 0
  let hi = samples.length - 1
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1
    if (samples[mid].t < t) lo = mid
    else hi = mid
  }
  return Math.abs(samples[lo].t - t) <= Math.abs(samples[hi].t - t) ? samples[lo] : samples[hi]
}

// The playhead is magnetic: within `px` pixels of an event marker it sticks to it.
// Returns { event, x } for the nearest marker in reach, else null.
export function snapToEvent(events, x, now, geo, px = SNAP_PX) {
  let best = null
  for (const e of events || []) {
    const ex = xAt(e.t, now, geo)
    const d = Math.abs(ex - x)
    if (d < px && (!best || d < best.d)) best = { event: e, x: ex, d }
  }
  return best && { event: best.event, x: best.x }
}

// Exponential follow of the drawn playhead towards the pointer (40 ms), instant when
// there is nothing to follow from or below full motion.
export function followPlayhead(current, target, dt, animate = true) {
  if (current === null || current === undefined || !animate) return target
  return current + (target - current) * (1 - Math.exp(-dt / PLAYHEAD_TAU_MS))
}

// Tick sets of the time ruler, finest first. A set shows its ticks once they are 5 px
// apart and its labels once they are 48 px apart; a coarser set's labels fade out as the
// next finer one becomes readable, so the scale crossfades while the window animates.
export const RULER_STEPS = [1000, 2000, 5000, 10000, 30000, 60000, 300000, 600000, 900000, 1800000, 3600000]
const LABELLED = new Set([5000, 10000, 30000, 60000, 300000, 600000, 900000, 1800000, 3600000])

export function rulerLevels(plotW, win) {
  const spacing = (step) => (plotW * step) / win
  const labelAlpha = (step) => (LABELLED.has(step) ? clamp((spacing(step) - 48) / 36, 0, 1) : 0)
  const levels = []
  RULER_STEPS.forEach((step, i) => {
    const tick = clamp((spacing(step) - 5) / 8, 0, 1)
    if (tick <= 0) return
    // The finest readable labelled set wins; coarser ones fade under it.
    const finer = RULER_STEPS.slice(0, i).filter((s) => LABELLED.has(s))
    const finest = finer.length ? Math.max(...finer.map(labelAlpha)) : 0
    levels.push({ step, tick, label: labelAlpha(step) * (1 - finest), major: step >= 10000 })
  })
  return levels
}

// Ruler label of an age in ms: "-10 s", "-2 min", "-1 h".
export function rulerLabel(ageMs) {
  const s = Math.round(ageMs / 1000)
  if (s < 60 || s % 60) return `-${s} s`
  const m = s / 60
  if (m < 60 || m % 60) return `-${m} min`
  return `-${m / 60} h`
}

// Scale bar of the footer: a round span (10 s up to a 2 min window, 1 min up to 10 min,
// then 10 min) drawn over a 60 px reference, as a ratio of that reference.
export function scaleBar(win, plotW, reference = 60) {
  const span = win <= 120000 ? 10000 : win <= 600000 ? 60000 : 600000
  const px = plotW > 0 ? (plotW * span) / win : reference
  const label = span < 60000 ? `${span / 1000} s` : `${span / 60000} min`
  return { span, label, ratio: px / reference }
}

// Heartbeats measured from Kea status-get: the partner `age` (whole seconds since the last
// heartbeat answer) at `collectedAt` puts the beat in [collectedAt - (age + 1) s,
// collectedAt - age s]. Observations of the same beat narrow that interval; one that does
// not overlap the newest beat is a new beat. Beats are newest first: { t, lo, hi }.
export function observeBeat(beats, { collectedAt, age }, max = MAX_BEATS) {
  if (!Number.isFinite(collectedAt) || !Number.isFinite(age) || age < 0) return beats
  const lo = collectedAt - (age + 1) * 1000
  const hi = collectedAt - age * 1000
  const head = beats[0]
  if (head && lo <= head.hi && hi >= head.lo) {
    const nlo = Math.max(lo, head.lo)
    const nhi = Math.min(hi, head.hi)
    if (nlo === head.lo && nhi === head.hi) return beats
    return [{ ...head, t: (nlo + nhi) / 2, lo: nlo, hi: nhi }, ...beats.slice(1)]
  }
  // An observation older than the newest beat is a stale snapshot: nothing new.
  if (head && hi < head.lo) return beats
  return [{ t: (lo + hi) / 2, lo, hi }, ...beats].slice(0, max)
}

// Mean interval and jitter (standard deviation) of the last `n` heartbeat intervals,
// newest first. The span of an outage (ending on a beat marked `afterGap`) and gaps longer
// than twice the median (a lost partner) are not intervals.
export function beatStats(beats, n = 10) {
  const iv = []
  for (let i = 0; i < beats.length - 1 && iv.length < n; i += 1) if (!beats[i].afterGap) iv.push(beats[i].t - beats[i + 1].t)
  if (!iv.length) return null
  const median = [...iv].sort((a, b) => a - b)[Math.floor(iv.length / 2)]
  const kept = iv.filter((d) => d > 0 && d <= median * 2)
  if (!kept.length) return null
  const mean = kept.reduce((a, b) => a + b, 0) / kept.length
  const sd = Math.sqrt(kept.reduce((a, b) => a + (b - mean) ** 2, 0) / kept.length)
  return { mean, sd, count: kept.length }
}

// Jitter as the readout prints it: milliseconds up to a second, then seconds.
export function formatJitter(sd) {
  if (!Number.isFinite(sd)) return ''
  return sd < 1000 ? `±${Math.round(sd)} ms` : `±${(sd / 1000).toFixed(1)} s`
}

// Interval between the beat at or before `t` and the one before it (playhead readout).
export function beatIntervalAt(beats, t) {
  let i = 0
  while (i < beats.length && beats[i].t > t) i += 1
  const a = beats[i]
  const b = beats[i + 1]
  return a && b ? a.t - b.t : null
}

// Events lane: a WebSocket message as a trace event { t, kind, key, params }, or null.
// Kinds: plan, rb (rolled back), fail, alert (opened), ok (resolved), axfr (a zone that
// caught up: serial divergence resolved), repl (replication), ha (HA transition).
export function traceEventOf(message) {
  const { topic, event, data = {} } = message || {}
  const t = Date.parse(message?.ts || '') || Date.now()
  const id = data.id || data.plan_id || null
  if (topic === 'plans') {
    const kind = { applied: 'plan', rolled_back: 'rb', failed: 'fail' }[event]
    return kind ? { t, kind, key: `events.${kind}`, params: { plan: String(data.plan_id || '').slice(-6) }, id } : null
  }
  if (topic === 'alerts') {
    if (event === 'opened') return { t, kind: 'alert', key: 'events.alert', params: { kind: data.kind || '', subject: data.subject || '' }, id }
    if (event === 'resolved') {
      if (data.kind === 'serial_divergence') return { t, kind: 'axfr', key: 'events.axfr', params: { subject: data.subject || '' }, id }
      return { t, kind: 'ok', key: 'events.ok', params: { kind: data.kind || '', subject: data.subject || '' }, id }
    }
    return null
  }
  if (topic === 'system' && event === 'replication') return { t, kind: 'repl', key: 'events.repl', params: { version: data.version ?? data.config_version ?? '' }, id }
  if (topic === 'ha' && event === 'state') {
    return { t, kind: 'ha', key: 'events.ha', params: { server: data.server_name || '', state: data.state || '', family: data.family || '' }, id }
  }
  return null
}

// Adds an event to the lane (sorted by time), skipping a duplicate of the same kind and
// id at the same instant, keeping only what a 5 min window can show.
export function pushEvent(events, e, now = Date.now(), keepMs = 2 * TRACE_WINDOWS[TRACE_WINDOWS.length - 1]) {
  if (!e) return events
  if (events.some((x) => x.kind === e.kind && x.t === e.t && x.id === e.id)) return events
  return [...events.filter((x) => now - x.t <= keepMs), e].sort((a, b) => a.t - b.t)
}

// Pool pressure: a /series/pools series ([ts, assigned, total]) as percent samples.
export function poolPressure(points) {
  return (points || [])
    .filter((p) => Array.isArray(p) && p[2] > 0)
    .map(([ts, assigned, total]) => ({ t: ts * 1000, v: (assigned / total) * 100 }))
}

// Latches of a pool alert on its pressure trace: an open alert closes a red latch at the
// instant it opened; a resolved one leaves a hollow latch there and a green one at its end.
export function poolLatches(alerts, samples) {
  const valueAt = (t) => nearestSample(samples, t)?.v ?? null
  const out = []
  for (const a of alerts || []) {
    const opened = Date.parse(a.first_seen || '')
    if (!Number.isFinite(opened)) continue
    const resolved = Date.parse(a.resolved_at || '')
    out.push({ t: opened, v: valueAt(opened), state: Number.isFinite(resolved) ? 'held' : 'open', id: a.id })
    if (Number.isFinite(resolved)) out.push({ t: resolved, v: valueAt(resolved), state: 'released', id: a.id })
  }
  return out.sort((a, b) => a.t - b.t)
}

// Subject of the pool alerts: "<engine>:subnet:<id>:pool:<pool without spaces>".
export const poolSubject = (pool) => `${pool.engine}:subnet:${pool.subnet_id}:pool:${String(pool.pool || '').replace(/\s+/g, '')}`

export function alertForPool(alert, pool) {
  if (!alert || !pool || !['pool_near_full', 'pool_full'].includes(alert.kind)) return false
  return alert.subject === poolSubject(pool) && (!alert.node_id || !pool.node_id || alert.node_id === pool.node_id)
}

// The pool a pressure trace shows: the one of the latest pool alert, open or resolved
// within `windowMs`, so a resolution keeps its latches in view; else the hottest pool.
export function tracedPool(pools, openAlerts, resolved, now = Date.now(), windowMs = 3600000) {
  const moments = [
    ...(openAlerts || []).map((a) => ({ a, t: Date.parse(a.first_seen || '') || 0 })),
    ...(resolved || []).filter((a) => now - a.t <= windowMs).map((a) => ({ a, t: a.t })),
  ].sort((x, y) => y.t - x.t)
  for (const { a } of moments) {
    const pool = (pools || []).find((p) => alertForPool(a, p))
    if (pool) return pool
  }
  return pools?.[0] || null
}
