// SPDX-License-Identifier: Apache-2.0
// Signals of the cluster trace beyond the counter rates. Heartbeats: the `ha` topic (every
// collector sends one `heartbeat` per server and family every few seconds, relayed to the
// other nodes), with GET /dhcp/{family}/ha as the fallback poll, slower while the socket is
// up; each server's heartbeat window places the last heartbeat (lib/trace observeBeat), an
// out-of-touch partner opens an outage and marks each sample that found it lost. Events:
// WebSocket alerts, plans, HA transitions, zone transfers and replication (a node whose
// config version rises). Both live in module stores, so leaving the dashboard and coming
// back keeps the recent history; sign-out clears them.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import { LIVE_INTERVAL_MS } from '../lib/liveRates'
import { observeBeat, pushEvent, traceEventOf } from '../lib/trace'
import { useWebSocket, useWsTopic } from './useWebSocket'
import { partnerLost } from '../lib/ha'

// Fallback polls run this many times slower while the WebSocket delivers the events.
export const LIVE_FALLBACK_FACTOR = 4

const LOST_KEEP = 60
const BAD_STATES = ['partner-down', 'terminated', 'unavailable']

let beats = {}
let events = []
let versions = {}
let haStates = {}
let zoneSerials = {}
let poolAlerts = { open: new Map(), resolved: [] }
const listeners = new Set()
const notify = () => listeners.forEach((fn) => fn())

export function resetClusterSignals() {
  beats = {}
  events = []
  versions = {}
  haStates = {}
  zoneSerials = {}
  poolAlerts = { open: new Map(), resolved: [] }
  notify()
}

// One HAState observation into the heartbeat record of its server ({ beats, lost, outage }).
export function observeHa(record, h) {
  const rec = record || { beats: [], lost: [], outage: null }
  const at = Date.parse(h?.collected_at || '')
  if (!h || h.enabled === false || !h.partner || !Number.isFinite(at)) return rec
  const lostPartner = partnerLost(h.partner) || BAD_STATES.includes(h.state)
  const base = { ...rec, state: h.state, partnerState: h.partner.state, unsent: h.unsent_update_count ?? null, inTouch: !lostPartner }
  if (lostPartner) {
    if (rec.lost.includes(at)) return rec
    return { ...base, lost: [at, ...rec.lost].slice(0, LOST_KEEP), outage: rec.outage && !rec.outage.to ? rec.outage : { from: at, to: null } }
  }
  const closing = Boolean(rec.outage && !rec.outage.to)
  const outage = closing ? { ...rec.outage, to: at } : rec.outage
  const lo = Date.parse(h.heartbeat?.lo || '')
  const hi = Date.parse(h.heartbeat?.hi || '')
  let next = observeBeat(rec.beats, { collectedAt: at, age: h.partner.age, lo, hi })
  // The first beat after an outage starts a new run: the interval across it is no heartbeat.
  let gapPending = Boolean(rec.gapPending || closing)
  const prepended = next !== rec.beats && next.length > 0 && rec.beats.length > 0 && next[1] === rec.beats[0]
  if (gapPending && prepended) {
    next = [{ ...next[0], afterGap: true }, ...next.slice(1)]
    gapPending = false
  }
  if (next === rec.beats && outage === rec.outage && rec.state === h.state && rec.unsent === base.unsent && gapPending === Boolean(rec.gapPending)) return rec
  return { ...base, beats: next, outage, gapPending }
}

function useStore() {
  const [version, setVersion] = useState(0)
  useEffect(() => {
    const fn = () => setVersion((v) => v + 1)
    listeners.add(fn)
    return () => listeners.delete(fn)
  }, [])
  return version
}

// One HAState (a poll row or an `ha` message) into the store; true when it changed.
export function recordHa(family, h) {
  if (!family || !h?.node_id) return false
  const key = `${family}:${h.node_id}`
  const next = observeHa(beats[key], h)
  if (next === beats[key]) return false
  beats = { ...beats, [key]: next }
  return true
}

// Poll period of a fallback: `ms`, or LIVE_FALLBACK_FACTOR times longer while the socket is up.
export function useFallbackMs(ms) {
  const { isConnected } = useWebSocket()
  return isConnected ? ms * LIVE_FALLBACK_FACTOR : ms
}

// { "<family>:<node_id>": record } for the given families, from the `ha` topic and a poll.
export function useHaHeartbeats(families, { enabled = true, interval = LIVE_INTERVAL_MS } = {}) {
  const version = useStore()
  const signature = (families || []).join(',')
  const period = useFallbackMs(interval)
  useWsTopic(enabled && signature ? 'ha' : null, (message) => {
    const h = message?.data
    const family = h?.family === 'v6' ? 'v6' : h?.family === 'v4' ? 'v4' : null
    if (!family || !signature.split(',').includes(family)) return
    if (recordHa(family, h)) notify()
  })
  useEffect(() => {
    if (!enabled || !signature) return undefined
    let alive = true
    let busy = false
    const tick = async () => {
      if (busy || document.visibilityState === 'hidden') return
      busy = true
      try {
        const results = await Promise.allSettled(signature.split(',').map((f) => Promise.resolve().then(() => api.dhcp.ha(f)).then((r) => [f, r?.items || []])))
        if (!alive) return
        let changed = false
        for (const r of results) {
          if (r.status !== 'fulfilled') continue
          const [family, items] = r.value
          for (const h of items) if (recordHa(family, h)) changed = true
        }
        if (changed) notify()
      } finally {
        busy = false
      }
    }
    tick()
    const id = setInterval(tick, period)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [signature, enabled, period])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => beats, [version])
}

export function addTraceEvent(e) {
  // A transfer is seen twice (the `zones` event and the summary refresh): one mark.
  if (e?.kind === 'axfr' && e.id && events.some((x) => x.kind === 'axfr' && x.id === e.id)) return
  const next = pushEvent(events, e)
  if (next !== events) {
    events = next
    notify()
  }
}

// Replication: a node whose config version rises is a replicated change. The first
// sighting only records the version.
export function observeNodeVersion(node) {
  const id = node?.peer?.id
  const v = node?.config_version
  if (!id || typeof v !== 'number') return null
  const before = versions[id]
  versions = { ...versions, [id]: v }
  if (typeof before === 'number' && v > before) {
    const e = { t: Date.now(), kind: 'repl', key: 'events.repl', params: { version: v, node: node.peer.name || '' }, id: `${id}:${v}`, node: id }
    addTraceEvent(e)
    return e
  }
  return null
}

// Zone transfers, from the summary refresh: a zone whose nodes all reach a serial that
// one of them did not hold at the previous refresh caught up through a transfer. The
// first sighting only records the serials. Returns the new events.
export function observeZoneSerials(zones, now = Date.now()) {
  if (!Array.isArray(zones)) return []
  const out = []
  const next = {}
  for (const z of zones || []) {
    const key = `${z.view || '_default'}|${z.zone}`
    const values = Object.values(z.serials || {}).filter((v) => typeof v === 'number')
    next[key] = z.serials || {}
    const before = zoneSerials[key]
    if (!before || values.length < 2) continue
    const serial = Math.max(...values)
    const inSync = values.every((v) => v === serial)
    const caughtUp = Object.keys(z.serials).filter((id) => typeof before[id] === 'number' && before[id] < serial)
    if (inSync && caughtUp.length) {
      const subject = String(z.zone).replace(/\.$/, '')
      // `nodes`: the copies that caught up, each the end of one transfer from the primary.
      const e = { t: now, kind: 'axfr', key: 'events.axfr', params: { subject, serial }, id: `${key}:${serial}`, nodes: caughtUp }
      addTraceEvent(e)
      out.push(e)
    }
  }
  zoneSerials = next
  return out
}

// Pool alerts seen open on the dashboard; one that leaves the open list resolved then. The
// resolved ones stay for `keepMs`, whatever pool the pressure trace shows meanwhile.
// Returns true when the store changed.
export function observePoolAlerts(openAlerts, now = Date.now(), keepMs = 3600000) {
  if (!Array.isArray(openAlerts)) return false
  const mine = openAlerts.filter((a) => ['pool_near_full', 'pool_full'].includes(a?.kind))
  const ids = new Set(mine.map((a) => a.id))
  let changed = false
  const open = new Map(poolAlerts.open)
  const resolved = poolAlerts.resolved.filter((a) => now - a.t <= keepMs)
  if (resolved.length !== poolAlerts.resolved.length) changed = true
  for (const [id, a] of poolAlerts.open) {
    if (ids.has(id)) continue
    open.delete(id)
    resolved.push({ ...a, t: now, resolved_at: a.resolved_at || new Date(now).toISOString() })
    changed = true
  }
  for (const a of mine) {
    if (!open.has(a.id)) changed = true
    open.set(a.id, a)
  }
  if (changed) poolAlerts = { open, resolved }
  return changed
}

export const poolAlertsSeen = () => poolAlerts

// An ha/state message is a transition only when the server's state differs from the last
// one seen for it; a repeat (an unsent counter that grew) is no event.
export function isHaTransition(message) {
  if (message?.topic !== 'ha' || message.event !== 'state') return true
  const d = message.data || {}
  const key = `${d.server_name || d.node_id || ''}|${d.family || ''}`
  const state = `${d.state || ''}|${partnerLost(d.partner) ? 'lost' : ''}`
  if (haStates[key] === state) return false
  haStates = { ...haStates, [key]: state }
  return true
}

// Events lane of the trace, fed by the WebSocket; `onEvent(e)` fires for each new one.
export function useTraceEvents(onEvent) {
  const version = useStore()
  const handle = useCallback(
    (message) => {
      if (!isHaTransition(message)) return
      const e = traceEventOf(message)
      if (e) {
        addTraceEvent(e)
        onEvent?.(e, message)
      }
    },
    [onEvent],
  )
  const onNode = useCallback(
    (message) => {
      const e = observeNodeVersion(message?.data)
      if (e) onEvent?.(e, message)
    },
    [onEvent],
  )
  useWsTopic('alerts', handle)
  useWsTopic('plans', handle)
  useWsTopic('ha', handle)
  useWsTopic('zones', handle)
  useWsTopic('system', handle)
  useWsTopic('nodes', onNode)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => events, [version])
}
