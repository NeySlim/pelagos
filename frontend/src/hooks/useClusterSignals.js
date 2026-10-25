// SPDX-License-Identifier: Apache-2.0
// Signals of the cluster trace beyond the counter rates. Heartbeats: GET /dhcp/{family}/ha
// polled at the live cadence; each server's partner `age` places the last heartbeat
// (lib/trace observeBeat), an out-of-touch partner opens an outage and marks each poll
// that found it lost. Events: WebSocket alerts, plans, HA transitions and replication
// (a node whose config version rises). Both live in module stores, so leaving the
// dashboard and coming back keeps the recent history; sign-out clears them.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import { LIVE_INTERVAL_MS } from '../lib/liveRates'
import { observeBeat, pushEvent, traceEventOf } from '../lib/trace'
import { useWsTopic } from './useWebSocket'

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
  const lostPartner = h.partner.in_touch === false || BAD_STATES.includes(h.state)
  const base = { ...rec, state: h.state, partnerState: h.partner.state, unsent: h.unsent_update_count ?? null, inTouch: !lostPartner }
  if (lostPartner) {
    if (rec.lost.includes(at)) return rec
    return { ...base, lost: [at, ...rec.lost].slice(0, LOST_KEEP), outage: rec.outage && !rec.outage.to ? rec.outage : { from: at, to: null } }
  }
  const closing = Boolean(rec.outage && !rec.outage.to)
  const outage = closing ? { ...rec.outage, to: at } : rec.outage
  let next = observeBeat(rec.beats, { collectedAt: at, age: h.partner.age })
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

// { "<family>:<node_id>": record } for the given families, polled while visible.
export function useHaHeartbeats(families, { enabled = true, interval = LIVE_INTERVAL_MS } = {}) {
  const version = useStore()
  const signature = (families || []).join(',')
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
          for (const h of items) {
            const key = `${family}:${h.node_id}`
            const next = observeHa(beats[key], h)
            if (next !== beats[key]) {
              beats = { ...beats, [key]: next }
              changed = true
            }
          }
        }
        if (changed) notify()
      } finally {
        busy = false
      }
    }
    tick()
    const id = setInterval(tick, interval)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [signature, enabled, interval])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => beats, [version])
}

export function addTraceEvent(e) {
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
    const e = { t: Date.now(), kind: 'repl', key: 'events.repl', params: { version: v, node: node.peer.name || '' }, id: `${id}:${v}` }
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
    const caughtUp = Object.keys(z.serials).some((id) => typeof before[id] === 'number' && before[id] < serial)
    if (inSync && caughtUp) {
      const subject = String(z.zone).replace(/\.$/, '')
      const e = { t: now, kind: 'axfr', key: 'events.axfr', params: { subject, serial }, id: `${key}:${serial}` }
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
  const state = `${d.state || ''}|${d.partner?.in_touch === false ? 'lost' : ''}`
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
  useWsTopic('system', handle)
  useWsTopic('nodes', onNode)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => events, [version])
}
