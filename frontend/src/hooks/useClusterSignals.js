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
const listeners = new Set()
const notify = () => listeners.forEach((fn) => fn())

export function resetClusterSignals() {
  beats = {}
  events = []
  versions = {}
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
  const outage = rec.outage && !rec.outage.to ? { ...rec.outage, to: at } : rec.outage
  const next = observeBeat(rec.beats, { collectedAt: at, age: h.partner.age })
  if (next === rec.beats && outage === rec.outage && rec.state === h.state && rec.unsent === base.unsent) return rec
  return { ...base, beats: next, outage }
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

// Events lane of the trace, fed by the WebSocket; `onEvent(e)` fires for each new one.
export function useTraceEvents(onEvent) {
  const version = useStore()
  const handle = useCallback(
    (message) => {
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
