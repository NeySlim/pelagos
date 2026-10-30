// SPDX-License-Identifier: Apache-2.0
// Polls counter endpoints while the page is visible and turns them into rate series
// (lib/liveRates.js). Series live in a module store mirrored to sessionStorage, so leaving the
// dashboard and coming back, or reloading the tab, keeps the recent history.
import { useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import { LIVE_HISTORY, LIVE_INTERVAL_MS, advance, dhcpCounters, dnsCounters, emptySource, prune, sampleTime } from '../lib/liveRates'

const STORAGE_KEY = 'pelagos-live-rates'
const MAX_AGE_MS = LIVE_HISTORY * LIVE_INTERVAL_MS * 1.5

function load() {
  try {
    const raw = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}')
    const now = Date.now()
    return Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, prune(v, now, MAX_AGE_MS)]))
  } catch {
    return {}
  }
}

let store = null
const getStore = () => (store ??= load())
// Keys with a request in flight, shared by every poller; a reset bumps the generation so
// answers requested before it are dropped.
const inFlight = new Set()
let generation = 0

function save() {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(getStore()))
  } catch {
    // storage full or disabled: the series still live in memory
  }
}

// Forgets every series: called when the session ends (sign-out, expiry) and by tests.
export function resetLiveRates() {
  store = {}
  generation += 1
  inFlight.clear()
  pending.forEach((c) => c.abort())
  try {
    sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // nothing stored
  }
}

export const dnsTarget = (id) => ({ key: `dns:${id}`, kind: 'dns', node: id, load: (options) => api.dns.stats(id, options), counters: dnsCounters })
export const dhcpTarget = (family, id) => ({
  key: `dhcp:${family}:${id}`, kind: 'dhcp', family, node: id, load: (options) => api.dhcp.stats(family, id, options), counters: (res) => dhcpCounters(res, family),
})

// Targets for the dashboard: BIND and Kea counters of every node that runs them. Kea6
// also needs the cluster module dhcpv6, which the backend requires on /dhcp/v6.
export function liveTargets(nodes, { dns = true, dhcp = true, dhcpv6 = true } = {}) {
  const out = []
  for (const n of nodes || []) {
    if (n.status && n.status !== 'online') continue
    const id = n.peer?.id
    if (!id) continue
    const m = n.peer?.modules
    const has = (engine) => !m || m[engine] !== false
    if (dns && has('bind')) out.push(dnsTarget(id))
    for (const family of ['v4', 'v6']) {
      if (family === 'v6' && !dhcpv6) continue
      if (dhcp && has(family === 'v4' ? 'kea4' : 'kea6')) out.push(dhcpTarget(family, id))
    }
  }
  return out
}

// A request that never answers is aborted at the deadline: the series must not stop at one point,
// and a hung request must not keep one of the browser's few connections to the origin.
const SAMPLE_DEADLINE_MS = LIVE_INTERVAL_MS * 3
const pending = new Set()
function sample(tg, ms) {
  const controller = new AbortController()
  pending.add(controller)
  const timer = setTimeout(() => controller.abort(), ms)
  const aborted = new Promise((_, reject) => {
    controller.signal.addEventListener('abort', () => reject(new DOMException('live sample timed out', 'AbortError')))
  })
  return Promise.race([Promise.resolve().then(() => tg.load({ signal: controller.signal })), aborted]).finally(() => {
    clearTimeout(timer)
    pending.delete(controller)
  })
}

async function sampleAll(all) {
  const targets = all.filter((tg) => !inFlight.has(tg.key))
  if (targets.length === 0) return false
  const gen = generation
  targets.forEach((tg) => inFlight.add(tg.key))
  let results
  try {
    // A rejected sample (aborted, failed) is skipped: the next interval tries again.
    results = await Promise.allSettled(targets.map((tg) => sample(tg, SAMPLE_DEADLINE_MS)))
  } finally {
    if (gen === generation) targets.forEach((tg) => inFlight.delete(tg.key))
  }
  if (gen !== generation) return false
  const now = Date.now()
  const s = getStore()
  let changed = false
  results.forEach((r, i) => {
    if (r.status !== 'fulfilled') return
    const tg = targets[i]
    const counters = tg.counters(r.value)
    if (!counters) return
    const next = advance(s[tg.key] || emptySource(), { t: sampleTime(r.value, now), counters }, LIVE_HISTORY)
    if (next === s[tg.key]) return
    s[tg.key] = next
    changed = true
  })
  if (changed) save()
  return changed
}

// Returns { [key]: source } for the given targets, refreshed every LIVE_INTERVAL_MS.
export function useLiveRates(targets, { interval = LIVE_INTERVAL_MS } = {}) {
  const signature = (targets || []).map((t) => t.key).join('|')
  const [version, setVersion] = useState(0)
  useEffect(() => {
    if (!targets?.length) return undefined
    let alive = true
    let busy = false
    const tick = async () => {
      if (busy || (typeof document !== 'undefined' && document.visibilityState === 'hidden')) return
      busy = true
      try {
        if ((await sampleAll(targets)) && alive) setVersion((v) => v + 1)
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
    // The signature stands for the targets: their loaders are rebuilt on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature, interval])
  return useMemo(() => {
    const s = getStore()
    return Object.fromEntries((targets || []).map((t) => [t.key, s[t.key] || emptySource()]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature, version])
}
