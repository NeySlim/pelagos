// SPDX-License-Identifier: Apache-2.0
// Polls counter endpoints while the page is visible and turns them into rate series
// (lib/liveRates.js). Series live in a module store mirrored to sessionStorage, so leaving the
// dashboard and coming back, or reloading the tab, keeps the recent history.
import { useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import { LIVE_CAPACITY, LIVE_INTERVAL_MS, advance, dhcpCounters, dnsCounters, emptySource, prune, sampleTime } from '../lib/liveRates'

const STORAGE_KEY = 'pelagos-live-rates'
const MAX_AGE_MS = LIVE_CAPACITY * LIVE_INTERVAL_MS * 1.5

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

function save() {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(getStore()))
  } catch {
    // storage full or disabled: the series still live in memory
  }
}

// Forgets every series (sign-out, tests).
export function resetLiveRates() {
  store = {}
  try {
    sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // nothing stored
  }
}

export const dnsTarget = (id) => ({ key: `dns:${id}`, kind: 'dns', node: id, load: () => api.dns.stats(id), counters: dnsCounters })
export const dhcpTarget = (family, id) => ({
  key: `dhcp:${family}:${id}`, kind: 'dhcp', family, node: id, load: () => api.dhcp.stats(family, id), counters: (res) => dhcpCounters(res, family),
})

// Targets for the dashboard: BIND and Kea counters of every node that runs them.
export function liveTargets(nodes, { dns = true, dhcp = true } = {}) {
  const out = []
  for (const n of nodes || []) {
    if (n.status && n.status !== 'online') continue
    const id = n.peer?.id
    if (!id) continue
    const m = n.peer?.modules
    const has = (engine) => !m || m[engine] !== false
    if (dns && has('bind')) out.push(dnsTarget(id))
    for (const family of ['v4', 'v6']) {
      if (dhcp && has(family === 'v4' ? 'kea4' : 'kea6')) out.push(dhcpTarget(family, id))
    }
  }
  return out
}

async function sampleAll(targets) {
  const results = await Promise.allSettled(targets.map((tg) => Promise.resolve().then(tg.load)))
  const now = Date.now()
  const s = getStore()
  let changed = false
  results.forEach((r, i) => {
    if (r.status !== 'fulfilled') return
    const tg = targets[i]
    const counters = tg.counters(r.value)
    if (!counters) return
    s[tg.key] = advance(s[tg.key] || emptySource(), { t: sampleTime(r.value, now), counters })
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
