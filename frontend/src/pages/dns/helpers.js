// SPDX-License-Identifier: Apache-2.0
// Non-visual helpers shared by the DNS screens: node names, zone links, lag
// detection, the resynchronize action and the "build a plan, then review it" flow.
import { createElement, useCallback, useState } from 'react'
import { PlanPreviewModal } from '../../components/PlanPreview'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'

// Node id -> { name, is_self, status }, from GET /nodes; ids stay readable if it fails.
export function useNodeNames() {
  const { data } = useApi(() => api.nodes.list().catch(() => ({ items: [] })), [])
  const nodes = data?.items || []
  const byId = Object.fromEntries(nodes.map((n) => [n.peer.id, { name: n.peer.name, is_self: n.is_self, status: n.status }]))
  const nameOf = (id) => byId[id]?.name || (id ? String(id).slice(-6) : '')
  return { nodes, byId, nameOf }
}

export const stripDot = (name) => String(name || '').replace(/\.$/, '')

// Zone path for the router: no trailing dot, the view as ?view= when not the default.
export function zoneHref(zone, view) {
  const base = `/dns/zones/${encodeURIComponent(stripDot(zone))}`
  return view && view !== '_default' ? `${base}?view=${encodeURIComponent(view)}` : base
}

// Highest serial wins; a node below it, or without an answer, lags.
export function laggingNodes(serials = {}) {
  const values = Object.values(serials).filter((v) => v !== null && v !== undefined)
  if (!values.length) return []
  const max = Math.max(...values)
  return Object.entries(serials)
    .filter(([, v]) => v === null || v === undefined || v < max)
    .map(([id]) => id)
}

// Maps fn over items with at most `limit` calls in flight; keeps the input order.
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i], i)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

export const SECONDARY_KINDS = ['secondary', 'mirror', 'stub']

export const RESOLVER_KEYS = ['recursion', 'allow_recursion', 'forwarders', 'forward', 'dnssec_validation']

export const sameValue = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null)

// Only the keys that differ go into the POST /dns/resolver/plan body.
export function resolverChanges(current, next) {
  const out = {}
  for (const key of RESOLVER_KEYS) if (!sameValue(current?.[key], next[key])) out[key] = next[key]
  return out
}

// Resynchronize (design section 4): rndc retransfer on lagging secondaries,
// rndc notify from the primary. Returns the command outputs.
export async function resynchronizeZone({ zone, kind, view, serials }, dnsApi = api.dns) {
  const name = stripDot(zone)
  const v = view && view !== '_default' ? view : undefined
  const outputs = []
  if (SECONDARY_KINDS.includes(kind)) {
    const lag = laggingNodes(serials)
    const targets = lag.length ? lag : Object.keys(serials || {})
    for (const nodeId of targets) {
      const res = await dnsApi.retransfer(name, nodeId, v)
      outputs.push(res?.output)
    }
  } else {
    const res = await dnsApi.notify(name, v ? { view: v } : {})
    outputs.push(res?.output)
  }
  return outputs.filter(Boolean)
}

// Build a plan with `build()`, show it in PlanPreviewModal, call `onDone` after apply or rollback.
export function usePlanFlow({ onDone, onError, onClose } = {}) {
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const run = useCallback(
    async (build) => {
      setBusy(true)
      try {
        const p = await build()
        setPlan(p)
        return p
      } catch (err) {
        onError?.(errorMessage(err), err)
        return null
      } finally {
        setBusy(false)
      }
    },
    [onError],
  )
  const close = useCallback(() => {
    setPlan(null)
    onClose?.()
  }, [onClose])
  const modal = createElement(PlanPreviewModal, { open: Boolean(plan), plan, onClose: close, onApplied: onDone, onRolledBack: onDone })
  return { run, busy, modal, plan, close }
}
