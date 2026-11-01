// SPDX-License-Identifier: Apache-2.0
// Plans page helpers: filters <-> query and the rollback window of a listed plan.

export const FILTER_KEYS = ['state', 'user']
export const STATES = ['validated', 'applying', 'applied', 'failed', 'rolled_back', 'expired']

export function filtersFromParams(params) {
  return Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) || '']))
}

export function toQuery(filters) {
  return Object.fromEntries(FILTER_KEYS.filter((k) => filters[k]).map((k) => [k, filters[k]]))
}

// 'open' while a rollback can still be asked, 'closed' once the window passed, 'none' when the
// plan was never rollable (not applied, or a scope without rollback: rollback_until is null).
export function rollbackWindow(plan, now = Date.now()) {
  if (plan?.state !== 'applied' || !plan.rollback_until) return { status: 'none', leftMs: 0 }
  const leftMs = Date.parse(plan.rollback_until) - now
  return leftMs > 0 ? { status: 'open', leftMs } : { status: 'closed', leftMs: 0 }
}

// 23h 59m, 4m 12s, 9s.
export function formatLeft(ms) {
  const total = Math.max(0, Math.floor(ms / 1000))
  const d = Math.floor(total / 86400)
  const h = Math.floor((total % 86400) / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}
