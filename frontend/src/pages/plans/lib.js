// SPDX-License-Identifier: Apache-2.0
// Plans page helpers: filters <-> query and the rollback window of a listed plan.

export const FILTER_KEYS = ['state', 'user']
// An expired plan is dropped by the node, so the list never holds one.
export const STATES = ['validated', 'applying', 'applied', 'failed', 'rolled_back']

// The browser clock may lag the node's: the button goes away this long before rollback_until
// (the server answers 410 for the rest).
export const SKEW_MARGIN_MS = 30000

export function filtersFromParams(params) {
  return Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) || '']))
}

// Without read:audit the node lists your own plans only: the user filter is not sent.
export function toQuery(filters, { canSeeAll = true } = {}) {
  return Object.fromEntries(FILTER_KEYS.filter((k) => filters[k] && (k !== 'user' || canSeeAll)).map((k) => [k, filters[k]]))
}

// rollback_until alone says whether a plan can be rolled back (an interrupted FAILED plan has
// one too). 'open' while it is ahead, 'closed' once it passed, 'none' when it is null.
export function rollbackWindow(plan, now = Date.now()) {
  if (!plan?.rollback_until) return { status: 'none', leftMs: 0 }
  const leftMs = Date.parse(plan.rollback_until) - now
  return leftMs > SKEW_MARGIN_MS ? { status: 'open', leftMs } : { status: 'closed', leftMs: 0 }
}

// A plan the viewer may roll back: its creator or an admin (the server also checks the scope).
export function ownsPlan(plan, user, isAdmin) {
  return Boolean(isAdmin) || (Boolean(user?.username) && plan?.created_by === user.username)
}

const EN_UNITS = { d: '{{n}}d', h: '{{n}}h', m: '{{n}}m', s: '{{n}}s' }

// 2d 3h, 23h 59m, 4m 12s, 9s; `unit(key, n)` renders one number with its translated unit.
export function formatLeft(ms, unit = (key, n) => EN_UNITS[key].replace('{{n}}', n)) {
  const total = Math.max(0, Math.floor(ms / 1000))
  const d = Math.floor(total / 86400)
  const h = Math.floor((total % 86400) / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (d > 0) return `${unit('d', d)} ${unit('h', h)}`
  if (h > 0) return `${unit('h', h)} ${unit('m', m)}`
  if (m > 0) return `${unit('m', m)} ${unit('s', s)}`
  return unit('s', s)
}
