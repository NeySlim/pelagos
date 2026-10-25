// SPDX-License-Identifier: Apache-2.0
// Plan lifecycle inside this tab, for views that draw it (the zone serial trace): applied,
// rollback started, rolled back. The server's own outcome still comes on the `plans` topic;
// this only says what the operator just did here, with the instants measured here.
// The last apply of each plan is kept so a reopened plan shows the rail it ran.

const listeners = new Set()
const applies = new Map() // plan id -> { at, steps, result }
const MAX_KEPT = 20

export function onPlanEvent(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

// event: { type: 'applied' | 'rollback-start' | 'rolled-back', plan, at, result? }
export function emitPlanEvent(event) {
  for (const fn of [...listeners]) {
    try {
      fn(event)
    } catch (err) {
      console.error('plan event', err)
    }
  }
}

export function rememberApply(planId, record) {
  applies.delete(planId)
  applies.set(planId, record)
  while (applies.size > MAX_KEPT) applies.delete(applies.keys().next().value)
}

export function recalledApply(planId) {
  return applies.get(planId) || null
}

// Zone a plan writes to, from its first change target ("example.lan./www/A"), or null.
export function planZone(plan) {
  if (!plan || !String(plan.scope || '').startsWith('dns.')) return null
  const target = plan.changes?.[0]?.target
  if (!target) return null
  const zone = String(target).split('/')[0]
  return zone ? (zone.endsWith('.') ? zone : `${zone}.`) : null
}
