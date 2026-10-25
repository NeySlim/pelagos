// SPDX-License-Identifier: Apache-2.0
// Serial history of a zone per node for the serial trace: seeded once per session from
// GET /series/serials, then a step each time a zone status read shows a new serial, and a
// marker for each plan applied or rolled back from this tab. Kept for the session per
// zone and view, so leaving the zone and coming back keeps the trace.
import { useEffect, useMemo, useState } from 'react'
import { api } from '../../services/api'
import { onPlanEvent, planZone } from '../../lib/planEvents'

const cache = new Map()
const MAX_POINTS = 200

const keyOf = (zone, view) => `${view || ''}|${zone}`

function entryOf(zone, view) {
  const key = keyOf(zone, view)
  if (!cache.has(key)) cache.set(key, { lanes: new Map(), markers: [], seeded: false })
  return cache.get(key)
}

// Adds a sample to a lane: only a change of serial makes a step (samples stay sorted).
export function pushSample(points, t, serial) {
  if (serial === null || serial === undefined) return false
  const value = Number(serial)
  if (!Number.isFinite(value)) return false
  let i = points.length
  while (i > 0 && points[i - 1][0] > t) i -= 1
  const before = i > 0 ? points[i - 1][1] : undefined
  if (before === value) return false
  points.splice(i, 0, [t, value])
  // A later sample equal to the new value is now redundant.
  if (points[i + 1] && points[i + 1][1] === value) points.splice(i + 1, 1)
  if (points.length > MAX_POINTS) points.splice(0, points.length - MAX_POINTS)
  return true
}

// Series answer ({"series": [{"node_id", "points": [[ts, serial, divergent]]}]}) into lanes.
export function mergeSeries(entry, res) {
  let changed = false
  for (const s of res?.series || []) {
    if (!s?.node_id) continue
    if (!entry.lanes.has(s.node_id)) entry.lanes.set(s.node_id, [])
    const points = entry.lanes.get(s.node_id)
    for (const [ts, serial] of s.points || []) changed = pushSample(points, Number(ts) * 1000, serial) || changed
  }
  return changed
}

export function resetSerialHistory() {
  cache.clear()
}

export function useSerialHistory({ zone, view, status, windowMs = 300000 }) {
  const [version, setVersion] = useState(0)
  const bump = () => setVersion((v) => v + 1)
  const entry = zone ? entryOf(zone, view) : null

  useEffect(() => {
    if (!zone) return undefined
    const e = entryOf(zone, view)
    if (e.seeded) return undefined
    e.seeded = true
    const to = Date.now()
    // The cache outlives this effect (StrictMode runs it twice): the answer is merged anyway.
    api.series
      .serials({ zone, ...(view ? { view } : {}), from: new Date(to - windowMs * 2).toISOString(), to: new Date(to).toISOString() })
      .then((res) => {
        if (mergeSeries(e, res)) bump()
      })
      .catch(() => {
        // no read:series, or no history yet: the trace starts with the live samples
      })
    return undefined
  }, [zone, view, windowMs])

  useEffect(() => {
    if (!zone || !status) return
    const e = entryOf(zone, view)
    const now = Date.now()
    let changed = false
    for (const [id, s] of Object.entries(status)) {
      if (!e.lanes.has(id)) {
        e.lanes.set(id, [])
        changed = true
      }
      changed = pushSample(e.lanes.get(id), now, s?.serial) || changed
    }
    if (changed) bump()
  }, [zone, view, status])

  useEffect(() => {
    if (!zone) return undefined
    return onPlanEvent((event) => {
      if (planZone(event.plan) !== zone || !event.at) return
      if (event.type === 'applied') entryOf(zone, view).markers.push({ t: event.at, kind: 'plan', id: event.plan.id })
      else if (event.type === 'rolled-back' && event.result) entryOf(zone, view).markers.push({ t: event.at, kind: 'rollback', id: event.plan.id })
      else return
      bump()
    })
  }, [zone, view])

  return useMemo(
    () => ({
      lanes: entry ? [...entry.lanes].map(([id, points]) => ({ id, points: [...points] })) : [],
      markers: entry ? [...entry.markers] : [],
    }),
    [entry, version], // eslint-disable-line react-hooks/exhaustive-deps
  )
}
