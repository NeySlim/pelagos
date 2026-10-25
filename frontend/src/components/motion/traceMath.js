// SPDX-License-Identifier: Apache-2.0
// Pure geometry behind the canvas traces: time to x on a window that ends at `now`,
// step levels for serials, the value of a step series at an instant, ruler ticks,
// magnetic snapping to markers and threshold crossings.

export const MAGNET_PX = 7

// x of instant `t` on a window of `windowMs` ending at `end`, drawn over [left, right].
export function timeToX(t, end, windowMs, left, right) {
  return right - ((end - t) / windowMs) * (right - left)
}

export function xToTime(x, end, windowMs, left, right) {
  return end - ((right - x) / (right - left)) * windowMs
}

// Value of a step series (points sorted by time) at instant t; undefined before the first.
export function valueAt(points, t) {
  let out
  for (const [pt, v] of points) {
    if (pt > t) break
    out = v
  }
  return out
}

// Distinct values of every lane in the window, sorted: a serial's rank is its step height,
// so a lagging node sits visibly lower than the one it follows.
export function stepLevels(lanes, from) {
  const values = new Set()
  for (const lane of lanes) {
    const before = valueAt(lane.points, from)
    if (before !== undefined && before !== null) values.add(Number(before))
    for (const [t, v] of lane.points) if (t >= from && v !== null && v !== undefined) values.add(Number(v))
  }
  return [...values].sort((a, b) => a - b)
}

// Share of a lane's height for `value`: 0 for the lowest level, 1 for the highest.
export function levelOf(levels, value) {
  if (levels.length < 2) return 0.5
  const i = levels.indexOf(Number(value))
  return i < 0 ? 0.5 : i / (levels.length - 1)
}

// Ruler ticks for a window: a step that leaves about 6 ticks, in round seconds.
const STEPS = [2000, 5000, 10000, 15000, 30000, 60000, 120000, 300000, 600000, 1800000, 3600000]
export function rulerStep(windowMs, count = 6) {
  return STEPS.find((s) => windowMs / s <= count) || STEPS[STEPS.length - 1]
}

export function rulerTicks(end, windowMs, count = 6) {
  const step = rulerStep(windowMs, count)
  const out = []
  for (let ago = 0; ago <= windowMs + 1; ago += step) out.push({ t: end - ago, ago })
  return out
}

// Marker within MAGNET_PX of x, the nearest one, or null.
export function snapMarker(markers, x, toX) {
  let best = null
  let bestDist = MAGNET_PX + 1e-9
  for (const m of markers) {
    const d = Math.abs(toX(m.t) - x)
    if (d <= bestDist) {
      best = m
      bestDist = d
    }
  }
  return best
}

// First instant a linear series crosses `threshold` upward at or after `after`, by linear
// interpolation between samples; null when it never does.
export function crossingTime(points, threshold, after = -Infinity) {
  for (let i = 1; i < points.length; i += 1) {
    const [t0, v0] = points[i - 1]
    const [t1, v1] = points[i]
    if (t1 < after) continue
    if (v0 < threshold && v1 >= threshold) return t0 + ((threshold - v0) / (v1 - v0)) * (t1 - t0)
  }
  return null
}

// Points clipped to [from, to] with the last sample before `from` kept, so lines start at the edge.
export function clipPoints(points, from, to) {
  const out = []
  let before = null
  for (const p of points) {
    if (p[0] < from) before = p
    else if (p[0] <= to) out.push(p)
  }
  return before ? [before, ...out] : out
}
