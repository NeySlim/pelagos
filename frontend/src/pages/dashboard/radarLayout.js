// SPDX-License-Identifier: Apache-2.0
// Geometry and state mapping of the cluster radar. The disc is a circle on the ground,
// seen from above at an angle: a floor point (x, y) in [-1, 1] lands on screen at
// (cx + x * r, cy + y * r * squash). Positive y is the front of the disc.

export const RADAR_SQUASH = 0.4
export const NODE_RADIUS = 0.62

const NORMAL_HA = ['hot-standby', 'load-balancing', 'backup', 'passive-backup', 'ready']
const BAD_HA = ['partner-down', 'terminated', 'unavailable']

// Angles (degrees, 0 = right, 90 = front) of n nodes: one node in front, two face to
// face left and right, more spread evenly from the front left.
export function nodeAngles(n) {
  if (n <= 0) return []
  if (n === 1) return [90]
  return Array.from({ length: n }, (_, i) => (90 + 180 / n + (360 * i) / n) % 360)
}

export function polar(angleDeg, radius) {
  const a = (angleDeg * Math.PI) / 180
  return { x: Math.cos(a) * radius, y: Math.sin(a) * radius }
}

// Disc radius and center that fit a W x H stage, leaving headroom above for the pins
// and the beam readout and room below for the HA rail.
export function radarFrame(width, height, { squash = RADAR_SQUASH, top = 64, bottom = 64, side = 24 } = {}) {
  const w = Math.max(0, width - side * 2)
  const h = Math.max(0, height - top - bottom)
  const r = Math.max(0, Math.min(w / 2, h / (2 * squash)))
  return { r, cx: width / 2, cy: top + h / 2, squash }
}

export function project(point, frame) {
  return { left: frame.cx + point.x * frame.r, top: frame.cy + point.y * frame.r * frame.squash }
}

// Straight segment between two floor points, in floor percent units (the floor element
// is a 2r square): center, length and angle, for a rotated dashed strip.
export function segment(a, b) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  return {
    left: 50 + ((a.x + b.x) / 2) * 50,
    top: 50 + ((a.y + b.y) / 2) * 50,
    length: Math.hypot(dx, dy) * 50,
    angle: (Math.atan2(dy, dx) * 180) / Math.PI,
  }
}

// Stable pseudo-random value in [0, 1) for a string (zone blips keep their place).
export function hash01(text) {
  let h = 2166136261
  for (const ch of String(text)) {
    h ^= ch.codePointAt(0)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 100000) / 100000
}

// Zones as blips inside the node ring, placed by name.
export function blipPoint(name) {
  const angle = hash01(`a:${name}`) * 360
  const radius = 0.18 + hash01(`r:${name}`) * 0.32
  return polar(angle, radius)
}

// Node tone: offline red, error or critical alert on it yellow, else green.
export function nodeTone(node, alerts = []) {
  if (!node || (node.status && node.status !== 'online')) return 'danger'
  if (node.error) return 'warning'
  if (alerts.some((a) => a.node_id === node.peer?.id && a.severity === 'critical')) return 'warning'
  return 'success'
}

// Replication link from the local node to a peer: down when the peer is offline,
// lag when a zone serial on the peer is behind the newest one, ok otherwise.
export function linkState(peer, zones = []) {
  if (!peer || (peer.status && peer.status !== 'online')) return { state: 'down', behind: 0 }
  const id = peer.peer?.id
  let behind = 0
  for (const z of zones) {
    const values = Object.values(z.serials || {}).filter((v) => typeof v === 'number')
    if (!values.length || typeof z.serials?.[id] !== 'number') continue
    if (z.serials[id] < Math.max(...values)) behind += 1
  }
  return { state: behind ? 'lag' : 'ok', behind }
}

export const LINK_TONE = { ok: 'success', lag: 'warning', down: 'danger' }

// Dash flow period in seconds: healthy links flow fast, lagging ones crawl, down ones stop.
export function linkDuration(state) {
  return { ok: 1.1, lag: 3.2 }[state] ?? null
}

// Beam pulse period from the query rate: faster with more traffic, stopped at zero.
export function beamDuration(rate) {
  if (!(rate > 0)) return null
  return Math.min(2.4, Math.max(0.35, 2.4 - 0.6 * Math.log10(rate + 1)))
}

// HA pill tone, like the reference waypoints: the serving server ember, a healthy
// standby green, a backup gray, a broken pair red, a transition yellow.
export function haTone(h) {
  if (!h) return 'neutral'
  if (BAD_HA.includes(h.state) || h.partner?.in_touch === false) return 'danger'
  if (!NORMAL_HA.includes(h.state)) return 'warning'
  if (h.state === 'backup' || h.state === 'passive-backup' || h.role === 'backup') return 'neutral'
  if (h.role === 'primary' || h.state === 'load-balancing') return 'primary'
  return 'success'
}

// Alert markers: alerts of a node sit on its pin; cluster-wide ones spread on the back rim.
export function alertMarkers(alerts = [], nodeIds = [], limit = 5) {
  const byNode = {}
  const rim = []
  for (const a of alerts) {
    if (a.node_id && nodeIds.includes(a.node_id)) (byNode[a.node_id] ||= []).push(a)
    else rim.push(a)
  }
  const shown = rim.slice(0, limit)
  const markers = shown.map((a, i) => ({ alert: a, point: polar(200 + ((i + 0.5) * 140) / shown.length, 0.94) }))
  return { byNode, markers }
}

// Pool utilization as segments: filled ones take the pool's state (green, yellow past
// the warning threshold, red past the critical one), the partly filled one ember, the
// rest gray. A pool that rounds to 0% stays all gray.
export function utilizationSegments(percent, { count = 12, warn = 80, full = 95 } = {}) {
  const p = Math.min(100, Math.max(0, Number(percent) || 0))
  const filled = (p / 100) * count
  const fill = p >= full ? 'danger' : p >= warn ? 'warning' : 'done'
  return Array.from({ length: count }, (_, i) => {
    let state = 'next'
    if (i + 1 <= filled) state = fill
    else if (i < filled && p >= 0.5) state = 'current'
    return { key: i, state }
  })
}
