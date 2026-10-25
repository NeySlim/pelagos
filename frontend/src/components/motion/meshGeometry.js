// SPDX-License-Identifier: Apache-2.0
// Geometry of the mesh links (MeshLinks): every link is one quadratic curve between two card
// boxes { x, y, w, h } measured in the container.

// Room the container keeps above (replication arcs) and below (backup feeds) the cards.
export const MESH_TOP = 26
export const MESH_BOTTOM = 14

// [p0, control, p1] of a link of `kind` ('repl', 'ha', 'feed'); `order` is how far apart
// the two cards sit in the row, so replication arcs between distant nodes nest higher.
export function linkCurve(kind, a, b, order = 1) {
  const sameRow = Math.abs(a.y - b.y) < 4
  const ax = a.x + a.w / 2
  const bx = b.x + b.w / 2
  if (kind === 'ha' && sameRow) {
    const [l, r] = ax < bx ? [a, b] : [b, a]
    const y = a.y + a.h / 2
    const left = [l.x + l.w, y]
    const right = [r.x, y]
    const [p0, p1] = ax < bx ? [left, right] : [right, left]
    return [p0, [(left[0] + right[0]) / 2, y], p1]
  }
  if (!sameRow) return [[ax, a.y + a.h / 2], [(ax + bx) / 2, (a.y + b.y + a.h) / 2], [bx, b.y + b.h / 2]]
  if (kind === 'feed') {
    const y = Math.max(a.y + a.h, b.y + b.h)
    return [[ax, y], [(ax + bx) / 2, y + MESH_BOTTOM * 1.6], [bx, y]]
  }
  const top = Math.min(a.y, b.y)
  const lift = Math.min(MESH_TOP * 1.7, 9 + 6 * order)
  return [[ax, top], [(ax + bx) / 2, top - lift], [bx, top]]
}

// The point at `t` (0 to 1) of a curve.
export function pointOn([p0, c, p1], t) {
  const u = 1 - t
  return [u * u * p0[0] + 2 * u * t * c[0] + t * t * p1[0], u * u * p0[1] + 2 * u * t * c[1] + t * t * p1[1]]
}
