// SPDX-License-Identifier: Apache-2.0
// Dashboard grid: the tiles, their default placement and the normalization of a
// layout read from GET /dashboard/layout (unknown tiles dropped, missing ones
// appended, sizes clamped), so an old or hand-edited layout always renders.

export const COLS = 12
export const ROW_HEIGHT = 40

export const TILES = [
  { i: 'nodes', minW: 3, minH: 4 },
  { i: 'ha', minW: 3, minH: 4 },
  { i: 'inconsistencies', minW: 3, minH: 4 },
  { i: 'zones', minW: 4, minH: 4 },
  { i: 'pools', minW: 4, minH: 4 },
  { i: 'd2', minW: 4, minH: 4 },
]

export const TILE_IDS = TILES.map((tile) => tile.i)

export const DEFAULT_LAYOUT = [
  { i: 'nodes', x: 0, y: 0, w: 4, h: 6 },
  { i: 'ha', x: 4, y: 0, w: 4, h: 6 },
  { i: 'inconsistencies', x: 8, y: 0, w: 4, h: 6 },
  { i: 'zones', x: 0, y: 6, w: 6, h: 8 },
  { i: 'pools', x: 6, y: 6, w: 6, h: 8 },
  { i: 'd2', x: 0, y: 14, w: 12, h: 6 },
]

const int = (v) => (Number.isFinite(Number(v)) ? Math.round(Number(v)) : null)

export function normalizeLayout(saved) {
  const byId = new Map()
  for (const item of Array.isArray(saved) ? saved : []) {
    if (!item || !TILE_IDS.includes(item.i) || byId.has(item.i)) continue
    const tile = TILES.find((x) => x.i === item.i)
    const [x, y, w, h] = [int(item.x), int(item.y), int(item.w), int(item.h)]
    if ([x, y, w, h].some((v) => v === null)) continue
    const width = Math.min(COLS, Math.max(tile.minW, w))
    byId.set(item.i, {
      i: item.i,
      x: Math.min(Math.max(0, x), COLS - width),
      y: Math.max(0, y),
      w: width,
      h: Math.max(tile.minH, h),
    })
  }
  let bottom = Math.max(0, ...[...byId.values()].map((it) => it.y + it.h))
  const out = []
  for (const tile of TILES) {
    if (byId.has(tile.i)) out.push(byId.get(tile.i))
    else if (byId.size === 0) out.push({ ...DEFAULT_LAYOUT.find((d) => d.i === tile.i) })
    else {
      const def = DEFAULT_LAYOUT.find((d) => d.i === tile.i)
      out.push({ ...def, x: 0, y: bottom })
      bottom += def.h
    }
  }
  return out.map((it) => ({ ...it, minW: TILES.find((x) => x.i === it.i).minW, minH: TILES.find((x) => x.i === it.i).minH }))
}

// What PUT /dashboard/layout stores: only the placement keys.
export function serializeLayout(layout) {
  return (layout || []).filter((it) => TILE_IDS.includes(it.i)).map(({ i, x, y, w, h }) => ({ i, x, y, w, h }))
}

export function sameLayout(a, b) {
  const key = (l) => JSON.stringify(serializeLayout(l).sort((p, q) => p.i.localeCompare(q.i)))
  return key(a) === key(b)
}
