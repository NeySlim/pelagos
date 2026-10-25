// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { DEFAULT_LAYOUT, TILE_IDS, TILES, COLS, HERO_HEIGHT, normalizeLayout, serializeLayout, sameLayout } from './layout'

describe('dashboard layout', () => {
  it('falls back to the default layout when nothing is saved', () => {
    for (const saved of [undefined, null, [], 'junk', [{ i: 'unknown', x: 0, y: 0, w: 2, h: 2 }]]) {
      expect(serializeLayout(normalizeLayout(saved))).toEqual(DEFAULT_LAYOUT)
    }
  })

  it('keeps saved positions, drops unknown tiles and duplicates', () => {
    const saved = [
      { i: 'zones', x: 6, y: 0, w: 6, h: 8 },
      { i: 'zones', x: 0, y: 0, w: 6, h: 8 },
      { i: 'weather', x: 0, y: 0, w: 4, h: 4 },
    ]
    const out = normalizeLayout(saved)
    expect(out.map((it) => it.i).sort()).toEqual([...TILE_IDS].sort())
    expect(out.find((it) => it.i === 'zones')).toMatchObject({ x: 6, y: HERO_HEIGHT, w: 6, h: 8 })
  })

  it('appends missing tiles below the saved ones', () => {
    const out = normalizeLayout([{ i: 'trace', x: 0, y: 0, w: 12, h: 9 }, { i: 'pools', x: 0, y: 9, w: 12, h: 5 }])
    expect(out.find((it) => it.i === 'trace')).toMatchObject({ y: 0, h: 9 })
    const others = out.filter((it) => !['pools', 'trace'].includes(it.i))
    expect(Math.min(...others.map((it) => it.y))).toBe(14)
    for (const a of others) for (const b of others) if (a !== b) expect(a.y + a.h <= b.y || b.y + b.h <= a.y).toBe(true)
  })

  it('turns the old radar tile into the cluster trace, in its place', () => {
    const out = normalizeLayout([{ i: 'radar', x: 3, y: 0, w: 6, h: 11 }, { i: 'dns', x: 0, y: 0, w: 3, h: 11 }])
    expect(out.find((it) => it.i === 'radar')).toBeUndefined()
    expect(out.find((it) => it.i === 'trace')).toMatchObject({ x: 3, y: 0, w: 6, h: 11 })
    // A layout holding both keeps the first one.
    const both = normalizeLayout([{ i: 'trace', x: 0, y: 0, w: 6, h: 11 }, { i: 'radar', x: 6, y: 0, w: 6, h: 11 }])
    expect(both.filter((it) => it.i === 'trace')).toHaveLength(1)
    expect(both.find((it) => it.i === 'trace').x).toBe(0)
    // A radar saved smaller than the trace needs grows to its minimum height.
    expect(normalizeLayout([{ i: 'radar', x: 0, y: 0, w: 6, h: 7 }]).find((it) => it.i === 'trace').h).toBe(9)
  })

  it('puts the hero row on top of a layout saved before it', () => {
    const out = normalizeLayout([{ i: 'pools', x: 0, y: 0, w: 12, h: 5 }])
    const hero = TILES.filter((tile) => tile.hero).map((tile) => out.find((it) => it.i === tile.i))
    expect(hero.every((it) => it.y === 0 && it.h === HERO_HEIGHT)).toBe(true)
    expect(out.find((it) => it.i === 'pools')).toMatchObject({ x: 0, y: HERO_HEIGHT, w: 12, h: 5 })
    const rest = out.filter((it) => !TILES.find((tile) => tile.i === it.i).hero && it.i !== 'pools')
    expect(Math.min(...rest.map((it) => it.y))).toBe(HERO_HEIGHT + 5)
  })

  it('clamps sizes and positions into the grid', () => {
    const out = normalizeLayout([{ i: 'd2', x: 11, y: -3, w: 1, h: 1 }])
    const d2 = out.find((it) => it.i === 'd2')
    expect(d2.w).toBeGreaterThanOrEqual(4)
    expect(d2.x + d2.w).toBeLessThanOrEqual(COLS)
    expect(d2.y).toBe(HERO_HEIGHT)
    expect(d2.h).toBeGreaterThanOrEqual(4)
  })

  it('ignores items with non numeric coordinates', () => {
    const out = normalizeLayout([{ i: 'ha', x: 'a', y: 0, w: 4, h: 4 }, { i: 'nodes', x: 0, y: 0, w: 4, h: 6 }])
    expect(out.find((it) => it.i === 'ha').y).toBe(HERO_HEIGHT + 6)
  })

  it('serializes only placement keys and compares regardless of order', () => {
    const out = normalizeLayout(DEFAULT_LAYOUT)
    expect(Object.keys(serializeLayout(out)[0])).toEqual(['i', 'x', 'y', 'w', 'h'])
    expect(sameLayout(out, [...DEFAULT_LAYOUT].reverse())).toBe(true)
    expect(sameLayout(out, [{ ...DEFAULT_LAYOUT[0], x: 1 }, ...DEFAULT_LAYOUT.slice(1)])).toBe(false)
  })
})
