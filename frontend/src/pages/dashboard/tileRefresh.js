// SPDX-License-Identifier: Apache-2.0
// Per-tile ambient events: `sweeps` counts the calibration sweeps asked of each tile id,
// `pulses` the domain events it should ping for, `order` its reading-order index (stagger).
import { createContext } from 'react'

export const TileRefresh = createContext(null)
export const SWEEP_STEP_MS = 60
export const SWEEP_MAX_STEPS = 8

// Summary slices a tile shows: a new sweep is asked only when one of them changed.
export const TILE_SLICES = {
  trace: ['nodes', 'zones', 'ha', 'alerts'],
  dns: ['zones'],
  dhcp: ['pools', 'ha'],
  nodes: ['nodes'],
  ha: ['ha'],
  inconsistencies: ['alerts', 'zones'],
  zones: ['zones'],
  pools: ['pools'],
  d2: ['d2'],
}

export function changedTiles(prev, next) {
  const same = (k) => JSON.stringify(prev?.[k]) === JSON.stringify(next?.[k])
  return Object.keys(TILE_SLICES).filter((id) => !TILE_SLICES[id].every(same))
}
