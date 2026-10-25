// SPDX-License-Identifier: Apache-2.0
// Magnetic feedback: a primary button leans toward the pointer by at most one pixel.

export const MAGNET_MAX = 1

// Offset in px of a box leaning toward (x, y): proportional to the distance from its
// centre, clamped to +-max on each axis.
export function magnetOffset(rect, x, y, max = MAGNET_MAX) {
  const nx = (x - (rect.left + rect.width / 2)) / (rect.width / 2 || 1)
  const ny = (y - (rect.top + rect.height / 2)) / (rect.height / 2 || 1)
  const clamp = (v) => Math.max(-max, Math.min(max, v * max))
  return { x: clamp(nx), y: clamp(ny) }
}
