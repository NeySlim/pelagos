// SPDX-License-Identifier: Apache-2.0
// Theme tokens as canvas colors. A hidden probe resolves each token (var() and
// color-mix() included) to its computed color once per theme change, never in a frame.

export const INK_TOKENS = {
  dns: '--accent-primary',
  dhcp: '--accent-pro',
  ok: '--accent-success',
  bad: '--accent-danger',
  warn: '--accent-warning-fill',
  t1: '--text-primary',
  t2: '--text-secondary',
  t3: '--text-tertiary',
  t4: '--fx-faint',
  hair: '--fx-hair',
  hair3: '--fx-hair-3',
  panel: '--bg-secondary',
  canvas: '--bg-primary',
}

const FALLBACK = [136, 136, 136, 1]

// [r, g, b, a] of a computed color: rgb(), rgba(), color(srgb r g b / a) or #hex.
export function parseColor(text) {
  const s = String(text || '').trim()
  let m = /^rgba?\(([^)]+)\)$/.exec(s)
  if (m) {
    const parts = m[1].split(/[\s,/]+/).filter(Boolean).map(Number)
    if (parts.length >= 3 && parts.slice(0, 3).every(Number.isFinite)) return [parts[0], parts[1], parts[2], Number.isFinite(parts[3]) ? parts[3] : 1]
  }
  m = /^color\(srgb\s+([^)]+)\)$/.exec(s)
  if (m) {
    const parts = m[1].split(/[\s/]+/).filter(Boolean).map(Number)
    if (parts.length >= 3 && parts.slice(0, 3).every(Number.isFinite)) return [parts[0] * 255, parts[1] * 255, parts[2] * 255, Number.isFinite(parts[3]) ? parts[3] : 1]
  }
  m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(s)
  if (m) {
    const hex = m[1].length === 3 ? [...m[1]].map((c) => c + c).join('') : m[1]
    const n = parseInt(hex, 16)
    return [n >> 16, (n >> 8) & 255, n & 255, 1]
  }
  return null
}

// Reads every token through one probe element under `root` (the canvas host, so a
// tile-scoped override applies too). Returns { name: [r, g, b, a] }.
export function readInks(root = typeof document !== 'undefined' ? document.body : null) {
  const out = {}
  if (!root || typeof getComputedStyle === 'undefined') {
    for (const name of Object.keys(INK_TOKENS)) out[name] = FALLBACK
    return out
  }
  const probe = document.createElement('span')
  probe.style.display = 'none'
  root.appendChild(probe)
  for (const [name, token] of Object.entries(INK_TOKENS)) {
    probe.style.color = `var(${token})`
    out[name] = parseColor(getComputedStyle(probe).color) || FALLBACK
  }
  probe.remove()
  return out
}

// Canvas color string of an ink at `alpha` (multiplied with the token's own alpha).
export function ink(color, alpha = 1) {
  const [r, g, b, a] = color || FALLBACK
  return `rgba(${Math.round(r)},${Math.round(g)},${Math.round(b)},${+(a * alpha).toFixed(3)})`
}

// Repaints `fn` whenever the theme changes (family, mode or tokens on <html>).
export function onThemeChange(fn) {
  if (typeof MutationObserver === 'undefined' || typeof document === 'undefined') return () => {}
  const mo = new MutationObserver(fn)
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme', 'data-effects'] })
  return () => mo.disconnect()
}
