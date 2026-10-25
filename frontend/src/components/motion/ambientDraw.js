// SPDX-License-Identifier: Apache-2.0
// Canvas drawing of the tile ambient layers, kept pure so the level gating lives in the
// components. Every mark is a flat stroke or fill at an alpha below the hairline; the
// quantity that drives it is a real rate, never a random source.

export const FRAME_MS = 32 // ambient canvases redraw at about 30 fps from the shared loop
export const WAVE_ALPHA = 0.06
export const SPECTRUM_BARS = 28
export const SPECTRUM_ALPHA = 0.035
export const DOT_PITCH = 11
export const DOT_ALPHA = 0.09
export const MESH_PITCH = DOT_PITCH * 5
export const RIPPLE_MS = 1300
export const RIPPLE_SPEED = 260 // px per second, from the link outwards

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v))
const TAU = Math.PI * 2

// Wave amplitude as a share of the height: 3 % idle, 12 % at the series peak.
export function waveAmplitude(rate, peak) {
  const ratio = peak > 0 ? clamp(rate / peak, 0, 1) : 0
  return 0.03 + 0.09 * ratio
}

// Three sines modulated by a slow envelope; the phase advances in 9 s.
export function drawWave(ctx, width, height, { rate = 0, peak = 0, phase = 0, color }) {
  const amp = height * waveAmplitude(rate, peak)
  ctx.lineWidth = 1
  ctx.strokeStyle = color
  for (let i = 0; i < 3; i += 1) {
    ctx.globalAlpha = WAVE_ALPHA - i * 0.015
    ctx.beginPath()
    for (let x = 0; x <= width; x += 4) {
      const y = height * 0.56 + amp * Math.sin(x / (46 + i * 9) + (phase / (9000 + i * 1700)) * TAU + i) * Math.sin(x / 170 + (phase / 23000) * TAU)
      if (x) ctx.lineTo(x, y)
      else ctx.moveTo(x, y)
    }
    ctx.stroke()
  }
  ctx.globalAlpha = 1
}

// Heights (0 to 1) of the last `bars` samples, newest on the right, scaled to the largest.
export function spectrumLevels(values, bars = SPECTRUM_BARS) {
  const data = (values || []).slice(-bars).map((v) => (Number.isFinite(Number(v)) ? Math.max(0, Number(v)) : 0))
  const max = Math.max(...data, 0)
  const levels = data.map((v) => (max > 0 ? v / max : 0))
  return [...Array(bars - levels.length).fill(0), ...levels]
}

// The 28 latest lease samples as bars at 38 % of the height; the whole breathes by 10 % in 8 s.
export function drawSpectrum(ctx, width, height, { values = [], phase = 0, color }) {
  const levels = spectrumLevels(values)
  const bw = width / levels.length
  const breath = 0.9 + 0.1 * Math.sin((phase / 8000) * TAU)
  ctx.fillStyle = color
  ctx.globalAlpha = SPECTRUM_ALPHA
  levels.forEach((l, i) => {
    const h = height * 0.38 * l * breath
    if (h > 0) ctx.fillRect(i * bw + 1, height - h, Math.max(1, bw - 2), h)
  })
  ctx.globalAlpha = 1
}

// Radius of the ripple `elapsed` ms after an event, or null once it has faded.
export function rippleRadius(elapsed) {
  return elapsed === null || elapsed === undefined || elapsed < 0 || elapsed >= RIPPLE_MS ? null : (elapsed / 1000) * RIPPLE_SPEED
}

const restCache = new WeakMap()

// The resting matrix and hairline mesh are drawn once per size and ink, then blitted.
function restLayer(canvas, width, height, color, dpr) {
  const key = `${width}x${height}@${dpr}${color}`
  const hit = restCache.get(canvas)
  if (hit && hit.key === key) return hit.layer
  const layer = document.createElement('canvas')
  layer.width = Math.max(1, Math.round(width * dpr))
  layer.height = Math.max(1, Math.round(height * dpr))
  const c = layer.getContext?.('2d')
  if (!c) return null
  c.scale(dpr, dpr)
  c.fillStyle = color
  c.globalAlpha = DOT_ALPHA
  for (let y = DOT_PITCH / 2; y < height; y += DOT_PITCH) for (let x = DOT_PITCH / 2; x < width; x += DOT_PITCH) c.fillRect(x - 0.5, y - 0.5, 1, 1)
  c.globalAlpha = DOT_ALPHA * 0.6
  for (let x = MESH_PITCH; x < width; x += MESH_PITCH) c.fillRect(x, 0, 1, height)
  for (let y = MESH_PITCH; y < height; y += MESH_PITCH) c.fillRect(0, y, width, 1)
  restCache.set(canvas, { key, layer })
  return layer
}

// Dot matrix with a hairline mesh; `elapsed` ms after an event a ring of lit dots leaves
// the centre (the link) at RIPPLE_SPEED and fades by RIPPLE_MS.
export function drawDots(ctx, width, height, { color, elapsed = null, dpr = 1 }) {
  const layer = restLayer(ctx.canvas, width, height, color, dpr)
  if (layer) ctx.drawImage(layer, 0, 0, width, height)
  const radius = rippleRadius(elapsed)
  if (radius === null) return
  const cx = width / 2
  const cy = height / 2
  const fade = 1 - elapsed / RIPPLE_MS
  ctx.fillStyle = color
  for (let y = DOT_PITCH / 2; y < height; y += DOT_PITCH) {
    for (let x = DOT_PITCH / 2; x < width; x += DOT_PITCH) {
      const g = Math.exp(-((Math.hypot(x - cx, y - cy) - radius) ** 2) / 500)
      if (g < 0.02) continue
      ctx.globalAlpha = 0.22 * g * fade
      ctx.fillRect(x - 0.5, y - 0.5, 1, 1)
    }
  }
  ctx.globalAlpha = 1
}
