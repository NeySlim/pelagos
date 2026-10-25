// SPDX-License-Identifier: Apache-2.0
// Theme families: same keys everywhere, the default (Instrument) matches index.css,
// and the text and accent tokens keep WCAG AA contrast (4.5:1) on bg-secondary.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { themeFamilies, DEFAULT_FAMILY } from './ThemeContext'

function luminance(hex) {
  const [r, g, b] = hex
    .replace('#', '')
    .match(/../g)
    .map((h) => parseInt(h, 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

function hue(hex) {
  const [r, g, b] = hex.replace('#', '').match(/../g).map((h) => parseInt(h, 16) / 255)
  const max = Math.max(r, g, b)
  const d = max - Math.min(r, g, b)
  if (d === 0) return 0
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4
  return (h * 60 + 360) % 360
}

const hueDistance = (a, b) => Math.min(Math.abs(a - b), 360 - Math.abs(a - b))

const families = Object.values(themeFamilies)
const TOKENS = ['text-primary', 'text-secondary', 'text-tertiary', 'accent-primary', 'accent-pro']

describe('theme families', () => {
  it('Instrument is the default and every family has the same keys', () => {
    expect(DEFAULT_FAMILY).toBe('instrument')
    expect(Object.keys(themeFamilies)[0]).toBe('instrument')
    for (const key of ['bg-inset', 'border-strong', 'contrast-bg', 'contrast-fg']) expect(themeFamilies.pelagic.dark, key).toHaveProperty(key)
    const shape = (f) => ({ top: Object.keys(f).sort(), dark: Object.keys(f.dark).sort(), light: Object.keys(f.light).sort() })
    const reference = shape(themeFamilies.pelagic)
    for (const family of families) expect(shape(family), family.id).toEqual(reference)
  })

  // The UCM families are copied unchanged (design section 8); new families take
  // the status colors of the UCM reference family, gray.
  it('Pelagic keeps the UCM status colors', () => {
    for (const mode of ['dark', 'light']) {
      for (const token of ['accent-success', 'accent-warning', 'accent-danger']) {
        expect(themeFamilies.pelagic[mode][token], `${mode} ${token}`).toBe(themeFamilies.gray[mode][token])
      }
    }
  })

  it.each(families.flatMap((f) => ['dark', 'light'].map((mode) => [f.id, mode])))('%s %s text meets AA contrast', (id, mode) => {
    const palette = themeFamilies[id][mode]
    for (const token of TOKENS.filter((t) => t.startsWith('text-'))) {
      const ratio = contrast(palette[token], palette['bg-secondary'])
      expect(ratio, `${id} ${mode} ${token} ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it.each([['instrument', 'dark'], ['instrument', 'light'], ['pelagic', 'dark'], ['pelagic', 'light'], ['mission', 'dark'], ['mission', 'light']])('%s %s accents meet AA contrast', (id, mode) => {
    const palette = themeFamilies[id][mode]
    for (const token of TOKENS) {
      const ratio = contrast(palette[token], palette['bg-secondary'])
      expect(ratio, `${id} ${mode} ${token} ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5)
    }
  })

  // Mission status colors are its own (neon green, yellow, red-pink) and are read as text.
  it.each(['dark', 'light'])('Mission %s status colors meet AA contrast on panels and the ground', (mode) => {
    const palette = themeFamilies.mission[mode]
    for (const token of ['accent-success', 'accent-warning', 'accent-danger']) {
      for (const bg of ['bg-secondary', 'bg-primary']) {
        const ratio = contrast(palette[token], palette[bg])
        expect(ratio, `mission ${mode} ${token} on ${bg} ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5)
      }
    }
  })

  // Light Mission darkens the warning text for AA; bars and dots keep a bright yellow.
  it('Mission light warning fill stays a bright yellow distinct from the text token', () => {
    const light = themeFamilies.mission.light
    expect(light['accent-warning-fill']).not.toBe(light['accent-warning'])
    expect(luminance(light['accent-warning-fill'])).toBeGreaterThan(luminance(light['accent-warning']) * 2)
    const h = hue(light['accent-warning-fill'])
    expect(h).toBeGreaterThanOrEqual(40)
    expect(h).toBeLessThanOrEqual(55)
    for (const family of families) {
      if (family.id !== 'mission') expect(family.dark['accent-warning-fill'], family.id).toBe(family.dark['accent-warning'])
    }
    expect(themeFamilies.instrument.light['accent-warning-fill']).not.toBe(themeFamilies.instrument.light['accent-warning'])
  })

  it.each(['dark', 'light'])('Mission %s keeps warning, DNS and DHCP accents apart', (mode) => {
    const palette = themeFamilies.mission[mode]
    const pairs = [['accent-warning', 'accent-primary'], ['accent-pro', 'accent-primary'], ['accent-danger', 'accent-primary'], ['accent-success', 'accent-pro']]
    for (const [a, b] of pairs) {
      const d = hueDistance(hue(palette[a]), hue(palette[b]))
      expect(d, `mission ${mode} ${a} vs ${b} ${d.toFixed(0)} deg`).toBeGreaterThanOrEqual(20)
    }
  })

  it('Instrument and Mission have their own effects layer, the other families none', () => {
    const layers = { instrument: 'instrument', mission: 'mission' }
    for (const family of families) expect(family.effects, family.id).toBe(layers[family.id] || 'none')
  })

  // Status colors are read as text next to their dot: AA on panels and on the ground.
  it.each(['dark', 'light'])('Instrument %s status colors and tertiary text meet AA on panels and the ground', (mode) => {
    const palette = themeFamilies.instrument[mode]
    for (const token of ['accent-success', 'accent-warning', 'accent-danger', 'accent-primary', 'accent-pro', 'text-tertiary']) {
      for (const bg of ['bg-secondary', 'bg-primary', 'bg-tertiary']) {
        const ratio = contrast(palette[token], palette[bg])
        expect(ratio, `instrument ${mode} ${token} on ${bg} ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5)
      }
    }
  })

  // One signal color per protocol, never confused with a status color.
  it.each(['dark', 'light'])('Instrument %s keeps DNS, DHCP and status hues apart', (mode) => {
    const palette = themeFamilies.instrument[mode]
    const signals = ['accent-primary', 'accent-pro']
    for (const a of signals) {
      for (const b of ['accent-success', 'accent-warning', 'accent-danger', ...signals.filter((s) => s !== a)]) {
        const d = hueDistance(hue(palette[a]), hue(palette[b]))
        expect(d, `instrument ${mode} ${a} vs ${b} ${d.toFixed(0)} deg`).toBeGreaterThanOrEqual(40)
      }
    }
  })

  it.each(['dark', 'light'])('Instrument %s primary action is neutral and high contrast', (mode) => {
    const palette = themeFamilies.instrument[mode]
    expect(contrast(palette['contrast-fg'], palette['contrast-bg'])).toBeGreaterThanOrEqual(12)
    expect(palette['contrast-bg']).toBe(palette['text-primary'])
  })

  it('index.css defaults match the default family', () => {
    const css = readFileSync(resolve(import.meta.dirname, '../index.css'), 'utf8')
    const block = (selector) => css.slice(css.indexOf(`${selector} {`), css.indexOf('}', css.indexOf(`${selector} {`)))
    for (const [selector, mode] of [[':root', 'dark'], ['.theme-light', 'light']]) {
      const text = block(selector)
      for (const token of ['bg-primary', 'bg-secondary', 'bg-tertiary', 'bg-inset', ...TOKENS, 'accent-success', 'accent-warning', 'accent-warning-fill', 'accent-danger', 'border', 'border-strong', 'contrast-bg', 'contrast-fg']) {
        expect(text, `${selector} --${token}`).toContain(`--${token}: ${themeFamilies[DEFAULT_FAMILY][mode][token]};`)
      }
    }
  })
})
