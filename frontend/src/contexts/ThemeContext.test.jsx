// SPDX-License-Identifier: Apache-2.0
// Theme families: same keys everywhere, the default matches index.css, and the
// text and accent tokens keep WCAG AA contrast (4.5:1) on bg-secondary.
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

const families = Object.values(themeFamilies)
const TOKENS = ['text-primary', 'text-secondary', 'text-tertiary', 'accent-primary', 'accent-pro']

describe('theme families', () => {
  it('Pelagic is the default and every family has the same keys', () => {
    expect(DEFAULT_FAMILY).toBe('pelagic')
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

  it.each(['dark', 'light'])('Pelagic %s accents meet AA contrast', (mode) => {
    const palette = themeFamilies.pelagic[mode]
    for (const token of TOKENS) {
      const ratio = contrast(palette[token], palette['bg-secondary'])
      expect(ratio, `pelagic ${mode} ${token} ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('index.css defaults match the Pelagic family', () => {
    const css = readFileSync(resolve(import.meta.dirname, '../index.css'), 'utf8')
    const block = (selector) => css.slice(css.indexOf(`${selector} {`), css.indexOf('}', css.indexOf(`${selector} {`)))
    for (const [selector, mode] of [[':root', 'dark'], ['.theme-light', 'light']]) {
      const text = block(selector)
      for (const token of ['bg-primary', 'bg-secondary', 'bg-tertiary', ...TOKENS, 'border']) {
        expect(text, `${selector} --${token}`).toContain(`--${token}: ${themeFamilies.pelagic[mode][token]};`)
      }
    }
  })
})
