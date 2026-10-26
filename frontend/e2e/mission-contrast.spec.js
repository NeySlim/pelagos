// SPDX-License-Identifier: Apache-2.0
// The dashboard stat values and badge words are text: they keep WCAG AA (4.5:1) over
// their own fill in both schemes of Instrument (the default) and Mission Control. The
// ground is the element's fill composited over its ancestors.
import { test, expect } from '@playwright/test'
import { setServerFamily } from './family'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

// Contrast of the text (`value` selector inside, or the element itself) of every `selector`
// element against its composited background.
const contrasts = (page, selector, value, label) =>
  page.locator(selector).evaluateAll((chips, [value, label]) => {
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })
    const rgba = (css) => {
      ctx.clearRect(0, 0, 1, 1)
      ctx.fillStyle = '#000'
      ctx.fillStyle = css
      ctx.fillRect(0, 0, 1, 1)
      const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data
      return [r, g, b, a / 255]
    }
    const over = (top, base) => [0, 1, 2].map((i) => top[i] * top[3] + base[i] * (1 - top[3])).concat(1)
    const ground = (el) => {
      const layers = []
      for (let n = el; n; n = n.parentElement) layers.push(rgba(getComputedStyle(n).backgroundColor))
      const root = rgba(getComputedStyle(document.body).backgroundColor)
      return layers.reverse().reduce((acc, layer) => over(layer, acc), root[3] ? root : [0, 0, 0, 1])
    }
    const lum = ([r, g, b]) => {
      const c = [r, g, b].map((v) => {
        const s = v / 255
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
      })
      return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
    }
    return chips.map((chip) => {
      const text = value ? chip.querySelector(value) : chip
      const bg = ground(chip)
      const fg = over(rgba(getComputedStyle(text).color), bg)
      const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a)
      const name = (label ? chip.querySelector(label) : chip)?.textContent
      return { label: `${chip.className}: ${name}`, ratio: (hi + 0.05) / (lo + 0.05) }
    })
  }, [value, label])
const chipContrasts = (page) => contrasts(page, '.dash-stat', '.dash-stat-value', '.dash-stat-label')

for (const [family, name] of [['instrument', 'Instrument'], ['mission', 'Mission']]) {
  test.describe(name, () => {
    test.beforeAll(async ({ playwright }, info) => setServerFamily(playwright, info.project.use.baseURL, family))
    test.afterAll(async ({ playwright }, info) => setServerFamily(playwright, info.project.use.baseURL, 'instrument'))

    for (const scheme of ['dark', 'light']) {
      test(`dashboard chip values keep AA contrast in ${name} ${scheme}`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme })
        await signIn(page)
        await page.goto('/')
        await expect(page.getByTestId('dns-rate')).toBeVisible({ timeout: 20000 })
        await expect.poll(() => page.evaluate(() => document.documentElement.classList.contains('theme-light'))).toBe(scheme === 'light')
        const results = await chipContrasts(page)
        expect(results.length).toBeGreaterThanOrEqual(4)
        for (const r of results) expect(r.ratio, r.label).toBeGreaterThanOrEqual(4.5)
      })

      test(`badge text keeps AA contrast over its own fill in ${name} ${scheme}`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme })
        await signIn(page)
        await page.goto('/alerts')
        await expect(page.getByTestId('alert-row-ack').first()).toBeVisible()
        await expect(page.locator('.ui-badge-info').first()).toBeVisible()
        const results = await contrasts(page, '.ui-badge:not(.ui-badge-outline)')
        expect(results.length).toBeGreaterThanOrEqual(4)
        for (const r of results) expect(r.ratio, r.label).toBeGreaterThanOrEqual(4.5)
      })
    }
  })
}
