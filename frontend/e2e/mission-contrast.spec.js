// SPDX-License-Identifier: Apache-2.0
// The dashboard stat chip values are text: they keep WCAG AA (4.5:1) over their chip in
// both Mission schemes. The chip ground is its own fill composited over its ancestors.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

// Contrast of every `.dash-chip` value against its composited background.
const chipContrasts = (page) =>
  page.locator('.dash-chip').evaluateAll((chips) => {
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
      const value = chip.querySelector('.ui-stat-chip-value')
      const bg = ground(chip)
      const fg = over(rgba(getComputedStyle(value).color), bg)
      const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a)
      return { label: chip.querySelector('.ui-stat-chip-label')?.textContent, ratio: (hi + 0.05) / (lo + 0.05) }
    })
  })

for (const scheme of ['dark', 'light']) {
  test(`dashboard chip values keep AA contrast in Mission ${scheme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await signIn(page)
    await page.goto('/')
    await expect(page.getByTestId('dns-rate')).toBeVisible()
    await expect.poll(() => page.evaluate(() => document.documentElement.classList.contains('theme-light'))).toBe(scheme === 'light')
    const results = await chipContrasts(page)
    expect(results.length).toBeGreaterThanOrEqual(4)
    for (const r of results) expect(r.ratio, r.label).toBeGreaterThanOrEqual(4.5)
  })
}
