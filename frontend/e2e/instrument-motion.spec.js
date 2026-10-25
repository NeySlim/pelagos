// SPDX-License-Identifier: Apache-2.0
// Instrument budget and legibility: the shared loop stays under 2 ms p95 while the trace
// draws, the new Instrument elements keep WCAG AA in both schemes, and no route scrolls
// sideways at 400px in either scheme.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

const ROUTES = [
  '/', '/dns/zones', '/dns/zones/example.lan', '/dns/resolver', '/dns/acls-keys', '/dns/secondaries', '/dns/dnssec',
  '/dns/rpz', '/dns/catalogs', '/dns/instances', '/dhcp/v4/subnets', '/dhcp/v4/shared-networks', '/dhcp/v4/options',
  '/dhcp/v4/classes', '/dhcp/v4/leases', '/dhcp/v4/reservations', '/dhcp/v4/ha', '/dhcp/v4/ddns', '/dhcp/v4/hooks',
  '/dhcp/v4/stats', '/dhcp/v6/subnets', '/dhcp/v6/leases', '/hosts', '/alerts', '/nodes', '/audit', '/advanced/bind',
  '/advanced/kea', '/advanced/history', '/advanced/ops', '/install', '/install/security', '/admin/users',
  '/admin/roles', '/admin/modules', '/admin/settings', '/account',
]

test('the shared loop stays within 2 ms p95 while the trace draws', async ({ page }) => {
  await signIn(page)
  await expect(page.getByTestId('cluster-trace')).toHaveAttribute('data-running', 'true')
  await page.waitForTimeout(4000)
  const stats = await page.evaluate(() => window.__pelagosLoop())
  expect(stats.running).toBe(true)
  expect(stats.frames).toBeGreaterThan(60)
  expect(stats.p95).toBeLessThan(2)
})

// Worst contrast of every text-bearing descendant of each `selector` against its composited ground.
const worst = (page, selector) =>
  page.locator(selector).evaluateAll((roots) => {
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
    const out = []
    for (const root of roots) {
      for (const el of [root, ...root.querySelectorAll('*')]) {
        const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())
        if (!own || el.closest('.sr-only, svg')) continue
        const cs = getComputedStyle(el)
        if (cs.visibility === 'hidden' || cs.display === 'none') continue
        const bg = ground(el)
        const fg = over(rgba(cs.color), bg)
        const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a)
        out.push({ label: `${el.tagName}.${String(el.className).slice(0, 30)}: ${el.textContent.trim().slice(0, 20)}`, ratio: (hi + 0.05) / (lo + 0.05) })
      }
    }
    return out
  })

for (const scheme of ['dark', 'light']) {
  test.describe(`${scheme} at 1440`, () => {
  test.use({ viewport: { width: 1440, height: 900 } })
  test(`trace, scale bar, readout, DORA and latch text keep AA in ${scheme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await signIn(page)
    const tile = page.getByTestId('tile-trace')
    await expect(tile.getByTestId('trace-dns-rate')).toHaveText(/\d/, { timeout: 20000 })
    await tile.getByTestId('cluster-trace').focus()
    await expect(tile.getByTestId('cluster-trace-readout')).toHaveClass(/is-on/)
    const checks = [
      '[data-testid=trace-values]', '[data-testid=trace-topology]', '[data-testid=cluster-trace-readout]',
      '[data-testid=scalebar]', '[data-testid=trace-range]', '[data-testid=dora]', '[data-testid=incident-trace]',
    ]
    for (const sel of checks) {
      if (!(await page.locator(sel).count())) continue
      for (const r of await worst(page, sel)) expect(r.ratio, `${sel} ${r.label}`).toBeGreaterThanOrEqual(4.5)
    }
    // Always present on the dashboard: values, topology, scale bar.
    for (const sel of ['trace-values', 'trace-topology', 'scalebar']) await expect(page.getByTestId(sel).first()).toBeVisible()
  })
  })
}

test('the plan rail and the alert latches keep AA contrast in both schemes', async ({ page }) => {
  await signIn(page)
  for (const scheme of ['dark', 'light']) {
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/alerts')
    await expect(page.getByTestId('alert-row-ack').first()).toBeVisible()
    for (const r of await worst(page, '[data-testid=incident-trace], .ui-badge')) expect(r.ratio, r.label).toBeGreaterThanOrEqual(4.5)
    await page.goto('/dns/zones/example.lan')
    await expect(page.getByRole('heading').first()).toBeVisible()
    await page.goto('/')
    for (const r of await worst(page, '[data-testid=plan-rail]')) expect(r.ratio, r.label).toBeGreaterThanOrEqual(4.5)
  }
})

test.describe('at 400px', () => {
  test.use({ viewport: { width: 400, height: 860 } })
  for (const scheme of ['dark', 'light']) {
    test(`no route scrolls sideways in ${scheme}`, async ({ page }) => {
      test.setTimeout(240000)
      await page.emulateMedia({ colorScheme: scheme })
      await signIn(page)
      for (const route of ROUTES) {
        await page.goto(route)
        await page.waitForTimeout(400)
        const w = await page.evaluate(() => ({ s: document.documentElement.scrollWidth, c: document.documentElement.clientWidth }))
        expect(w.s, `${route} scrollWidth`).toBeLessThanOrEqual(w.c)
      }
    })
  }
})
