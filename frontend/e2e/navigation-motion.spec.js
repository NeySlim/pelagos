// SPDX-License-Identifier: Apache-2.0
// Navigation choreography: page changes run in a view transition, a zone name travels from
// the list to its page and back, and reduced or off motion has no travel at all.
import { test, expect } from '@playwright/test'
import { setServerFamily, signIn } from './family'

// Records the pseudo-element animations of view transitions seen from now on.
const watch = (page) =>
  page.evaluate(() => {
    window.__vt = { pseudo: new Set(), names: new Set() }
    const tick = () => {
      for (const a of document.getAnimations()) {
        const p = a.effect?.pseudoElement
        if (p) {
          window.__vt.pseudo.add(p)
          window.__vt.names.add(a.animationName)
        }
      }
      window.__vtRaf = requestAnimationFrame(tick)
    }
    tick()
  })
const seen = (page) => page.evaluate(() => ({ pseudo: [...window.__vt.pseudo], names: [...window.__vt.names] }))
const rootData = (page, key) => page.evaluate((k) => document.documentElement.dataset[k], key)

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('a zone name travels from the list to its page and back through the breadcrumb', async ({ page }) => {
  await signIn(page)
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await watch(page)
  await page.getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first().click()
  await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
  await page.waitForTimeout(500)
  let s = await seen(page)
  expect(s.pseudo).toContain('::view-transition-group(zone-title)')
  expect(s.pseudo).toContain('::view-transition-new(main)')
  expect(s.names).toContain('fx-vt-in')
  // No shared name stays behind.
  expect(await page.evaluate(() => [...document.querySelectorAll('*')].filter((e) => e.style.viewTransitionName).length)).toBe(0)

  await watch(page)
  await page.getByTestId('breadcrumb').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.waitForTimeout(500)
  s = await seen(page)
  expect(await rootData(page, 'dir')).toBe('back')
  expect(s.pseudo).toContain('::view-transition-group(zone-title)')
  expect(s.names).toContain('fx-vt-in-back')
})

test('the zones panel travels between the dashboard tile and the list', async ({ page }) => {
  await signIn(page)
  // Visit the list once so its chunk is loaded and its rows are kept.
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.locator('[data-nav="dashboard"]').click()
  await expect(page.getByTestId('tile-zones')).toBeVisible()
  await watch(page)
  await page.getByTestId('tile-zones').getByRole('link', { name: /open/i }).click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.waitForTimeout(500)
  const s = await seen(page)
  expect(s.pseudo).toContain('::view-transition-group(zones-panel)')
})

test('the theme switch cross-fades the whole document', async ({ page }) => {
  await signIn(page)
  await watch(page)
  await page.getByTestId('user-menu').click()
  await page.getByRole('menuitem', { name: /^light$/i }).click()
  await expect.poll(() => rootData(page, 'theme')).toBe('light')
  await page.waitForTimeout(400)
  expect((await seen(page)).pseudo).toContain('::view-transition-new(root)')
  expect(await rootData(page, 'vt')).toBeUndefined()
  await page.getByTestId('user-menu').click()
  await page.getByRole('menuitem', { name: /^dark$/i }).click()
  await expect.poll(() => rootData(page, 'theme')).toBe('dark')
})

test('hovering a column lights its band and header', async ({ page }) => {
  await signIn(page)
  await page.locator('[data-nav="dns-zones"]').click()
  const cell = page.getByTestId('data-table-row').first().locator('td').nth(1)
  await cell.hover()
  const band = page.locator('.fx-colband').first()
  await expect(band).toHaveClass(/is-on/)
  await expect(page.locator('th.is-col-hover')).toHaveCount(1)
  await page.getByTestId('sidebar').hover()
  await expect(band).not.toHaveClass(/is-on/)
})

test('a primary button leans at most one pixel toward the pointer', async ({ page }) => {
  await signIn(page)
  await page.locator('[data-nav="dns-zones"]').click()
  // A running view transition swallows pointer events; wait for it to end.
  await expect.poll(() => rootData(page, 'vt')).toBeUndefined()
  const add = page.getByTestId('zone-add')
  const box = await add.boundingBox()
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await page.mouse.move(box.x + box.width - 2, box.y + box.height / 2, { steps: 3 })
  await expect.poll(() => add.evaluate((el) => parseFloat(el.style.translate))).toBeGreaterThan(0.8)
  expect(await add.evaluate((el) => parseFloat(el.style.translate))).toBeLessThanOrEqual(1)
  await page.mouse.move(5, 5)
  await expect.poll(() => add.evaluate((el) => el.style.translate)).toBe('')
})

test.describe('reduced motion from the system', () => {
  test.use({ reducedMotion: 'reduce' })

  test('pages cross-fade for 100 ms and nothing travels', async ({ page }) => {
    await signIn(page)
    await page.locator('[data-nav="dns-zones"]').click()
    await expect(page.getByTestId('zones-table')).toBeVisible()
    await watch(page)
    await page.getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first().click()
    await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
    await page.waitForTimeout(400)
    const s = await seen(page)
    expect(s.pseudo.some((p) => p.includes('zone-title'))).toBe(false)
    expect(s.names).not.toContain('fx-vt-in')
    expect(s.names).not.toContain('fx-vt-in-back')
    expect(s.names).toContain('fx-vt-in-fade')
    await page.getByTestId('breadcrumb').click()
    await expect(page.getByTestId('zone-add')).toBeVisible()
    await expect.poll(() => rootData(page, 'vt')).toBeUndefined()
    const add = page.getByTestId('zone-add')
    const box = await add.boundingBox()
    await page.mouse.move(box.x + 2, box.y + box.height / 2)
    await page.mouse.move(box.x + box.width - 2, box.y + box.height / 2, { steps: 3 })
    expect(await add.evaluate((el) => el.style.translate)).toBe('')
    expect(await add.evaluate((el) => getComputedStyle(el).translate)).toMatch(/^(none|0px)/)
    await page.goBack()
    await page.waitForTimeout(300)
    expect((await seen(page)).names).not.toContain('fx-vt-in-back')
  })
})

test('with animations off a navigation starts no transition', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('off')
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await watch(page)
  await page.getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first().click()
  await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
  await page.waitForTimeout(400)
  expect((await seen(page)).pseudo).toEqual([])
  expect(await rootData(page, 'vt')).toBeUndefined()
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Full' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('full')
})

// History pops: the replayed view transition obeys the level and the family.
const zoneDetail = async (page) => {
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first().click()
  await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
  await expect.poll(() => rootData(page, 'vt')).toBeUndefined()
}
const countStarts = (page) =>
  page.evaluate(() => {
    window.__starts = 0
    const orig = document.startViewTransition.bind(document)
    document.startViewTransition = (...a) => {
      window.__starts++
      return orig(...a)
    }
  })

test('browser Back runs the directional transition at full, without a root cross-fade', async ({ page }) => {
  await signIn(page)
  await zoneDetail(page)
  await watch(page)
  await page.goBack()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.waitForTimeout(500)
  const s = await seen(page)
  expect(s.pseudo).toContain('::view-transition-new(main)')
  expect(s.pseudo).not.toContain('::view-transition-old(root)')
  expect(s.names).toContain('fx-vt-in-back')
})

test('browser Back starts no transition with animations off', async ({ page }) => {
  await signIn(page)
  await zoneDetail(page)
  await page.evaluate(() => document.documentElement.setAttribute('data-motion', 'off'))
  await countStarts(page)
  await page.goBack()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  expect(await page.evaluate(() => window.__starts)).toBe(0)
})

test.describe('Mission family', () => {
  test.beforeAll(async ({ playwright, baseURL }) => setServerFamily(playwright, baseURL, 'mission'))
  test.afterAll(async ({ playwright, baseURL }) => setServerFamily(playwright, baseURL, 'instrument'))

  test('browser Back starts no transition', async ({ page }) => {
    await signIn(page)
    await page.locator('[data-nav="dns-zones"]').click()
    await expect(page.getByTestId('zones-table')).toBeVisible()
    await page.getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first().click()
    await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
    await countStarts(page)
    await page.goBack()
    await expect(page.getByTestId('zones-table')).toBeVisible()
    expect(await page.evaluate(() => window.__starts)).toBe(0)
  })
})

test('split-horizon zones: only the clicked view travels and nothing errors', async ({ page }) => {
  const logs = []
  page.on('console', (m) => m.type() === 'error' && logs.push(m.text()))
  await page.route('**/api/v1/dns/zones?*', async (route) => {
    const res = await route.fetch()
    const body = await res.json()
    const first = body.items.find((it) => it.zone.name.startsWith('example.lan'))
    if (first && !body.items.some((it) => it.zone.view === 'internal' && it.zone.name === first.zone.name)) {
      body.items.push({ ...first, zone: { ...first.zone, view: 'internal' } })
    }
    await route.fulfill({ response: res, json: body })
  })
  await signIn(page)
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await expect(page.getByTestId('data-table-row').filter({ hasText: /example\.lan.*internal/s })).toHaveCount(1)
  await watch(page)
  await page.getByTestId('data-table-row').filter({ hasText: /example\.lan.*internal/s }).first().click()
  await expect(page.locator('h1.ui-page-title')).toContainText('example.lan')
  await page.waitForTimeout(500)
  expect((await seen(page)).pseudo).toContain('::view-transition-group(zone-title)')
  await page.getByTestId('breadcrumb').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await page.waitForTimeout(500)
  expect(logs.filter((l) => /view-transition|Snapshot|Animation start/i.test(l))).toEqual([])
})
