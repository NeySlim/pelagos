// SPDX-License-Identifier: Apache-2.0
// Instrument is the default family: materials without glass, IBM Plex, neutral actions, a
// nav cursor and a tab ink that glide, an ambient graticule under the data, the boot
// cascade once per session, and the motion and ambient preferences enforced everywhere.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const rootData = (page, key) => page.evaluate((k) => document.documentElement.dataset[k], key)
const style = (locator, prop, pseudo) => locator.evaluate((el, [p, ps]) => getComputedStyle(el, ps)[p], [prop, pseudo])
const translateY = (t) => Number(/matrix\(.*,\s*([-\d.]+)\)$/.exec(t)?.[1] ?? NaN)

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('Instrument is the default: plain materials, Plex faces, neutral primary action', async ({ page }) => {
  await signIn(page)
  expect(await rootData(page, 'effects')).toBe('instrument')
  expect(await rootData(page, 'ambient')).toBe('on')
  await expect(page.getByTestId('app-backdrop')).toHaveCount(0)
  await expect(page.getByTestId('ambient-screen')).toBeAttached()
  expect(await style(page.getByTestId('sidebar'), 'backdropFilter')).toBe('none')
  expect(await style(page.locator('.ui-page-title').first(), 'fontFamily')).toContain('IBM Plex Sans')
  await expect.poll(() => page.evaluate(() => document.fonts.check('13px "IBM Plex Sans"') && document.fonts.check('12px "IBM Plex Mono"'))).toBe(true)
  // The page header has no colored icon tile, and labels are not spaced capitals.
  await expect(page.locator('.ui-page-icon').first()).toBeHidden()
  await page.goto('/dns/zones/example.lan')
  const add = page.getByTestId('record-add')
  await expect(add).toBeVisible()
  const [bg, contrast] = await add.evaluate((el) => [getComputedStyle(el).backgroundColor, getComputedStyle(document.documentElement).getPropertyValue('--contrast-bg').trim()])
  const probe = await page.evaluate((c) => {
    const el = document.createElement('div')
    el.style.color = c
    document.body.appendChild(el)
    const v = getComputedStyle(el).color
    el.remove()
    return v
  }, contrast)
  expect(bg).toBe(probe)
  expect(await style(page.locator('h1.ui-page-title'), 'fontFamily')).toContain('IBM Plex Mono')
})

test('the nav cursor glides to the active entry and the tab ink follows the tab', async ({ page }) => {
  await signIn(page)
  const cursor = page.getByTestId('nav-cursor')
  await expect(cursor).toHaveClass(/is-placed/)
  const onDashboard = translateY(await style(cursor, 'transform'))
  expect(await style(cursor, 'transitionTimingFunction')).toContain('linear(')
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('zones-table')).toBeVisible()
  await expect.poll(async () => translateY(await style(cursor, 'transform'))).toBeGreaterThan(onDashboard + 20)
  const zones = await page.locator('[data-nav="dns-zones"]').boundingBox()
  const nav = await page.locator('.ui-nav').boundingBox()
  await expect.poll(async () => Math.abs(translateY(await style(cursor, 'transform')) + nav.y - (zones.y + zones.height / 2 - 8))).toBeLessThan(3)

  await page.goto('/dns/zones/example.lan')
  const ink = page.getByTestId('tab-ink').first()
  await expect(ink).toHaveClass(/is-placed/)
  const tab = page.getByRole('button', { name: 'Status per node' })
  await tab.click()
  const box = await tab.boundingBox()
  await expect.poll(async () => {
    const r = await ink.boundingBox()
    return Math.abs(r.x - box.x) < 2 && Math.abs(r.width - box.width) < 2
  }).toBe(true)
})

test('the ambient preference switches the graticule off and is kept', async ({ page }) => {
  await signIn(page)
  const grid = page.locator('.fx-ambient-grid')
  expect(await style(grid, 'animationPlayState')).toContain('running')
  expect(await style(grid, 'animationName')).toContain('fx-paper-drift')
  await page.goto('/account')
  await page.getByTestId('pref-ambient').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect.poll(() => rootData(page, 'ambient')).toBe('off')
  await expect(page.getByTestId('ambient-screen')).toBeHidden()
  await page.reload()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  expect(await rootData(page, 'ambient')).toBe('off')
  await page.getByTestId('pref-ambient').getByRole('combobox').click()
  await page.getByRole('option', { name: 'On' }).click()
  await expect.poll(() => rootData(page, 'ambient')).toBe('on')
  await expect(page.getByTestId('ambient-screen')).toBeVisible()
})

test('the chrome lights up once per session', async ({ page }) => {
  await page.addInitScript(() => {
    window.__bootSeen = false
    new MutationObserver(() => {
      if (document.documentElement.classList.contains('boot')) window.__bootSeen = true
    }).observe(document, { attributes: true, subtree: true, attributeFilter: ['class'] })
  })
  await signIn(page)
  await expect.poll(() => page.evaluate(() => window.__bootSeen)).toBe(true)
  expect(await style(page.locator('.ui-nav-section').first(), 'animationName')).toMatch(/fx-rise|none/)
  await page.reload()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.waitForTimeout(300)
  expect(await page.evaluate(() => window.__bootSeen)).toBe(false)
})

test('dialogs and menus enter from their origin and leave', async ({ page }) => {
  await signIn(page)
  await page.getByTestId('user-menu').click()
  const menu = page.locator('.ui-menu').first()
  await expect(menu).toBeVisible()
  expect(await style(menu, 'animationName')).toBe('fx-pop-in')
  expect(await style(menu, 'backdropFilter')).toBe('none')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  const modal = page.locator('.ui-modal')
  await expect(modal).toBeVisible()
  expect(await style(modal, 'animationName')).toBe('fx-dialog-in')
  expect(await style(page.locator('.modal-backdrop'), 'backdropFilter')).toBe('none')
  await page.keyboard.press('Escape')
  await expect(modal).toHaveCount(0)
})

test('motion off removes every transition, the cursor jumps', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('off')
  expect(await style(page.getByTestId('nav-cursor'), 'transitionDuration')).toBe('0s')
  expect(await style(page.getByTestId('page-transition'), 'animationName')).toBe('none')
  expect(await style(page.locator('.fx-ambient-grid'), 'animationName')).toBe('none')
  await page.reload()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  expect(await rootData(page, 'motion')).toBe('off')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Full' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('full')
})

test.describe('reduced motion from the system', () => {
  test.use({ reducedMotion: 'reduce' })

  test('holds the ambient frame, stops travel and runs no animation loop', async ({ page }) => {
    await signIn(page)
    expect(await rootData(page, 'motion')).toBe('reduced')
    expect(await style(page.locator('.fx-ambient-grid'), 'animationName')).toBe('none')
    expect(parseFloat(await style(page.getByTestId('nav-cursor'), 'transitionDuration'))).toBeLessThan(0.01)
    const before = await page.evaluate(() => window.__pelagosLoop?.() ?? { active: 0, frames: 0 })
    await page.waitForTimeout(1000)
    const after = await page.evaluate(() => window.__pelagosLoop?.() ?? { active: 0, frames: 0 })
    expect(after.active).toBe(0)
    expect(after.frames).toBe(before.frames)
  })
})

for (const scheme of ['dark', 'light']) {
  test.describe(`at 400px, ${scheme}`, () => {
    test.use({ viewport: { width: 400, height: 860 }, colorScheme: scheme })

    test('the Instrument shell fits a phone without horizontal scroll', async ({ page }) => {
      await signIn(page)
      for (const path of ['/', '/dns/zones/example.lan', '/dhcp/v4/leases', '/alerts']) {
        await page.goto(path)
        await expect(page.locator('.ui-topbar')).toBeVisible()
        await page.waitForTimeout(400)
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
        expect(overflow, path).toBeLessThanOrEqual(0)
      }
      expect(await rootData(page, 'effects')).toBe('instrument')
    })
  })
}
