// SPDX-License-Identifier: Apache-2.0
// Tile ambient layers: canvases driven by the live rates, registration marks and a refresh
// sweep, gated by the ambient preference and the motion level, on the one shared loop.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const rootData = (page, key) => page.evaluate((k) => document.documentElement.dataset[k], key)
const style = (locator, prop) => locator.evaluate((el, p) => getComputedStyle(el)[p], prop)

// True when the canvas holds at least one painted (non transparent) pixel.
const painted = (locator) =>
  locator.evaluate((cv) => {
    const data = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height).data
    for (let i = 3; i < data.length; i += 4) if (data[i] > 0) return true
    return false
  })

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('tiles carry canvas layers and registration marks, and the loop runs while they move', async ({ page }) => {
  await signIn(page)
  const dns = page.getByTestId('tile-dns')
  await expect(dns.getByTestId('ambient-wave')).toBeAttached()
  await expect(page.getByTestId('tile-dhcp').getByTestId('ambient-spectrum')).toBeAttached()
  await expect(page.getByTestId('tile-radar').getByTestId('ambient-dots')).toBeAttached()
  await expect(dns.getByTestId('reg-marks')).toBeAttached()
  await expect.poll(() => painted(dns.getByTestId('ambient-wave'))).toBe(true)
  await expect.poll(() => painted(page.getByTestId('tile-radar').getByTestId('ambient-dots'))).toBe(true)
  // The layers sit under the data and never take the pointer.
  expect(await style(dns.getByTestId('ambient-tile'), 'pointerEvents')).toBe('none')
  const before = await page.evaluate(() => window.__pelagosLoop().frames)
  await page.waitForTimeout(600)
  expect(await page.evaluate(() => window.__pelagosLoop().frames)).toBeGreaterThan(before)
})

test('ambient off removes every layer', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  const setAmbient = async (name) => {
    await page.getByTestId('pref-ambient').getByRole('combobox').click()
    await page.getByRole('option', { name }).click()
    await expect.poll(() => rootData(page, 'ambient')).toBe(name.toLowerCase())
  }
  await setAmbient('Off')
  // Nothing else animates on this page: the ambient animator has left the shared loop.
  await expect.poll(() => page.evaluate(() => window.__pelagosLoop().active)).toBe(0)
  try {
    await page.goto('/')
    await expect(page.getByTestId('tile-dns')).toBeVisible()
    for (const id of ['ambient-screen', 'ambient-tile', 'ambient-wave', 'ambient-spectrum', 'ambient-dots', 'reg-marks', 'tile-sweep']) {
      await expect(page.getByTestId(id), id).toHaveCount(0)
    }
  } finally {
    // The mock keeps preferences for the whole run: put the default back.
    await page.goto('/account')
    await setAmbient('On')
  }
})

test('animations off: layers hold one still frame, no ping, no sweep, no loop', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  const setMotion = async (name, value) => {
    await page.getByTestId('pref-animations').getByRole('combobox').click()
    await page.getByRole('option', { name }).click()
    await expect.poll(() => rootData(page, 'motion')).toBe(value)
  }
  await setMotion('Off', 'off')
  try {
    await page.goto('/')
    const wave = page.getByTestId('tile-dns').getByTestId('ambient-wave')
    await expect.poll(() => painted(wave)).toBe(true)
    const first = await wave.evaluate((cv) => cv.toDataURL())
    await page.waitForTimeout(1000)
    expect(await wave.evaluate((cv) => cv.toDataURL())).toBe(first)
    expect((await page.evaluate(() => window.__pelagosLoop())).active).toBe(0)
    await expect(page.locator('.fx-sweep.is-go, .fx-regs.is-ping')).toHaveCount(0)
  } finally {
    await page.goto('/account')
    await setMotion('Full', 'full')
  }
})

test('the registration marks do not ping on live samples alone', async ({ page }) => {
  await signIn(page)
  await expect(page.getByTestId('tile-dns').getByTestId('reg-marks')).toBeAttached()
  // Let the first-load sweep finish, then watch across two live samples (4 s each).
  await page.waitForTimeout(1500)
  await page.evaluate(() => {
    window.__pings = 0
    new MutationObserver((list) => {
      for (const m of list) if (m.target.classList?.contains('is-ping') || [...m.addedNodes].some((n) => n.classList?.contains('is-ping'))) window.__pings += 1
    }).observe(document.querySelector('[data-testid="dashboard-grid"]'), { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] })
  })
  await page.waitForTimeout(9000)
  expect(await page.evaluate(() => window.__pings)).toBe(0)
})

test.describe('reduced motion and ambient layers', () => {
  test.use({ reducedMotion: 'reduce' })

  test('draws one static frame and joins no loop', async ({ page }) => {
    await signIn(page)
    const wave = page.getByTestId('tile-dns').getByTestId('ambient-wave')
    await expect(wave).toBeAttached()
    await expect.poll(() => painted(wave)).toBe(true)
    const snapshot = () => wave.evaluate((cv) => cv.toDataURL())
    const first = await snapshot()
    const before = await page.evaluate(() => window.__pelagosLoop())
    await page.waitForTimeout(1000)
    const after = await page.evaluate(() => window.__pelagosLoop())
    expect(after.active).toBe(0)
    expect(after.frames).toBe(before.frames)
    expect(await snapshot()).toBe(first)
    await expect(page.locator('.fx-sweep.is-go, .fx-regs.is-ping')).toHaveCount(0)
  })

  test('the wave is visible through the query panel, not hidden under it', async ({ page }) => {
    await signIn(page)
    const panel = page.getByTestId('tile-dns').locator('.dash-subpanel')
    const wave = panel.getByTestId('ambient-wave')
    await expect.poll(() => painted(wave)).toBe(true)
    await page.waitForTimeout(500)
    const shot = () => panel.screenshot({ animations: 'disabled' })
    const on = await shot()
    expect((await shot()).equals(on)).toBe(true)
    await wave.evaluate((cv) => { cv.style.visibility = 'hidden' })
    expect((await shot()).equals(on)).toBe(false)
  })
})
