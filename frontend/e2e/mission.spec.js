// SPDX-License-Identifier: Apache-2.0
// Mission Control is the default family and drives the effects layer; the animation
// preference (Account > Preferences) reaches data-motion and survives a reload.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const rootData = (page, key) => page.evaluate((k) => document.documentElement.dataset[k], key)

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('Mission Control is the default family, with glass panels over the backdrop', async ({ page }) => {
  await signIn(page)
  expect(await rootData(page, 'effects')).toBe('mission')
  await expect(page.getByTestId('app-backdrop')).toBeAttached()
  const sidebar = page.getByTestId('sidebar')
  const blur = await sidebar.evaluate((el) => getComputedStyle(el).backdropFilter)
  expect(blur).toContain('blur')
  const font = await page.locator('.ui-page-title').first().evaluate((el) => getComputedStyle(el).fontFamily)
  expect(font).toContain('Michroma')
  // The display face is self-hosted and actually loads.
  await expect.poll(() => page.evaluate(() => document.fonts.check('12px Michroma'))).toBe(true)
})

test('the Mission dashboard tiles enter staggered', async ({ page }) => {
  await signIn(page)
  await page.goto('/')
  await expect(page.getByTestId('tile-nodes')).toBeVisible()
  const entries = await page.locator('.fx-stagger-item').evaluateAll((els) =>
    els.map((el) => ({ name: getComputedStyle(el).animationName, delay: parseFloat(getComputedStyle(el).animationDelay) })),
  )
  expect(entries.length).toBeGreaterThanOrEqual(3)
  expect(entries.every((e) => e.name === 'fx-rise')).toBe(true)
  expect(new Set(entries.map((e) => e.delay)).size).toBe(entries.length)
  // The active nav entry carries no ember alert dot.
  const indicator = await page.locator('.ui-nav-indicator').first().evaluate((el) => getComputedStyle(el).boxShadow)
  expect(indicator).toBe('none')
})

test('the sign-in page shows the radar scene behind an unblurred card', async ({ page }) => {
  await page.goto('/login')
  await expect(page.getByTestId('login-scene')).toBeAttached()
  const blur = await page.getByTestId('login-form').evaluate((el) => getComputedStyle(el).backdropFilter)
  expect(blur).toBe('none')
})

test('the dashboard hero draws the cluster radar and live rates', async ({ page }) => {
  await signIn(page)
  await page.goto('/')
  const radar = page.getByTestId('cluster-radar')
  await expect(radar.getByTestId('radar-node')).toHaveCount(2)
  await expect(radar.getByTestId('radar-ha-pill').first()).toBeVisible()
  await expect(radar.getByTestId('radar-link')).toHaveCount(1)
  // The sweep and the tick ring turn at full motion.
  const sweep = await radar.locator('.radar-sweep').evaluate((el) => getComputedStyle(el).animationName)
  expect(sweep).toBe('fx-spin')
  // Two polls of the mock's growing counters give a query rate, on the tile and the pins.
  await expect(page.getByTestId('dns-rate').locator('.sr-only')).toHaveText(/^[1-9][\d,.]*$/, { timeout: 20000 })
  await expect(page.getByTestId('tile-dns').getByTestId('stippled-area-chart')).toBeVisible()
  await expect(radar.getByTestId('radar-node').first()).toContainText('q/s')
  await expect(page.getByTestId('tile-dhcp').getByTestId('dhcp-pool').first()).toBeVisible()
})

test('a zone page keeps the DNS name case in the display title', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/lab.example.lan')
  const title = page.locator('h1.ui-page-title')
  await expect(title).toHaveText('lab.example.lan.')
  await expect(title).toHaveClass(/ui-title-literal/)
  expect(await title.evaluate((el) => getComputedStyle(el).textTransform)).toBe('none')
})

test('another family turns the effects layer off', async ({ page }) => {
  await signIn(page)
  await page.getByTestId('user-menu').click()
  await page.locator('[data-theme-option="gray"]').click()
  await expect.poll(() => rootData(page, 'effects')).toBe('none')
  await expect(page.getByTestId('app-backdrop')).toHaveCount(0)
  const blur = await page.getByTestId('sidebar').evaluate((el) => getComputedStyle(el).backdropFilter)
  expect(blur).toBe('none')
  // The mock keeps preferences for the run: put the default back.
  await page.getByTestId('user-menu').click()
  await page.locator('[data-theme-option="mission"]').click()
  await expect.poll(() => rootData(page, 'effects')).toBe('mission')
})

test('the animations preference sets the motion level and is kept', async ({ page }) => {
  await signIn(page)
  expect(await rootData(page, 'motion')).toBe('full')
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('off')
  const anim = await page.getByTestId('page-transition').evaluate((el) => getComputedStyle(el).animationName)
  expect(anim).toBe('none')
  await page.reload()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  expect(await rootData(page, 'motion')).toBe('off')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Full' }).click()
  await expect.poll(() => rootData(page, 'motion')).toBe('full')
})

test.describe('reduced motion from the system', () => {
  test.use({ reducedMotion: 'reduce' })

  test('lowers a full preference to reduced and stops loops', async ({ page }) => {
    await signIn(page)
    expect(await rootData(page, 'motion')).toBe('reduced')
    const pulse = await page.getByTestId('ws-dot').evaluate((el) => getComputedStyle(el, '::after').animationName)
    expect(pulse).toBe('none')
    await page.goto('/')
    const sweep = page.getByTestId('cluster-radar').locator('.radar-sweep')
    await expect(sweep).toBeAttached()
    expect(await sweep.evaluate((el) => getComputedStyle(el).animationName)).toBe('none')
  })
})

test.describe('at 400px', () => {
  test.use({ viewport: { width: 400, height: 800 } })

  test('the mission shell fits a phone without horizontal scroll', async ({ page }) => {
    await page.goto('/login')
    await page.getByTestId('login-username').fill('admin')
    await page.getByTestId('login-password').fill('admin')
    await page.getByTestId('login-submit').click()
    await page.goto('/dhcp/v4/subnets')
    await expect(page.getByTestId('subnets-table')).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
    expect(await rootData(page, 'effects')).toBe('mission')
  })
})
