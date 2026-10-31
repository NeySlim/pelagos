// SPDX-License-Identifier: Apache-2.0
// Phone width keeps page actions, form fields and selects have accessible names,
// and the French UI is French down to dates, relative times and <html lang>.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page).not.toHaveURL(/\/login$/)
}

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test.describe('at 400px', () => {
  test.use({ viewport: { width: 400, height: 800 } })

  test('page actions stay reachable: new subnet, enroll a node', async ({ page }) => {
    await signIn(page)
    await page.goto('/dhcp/v4/subnets')
    await page.getByTestId('subnet-create').click()
    await expect(page.getByTestId('subnet-prefix')).toBeVisible()
    await page.keyboard.press('Escape')
    await page.goto('/nodes')
    await expect(page.getByTestId('enroll-open')).toBeVisible()
  })
})

test('form fields and selects are named', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  await expect(page.getByLabel('Current password')).toHaveAttribute('data-testid', 'password-current')
  await expect(page.getByRole('combobox', { name: /Theme/ })).toBeVisible()
  await page.goto('/dns/zones')
  await expect(page.getByTestId('zones-table')).toBeVisible()
  for (const combo of await page.getByRole('combobox').all()) {
    const name = await combo.evaluate((el) => el.getAttribute('aria-label') || el.getAttribute('aria-labelledby'))
    expect(name).toBeTruthy()
  }
  await page.goto('/admin/modules')
  for (const toggle of await page.getByTestId('modules-nodes').getByRole('switch').all()) {
    expect(await toggle.getAttribute('aria-label')).toBeTruthy()
  }
})

test('the French UI shows French dates and relative times', async ({ page }) => {
  await signIn(page)
  await page.getByTestId('user-menu').click()
  await page.getByText('English').hover()
  await page.getByText('Français').click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr')
  await page.goto('/nodes')
  await expect(page.getByTestId('nodes-table')).toBeVisible()
  await expect(page.getByTestId('nodes-table')).not.toContainText(/ ago|just now/)
  await page.goto('/alerts')
  await expect(page.getByTestId('alerts-table').getByTestId('data-table-row').first()).toBeVisible()
  await expect(page.getByTestId('alerts-table')).not.toContainText(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d/)
  // The mock keeps preferences across tests: back to English for the next specs.
  await page.getByTestId('user-menu').click()
  await page.getByText('Français').hover()
  await page.getByText('English').click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
})

test.describe('at 390px', () => {
  test.use({ viewport: { width: 390, height: 800 } })

  // Header tabs keep their text on a phone and scroll sideways; the page itself never does.
  test('header tabs keep their text and the page has no horizontal scroll', async ({ page }) => {
    await signIn(page)
    await page.goto('/hosts')
    const tabs = page.locator('.ui-tabs .ui-tab')
    await expect(tabs.first()).toBeVisible()
    for (const tab of await tabs.all()) {
      await expect(tab.locator('span').first()).toBeVisible()
      expect(((await tab.textContent()) || '').trim().length).toBeGreaterThan(0)
      expect(await tab.getAttribute('title')).toBeTruthy()
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  })

  // A table that opts into mobileCard renders as cards: nothing scrolls sideways.
  test('tables with mobile cards do not scroll horizontally', async ({ page }) => {
    await signIn(page)
    for (const path of ['/hosts', '/dns/zones', '/nodes', '/alerts']) {
      await page.goto(path)
      await expect(page.getByTestId('page-stagger')).toBeVisible()
      for (const cards of await page.getByTestId('data-table-cards').all()) {
        expect(await cards.evaluate((el) => el.parentElement.scrollWidth <= el.parentElement.clientWidth)).toBe(true)
      }
    }
  })
})
