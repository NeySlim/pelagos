// SPDX-License-Identifier: Apache-2.0
// Cluster settings against the mock: one form per domain from the server schema, validation
// before the save, partial saves that persist, view keys, search; exceptions typed by hand.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const scenario = (page, name) => page.request.post('/api/v1/_mock/scenario', { data: { name } }).then((r) => r.json())

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(async ({ page }) => {
  await scenario(page, 'pair')
  expect(errors).toEqual([])
})

test('alert thresholds are validated, saved and kept after a reload', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/settings')
  await expect(page.getByTestId('settings-auth')).toBeVisible()
  await page.getByTestId('settings-tab-checks').click()
  await expect(page).toHaveURL(/section=checks/)
  const checks = page.getByTestId('settings-checks')
  await expect(checks.getByTestId('settings-group-checks-ha')).toBeVisible()
  await expect(checks.getByTestId('settings-group-checks-clock')).toBeVisible()
  await expect(checks.getByTestId('settings-group-checks-certificates')).toBeVisible()

  // Warning above critical: refused before the server sees it.
  await page.getByTestId('setting-checks-pool_warning_percent').fill('97')
  await expect(checks.getByText('Must be lower than “Pool critical”')).toBeVisible()
  await expect(page.getByTestId('settings-save')).toBeDisabled()
  await page.getByTestId('setting-checks-pool_warning_percent').fill('85')
  await page.getByTestId('setting-checks-ha_grace_seconds').fill('120')
  await page.getByTestId('setting-checks-clock_skew_warning_seconds').fill('4')
  await page.getByTestId('setting-checks-cert_warning_days').fill('21')
  await expect(page.getByTestId('settings-changes')).toHaveText('4 changes')
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-changes')).toHaveCount(0)

  await page.reload()
  await expect(page.getByTestId('setting-checks-ha_grace_seconds')).toHaveValue('120')
  await expect(page.getByTestId('setting-checks-cert_warning_days')).toHaveValue('21')
  const saved = await page.request.get('/api/v1/admin/settings').then((r) => r.json())
  expect(saved.checks).toMatchObject({ pool_warning_percent: 85, ha_grace_seconds: 120, clock_skew_warning_seconds: 4, cert_warning_days: 21 })
})

test('RPZ, certificates and DNS view keys have their forms', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/settings?section=rpz')
  await page.getByTestId('setting-rpz-memory_warning_percent').fill('30')
  await page.getByTestId('settings-tab-certificates').click()
  await page.getByTestId('setting-certificates-retry_min_seconds').fill('90000')
  await expect(page.getByText('Between 30 and 86400')).toBeVisible()
  await page.getByTestId('setting-certificates-retry_min_seconds').fill('600')
  await page.getByTestId('settings-tab-dns').click()
  const views = page.getByTestId('setting-dns-view_keys')
  await views.getByTestId('view-key-add').click()
  await views.getByTestId('view-key-view').last().fill('inside')
  await views.getByTestId('view-key-admin').last().fill('ddi-inside')
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-changes')).toHaveCount(0)
  const saved = await page.request.get('/api/v1/admin/settings').then((r) => r.json())
  expect(saved.rpz.memory_warning_percent).toBe(30)
  expect(saved.certificates.retry_min_seconds).toBe(600)
  expect(saved.dns.view_keys).toEqual({ inside: 'ddi-inside' })
})

test('search finds a setting in any section', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/settings')
  await page.getByTestId('settings-search').fill('custom hooks')
  await expect(page.getByTestId('setting-checks-custom_hooks_enabled-field')).toBeVisible()
  await expect(page.getByTestId('settings-auth')).toHaveCount(0)
})

// The language is a saved preference: switched from the menu, then back for the other specs.
async function switchLanguage(page, from, to, lang) {
  await page.getByTestId('user-menu').click()
  await page.getByText(from, { exact: true }).hover()
  await page.getByText(to, { exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', lang)
}

test('the settings screen speaks French', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/settings?section=checks')
  await switchLanguage(page, 'English', 'Français', 'fr')
  await expect(page.getByTestId('settings-checks').getByRole('heading', { name: 'Haute disponibilité' })).toBeVisible()
  await expect(page.getByLabel('Délai de grâce des alertes HA (s)')).toHaveValue('45')
  await page.getByTestId('setting-checks-ha_grace_seconds').fill('5000')
  await expect(page.getByText('Entre 0 et 3600')).toBeVisible()
  await switchLanguage(page, 'Français', 'English', 'en')
})

test('an exception is created by hand and revoked', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts/exceptions')
  await page.getByTestId('exception-new').click()
  const dialog = page.getByTestId('new-exception-dialog')
  await dialog.getByTestId('new-exception-key').fill('mail.example.net.')
  await dialog.getByRole('button', { name: 'Create' }).click()
  await expect(dialog.getByText('Expected like 192.0.2.90|mail.example.net.')).toBeVisible()
  await dialog.getByTestId('new-exception-key').fill('192.0.2.91|relay.example.net.')
  await dialog.getByTestId('new-exception-comment').fill('relay of the provider')
  await dialog.getByRole('button', { name: 'Create' }).click()
  await expect(dialog).toHaveCount(0)
  const row = page.getByTestId('exceptions-table').getByTestId('data-table-row').filter({ hasText: '192.0.2.91|relay.example.net.' })
  await expect(row).toContainText('relay of the provider')
  await row.getByTestId('exception-revoke').click()
  await page.getByRole('button', { name: 'Revoke' }).last().click()
  await expect(row).toHaveCount(0)
})
