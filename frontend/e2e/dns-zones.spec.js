// SPDX-License-Identifier: Apache-2.0
// Zone modes and edits, catalog members, DNSSEC policies and key operations, and the
// advanced BIND editor writing to a managed file, against the mock server.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function applyPlan(page) {
  const preview = page.getByTestId('plan-preview')
  await expect(preview).toBeVisible()
  const confirm = preview.getByTestId('plan-confirm-checkbox')
  if (await confirm.count()) await confirm.check()
  await preview.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
}

test('a static zone says how it is written and offers the conversion', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones')
  const row = page.getByTestId('zones-table').getByTestId('data-table-row').filter({ hasText: 'rpz.example.lan.' })
  await expect(row.getByTestId('zone-mode')).toHaveText('Static file')
  await page.goto('/dns/zones/rpz.example.lan')
  await expect(page.getByTestId('zone-static-note')).toContainText('rndc freeze')
  await page.getByTestId('zone-more').click()
  await page.getByTestId('zone-convert').click()
  await expect(page.getByTestId('plan-preview')).toContainText('security/bind:static_zone:_default/rpz.example.lan.')
})

test('deleting a Pelagos primary also removes the peers\' secondary copies', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/lab.example.lan')
  await page.getByTestId('zone-delete').click()
  const dialog = page.getByTestId('confirm-dialog')
  await expect(dialog).toContainText('Also remove the secondary copies on')
  await expect(dialog.getByTestId('zone-delete-peers')).toBeChecked()
  const request = page.waitForRequest((r) => r.url().endsWith('/dns/zones/plan') && r.method() === 'POST')
  await dialog.getByRole('button', { name: 'Delete zone' }).click()
  const body = (await request).postDataJSON()
  expect(body.change.op).toBe('delete')
  expect(body.node_ids?.length).toBeGreaterThan(0)
  await expect(page.getByTestId('plan-preview')).toBeVisible()
})

test('the zone header keeps the zone name visible in French at 1280px', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 })
  await signIn(page)
  await page.getByTestId('user-menu').click()
  await page.getByText('English').hover()
  await page.getByText('Français').click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr')
  await page.goto('/dns/zones/lab.example.lan')
  const title = page.getByTestId('page-dns-zoneDetail').locator('h1').first()
  await expect(title).toHaveText('lab.example.lan.')
  const fits = await title.evaluate((el) => el.scrollWidth <= el.clientWidth + 1 && el.clientWidth > 0)
  expect(fits).toBe(true)
  await page.getByTestId('user-menu').click()
  await page.getByText('Français').hover()
  await page.getByText('English').click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
})

test('a Pelagos zone is edited through a replace plan', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/lab.example.lan')
  await page.getByTestId('zone-edit-open').click()
  await page.getByTestId('zone-edit-also_notify').fill('192.0.2.54')
  await page.getByTestId('zone-edit').getByRole('button', { name: 'Preview the plan' }).click()
  await expect(page.getByTestId('plan-preview')).toBeVisible()
  await expect(page.getByTestId('plan-diff')).toContainText('192.0.2.54')
})

test('a member is added to a producer catalog', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/catalogs')
  const producer = page.getByTestId('catalog-card').filter({ hasText: 'catalog.example.lan.' })
  await producer.getByTestId('catalog-add-member').click()
  await page.getByTestId('catalog-member-input').fill('new.example.lan')
  await page.getByTestId('catalog-add').getByRole('button', { name: 'Preview the plan' }).click()
  await applyPlan(page)
  await expect(producer.getByTestId('catalog-members')).toContainText('new.example.lan.')
  await expect(page.getByTestId('catalog-card').filter({ hasText: 'catalog.partner.example.' }).getByTestId('catalog-add-member')).toHaveCount(0)
})

test('a dnssec-policy is created and a key rollover is planned', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/dnssec?zone=lab.example.lan.')
  await page.getByTestId('dnssec-policy-add').click()
  const modal = page.getByTestId('dnssec-policy-modal')
  await modal.getByTestId('dnssec-policy-name').fill('slow')
  await expect(modal).toContainText('Allowed statements')
  const body = modal.getByTestId('dnssec-policy-text')
  const original = await body.inputValue()
  await body.fill(`${original}\nbogus 1;`)
  await modal.getByRole('button', { name: 'Preview the plan' }).click()
  await expect(modal).toContainText('bogus is not a dnssec-policy statement')
  await body.fill(original)
  await modal.getByRole('button', { name: 'Preview the plan' }).click()
  await applyPlan(page)
  await expect(page.getByTestId('dnssec-policies')).toContainText('slow')
  await expect(page.getByTestId('dnssec-guidance')).toContainText('publish this DS')
  await page.getByTestId('dnssec-rollover').first().click()
  await expect(page.getByTestId('plan-preview')).toContainText('rndc dnssec -rollover -key 48217 lab.example.lan')
})

test('the BIND editor adds a logging block to a managed file', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/bind')
  const keysFile = page.getByTestId('bind-tree').locator('div.mb-2').filter({ hasText: '/etc/bind/pelagos/keys.conf' })
  await keysFile.getByTestId('bind-add-top').click()
  const add = page.getByTestId('statement-add')
  await add.getByRole('combobox').click()
  await page.getByRole('option', { name: 'logging', exact: true }).click()
  await add.getByTestId('statement-add-submit').click()
  await expect(page.getByTestId('bind-changes')).toContainText('raw:/etc/bind/pelagos/keys.conf')
  await page.getByTestId('bind-plan').click()
  await expect(page.getByTestId('plan-preview')).toBeVisible()
})

test('the zone page names its zone and lists records as cards at phone width', async ({ page }) => {
  await signIn(page)
  await page.setViewportSize({ width: 400, height: 800 })
  await page.goto('/dns/zones/example.lan')
  await expect(page.getByRole('heading', { name: 'example.lan.' })).toBeVisible()
  await expect(page.getByTestId('record-card').first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Status per node' })).toBeVisible()
})
