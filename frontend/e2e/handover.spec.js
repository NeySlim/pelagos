// SPDX-License-Identifier: Apache-2.0
// Hand over to Pelagos: options, keys and a zone set in the user's own files move to the
// managed files through one plan, against the mock server.
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

test('the resolver screen hands every option over in one plan', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/resolver')
  const card = page.getByTestId('handover-options')
  await expect(card.getByTestId('handover-item')).toHaveCount(2)
  const request = page.waitForRequest((r) => r.url().endsWith('/dns/config/plan') && r.method() === 'POST')
  await card.getByTestId('handover-options-all').click()
  const body = (await request).postDataJSON()
  expect(body.changes.map((c) => c.target)).toEqual(['handover/options/max-ncache-ttl', 'handover/options/minimal-responses'])
  expect(body.node_ids.length).toBeGreaterThan(0)
  await expect(page.getByTestId('plan-preview')).toContainText('options.conf')
  await applyPlan(page)
  await expect(page.getByTestId('handover-options')).toHaveCount(0)
})

test('a key and a zone are handed over one at a time', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/acls-keys')
  await page.getByText('TSIG keys', { exact: true }).click()
  await page.getByTestId('handover-keys').getByTestId('handover-one').click()
  await applyPlan(page)
  await expect(page.getByTestId('handover-keys')).toHaveCount(0)

  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('zone-handover').click()
  await expect(page.getByTestId('plan-preview')).toContainText('zones.conf')
  await applyPlan(page)
  await expect(page.getByTestId('zone-handover')).toHaveCount(0)
})
