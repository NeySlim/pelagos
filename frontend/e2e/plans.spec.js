// SPDX-License-Identifier: Apache-2.0
// The Plans page: an applied plan is found again after its toast is gone, rolled back from the
// page and listed as rolled back; a plan past its window has no button; the audit links the plan.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function csrf(page) {
  return page.evaluate(() => sessionStorage.getItem('pelagos_csrf_token'))
}

// Builds and applies a one-record plan through the API.
async function applyRecord(page, name, rdata) {
  const headers = { 'X-CSRF-Token': await csrf(page) }
  const plan = await (await page.request.post('/api/v1/dns/zones/example.lan/records/plan', {
    headers,
    data: { changes: [{ op: 'add', target: `example.lan./${name}/A`, after: { ttl: 60, rdata: [rdata] } }] },
  })).json()
  const done = await page.request.post(`/api/v1/plans/${plan.id}/apply`, { headers, data: { confirm: true } })
  expect(done.ok()).toBe(true)
  return plan
}

test('an applied plan is found in Plans after its toast, rolled back, then shown as rolled back', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('plansui')
  await page.getByTestId('record-rdata').fill('192.0.2.91')
  const built = page.waitForResponse((r) => r.url().includes('/records/plan') && r.request().method() === 'POST')
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
  const plan = await (await built).json()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')

  // The toast offers both actions; the operator ignores it.
  await expect(page.getByTestId('toast-rollback-plan')).toBeVisible()
  await expect(page.getByTestId('toast-view-plan')).toBeVisible()
  await page.getByTestId('toast-close').first().click()

  await page.goto('/plans')
  await expect(page.getByTestId('page-plans-list')).toBeVisible()
  const row = page.getByTestId('plans-table').getByTestId('data-table-row').filter({ hasText: 'example.lan' }).first()
  await expect(row).toBeVisible()
  await expect(row.getByTestId('plan-rollback-left')).toHaveAttribute('data-status', 'open')
  await row.click()
  await expect(page.getByTestId('plan-detail')).toBeVisible()
  await expect(page.getByTestId('plan-preview')).toContainText(plan.id)
  await expect(page.getByTestId('plan-apply')).toHaveCount(0)
  await page.getByTestId('plan-rollback').click()
  await expect(page.getByTestId('plan-result')).toContainText('Rolled back')
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('plans-table')).toContainText('Rolled back')
  const records = await (await page.request.get('/api/v1/dns/zones/example.lan/records?name=plansui&type=A')).json()
  expect(records.total).toBe(0)
})

test('the toast opens the plan in the Plans page', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('plansview')
  await page.getByTestId('record-rdata').fill('192.0.2.92')
  const built = page.waitForResponse((r) => r.url().includes('/records/plan') && r.request().method() === 'POST')
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
  const plan = await (await built).json()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
  await page.getByTestId('toast-view-plan').click()
  await expect(page).toHaveURL(new RegExp(`/plans\\?id=${plan.id}`))
  await expect(page.getByTestId('plan-detail')).toBeVisible()
  await expect(page.getByTestId('plan-rollback')).toBeVisible()
})

test('a plan past its rollback window has no Roll back button', async ({ page }) => {
  await signIn(page)
  const plan = await applyRecord(page, 'plansold', '192.0.2.93')
  // The mock keeps the window for a day: the reply is aged to show a closed one.
  const aged = (body) => ({ ...body, rollback_until: new Date(Date.now() - 60000).toISOString() })
  await page.route(`**/api/v1/plans/${plan.id}`, async (route) => {
    const res = await route.fetch()
    await route.fulfill({ response: res, json: aged(await res.json()) })
  })
  await page.goto(`/plans?id=${plan.id}`)
  await expect(page.getByTestId('plan-detail')).toBeVisible()
  await expect(page.getByTestId('plan-rollback-closed')).toBeVisible()
  await expect(page.getByTestId('plan-rollback')).toHaveCount(0)
})

test('the audit entries of a plan link back to it', async ({ page }) => {
  await signIn(page)
  const plan = await applyRecord(page, 'plansaudit', '192.0.2.94')
  await page.goto(`/audit?plan_id=${plan.id}`)
  await expect(page.getByTestId('audit-plan-filter')).toContainText(plan.id)
  const table = page.getByTestId('audit-table')
  await expect(table.getByTestId('data-table-row').first()).toBeVisible()
  await table.getByTestId('data-table-row').first().click()
  await page.getByTestId('audit-entry-plan-link').click()
  await expect(page).toHaveURL(new RegExp(`/plans\\?id=${plan.id}`))
  await expect(page.getByTestId('plan-detail')).toBeVisible()
})
