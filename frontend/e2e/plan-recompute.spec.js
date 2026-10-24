// SPDX-License-Identifier: Apache-2.0
// A plan the server no longer holds (expired, or forgotten by a restart) is
// recomputed from the same inputs in PlanPreview, then applied.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('a forgotten record plan is recomputed, then applied', async ({ page }) => {
  await signIn(page)
  const records = () => page.request.get('/api/v1/dns/zones/example.lan/records?name=recompute&type=A').then((r) => r.json())
  expect((await records()).total).toBe(0)

  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('recompute')
  await page.getByTestId('record-rdata').fill('192.0.2.78')
  const built = page.waitForResponse((r) => r.url().includes('/records/plan') && r.request().method() === 'POST')
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
  const first = await (await built).json()
  await expect(page.getByTestId('plan-preview')).toBeVisible()

  // The server forgets the plan, as after a restart: apply answers 404.
  const csrf = await page.evaluate(() => sessionStorage.getItem('pelagos_csrf_token'))
  expect((await page.request.delete(`/api/v1/plans/${first.id}`, { headers: { 'X-CSRF-Token': csrf } })).ok()).toBe(true)
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-gone')).toBeVisible()
  expect((await records()).total).toBe(0)

  const rebuilt = page.waitForResponse((r) => r.url().includes('/records/plan') && r.request().method() === 'POST')
  await page.getByTestId('plan-recompute').click()
  const second = await (await rebuilt).json()
  expect(second.id).not.toBe(first.id)
  await expect(page.getByTestId('plan-gone')).toHaveCount(0)
  await expect(page.getByTestId('plan-preview')).toContainText(second.id)
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  expect((await records()).total).toBe(1)
})
