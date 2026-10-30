// SPDX-License-Identifier: Apache-2.0
// PTR next to its A in the record editor, the orphan PTR page and the "Ignore: admin's choice"
// exceptions, against the mock server.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const reverse = (page, name) =>
  page.request.get(`/api/v1/dns/zones/2.0.192.in-addr.arpa/records?name=${name}&type=PTR`).then((r) => r.json())

test('an A record and its PTR go in one plan, and roll back together', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('e2e-ptr')
  await page.getByTestId('record-rdata').fill('192.0.2.79')
  await expect(page.getByTestId('record-ptr-sync')).toBeChecked()
  await expect(page.getByTestId('record-ptr-help')).toContainText('2.0.192.in-addr.arpa.')
  const request = page.waitForRequest((r) => r.url().includes('/records/plan') && r.method() === 'POST')
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
  expect((await request).postDataJSON().ptr).toEqual({ sync: true, delete: true })
  const preview = page.getByTestId('plan-preview')
  await expect(preview.getByTestId('plan-changes')).toContainText('79.2.0.192.in-addr.arpa.')
  await preview.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  expect((await reverse(page, '79.2.0.192.in-addr.arpa.')).items[0].rdata).toEqual(['e2e-ptr.example.lan.'])
  await page.getByTestId('plan-rollback').click()
  await expect(page.getByTestId('plan-result')).toContainText('Rolled back')
  expect((await reverse(page, '79.2.0.192.in-addr.arpa.')).total).toBe(0)
})

test('an address outside every reverse zone leaves the PTR option off with the reason', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('e2e-far')
  await page.getByTestId('record-rdata').fill('203.0.113.9')
  await expect(page.getByTestId('record-ptr-help')).toContainText('No reverse zone served by the cluster covers this address')
  await expect(page.getByTestId('record-ptr-sync')).toBeDisabled()
})

test('an orphan PTR is listed and deleted through a plan', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/ptr-orphans')
  const table = page.getByTestId('orphans-table')
  const row = table.getByTestId('data-table-row').filter({ hasText: 'workstation7.example.lan.' })
  await expect(row).toContainText('192.0.2.106')
  // No lease, reservation or IPv6 observation holds the address under that name: no A to offer.
  await expect(row.getByTestId('orphan-create')).toHaveCount(0)
  await row.getByTestId('orphan-select').check()
  await page.getByTestId('orphans-delete-selected').click()
  const preview = page.getByTestId('plan-preview')
  await expect(preview.getByTestId('plan-changes')).toContainText('106.2.0.192.in-addr.arpa.')
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
  await expect(table.getByTestId('data-table-row').filter({ hasText: 'workstation7.example.lan.' })).toHaveCount(0)
})

test('an inconsistency is ignored with a comment, listed, then revoked', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts')
  await page.getByTestId('alerts-table').getByText('old-nas.example.lan.').first().click()
  await page.getByTestId('alert-ignore').click()
  const dialog = page.getByTestId('ignore-dialog')
  await expect(dialog).toContainText('old-nas.example.lan./A')
  await page.getByTestId('ignore-comment').fill('decommissioned NAS kept for the archive')
  await dialog.getByRole('button', { name: 'Ignore' }).click()
  await page.goto('/alerts/exceptions')
  const row = page.getByTestId('exceptions-table').getByTestId('data-table-row').filter({ hasText: 'old-nas.example.lan./A' })
  await expect(row).toContainText('decommissioned NAS kept for the archive')
  await expect(row).toContainText('admin')
  await row.getByTestId('exception-revoke').click()
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByTestId('exceptions-table').getByTestId('data-table-row').filter({ hasText: 'old-nas.example.lan./A' })).toHaveCount(0)
})
