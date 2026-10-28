// SPDX-License-Identifier: Apache-2.0
// The Failover tab on a real pair whose primary's named is stopped (tests/lab/test_ddns_failover_lab.py):
// the outage banner, the zones still prepared, the promotion of the copy from the banner.
import { test, expect } from '@playwright/test'

const { LAB_PASSWORD, FROM, TO } = process.env
const zoneRow = (page, zone) => page.getByTestId('ddns-zones').locator('tr', { has: page.locator(`[data-zone-row="${zone}"]`) })

test('promotes the copy from the outage banner', async ({ page }) => {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill(LAB_PASSWORD)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.goto('/dhcp/v4/ddns?tab=failover')
  const row = zoneRow(page, '_default/example.lan.')
  await expect(row).toContainText(new RegExp(`example\\.lan\\.\\s*${FROM}`), { timeout: 60000 })
  const banner = page.getByTestId('ddns-outage-banner')
  await expect(async () => {
    await page.getByTestId('page-refresh').click()
    await expect(banner).toBeVisible({ timeout: 30000 })
  }).toPass({ timeout: 180000 })
  await expect(row.getByTestId('ddns-zone-state')).toHaveAttribute('data-state', 'outage')
  await banner.getByTestId('ddns-promote').click()
  const form = page.getByTestId('ddns-role-form')
  await form.getByTestId('ddns-role-target').selectOption({ label: TO })
  await form.getByRole('button', { name: 'Preview the plan' }).click()
  const preview = page.getByTestId('plan-preview')
  await expect(preview.getByTestId('plan-summary')).toContainText(`promote ${TO} primary of 3 zones`, { timeout: 90000 })
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(preview).toHaveAttribute('data-plan-state', 'applied', { timeout: 120000 })
  await page.getByRole('button', { name: 'Close', exact: true }).last().click()
  await expect(row).toContainText(new RegExp(`example\\.lan\\.\\s*${TO}`), { timeout: 60000 })
  await expect(row.getByTestId('ddns-zone-state')).not.toHaveAttribute('data-state', 'outage')
})
