// SPDX-License-Identifier: Apache-2.0
// Leases: the subnet column reads as a prefix, DNS is two icons, a phone gets cards without a
// sideways scroll, and a deleted lease closes its card without asking the server for it again.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

let errors
let missing
test.beforeEach(async ({ page }) => {
  errors = []
  missing = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('response', (r) => r.status() === 404 && missing.push(r.url()))
  await signIn(page)
})
test.afterEach(async ({ page }) => {
  // The delete changed the mock's leases: back to the pair scenario for the specs that follow.
  await page.request.post('/api/v1/_mock/scenario', { data: { name: 'pair' } })
  expect(errors).toEqual([])
  expect(missing).toEqual([])
})

test('desktop: prefix, two DNS icons and a lease card that closes after its delete', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/dhcp/v4/leases?q=192.0.2.157')
  const row = page.getByTestId('data-table-row').first()
  await expect(row).toContainText('192.0.2.0/24')
  await expect(row.getByTestId('lease-dns-fwd')).toHaveAttribute('title', /forward/i)
  await expect(row.getByTestId('lease-dns-rev')).toHaveAttribute('title', /reverse/i)
  await row.click()
  const card = page.getByTestId('detail-window-lease')
  await expect(card).toBeVisible()
  await card.getByTestId('lease-delete').click()
  const preview = page.getByTestId('plan-preview')
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(preview.getByTestId('plan-result')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('detail-window-lease')).toHaveCount(0)
})

test('phone: lease cards, no sideways scroll, Detail opens the card', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 })
  await page.goto('/dhcp/v4/leases')
  await expect(page.getByTestId('data-table-card').first()).toBeVisible()
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(0)
  await page.getByTestId('lease-open').first().click()
  await expect(page.getByTestId('lease-detail')).toBeVisible()
})
