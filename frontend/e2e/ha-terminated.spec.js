// SPDX-License-Identifier: Apache-2.0
// A Kea HA pair stuck in `terminated` after a clock drift (mock scenario `terminated`, NTP fixed
// since): the HA page says so with the probable cause and repairs it through a plan that checks
// the clocks and restarts each server in turn; the nodes page shows every node's clock.
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

for (const width of [1440, 400]) {
  test.describe(`at ${width} px`, () => {
    test.use({ viewport: { width, height: 900 } })

    test('the HA page shows the terminated pair, its cause, and repairs it', async ({ page }) => {
      await scenario(page, 'terminated')
      await signIn(page)
      await page.goto('/dhcp/v4/ha')
      const banner = page.getByTestId('ha-terminated-banner')
      await expect(banner).toContainText('HA terminated on ns1, ns2')
      await expect(banner.getByTestId('ha-terminated-cause')).toContainText('clock skew of 75 s with ns2')
      await expect(banner.getByTestId('ha-terminated-skew').first()).toContainText('75 s')
      await banner.getByTestId('ha-repair').click()
      await page.getByTestId('confirm-button').click()
      const preview = page.getByTestId('plan-preview')
      await expect(preview.getByTestId('plan-summary')).toContainText('restart the HA service of ns2 (ns2), ns1 (ns1)')
      await preview.getByTestId('plan-confirm-checkbox').check()
      await preview.getByTestId('plan-apply').click()
      await expect(preview.getByTestId('plan-result')).toContainText('Applied')
      await expect(preview.getByTestId('plan-steps-step').last().getByTestId('plan-steps-node')).toHaveCount(2)
      await page.keyboard.press('Escape')
      await expect(banner).toHaveCount(0)
      await expect(page.getByTestId('ha-state').first()).toContainText('Hot standby')
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
      expect(overflow).toBeLessThanOrEqual(0)
    })

    test('the nodes page shows each clock against this node and its NTP state', async ({ page }) => {
      await scenario(page, 'terminated')
      await signIn(page)
      await page.goto('/nodes')
      const clocks = page.getByTestId('node-clock')
      await expect(clocks).toHaveCount(2)
      await expect(clocks.nth(0)).toContainText('reference')
      await expect(clocks.nth(1)).toContainText('-0.012 s')
      await expect(clocks.nth(1)).toContainText('NTP synchronized')
      await expect(clocks.nth(1)).toHaveAttribute('data-tone', 'success')
    })
  })
}
