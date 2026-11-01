// SPDX-License-Identifier: Apache-2.0
// U1-RECONCILE on the mock (scenario `reconcile`: ns2 missed a partial apply and both sides changed,
// the v4 file has comments): "Reconcile from <node>" on the config_divergence alert opens the plan
// preview, the DHCP screens say what happens to the comments, and the import wizard offers the include tree.
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

for (const width of [1440, 390]) {
  test.describe(`at ${width} px`, () => {
    test.use({ viewport: { width, height: 900 } })

    test('the divergence alert offers both directions and opens the reconcile plan', async ({ page }) => {
      await scenario(page, 'reconcile')
      await signIn(page)
      await page.goto('/alerts?alert=ALRT0000000000000000000030')
      await expect(page.getByTestId('alert-reconcile')).toHaveCount(2)
      await page.getByRole('button', { name: 'Reconcile from ns1' }).click()
      const preview = page.getByTestId('plan-preview')
      await expect(preview.getByTestId('plan-summary')).toContainText('reconcile ns2 from ns1')
      await expect(preview.getByTestId('plan-confirm-reasons')).toContainText('the configuration of a node is replaced')
      await expect(preview.getByTestId('plan-impact')).toContainText('differences are overwritten')
      await expect(preview.getByTestId('plan-impact')).toContainText('differences stay after the copy')
      await expect(preview.getByTestId('plan-impact')).toContainText('HA service restarts')
    })

    test('the DHCP screen says the comments are copied into user-context', async ({ page }) => {
      await scenario(page, 'reconcile')
      await signIn(page)
      await page.goto('/dhcp/v4/subnets')
      await expect(page.getByTestId('kea-comments-banner-v4')).toContainText('has 3 comments and no include')
    })

    test('the import wizard checks the include tree when a file has comments', async ({ page }) => {
      await scenario(page, 'reconcile')
      await signIn(page)
      await page.goto('/install')
      await page.getByTestId('wizard-next').click()
      await page.getByTestId('wizard-next').click()
      const box = page.getByTestId('wizard-include-tree')
      await expect(box).toContainText('Comments stay next to the settings they describe')
      await expect(box.locator('input')).toBeChecked()
      await page.getByTestId('wizard-build').click()
      await expect(page.getByTestId('plan-preview')).toBeVisible()
    })
  })
}
