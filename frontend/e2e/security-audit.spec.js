// SPDX-License-Identifier: Apache-2.0
// Security audit findings of another node: an exception added with its reason and removed, then
// one plan that fixes two findings out of three on that node.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const RNDC = 'bind:weak_rndc_key:rndc-key'
const STATS = 'bind:stats_nonlocal:0.0.0.0'
const TRANSFER = 'bind:open_allow_transfer:_default/partner.example.'
const row = (page, id) => page.locator(`[data-testid="security-finding"][data-finding="${id}"]`)

test('exception on a finding, then one plan fixing two findings of three', async ({ page }) => {
  await signIn(page)
  await page.goto('/install/security')
  await page.getByTestId('security-node-select').selectOption({ label: 'ns2' })
  await expect(page.getByTestId('security-finding')).toHaveCount(3)

  // Exception with its reason: the finding leaves the list and shows among the exceptions.
  await row(page, TRANSFER).getByTestId('security-except').click()
  const dialog = page.getByTestId('security-exception-dialog')
  await dialog.getByTestId('security-exception-reason-input').fill('partner transfers by address on purpose')
  await dialog.getByRole('button', { name: 'Add the exception' }).click()
  await expect(page.getByTestId('security-finding')).toHaveCount(2)
  const excepted = page.getByTestId('security-excepted')
  await expect(excepted).toHaveCount(1)
  await expect(excepted).toContainText('partner transfers by address on purpose')
  await expect(excepted).toContainText('ns2 only')

  // Removing it lists the finding again.
  await excepted.getByTestId('security-unexcept').click()
  await expect(page.getByTestId('security-excepted')).toHaveCount(0)
  await expect(page.getByTestId('security-finding')).toHaveCount(3)

  // Two of the three in one plan; the third stays.
  await row(page, RNDC).getByTestId('security-check').check()
  await row(page, STATS).getByTestId('security-check').check()
  await expect(page.getByTestId('security-remediation')).toContainText('2 findings selected')
  await page.getByTestId('security-build').click()
  await expect(page.getByTestId('plan-summary')).toContainText('2 findings')
  await page.getByTestId('plan-confirm-checkbox').check()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-job')).toContainText(`remediate ${RNDC}`)
  await expect(page.getByTestId('plan-job')).toContainText(`remediate ${STATS}`)
  await expect(page.getByTestId('plan-job')).toContainText('100% done', { timeout: 15000 })
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('security-finding')).toHaveCount(1)
  await expect(row(page, TRANSFER)).toBeVisible()
})
