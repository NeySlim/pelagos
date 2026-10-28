// SPDX-License-Identifier: Apache-2.0
// Administration > Backups on a real pair (tests/lab/test_archives_lab.py): the nodes, the four
// destinations and the key the scenario set up, the restore wizard up to the plan preview of a zone
// (built on the real engines, not applied), and a real run as a job.
import { test, expect } from '@playwright/test'

const PASSWORD = process.env.LAB_PASSWORD

test('backups screen on the real backend', async ({ page }) => {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill(PASSWORD)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.goto('/admin/archives')

  await expect(page.getByTestId('archives-node')).toHaveCount(2)
  await expect(page.getByTestId('archives-dest')).toHaveCount(4)
  await expect(page.getByTestId('archives-key')).toContainText('age1')
  await expect(page.getByTestId('archives-dest').filter({ hasText: 'lab sftp' })).toContainText('archive@')

  // The newest archive of ns1 was taken just before the scenario added a record: its zone part deletes it.
  const rows = page.getByTestId('archives-table').locator('tbody tr')
  await rows.filter({ hasText: 'ns1' }).first().getByTestId('archives-restore-open').click()
  const wizard = page.getByTestId('archives-restore')
  await expect(wizard).toHaveAttribute('data-step', 'source')
  await wizard.getByTestId('archives-restore-inspect').click()
  await expect(wizard).toHaveAttribute('data-step', 'parts', { timeout: 60000 })
  const zone = wizard.locator('[data-part="bind.zone:_default/example.lan"]')
  await expect(zone).toContainText('1 deleted')
  for (const box of await wizard.getByTestId('archives-restore-part').getByRole('checkbox').all()) {
    if (await box.isChecked()) await box.uncheck()
  }
  await zone.getByRole('checkbox').check()
  await wizard.getByTestId('archives-restore-build').click()
  await expect(wizard).toHaveAttribute('data-step', 'plan', { timeout: 60000 })
  const plan = wizard.getByTestId('plan-preview')
  await expect(plan.getByTestId('plan-summary')).toContainText('restore')
  await expect(plan.getByTestId('plan-apply')).toBeDisabled()
  await page.keyboard.press('Escape')
  await expect(wizard).toBeHidden()

  // A real run of both nodes as a job; the newest row is then a new archive.
  const before = await rows.first().innerText()
  await page.getByTestId('archives-run').click()
  await expect(page.getByTestId('archives-run-job')).toHaveAttribute('data-state', 'done', { timeout: 150000 })
  await expect(page.getByTestId('archives-run-step')).toHaveCount(2)
  await page.reload()
  await expect.poll(() => rows.first().innerText(), { timeout: 30000 }).not.toBe(before)
})
