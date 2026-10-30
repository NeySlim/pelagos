// SPDX-License-Identifier: Apache-2.0
// Kea migration: the analysis (series of every node, findings, packages, diff, kept after a reload,
// French too), then the wizard on the analysis: an automatic return when the window fails, a full
// migration with the measured outage and live HA states, and the return of the migrated pair.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('analysis of the migration to Kea 3.2 from ISC', async ({ page }) => {
  // The reference pair, whatever scenario an earlier spec left (a terminated HA changes the wizard).
  await page.request.post('/api/v1/_mock/scenario', { data: { name: 'pair' } })
  await signIn(page)
  await page.goto('/install/kea-migration')
  await expect(page.getByTestId('page-kea-migration')).toBeVisible()
  const rows = page.getByTestId('kea-migration-node')
  await expect(rows.first()).toContainText('2.6.3')
  await expect(page.getByTestId('kea-migration-obsolete').first()).toContainText('2026-07-30')
  await expect(page.getByTestId('kea-migration-none')).toBeVisible()
  await expect(page.getByTestId('kea-migration-target-select')).toHaveValue('3.2/isc')

  await page.getByTestId('kea-migration-analyze').click()
  const report = page.getByTestId('kea-migration-report')
  await expect(report).toBeVisible()
  await expect(report).toContainText('Analysis for Kea 3.2 from ISC')
  await expect(page.getByTestId('kea-migration-ready')).toBeVisible()
  const groups = page.getByTestId('kea-migration-group')
  await expect(groups.first()).toHaveAttribute('data-severity', 'converted')
  await expect(page.locator('[data-testid="kea-migration-finding"][data-code="d2_secret_file"]').first()).toContainText('kea-ddns')
  const node = page.getByTestId('kea-migration-node-report').first()
  await expect(node.getByTestId('kea-migration-packages-install')).toContainText('isc-kea-dhcp4')
  await node.getByTestId('kea-migration-diff').first().locator('summary').click()
  await expect(node.getByTestId('kea-migration-diff').first()).toContainText('evaluate-additional-classes')

  // Kept on the node: a reload shows the same report without analyzing again.
  await page.reload()
  await expect(page.getByTestId('kea-migration-report')).toBeVisible()

  await page.evaluate(() => localStorage.setItem('i18nextLng', 'fr'))
  await page.reload()
  await expect(page.getByTestId('kea-migration-report')).toContainText('Analyse pour Kea 3.2, paquets ISC')
  await expect(page.getByTestId('kea-migration-group').first()).toContainText('Converti')
})

// Builds the wizard's plan, confirms and applies it, waits for its job, closes the preview.
async function runPlan(page, phase) {
  await page.getByTestId(`kea-wizard-${phase}`).click()
  const preview = page.getByTestId('plan-preview')
  await expect(preview).toBeVisible()
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(preview.getByTestId('plan-job')).toBeVisible()
  await expect(preview).toHaveAttribute('data-plan-state', /applied|failed/, { timeout: 30000 })
  await page.keyboard.press('Escape')
  await expect(preview).toBeHidden()
}

test('migration wizard: automatic return, migration, return of the pair', async ({ page }) => {
  test.setTimeout(150000)
  await signIn(page)
  await page.evaluate(() => localStorage.setItem('i18nextLng', 'en'))
  await page.goto('/install/kea-migration')
  // The analysis of the first test is kept: the wizard starts at "Prepare".
  const wizard = page.getByTestId('kea-migration-wizard')
  await expect(wizard).toBeVisible()
  await expect(wizard).toHaveAttribute('data-state', 'none')
  await runPlan(page, 'prepare')
  await expect(wizard).toHaveAttribute('data-state', 'prepared')
  await expect(wizard.locator('[data-step="prepare"]')).toHaveAttribute('data-state', 'done')

  // The window fails: the pair goes back to 2.6 on its own.
  await page.request.post('/api/v1/_mock/kea-migration', { data: { fail_at: 'kea-mig-wait-partner-down' } })
  await runPlan(page, 'migrate')
  await expect(wizard).toHaveAttribute('data-state', 'rolled_back')
  await expect(page.getByTestId('kea-wizard-error')).toContainText('kea-mig-wait-partner-down')
  const times = page.getByTestId('kea-wizard-time-step')
  await expect(times).toHaveCount(4)
  await expect(times.nth(1)).toHaveAttribute('data-state', 'failed')
  await expect(times.nth(3)).toHaveAttribute('data-state', 'done')

  // Prepared again, the migration goes through: three times done, outage measured, HA back.
  await page.request.post('/api/v1/_mock/kea-migration', { data: { fail_at: null } })
  await runPlan(page, 'prepare')
  await expect(wizard).toHaveAttribute('data-state', 'prepared')
  await runPlan(page, 'migrate')
  await expect(wizard).toHaveAttribute('data-state', 'migrated')
  await expect(page.getByTestId('kea-wizard-verify')).toContainText('Every node runs Kea 3.2')
  await expect(times).toHaveCount(3)
  for (let i = 0; i < 3; i += 1) await expect(times.nth(i)).toHaveAttribute('data-state', 'done')
  await expect(page.getByTestId('kea-wizard-outage-value')).toContainText(/Measured DHCP outage: \d+\.\d s/)
  const nodes = page.getByTestId('kea-wizard-node')
  await expect(nodes).toHaveCount(2)
  for (let i = 0; i < 2; i += 1) {
    await expect(nodes.nth(i).getByTestId('kea-wizard-ha')).toHaveText('hot-standby')
    await expect(nodes.nth(i).getByTestId('kea-wizard-version')).toContainText('3.2.1')
  }

  // The French screen, then the return of the whole pair.
  await page.evaluate(() => localStorage.setItem('i18nextLng', 'fr'))
  await page.reload()
  await expect(page.getByTestId('kea-wizard-verify')).toContainText('Tous les nœuds tournent en Kea 3.2')
  await expect(page.getByTestId('kea-wizard-rollback')).toContainText('Revenir en Kea 2.6')
  await runPlan(page, 'rollback')
  await expect(wizard).toHaveAttribute('data-state', 'rolled_back')
  await expect(page.getByTestId('kea-wizard-verify')).toContainText('revenus en Kea 2.6')
  await expect(page.getByTestId('kea-wizard-time-step').nth(3)).toHaveAttribute('data-state', 'done')
  await page.evaluate(() => localStorage.setItem('i18nextLng', 'en'))
})
