// SPDX-License-Identifier: Apache-2.0
// Kea migration analysis, read only: the series of every node, an analysis for ISC 3.2 with its
// findings by severity and node, the packages and the diff of a daemon; the report stays after a
// reload (kept on the node), and the screen reads in French too.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('analysis of the migration to Kea 3.2 from ISC', async ({ page }) => {
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
