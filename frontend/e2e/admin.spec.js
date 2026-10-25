// SPDX-License-Identifier: Apache-2.0
// Administration areas against the mock: audit detail, the two advanced editors,
// the import wizard and the security remediation applied as jobs, users, account.
import { test, expect } from '@playwright/test'

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('audit filters from the URL and opens an entry with its diff', async ({ page }) => {
  await signIn(page)
  await page.goto('/audit?result=rolled_back')
  const rows = page.getByTestId('audit-table').getByTestId('data-table-row')
  await expect(rows.first()).toBeVisible()
  await expect(rows.first()).toContainText('dhcp.subnet.apply')
  await rows.first().click()
  await expect(page.getByTestId('audit-entry')).toContainText('kea4:subnet:3')
  await expect(page.getByTestId('audit-entry').getByTestId('diff-view')).toContainText('"valid-lifetime": 900')
  await expect(page).toHaveURL(/id=/)
})

test('import wizard builds a plan and applies it as a job', async ({ page }) => {
  await signIn(page)
  await page.goto('/install')
  await expect(page.getByTestId('install-engine-row')).toHaveCount(4)
  await page.getByTestId('wizard-next').click()
  await page.getByTestId('wizard-next').click()
  await page.getByTestId('wizard-build').click()
  await expect(page.getByTestId('plan-preview')).toContainText('import bind, kea4, kea6, d2')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-job')).toContainText('100% done', { timeout: 15000 })
})

test('security findings build a confirmed remediation plan', async ({ page }) => {
  await signIn(page)
  await page.goto('/install/security')
  await page.locator('[data-finding="kea:weak_shared_kea_key:kea-ddns"]').click()
  await expect(page.locator('[data-finding="kea:weak_shared_kea_key:kea-ddns"]').getByTestId('security-dual-key')).toBeVisible()
  // The same rotation reported from the BIND side, and nothing like it on a plain rndc key.
  await expect(page.locator('[data-finding="bind:weak_shared_kea_key:ddns-legacy"]').getByTestId('security-dual-key')).toBeVisible()
  await expect(page.locator('[data-finding="bind:weak_rndc_key:rndc-key"]').getByTestId('security-dual-key')).toHaveCount(0)
  // No automatic remediation: shown, but it cannot join a plan.
  const manual = page.locator('[data-finding="kea:kea_http_socket_plain:kea4:192.0.2.1"]')
  await expect(manual.getByTestId('security-manual')).toBeVisible()
  await expect(manual.locator('input[type=checkbox]')).toBeDisabled()
  await page.getByTestId('security-build').click()
  const apply = page.getByTestId('plan-apply')
  await expect(apply).toBeDisabled()
  await page.getByTestId('plan-confirm-checkbox').check()
  await apply.click()
  await expect(page.getByTestId('plan-job')).toContainText('switch D2 to the new key on every node')
  await expect(page.getByTestId('plan-job')).toContainText('100% done', { timeout: 15000 })
})

test('named.conf editor validates and applies an option change', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/bind')
  await page.locator('[data-testid="bind-statement"][data-name="directory"]').click()
  await expect(page.getByTestId('grammar-info')).toContainText('quoted_string')
  await page.getByTestId('value-input').fill('/var/lib/bind')
  await page.getByTestId('statement-save').click()
  await expect(page.getByTestId('bind-changes')).toContainText('options/directory')
  await page.getByTestId('bind-plan').click()
  await page.getByTestId('plan-validations').getByRole('button').click()
  await expect(page.getByTestId('plan-validations')).toContainText('named-checkconf')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
})

test('Kea editor edits a key and applies the configuration', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/kea')
  await page.getByTestId('kea-tree').getByText('valid-lifetime:', { exact: true }).first().click()
  await expect(page.getByTestId('kea-key-editor')).toContainText('Default lease lifetime')
  await page.getByTestId('kea-scalar-input').fill('7200')
  await page.getByTestId('kea-save').click()
  await expect(page.getByTestId('kea-pending').getByTestId('diff-view')).toContainText('"valid-lifetime": 7200')
  await page.getByTestId('kea-plan').click()
  await page.getByTestId('plan-validations').getByRole('button').click()
  await expect(page.getByTestId('plan-validations')).toContainText('config-test')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
})

test('history shows a backup and its changes since the previous one', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/history')
  await page.getByTestId('history-table').getByTestId('data-table-row').first().click()
  await expect(page.getByTestId('history-detail')).toContainText('sha256')
  await expect(page.getByTestId('history-detail').getByTestId('diff-view')).toBeVisible()
})

test('an administrator creates a user', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/users')
  await page.getByTestId('user-create').click()
  await page.getByTestId('user-username').fill('carol')
  await page.getByTestId('user-password').fill('Correct-horse-42')
  await page.getByTestId('user-form').getByRole('button', { name: 'Create' }).click()
  await expect(page.getByTestId('users-table')).toContainText('carol')
})

test('a user enrolls TOTP with the QR code, then turns it off', async ({ page }) => {
  await signIn(page, 'alice', 'alice')
  await page.goto('/account')
  await page.getByTestId('totp-enroll').click()
  await expect(page.getByTestId('totp-qr')).toBeVisible()
  await expect(page.getByTestId('totp-secret')).not.toBeEmpty()
  await page.getByTestId('totp-code').fill('654321')
  await page.getByTestId('totp-confirm').click()
  await expect(page.getByTestId('totp-disable')).toBeVisible()
  await page.getByTestId('totp-password').fill('alice')
  await page.getByTestId('totp-disable').click()
  await expect(page.getByTestId('totp-enroll')).toBeVisible()
})
