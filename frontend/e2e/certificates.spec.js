// SPDX-License-Identifier: Apache-2.0
// Administration > Certificates against the mock: every node's certificate, one ACME source
// applied to all nodes as a job with per-node progress, a manual upload checked then installed,
// a request made on the node.
import { test, expect } from '@playwright/test'

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('lists the certificate of every node', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/certificates')
  const cards = page.getByTestId('cert-node')
  await expect(cards).toHaveCount(2)
  await expect(cards.first().getByTestId('cert-source-badge')).toContainText('Self-signed')
  await expect(cards.first().getByTestId('cert-expiry-badge')).toHaveAttribute('data-level', 'ok')
  await expect(page.getByTestId('cert-cluster')).toContainText('no common source')
})

test('applies one ACME source to all nodes and follows each node', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/certificates')
  await page.getByTestId('cert-apply-all').click()
  const dialog = page.getByTestId('cert-source-dialog')
  await expect(dialog.getByTestId('cert-acme-form')).toBeVisible()
  await dialog.getByTestId('cert-acme-test').click()
  await expect(dialog.getByTestId('cert-test-result')).toContainText('acme-staging')
  await page.getByTestId('cert-source-apply').click()
  const job = page.getByTestId('cert-job')
  await expect(job).toHaveAttribute('data-state', 'done', { timeout: 15000 })
  await expect(job.locator('[data-state="done"][data-step]')).toHaveCount(2)
  const cards = page.getByTestId('cert-node')
  await expect(cards.first().getByTestId('cert-source-badge')).toContainText('(cluster)')
  await expect(cards.first()).toContainText('R11')
  await expect(page.getByTestId('cert-cluster')).toContainText('every node')
})

test('links the UCM source to its repository', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/certificates')
  await page.getByTestId('cert-apply-all').click()
  const dialog = page.getByTestId('cert-source-dialog')
  await dialog.getByRole('combobox', { name: /^Source/ }).click()
  await page.getByRole('option', { name: 'UCM', exact: true }).click()
  await expect(dialog.getByTestId('cert-ucm-link')).toHaveAttribute('href', 'https://github.com/NeySlim/ultimate-ca-manager')
})

test('checks a manual certificate before installing it', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/certificates')
  const card = page.getByTestId('cert-node').nth(1)
  await card.getByTestId('cert-upload').click()
  const dialog = page.getByTestId('cert-upload-dialog')
  await dialog.getByTestId('cert-pem').fill('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----')
  await page.getByTestId('cert-check').click()
  await expect(page.locator('[data-check="key"]')).toHaveAttribute('data-level', 'error')
  await expect(page.getByTestId('cert-install')).toBeDisabled()
  await dialog.getByTestId('cert-key').fill('-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----')
  await page.getByTestId('cert-check').click()
  await expect(page.locator('[data-check="key"]')).toHaveAttribute('data-level', 'ok')
  await page.getByTestId('cert-install').click()
  await expect(dialog).toBeHidden()
  await expect(card.getByTestId('cert-source-badge')).toContainText('Manual')
  await expect(card).toContainText('Example Corp Issuing CA')
})

test('makes a key and request on the node', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/certificates')
  const card = page.getByTestId('cert-node').first()
  await card.getByTestId('cert-upload').click()
  await page.getByTestId('cert-upload-dialog').getByRole('combobox').first().click()
  await page.getByRole('option', { name: 'Signed certificate for the request made on the node' }).click()
  await page.getByTestId('cert-make-request').click()
  await expect(page.getByTestId('cert-pending-request')).toContainText('BEGIN CERTIFICATE REQUEST')
})
