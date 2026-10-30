// SPDX-License-Identifier: Apache-2.0
// Administration > Updates against the mock: a signed release uploaded and rolled out with the
// password, followed across a page reload and a restart of the node under the page (every API
// call 503 for a few seconds); an unsigned release behind the extra confirmation whose second
// node fails at the health step, is rolled back automatically, and the rest cancelled.
import { test, expect } from '@playwright/test'

// Versions above anything the mock knows, distinct per run of the file.
const N = Math.floor(Date.now() / 1000) % 9000 + 1000
const SIGNED = `9.${N}.0`
const UNSIGNED = `9.${N}.1`

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const mock = (page, body) => page.request.post('/api/v1/_mock/updates', { data: body })

function releaseFiles(version, signed) {
  const file = (name, text) => ({ name, mimeType: 'application/octet-stream', buffer: Buffer.from(text) })
  const deb = `pelagos_${version}-1_amd64.deb`
  const files = [
    file(deb, 'deb'),
    file('release.json', JSON.stringify({ format: 1, name: 'pelagos', version, state_schema: 1 })),
    file('NOTES.md', `# Pelagos ${version}\n\n- e2e release\n`),
    file('SHA256SUMS', `${'0'.repeat(64)}  ${deb}\n`),
  ]
  if (signed) files.push(file('SHA256SUMS.sig', JSON.stringify({ format: 'pelagos-release-signature-v1', algorithm: 'ed25519', key_id: 'a1b2c3d4e5f60718', signature: 'c2ln' })))
  return files
}

async function applyWithPassword(preview) {
  await expect(preview.getByTestId('plan-preview')).toBeVisible()
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('updates-password').fill('admin')
  await preview.getByTestId('plan-apply').click()
}

test('rolls out a signed release and follows it across a reload and a restart', async ({ page }) => {
  await signIn(page)
  await mock(page, { step_ms: 300 })
  await page.goto('/admin/updates')
  await page.getByTestId('updates-upload-input').setInputFiles(releaseFiles(SIGNED, true))
  const release = page.locator(`[data-testid="updates-release"][data-version="${SIGNED}"]`)
  await expect(release.getByTestId('updates-signature')).toHaveAttribute('data-signature', 'valid')
  await release.getByTestId('updates-notes-toggle').click()
  await expect(release.getByTestId('updates-notes')).toContainText('Updates from the UI')

  await release.getByTestId('updates-prepare').click()
  const preview = page.getByTestId('updates-preview')
  await expect(preview.getByTestId('updates-order-node')).toHaveCount(2)
  await expect(preview.getByTestId('updates-estimate')).toContainText('min')
  // Wrong password: refused, the plan stays applicable.
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('updates-password').fill('wrong')
  await preview.getByTestId('plan-apply').click()
  await expect(preview.getByText(/password is wrong/i)).toBeVisible()
  await preview.getByTestId('updates-password').fill('admin')
  await preview.getByTestId('plan-apply').click()

  const panel = page.getByTestId('updates-rollout')
  await expect(panel).toHaveAttribute('data-state', 'running')
  await page.reload()
  await expect(page.getByTestId('updates-rollout')).toHaveAttribute('data-state', 'running')

  await mock(page, { down_ms: 4000 })
  await expect(page.getByTestId('updates-reconnecting')).toBeVisible()
  await expect(page.getByTestId('updates-reconnected')).toBeVisible({ timeout: 15000 })
  await expect(page.getByTestId('updates-rollout')).toHaveAttribute('data-state', 'done', { timeout: 30000 })
  await expect(page.getByTestId('updates-rollout-node')).toHaveCount(2)
  await expect(release).toContainText('installed everywhere')

  await page.getByRole('button', { name: 'History' }).click()
  await expect(page.getByTestId('updates-history-table')).toContainText(SIGNED)
})

test('installs an unsigned release only after the extra confirmation, stops on a failure, cancels the rest', async ({ page }) => {
  await signIn(page)
  await mock(page, { step_ms: 200 })
  await page.goto('/admin/updates')
  await page.getByTestId('updates-upload-input').setInputFiles(releaseFiles(UNSIGNED, false))
  const release = page.locator(`[data-testid="updates-release"][data-version="${UNSIGNED}"]`)
  await expect(release.getByTestId('updates-signature')).toHaveAttribute('data-signature', 'unsigned')
  await mock(page, { broken: UNSIGNED })

  await release.getByTestId('updates-prepare').click()
  const preview = page.getByTestId('updates-preview')
  const warning = preview.getByTestId('updates-unsigned')
  await expect(warning).toContainText(`${UNSIGNED} is not signed: its origin is not verified`)
  const go = warning.getByTestId('updates-unsigned-continue')
  await expect(go).toBeDisabled()
  await warning.getByTestId('updates-unsigned-accept').check()
  await warning.getByTestId('updates-unsigned-version').fill(UNSIGNED)
  await go.click()
  await applyWithPassword(preview)

  const panel = page.getByTestId('updates-rollout')
  await expect(panel).toHaveAttribute('data-state', 'failed', { timeout: 30000 })
  await expect(panel).toContainText('unsigned, accepted by admin')
  await expect(panel.locator('[data-testid="updates-rollout-node"][data-state="rolled_back"]')).toHaveCount(1)
  await expect(panel.getByTestId('updates-rollout-error')).toContainText('Health')
  await expect(page.getByTestId('updates-prepare').first()).toBeDisabled()

  await panel.getByTestId('updates-cancel').click()
  await page.getByRole('button', { name: 'Cancel the rest' }).last().click()
  await expect(panel).toHaveAttribute('data-state', 'cancelled')
  await page.getByRole('button', { name: 'History' }).click()
  await expect(page.getByTestId('updates-history-table')).toContainText(UNSIGNED)
})
