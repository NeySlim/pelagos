// SPDX-License-Identifier: Apache-2.0
// Runtime operations screen against the mock: an rndc read, an rndc change with a typed
// parameter, a Kea command that needs a confirmation, and a change refused on a peer.
import { test, expect } from '@playwright/test'

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('rndc reads and changes from the operations screen', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/ops')
  const list = page.getByTestId('ops-list')
  await list.locator('[data-op="status"]').click()
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-output')).toContainText('server is up and running')

  await list.locator('[data-op="flushname"]').click()
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-detail')).toContainText('Required')
  await page.getByTestId('ops-param-name').fill('www.example.lan')
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-output')).toContainText('Done, no output.')
})

test('a Kea command that needs a confirmation', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/ops')
  await page.getByRole('button', { name: 'Kea DHCPv4' }).click()
  const list = page.getByTestId('ops-list')
  await list.locator('[data-op="ha-reset"]').click()
  await expect(page.getByTestId('ops-run')).toBeDisabled()
  await page.getByTestId('ops-confirm').check()
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-output')).toBeVisible()
  await list.locator('[data-op="status-get"]').click()
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-output')).toContainText('pid')
})

test('a DNS operator sees Kea changes as not allowed', async ({ page }) => {
  await signIn(page, 'alice', 'alice')
  await page.goto('/advanced/ops')
  await page.getByRole('button', { name: 'Kea DHCPv4' }).click()
  await page.getByTestId('ops-list').locator('[data-op="ha-sync"]').click()
  await expect(page.getByTestId('ops-blocked')).toContainText('do not allow')
  await expect(page.getByTestId('ops-run')).toBeDisabled()
})

test.describe('at 400px', () => {
  test.use({ viewport: { width: 400, height: 800 } })

  test('every engine tab is visible and opens its operations', async ({ page }) => {
    // The sidebar is collapsed at phone width: wait for the redirect away from the login page.
    await page.goto('/login')
    await page.getByTestId('login-username').fill('admin')
    await page.getByTestId('login-password').fill('admin')
    await page.getByTestId('login-submit').click()
    await expect(page).not.toHaveURL(/\/login$/)
    await page.goto('/advanced/ops')
    const v4 = page.getByRole('button', { name: 'Kea DHCPv4' })
    await expect(v4).toBeVisible()
    // An inactive tab shows its icon or its label, never an empty button.
    await expect(v4.locator('svg, span:not(.hidden)').first()).toBeVisible()
    await v4.click()
    const op = page.getByTestId('ops-list').locator('[data-op="status-get"]')
    await expect(op).toBeVisible()
    await expect(op).toHaveAttribute('aria-pressed', 'false')
    await op.click()
    await expect(op).toHaveAttribute('aria-pressed', 'true')
  })
})
