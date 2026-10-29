// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 and Administration > IPv6 sources against the mock: classes, filters kept in the
// URL, an exception per address, then an OPNsense source added with its key and tested.
import { test, expect } from '@playwright/test'

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('lists observed IPv6 addresses, filters them and excepts one address', async ({ page }) => {
  await signIn(page)
  await page.goto('/hosts')
  await page.getByRole('button', { name: 'IPv6', exact: true }).click()
  await expect(page).toHaveURL(/tab=ipv6/)
  const table = page.getByTestId('ipv6-table')
  const printer = table.locator('tr', { hasText: '02:00:5e:00:53:10' })
  await expect(printer.getByTestId('ipv6-class')).toHaveText('EUI-64')
  await expect(printer.getByTestId('ipv6-proposal')).toContainText('2001:db8::5eff:fe00:5310')
  await expect(table.locator('tr', { hasText: '06:11:22:33:44:55' }).getByTestId('ipv6-random-mac')).toBeVisible()

  await page.getByTestId('ipv6-filter').and(page.locator('[data-value="stale"]')).click()
  await expect(page).toHaveURL(/filter=stale/)
  await expect(page.getByTestId('ipv6-total')).toHaveText('Hosts: 1')
  await expect(table.getByTestId('ipv6-stale')).toHaveCount(1)

  await page.goto('/hosts?tab=ipv6&filter=missing_aaaa')
  await expect(page.getByTestId('ipv6-total')).toHaveText('Hosts: 1')
  await printer.getByTestId('ipv6-except').click()
  const dialog = page.getByTestId('ipv6-exception-dialog')
  await dialog.getByTestId('ipv6-exception-target').and(page.locator('[data-key="mac:02:00:5e:00:53:10"]')).check()
  await dialog.getByTestId('ipv6-exception-comment').fill('printer stays IPv4 in DNS')
  await dialog.getByRole('button', { name: 'Add the exception' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByTestId('ipv6-total')).toHaveText('Hosts: 0')
  await page.goto('/alerts/exceptions')
  await expect(page.getByText('mac:02:00:5e:00:53:10')).toBeVisible()
})

test('adds an OPNsense source with its key, tests it and watches a prefix', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/ipv6')
  await expect(page.getByTestId('ipv6-sources')).toContainText('https://router.example.lan')
  await page.getByTestId('ipv6-source-add').click()
  const dialog = page.getByTestId('ipv6-source-dialog')
  await dialog.getByTestId('ipv6-source-name').fill('Edge')
  await dialog.getByTestId('ipv6-source-url').fill('https://edge.example.lan')
  await dialog.getByTestId('ipv6-source-test').click()
  await expect(dialog).toContainText('Fix the highlighted fields')
  await dialog.getByTestId('ipv6-source-key').fill('KEY')
  await dialog.getByTestId('ipv6-source-secret').fill('SECRET')
  await dialog.getByTestId('ipv6-source-test').click()
  await expect(dialog.getByTestId('ipv6-source-test-result')).toHaveAttribute('data-ok', 'true')
  await expect(dialog.getByTestId('ipv6-source-sample')).toContainText('2001:db8::5eff:fe00:5310')
  await dialog.getByTestId('ipv6-source-save').click()
  await expect(dialog).toBeHidden()
  const row = page.getByTestId('ipv6-sources').locator('tr', { hasText: 'Edge' })
  await expect(row.getByTestId('ipv6-source-nokey')).toHaveCount(0)
  await row.getByTestId('ipv6-source-row-test-button').click()
  await expect(row.getByTestId('ipv6-source-row-test')).toHaveAttribute('data-ok', 'true')

  await page.getByTestId('ipv6-prefixes-input').fill('2001:db8:1::/64')
  await page.getByTestId('ipv6-prefixes-save').click()
  await expect(page.getByTestId('ipv6-effective')).toContainText('2001:db8:1::/64')
})
