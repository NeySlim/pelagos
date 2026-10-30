// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 and Administration > IPv6 observation against the mock: classes, filters kept in
// the URL, an exception per address, the AAAA and PTR plans of a selection (reverse zone first
// when missing), the host card's IPv6 part, then the sources' status and a watched prefix.
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

test('shows the generic sources and watches a prefix', async ({ page }) => {
  await signIn(page)
  await page.goto('/admin/ipv6')
  await expect(page.getByTestId('ipv6-observation')).toContainText('Kea DHCPv6 leases')
  await expect(page.getByTestId('ipv6-status')).toContainText('DHCPv6 lease')
  await expect(page.getByTestId('ipv6-sources')).toHaveCount(0)
  await expect(page.getByTestId('ipv6-source-add')).toHaveCount(0)

  await page.getByTestId('ipv6-prefixes-input').fill('2001:db8:1::/64')
  await page.getByTestId('ipv6-prefixes-save').click()
  await expect(page.getByTestId('ipv6-effective')).toContainText('2001:db8:1::/64')
})

test('creates AAAA and PTR of a selection, the missing reverse zone first', async ({ page }) => {
  await signIn(page)
  await page.goto('/hosts?tab=ipv6')
  const table = page.getByTestId('ipv6-table')
  const camera = table.locator('tr', { hasText: '02:00:5e:00:53:30' })
  const laptop = table.locator('tr', { hasText: '02:00:5e:00:53:11' })
  // A temporary address is never offered for selection.
  await expect(laptop.locator('[data-class="temporary"]').getByTestId('ipv6-select-address')).toHaveCount(0)
  await camera.getByTestId('ipv6-select-address').check()
  await page.getByTestId('ipv6-plan-selection').click()
  const dialog = page.getByTestId('ipv6-reverse-dialog')
  await expect(dialog).toContainText('0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
  await dialog.getByTestId('ipv6-reverse-create').click()
  await expect(page.getByTestId('plan-summary')).toContainText('0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
  await page.keyboard.press('Escape')

  await page.getByTestId('ipv6-plan-selection').click()
  await expect(page.getByTestId('plan-summary')).toContainText('AAAA and PTR of 1 IPv6 addresses')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(camera.getByTestId('ipv6-records')).toContainText('2001:db8:1::5eff:fe00:5330')
  await expect(camera.getByTestId('ipv6-ptr')).toHaveAttribute('data-present', 'true')
})

test('checks a prefix replacement and asks for the new reverse zone', async ({ page }) => {
  await signIn(page)
  await page.goto('/hosts?tab=ipv6')
  await page.getByTestId('ipv6-replace-prefix').click()
  const dialog = page.getByTestId('ipv6-replace-dialog')
  await dialog.getByTestId('ipv6-replace-old').fill('2001:db8::/64')
  await dialog.getByTestId('ipv6-replace-new').fill('2001:db8:9::/48')
  await dialog.getByRole('button', { name: 'Build the plan' }).click()
  await expect(dialog).toContainText('Both prefixes must have the same length')
  await dialog.getByTestId('ipv6-replace-new').fill('2001:db8:9::/64')
  await dialog.getByRole('button', { name: 'Build the plan' }).click()
  await expect(page.getByTestId('ipv6-reverse-dialog')).toContainText('0.0.0.0.9.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
})

test('shows the IPv6 history in the host card', async ({ page }) => {
  await signIn(page)
  await page.goto('/hosts?q=192.0.2.10')
  await page.getByTestId('hosts-table').locator('tr', { hasText: '192.0.2.10' }).first().click()
  const part = page.getByTestId('host-card').getByTestId('host-ipv6')
  await expect(part.getByTestId('host-ipv6-class')).toHaveText('EUI-64')
  await expect(part.getByTestId('host-ipv6-seen')).toContainText('node neighbors, DHCPv6 lease')
  await expect(part.getByTestId('host-ipv6-proposal')).toContainText('2001:db8::5eff:fe00:5310')
  await part.getByTestId('host-ipv6-create').click()
  await expect(page.getByTestId('plan-summary')).toContainText('AAAA and PTR of 1 IPv6 addresses')
})
