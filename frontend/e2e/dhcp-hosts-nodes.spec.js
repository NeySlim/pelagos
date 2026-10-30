// SPDX-License-Identifier: Apache-2.0
// DHCP, hosts and nodes screens against the mock: subnet plan applied, v6 pd-pools,
// lease agreement between HA partners, HA maintenance with confirmation, host card,
// create-host plan and the enrollment token.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  await signIn(page)
})
test.afterEach(() => expect(errors).toEqual([]))

test('a new subnet goes through a plan and shows up', async ({ page }) => {
  await page.goto('/dhcp/v4/subnets')
  await page.getByTestId('data-table-row').first().click()
  await expect(page.getByTestId('subnet-detail')).toContainText('192.0.2.100 - 192.0.2.126')
  await page.getByTestId('subnet-create').click()
  await page.getByTestId('subnet-prefix').fill('198.51.100.0/24')
  await page.getByTestId('subnet-pools').fill('198.51.100.10 - 198.51.100.50')
  await page.getByTestId('subnet-form').getByRole('button', { name: 'Preview the plan' }).click()
  await expect(page.getByTestId('plan-preview')).toBeVisible()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('subnets-table')).toContainText('198.51.100.0/24')
})

test('DHCPv6 subnets show their prefix delegation pools', async ({ page }) => {
  await page.goto('/dhcp/v6/subnets')
  await expect(page.getByTestId('family-badge')).toHaveText('DHCPv6')
  await page.getByTestId('data-table-row').first().click()
  await expect(page.getByTestId('pd-pool-list')).toContainText('2001:db8:8000::/48')
})

test('a lease missing on the standby is flagged', async ({ page }) => {
  await page.goto('/dhcp/v4/leases?q=192.0.2.157')
  await page.getByTestId('data-table-row').first().click()
  await expect(page.getByTestId('lease-agreement')).toContainText('disagree')
  await expect(page.getByTestId('lease-missing')).toContainText('ns2')
})

test('HA maintenance needs the server name and the plan confirmation', async ({ page }) => {
  await page.goto('/dhcp/v4/ha')
  await page.getByTestId('ha-maintenance-start').first().click()
  await expect(page.getByTestId('confirm-button')).toBeDisabled()
  await page.getByTestId('confirm-type-input').fill('ns1')
  await page.getByTestId('confirm-button').click()
  await expect(page.getByTestId('plan-apply')).toBeDisabled()
  await page.getByTestId('plan-confirm-checkbox').check()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
  await page.keyboard.press('Escape')
  // Both cards of the pair offer the cancel, on the server in maintenance.
  await expect(page.getByTestId('ha-maintenance-cancel')).toHaveCount(2)
})

test('host card and create-host plan', async ({ page }) => {
  await page.goto('/hosts')
  await page.getByTestId('facet-inconsistent').click()
  await expect(page.getByTestId('host-total')).toContainText('Hosts: 4')
  await page.getByTestId('data-table-row').first().click()
  await expect(page.getByTestId('host-card')).toBeVisible()
  await expect(page.getByTestId('host-alerts')).not.toContainText('No open inconsistency')
  await page.getByTestId('host-create').click()
  await page.getByTestId('host-hostname').fill('printer2')
  await page.getByTestId('host-ip').fill('192.0.2.43')
  await page.getByTestId('host-reservation-toggle').check()
  await page.getByTestId('host-mac').fill('02:00:5e:00:09:09')
  await page.getByTestId('host-form').getByRole('button', { name: 'Preview the plan' }).click()
  await expect(page.getByTestId('plan-changes')).toContainText('PTR')
  await expect(page.getByTestId('plan-changes')).toContainText('reservations/hw-address=02:00:5e:00:09:09')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toBeVisible()
})

test('create-host plan in a view, with the PTR in the default view', async ({ page }) => {
  await page.goto('/hosts')
  await page.getByTestId('host-create').click()
  const form = page.getByTestId('host-form')
  await page.getByTestId('host-view').selectOption('internal')
  await expect(page.getByTestId('host-zone')).toHaveValue('corp.example.lan.')
  await page.getByTestId('host-hostname').fill('kiosk')
  await page.getByTestId('host-ip').fill('192.0.2.77')
  // The internal view has no reverse zone for 192.0.2.0/24; the default view has one.
  await expect(form).toContainText('No reverse zone covers this address')
  await page.getByTestId('host-reverse-view').selectOption('_default')
  await expect(form).toContainText('PTR goes to 2.0.192.in-addr.arpa.')
  const request = page.waitForRequest((r) => r.url().endsWith('/hosts/plan') && r.method() === 'POST')
  await form.getByRole('button', { name: 'Preview the plan' }).click()
  expect((await request).postDataJSON()).toMatchObject({ view: 'internal', reverse_view: '_default', zone: 'corp.example.lan.', reverse_zone: '2.0.192.in-addr.arpa.' })
  await expect(page.getByTestId('plan-changes')).toContainText('kiosk.corp.example.lan.')
  await expect(page.getByTestId('plan-changes')).toContainText('77.2.0.192.in-addr.arpa.')
})

test('IPv6 hosts: v6 lease joined with AAAA and PTR, and a v6 create-host plan', async ({ page }) => {
  await page.goto('/hosts?q=v6host1')
  const row = page.getByTestId('data-table-row').filter({ hasText: 'v6host1.example.lan.' })
  await expect(row).toContainText('2001:db8::1000')
  await expect(row.getByTestId('host-join')).toContainText('AAAA')
  await row.click()
  await expect(page.getByTestId('host-card')).toContainText('2001:db8::1000')

  await page.goto('/hosts')
  await page.getByTestId('host-create').click()
  await page.getByTestId('host-hostname').fill('cam6')
  await page.getByTestId('host-ip').fill('2001:db8::2b')
  await page.getByTestId('host-reservation-toggle').check()
  await page.getByTestId('host-mac').fill('02:00:5e:00:09:66')
  await expect(page.getByTestId('host-subnet')).toContainText('2001:db8::/64')
  await page.getByTestId('host-form').getByRole('button', { name: 'Preview the plan' }).click()
  await expect(page.getByTestId('plan-changes')).toContainText('AAAA')
  await expect(page.getByTestId('plan-changes')).toContainText('ip6.arpa')
  await expect(page.getByTestId('plan-changes')).toContainText('subnet6/1/reservations/hw-address=02:00:5e:00:09:66')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
  await page.goto('/hosts?q=cam6')
  await expect(page.getByTestId('hosts-table')).toContainText('2001:db8::2b')
})

test('leases page through the Kea cursor', async ({ page }) => {
  await page.goto('/dhcp/v4/leases')
  await page.getByTestId('lease-limit').getByRole('combobox').click()
  await page.getByRole('option', { name: '25', exact: true }).click()
  await expect(page.getByTestId('lease-total')).toContainText('25 leases on page 1')
  const first = await page.getByTestId('data-table-row').first().textContent()
  await page.getByTestId('lease-next').click()
  await expect(page.getByTestId('lease-total')).toContainText('page 2')
  await expect(page.getByTestId('data-table-row').first()).not.toHaveText(first)
  await page.getByTestId('lease-prev').click()
  await expect(page.getByTestId('lease-total')).toContainText('page 1')
  await expect(page.getByTestId('lease-prev')).toBeDisabled()
})

test('a diverged Kea file shows on the alert and blocks until a side is adopted', async ({ page }) => {
  await page.goto('/alerts')
  await page.getByTestId('alerts-table').getByText('/etc/kea/kea-dhcp-ddns.conf differs').click()
  await expect(page.getByTestId('alert-adopt-file')).toBeVisible()
  await expect(page.getByTestId('alert-adopt-running')).toBeVisible()
  await page.keyboard.press('Escape')
  await page.goto('/dhcp/v4/ddns')
  const banner = page.getByTestId('kea-file-banner-d2')
  await expect(banner).toContainText('/etc/kea/kea-dhcp-ddns.conf')
  await expect(banner.getByTestId('kea-file-differences')).toContainText('HMAC-MD5')
  await expect(page.getByTestId('kea-file-banner-v4')).toHaveCount(0)
  await banner.getByTestId('adopt-running').click()
  await expect(page.getByTestId('plan-preview')).toContainText('write the running configuration')
  await page.getByTestId('plan-confirm-checkbox').check()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('kea-file-banner-d2')).toHaveCount(0)
})

test('an enrollment token comes with the command to run', async ({ page }) => {
  await page.goto('/nodes')
  await expect(page.getByTestId('replication-sync')).toContainText('in sync')
  await page.getByTestId('enroll-open').click()
  await page.getByTestId('enroll-create').click()
  await expect(page.getByTestId('enroll-command')).toContainText('pelagos enroll')
  await expect(page.getByTestId('enroll-command-hint')).toContainText('Replace every <name>')
  await expect(page.getByTestId('enroll-expiry')).toContainText('Valid for')
})
