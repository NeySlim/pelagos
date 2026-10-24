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

test('an enrollment token comes with the command to run', async ({ page }) => {
  await page.goto('/nodes')
  await expect(page.getByTestId('replication-sync')).toContainText('in sync')
  await page.getByTestId('enroll-open').click()
  await page.getByTestId('enroll-create').click()
  await expect(page.getByTestId('enroll-command')).toContainText('pelagos enroll')
  await expect(page.getByTestId('enroll-expiry')).toContainText('Valid for')
})
