// SPDX-License-Identifier: Apache-2.0
// Smoke test against the mock server: sign in, visit every route of the area
// registry, switch theme and language, sign out.
import { test, expect } from '@playwright/test'

// Concrete paths for the routes of src/pages/*/routes.js (parameters filled in).
const PAGES = [
  ['/', 'page-dashboard-overview'],
  ['/dns/zones', 'page-dns-zones'],
  ['/dns/zones/example.lan', 'page-dns-zoneDetail'],
  ['/dns/resolver', 'page-dns-resolver'],
  ['/dns/acls-keys', 'page-dns-aclsKeys'],
  ['/dns/secondaries', 'page-dns-secondaries'],
  ['/dns/dnssec', 'page-dns-dnssec'],
  ['/dns/rpz', 'page-dns-rpz'],
  ...['v4', 'v6'].flatMap((family) =>
    [
      ['subnets', 'subnets'],
      ['shared-networks', 'sharedNetworks'],
      ['options', 'options'],
      ['classes', 'classes'],
      ['leases', 'leases'],
      ['reservations', 'reservations'],
      ['ha', 'ha'],
      ['ddns', 'ddns'],
      ['hooks', 'hooks'],
    ].map(([path, page]) => [`/dhcp/${family}/${path}`, `page-dhcp-${page}`]),
  ),
  ['/hosts', 'page-hosts-list'],
  ['/alerts', 'page-alerts-list'],
  ['/nodes', 'page-nodes-list'],
  ['/audit', 'page-audit-list'],
  ['/advanced/bind', 'page-advanced-bind'],
  ['/advanced/kea', 'page-advanced-kea'],
  ['/advanced/history', 'page-advanced-history'],
  ['/install', 'page-install-detect'],
  ['/install/security', 'page-install-security'],
  ['/admin/users', 'page-admin-users'],
  ['/admin/roles', 'page-admin-roles'],
  ['/admin/modules', 'page-admin-modules'],
  ['/admin/settings', 'page-admin-settings'],
  ['/account', 'page-account-account'],
]

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

test('rejects a wrong password', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/login$/)
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('wrong')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('login-error')).toBeVisible()
})

test('asks for the TOTP code when the account has one', async ({ page }) => {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('bob')
  await page.getByTestId('login-password').fill('bob')
  await page.getByTestId('login-submit').click()
  await page.getByTestId('login-totp').fill('123456')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
})

test('every page renders with data from the API', async ({ page }) => {
  const errors = []
  page.on('pageerror', (err) => errors.push(err.message))
  await signIn(page)
  for (const [path, testId] of PAGES) {
    await page.goto(path)
    await expect(page.getByTestId(testId), path).toBeVisible()
    // Placeholder pages show the raw answer; built pages must not show a read error.
    if (await page.getByTestId('placeholder-data').count()) await expect(page.getByTestId('json-tree'), path).toBeVisible()
    else await expect(page.getByTestId('data-table-loading')).toHaveCount(0)
    await expect(page.getByTestId('data-table-error'), path).toHaveCount(0)
  }
  expect(errors).toEqual([])
})

test('navigation, theme and language follow the user menu', async ({ page }) => {
  await signIn(page)
  // The event WebSocket goes through the Vite proxy to the mock.
  await expect(page.getByTestId('ws-dot')).toHaveAttribute('title', 'Live updates on')
  await page.locator('[data-nav="dns-zones"]').click()
  await expect(page.getByTestId('page-dns-zones')).toBeVisible()
  // Groups other than DNS and DHCP start collapsed.
  await page.getByRole('button', { name: 'Hosts', exact: true }).click()
  await page.locator('[data-nav="hosts"]').click()
  await expect(page.getByTestId('page-hosts-list')).toBeVisible()

  await page.getByTestId('user-menu').click()
  await page.locator('[data-theme-option="sunset"]').click()
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent-primary').trim())).not.toBe('#2DD4BF')

  await page.getByTestId('user-menu').click()
  await page.getByText('English').hover()
  await page.getByText('Français').click()
  await expect(page.locator('[data-nav="hosts"]')).toHaveText('Hôtes')

  await page.getByTestId('user-menu').click()
  await page.getByTestId('logout').click()
  await expect(page).toHaveURL(/\/login$/)
})

test('a viewer does not see administration', async ({ page }) => {
  await signIn(page, 'viewer', 'viewer')
  await expect(page.locator('[data-nav="admin-users"]')).toHaveCount(0)
  await page.goto('/admin/users')
  await expect(page.getByTestId('page-dashboard-overview')).toBeVisible()
})
