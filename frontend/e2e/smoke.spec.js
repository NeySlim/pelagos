// SPDX-License-Identifier: Apache-2.0
// Smoke test against the mock server: sign in, visit every route of the area
// registry and find each page's own data element, apply and roll back a plan
// through a real screen, switch theme and language, sign out.
import { test, expect } from '@playwright/test'

// Concrete paths for the routes of src/pages/*/routes.js (parameters filled in):
// [path, page test id, test id of an element the page fills from the API].
const PAGES = [
  ['/', 'page-dashboard-overview', 'tile-node'],
  ['/dns/zones', 'page-dns-zones', 'zones-table'],
  ['/dns/zones/example.lan', 'page-dns-zoneDetail', 'records-table'],
  ['/dns/resolver', 'page-dns-resolver', 'resolver-settings'],
  ['/dns/acls-keys', 'page-dns-aclsKeys', 'acls-table'],
  ['/dns/secondaries', 'page-dns-secondaries', 'secondaries-table'],
  ['/dns/dnssec', 'page-dns-dnssec', 'dnssec-zones'],
  ['/dns/rpz', 'page-dns-rpz', 'rpz-table'],
  ...['v4', 'v6'].flatMap((family) =>
    [
      ['subnets', 'subnets', 'subnets-table'],
      ['shared-networks', 'sharedNetworks', family === 'v4' ? 'network-list' : null],
      ['options', 'options', 'options-table'],
      ['classes', 'classes', 'classes-table'],
      ['leases', 'leases', 'leases-table'],
      ['reservations', 'reservations', 'reservations-table'],
      ['ha', 'ha', 'ha-summary'],
      ['ddns', 'ddns', 'ddns-params'],
      ['hooks', 'hooks', 'hooks-table'],
    ].map(([path, page, data]) => [`/dhcp/${family}/${path}`, `page-dhcp-${page}`, data]),
  ),
  ['/hosts', 'page-hosts-list', 'hosts-table'],
  ['/alerts', 'page-alerts-list', 'alerts-table'],
  ['/nodes', 'page-nodes-list', 'nodes-table'],
  ['/audit', 'page-audit-list', 'audit-table'],
  ['/advanced/bind', 'page-advanced-bind', 'bind-tree'],
  ['/advanced/kea', 'page-advanced-kea', 'kea-tree'],
  ['/advanced/history', 'page-advanced-history', 'history-table'],
  ['/advanced/ops', 'page-advanced-ops', 'ops-list'],
  ['/install', 'page-install-detect', 'install-detect'],
  ['/install/security', 'page-install-security', 'security-finding'],
  ['/admin/users', 'page-admin-users', 'users-table'],
  ['/admin/roles', 'page-admin-roles', 'roles-list'],
  ['/admin/modules', 'page-admin-modules', 'modules-cluster'],
  ['/admin/settings', 'page-admin-settings', 'settings-general'],
  ['/account', 'page-account-account', 'account-profile'],
]

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

// Page errors and console errors or warnings once signed in (React warnings included).
function watchConsole(page) {
  const problems = []
  let armed = false
  page.on('pageerror', (err) => problems.push(`pageerror: ${err.message}`))
  page.on('response', (res) => {
    if (armed && res.status() >= 400) problems.push(`http ${res.status()}: ${res.request().method()} ${new URL(res.url()).pathname}`)
  })
  page.on('console', (msg) => {
    if (armed && (msg.type() === 'error' || msg.type() === 'warning')) problems.push(`${msg.type()}: ${msg.text()}`)
  })
  return { problems, arm: () => { armed = true } }
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

test('every page renders its own data from the API, without console errors', async ({ page }) => {
  const watch = watchConsole(page)
  await signIn(page)
  watch.arm()
  for (const [path, pageId, dataId] of PAGES) {
    await page.goto(path)
    await expect(page.getByTestId(pageId), path).toBeVisible()
    if (dataId) await expect(page.getByTestId(dataId).first(), path).toBeVisible()
    await expect(page.getByTestId('data-table-loading'), path).toHaveCount(0)
    await expect(page.getByTestId('data-table-error'), path).toHaveCount(0)
    await expect(page.getByRole('alert').filter({ hasText: /error|failed/i }), path).toHaveCount(0)
  }
  expect(watch.problems).toEqual([])
})

test('a record plan is applied, then rolled back, through the zone screen', async ({ page }) => {
  const watch = watchConsole(page)
  await signIn(page)
  watch.arm()
  const records = () => page.request.get('/api/v1/dns/zones/example.lan/records?name=smoke&type=A').then((r) => r.json())
  expect((await records()).total).toBe(0)

  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill('smoke')
  await page.getByTestId('record-rdata').fill('192.0.2.77')
  await expect(page.getByTestId('record-preview')).toContainText('192.0.2.77')
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()

  await expect(page.getByTestId('plan-preview')).toBeVisible()
  await expect(page.getByTestId('plan-diff')).toContainText('smoke.example.lan.')
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  expect((await records()).total).toBe(1)

  await page.getByTestId('plan-rollback').click()
  await expect(page.getByTestId('plan-result')).toContainText('Rolled back')
  expect((await records()).total).toBe(0)
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('records-table')).not.toContainText('smoke.example.lan.')
  expect(watch.problems).toEqual([])
})

test('an alert is acknowledged from the alerts screen', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts')
  const table = page.getByTestId('alerts-table')
  await expect(table.getByTestId('data-table-row').first()).toBeVisible()
  const before = await table.getByTestId('alert-row-ack').count()
  await table.getByTestId('alert-row-ack').first().click()
  await page.getByRole('button', { name: 'Acknowledge' }).last().click()
  await expect(table.getByTestId('alert-row-ack')).toHaveCount(before - 1)
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
  await expect(page.getByTestId('route-forbidden')).toBeVisible()
  await page.getByTestId('route-forbidden').getByRole('button').click()
  await expect(page.getByTestId('page-dashboard-overview')).toBeVisible()
})

test('an unknown path explains itself and leads back to the dashboard', async ({ page }) => {
  await signIn(page)
  await page.goto('/no/such/page')
  await expect(page.getByTestId('route-not_found')).toBeVisible()
  await page.getByTestId('route-not_found').getByRole('button').click()
  await expect(page.getByTestId('page-dashboard-overview')).toBeVisible()
})
