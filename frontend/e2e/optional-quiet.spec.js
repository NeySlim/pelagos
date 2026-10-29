// SPDX-License-Identifier: Apache-2.0
// Pages stay quiet when an optional part is unused: /nodes and the dashboard call no /dhcp/v6
// route without the dhcpv6 module, and the DDNS replay card counts nothing without an outage.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const modules = (page, dhcpv6) => page.evaluate(async (on) => {
  const csrf = sessionStorage.getItem('pelagos_csrf_token') || localStorage.getItem('pelagos_csrf_token') || ''
  const res = await fetch('/api/v1/admin/modules', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify({ cluster: { dhcpv6: on } }) })
  return res.status
}, dhcpv6)

test.beforeEach(async ({ page }) => {
  await page.request.post('/api/v1/_mock/scenario', { data: { name: 'pair' } })
})

test('without the dhcpv6 module, /nodes and the dashboard call no v6 route', async ({ page }) => {
  await signIn(page)
  expect(await modules(page, false)).toBe(200)
  const bad = []
  page.on('response', (res) => {
    if (res.url().includes('/api/') && (res.status() >= 400 || res.url().includes('/dhcp/v6/'))) bad.push(`${res.status()} ${res.url()}`)
  })
  page.on('console', (m) => { if (m.type() === 'error') bad.push(m.text()) })
  try {
    await page.reload()
    await page.goto('/nodes')
    await expect(page.getByTestId('data-table-row').first()).toBeVisible()
    await page.goto('/')
    await page.waitForLoadState('networkidle')
    await page.goto('/nodes')
    await page.waitForLoadState('networkidle')
    expect(bad).toEqual([])
  } finally {
    await modules(page, true)
  }
})

test('the replay card counts nothing without an outage and offers a manual window', async ({ page }) => {
  await signIn(page)
  await page.goto('/dhcp/v4/ddns?tab=failover')
  const card = page.getByTestId('ddns-replay')
  await expect(card.getByTestId('ddns-replay-source')).toHaveText('No outage known')
  await expect(card.getByTestId('ddns-replay-none')).toContainText('nothing is counted')
  await expect(card).not.toContainText('Leases to replay')
  await expect(card.getByTestId('ddns-replay-open')).toHaveText('Manual window')
  await card.getByTestId('ddns-replay-open').click()
  await expect(page.getByTestId('ddns-replay-from')).toHaveValue('')
  await page.getByTestId('ddns-replay-form').getByRole('button', { name: 'Preview the plan' }).click()
  await expect(page.getByTestId('ddns-replay-error')).toHaveText('Enter the start of the window')
})
