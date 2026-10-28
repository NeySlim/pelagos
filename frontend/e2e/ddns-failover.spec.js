// SPDX-License-Identifier: Apache-2.0
// DHCP > DDNS > Failover against the mock: blockers with the handover link, the prepare plan,
// an outage raised by the collectors with its banner and alert link, the promotion, the old
// primary coming back stale then demoted, and the replay of the outage window.
import { test, expect } from '@playwright/test'

const event = (page, kind, extra = {}) => page.request.post('/api/v1/_mock/events', { data: { kind, ...extra } }).then((r) => r.json())

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function apply(page, summary, confirm = false) {
  const preview = page.getByTestId('plan-preview')
  await expect(preview.getByTestId('plan-summary')).toContainText(summary)
  if (confirm) await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(preview).toHaveAttribute('data-plan-state', 'applied', { timeout: 20000 })
  await page.getByRole('button', { name: 'Close', exact: true }).last().click()
  await expect(preview).toBeHidden()
}

const zoneRow = (page, zone) => page.getByTestId('ddns-zones').locator('tr', { has: page.locator(`[data-zone-row="${zone}"]`) })

test.beforeEach(async ({ page }) => {
  await page.request.post('/api/v1/_mock/scenario', { data: { name: 'pair' } })
})

test('prepares, promotes during an outage, demotes the old primary and replays the window', async ({ page }) => {
  await signIn(page)
  await page.goto('/dhcp/v4/ddns')
  await page.getByRole('button', { name: 'Failover' }).click()
  await expect(page).toHaveURL(/tab=failover/)

  const managed = zoneRow(page, '_default/example.lan.')
  await expect(managed.getByTestId('ddns-zone-state')).toHaveAttribute('data-state', 'blocked')
  await expect(managed.getByTestId('ddns-blocker-adopt')).toHaveAttribute('href', '/dns/zones/example.lan')
  await expect(zoneRow(page, 'internal/100.51.198.in-addr.arpa.').getByTestId('ddns-blocker')).toHaveAttribute('data-key', 'ddns.blocker.no_transfer')

  await page.getByTestId('ddns-prepare-all').click()
  await apply(page, 'prepare the DDNS failover of 2 zones')
  const corp = zoneRow(page, 'internal/corp.example.lan.')
  await expect(corp.getByTestId('ddns-zone-state')).toHaveAttribute('data-state', 'ready')
  await expect(page.getByTestId('ddns-d2-node').first()).toContainText('copy')

  const out = await event(page, 'ddns-outage')
  expect(out.alerts.length).toBe(2)
  await page.goto('/alerts')
  await page.getByText('has received no DDNS update', { exact: false }).first().click()
  await page.getByTestId('alert-open-subject').click()
  await expect(page).toHaveURL(/tab=failover&zone=/)
  const banner = page.getByTestId('ddns-outage-banner')
  await expect(banner).toContainText('named on ns1 does not answer')
  await expect(page.getByTestId('ddns-replay-source')).toHaveText('Outage in progress')

  await banner.getByTestId('ddns-promote').click()
  const form = page.getByTestId('ddns-role-form')
  await form.getByTestId('ddns-role-target').selectOption({ label: 'ns2' })
  await form.getByRole('button', { name: 'Preview the plan' }).click()
  await apply(page, 'promote ns2 primary of 2 zones in place of ns1 (epoch 2)', true)
  await expect(banner).toBeHidden()
  await expect(corp).toContainText('ns2')

  await event(page, 'ddns-return')
  await page.getByTestId('page-refresh').click()
  const stale = page.getByTestId('ddns-stale-banner')
  await expect(stale).toContainText('ns1 serves it as primary, the role belongs to ns2 (epoch 2)')
  await expect(corp.getByTestId('ddns-zone-state')).toHaveAttribute('data-state', 'stale')
  await event(page, 'ddns-demote')
  await page.getByTestId('page-refresh').click()
  await expect(stale).toBeHidden()

  const replay = page.getByTestId('ddns-replay')
  await expect(replay.getByTestId('ddns-replay-source')).toHaveText('Last outage')
  await replay.getByTestId('ddns-replay-open').click()
  await expect(page.getByTestId('ddns-replay-from')).not.toHaveValue('')
  await page.getByTestId('ddns-replay-form').getByRole('button', { name: 'Preview the plan' }).click()
  await apply(page, 'resend the DNS updates of 3 leases', true)
  await expect(replay).toContainText('0')

  await page.goto('/dns/zones/corp.example.lan?view=internal')
  await expect(page.getByTestId('zone-failover-badge')).toContainText('active primary on ns2')
})

test('hands the role back with a switchover while both nodes answer', async ({ page }) => {
  await signIn(page)
  await page.goto('/dhcp/v4/ddns?tab=failover')
  await page.getByTestId('ddns-prepare-all').click()
  await apply(page, 'prepare the DDNS failover')
  const row = zoneRow(page, 'internal/corp.example.lan.')
  await row.getByTestId('ddns-row-switchover').click()
  await page.getByTestId('ddns-role-form').getByRole('button', { name: 'Preview the plan' }).click()
  await apply(page, 'give the primary role of 1 zones back to ns2 from ns1 (epoch 2)', true)
  await expect(row).toContainText('ns2')
  await page.goto('/')
  await expect(page.getByTestId('tile-d2-failover')).toContainText('2/5 zones ready')
})
