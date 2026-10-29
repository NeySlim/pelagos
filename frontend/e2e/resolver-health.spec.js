// SPDX-License-Identifier: Apache-2.0
// DNS > Resolver > Health against the mock: the root servers stop answering, the proposing alert
// opens the fallback form, the fallback plan is applied, the banner and the dashboard tile show
// it, the deadline is extended, the probes recover and the return plan puts things back.
import { test, expect } from '@playwright/test'

const event = (page, kind, extra = {}) => page.request.post('/api/v1/_mock/events', { data: { kind, ...extra } }).then((r) => r.json())

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function apply(page, summary) {
  const preview = page.getByTestId('plan-preview')
  await expect(preview.getByTestId('plan-summary')).toContainText(summary)
  await preview.getByTestId('plan-confirm-checkbox').check()
  await preview.getByTestId('plan-apply').click()
  await expect(preview).toHaveAttribute('data-plan-state', 'applied', { timeout: 20000 })
  await page.getByRole('button', { name: 'Close', exact: true }).last().click()
  await expect(preview).toBeHidden()
}

test.beforeEach(async ({ page }) => {
  await page.request.post('/api/v1/_mock/scenario', { data: { name: 'pair' } })
})

test('falls back to forwarders from the alert, extends, then returns', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/resolver')
  const nodes = page.getByTestId('resolver-node')
  await expect(nodes).toHaveCount(2)
  await expect(nodes.first().getByTestId('resolver-roots-badge')).toContainText('13/13 root servers answer')
  await expect(page.getByTestId('resolver-thresholds')).toBeVisible()
  await expect(page.getByTestId('resolver-chart')).not.toHaveAttribute('data-points', '0')
  await page.getByTestId('resolver-range-7d').click()
  await expect(page.getByTestId('resolver-range-7d')).toHaveAttribute('aria-pressed', 'true')

  const out = await event(page, 'resolver-outage')
  expect(out.alerts.length).toBe(2)
  await page.goto('/alerts')
  await page.getByText('cannot reach the root servers', { exact: false }).first().click()
  const link = page.getByTestId('alert-open-subject')
  await expect(link).toContainText('Propose the forwarder fallback')
  await link.click()
  await expect(page).toHaveURL(/\/dns\/resolver\?fallback=1/)
  await expect(nodes.first().getByTestId('resolver-roots-badge')).toContainText('0/13 root servers answer')

  const form = page.getByTestId('resolver-fallback-form')
  await expect(form.getByTestId('resolver-fallback-forwarders-input')).toContainText('9.9.9.9')
  await expect(form.getByTestId('resolver-fallback-node')).toHaveCount(2)
  await form.getByRole('switch').click()
  await form.getByRole('button', { name: 'Preview the plan' }).click()
  await apply(page, 'send the queries of ns1, ns2 to 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9 (forward first)')
  await expect(page).not.toHaveURL(/fallback=1/)

  const banner = page.getByTestId('resolver-fallback-banner')
  await expect(banner.getByTestId('resolver-fallback-forwarders')).toContainText('9.9.9.9, 149.112.112.112')
  await expect(banner).toContainText('DNS over TLS: dns.quad9.net')
  await expect(banner.getByTestId('resolver-fallback-ready')).toBeHidden()
  await expect(page.getByTestId('resolver-settings')).toContainText('port 853 tls "dns.quad9.net"')
  await expect(page.getByTestId('resolver-fallback-open')).toBeHidden()

  await banner.getByTestId('resolver-fallback-extend').click()
  const extend = page.getByTestId('resolver-extend-form')
  await extend.getByRole('button', { name: 'Extend' }).click()
  await expect(extend).toBeHidden()
  await expect(banner.getByTestId('resolver-fallback-until')).toContainText(/\(3 h 5\d min left\)|\(4 h 0 min left\)/)

  await page.goto('/')
  const tile = page.getByTestId('tile-resolver')
  await expect(tile.getByTestId('tile-resolver-fallback')).toContainText('9.9.9.9, 149.112.112.112')
  await expect(tile.getByTestId('tile-resolver-probes')).toContainText('failing on 2 nodes')

  await event(page, 'resolver-recover', { minutes: 20 })
  await page.goto('/dns/resolver')
  await expect(banner.getByTestId('resolver-fallback-ready')).toBeVisible()
  await banner.getByTestId('resolver-fallback-return').click()
  await apply(page, 'resolve directly again on ns1, ns2')
  await expect(banner).toBeHidden()
  await expect(page.getByTestId('resolver-settings')).toContainText('192.0.2.1')
  await expect(page.getByTestId('resolver-settings')).not.toContainText('9.9.9.9')
  await expect(page.getByTestId('resolver-fallback-open')).toBeVisible()
})

test('refuses an own address list with a port, and keeps the viewer read-only', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/resolver')
  await page.getByTestId('resolver-fallback-open').click()
  const form = page.getByTestId('resolver-fallback-form')
  const input = form.getByTestId('resolver-fallback-forwarders-input').locator('input')
  await input.fill('192.0.2.53 port 5353')
  await input.press('Enter')
  await expect(form.getByTestId('resolver-fallback-forwarders-input')).not.toContainText('192.0.2.53 port 5353')
  await page.keyboard.press('Escape')
  await expect(form).toBeHidden()

  await page.context().clearCookies()
  await page.goto('/login')
  await page.getByTestId('login-username').fill('viewer')
  await page.getByTestId('login-password').fill('viewer')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.goto('/dns/resolver?fallback=1')
  await expect(page.getByTestId('resolver-node')).toHaveCount(2)
  await expect(page.getByTestId('resolver-fallback-open')).toBeHidden()
  await expect(page.getByTestId('resolver-fallback-form')).toBeHidden()
})
