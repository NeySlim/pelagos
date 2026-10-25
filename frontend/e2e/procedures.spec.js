// SPDX-License-Identifier: Apache-2.0
// Domain procedures and their motion against the live mock: a record plan ticks its checks,
// applies along the step rail and rewinds the zone serial trace when rolled back (also from
// the toast action); zone transfers, leases, HA, alerts and replication each move their
// mark when the mock produces the event; reduced motion keeps no travel, off keeps none.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const event = (page, kind, extra = {}) => page.request.post('/api/v1/_mock/events', { data: { kind, ...extra } }).then((r) => r.json())
const style = (locator, prop) => locator.evaluate((el, p) => getComputedStyle(el)[p], prop)

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

async function previewRecord(page, owner, ip) {
  await page.goto('/dns/zones/example.lan')
  await page.getByTestId('record-add').click()
  await page.getByTestId('record-owner').fill(owner)
  await page.getByTestId('record-rdata').fill(ip)
  await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
  const preview = page.getByTestId('plan-preview')
  await expect(preview).toBeVisible()
  return preview
}

test('a record plan ticks its checks, applies along the rail, and its rollback rewinds the serial trace', async ({ page }) => {
  await signIn(page)
  const preview = await previewRecord(page, 'e2e-rail', '192.0.2.71')
  await expect(page.getByTestId('zone-serial-trace')).toBeAttached()
  await expect(preview.getByTestId('plan-checklist').locator('li[data-state="done"]')).toHaveCount(1)
  await expect(preview.getByTestId('plan-validations-count')).toContainText('1/1')

  await preview.getByTestId('plan-apply').click()
  const rail = preview.getByTestId('plan-rail')
  await expect(rail).toHaveAttribute('data-direction', 'forward')
  await expect(preview.getByTestId('plan-validations')).toHaveAttribute('data-open', 'false')
  await expect(preview.getByTestId('plan-diff')).toHaveAttribute('data-open', 'false')
  // The mock applies at the pace of a node: the local step is seen running, then done.
  await expect(rail.getByTestId('plan-steps-step').first()).toHaveAttribute('data-state', 'running')
  await expect(preview.getByTestId('plan-result')).toContainText('Applied')
  await expect(rail.getByTestId('plan-steps-step')).toHaveCount(2)
  for (const step of await rail.getByTestId('plan-steps-step').all()) await expect(step).toHaveAttribute('data-state', 'done')
  await expect(rail.getByTestId('plan-steps-step').first()).toContainText(/\d+ ms/)
  expect(await style(rail.locator('.fx-rail-fill'), 'transitionTimingFunction')).toBe('linear')

  await preview.getByTestId('plan-rollback').click()
  await expect(rail).toHaveAttribute('data-direction', 'reverse')
  await expect(page.getByTestId('serial-trace')).toHaveAttribute('data-scrubbing', 'true')
  await expect(preview).toHaveAttribute('data-plan-state', 'rolled_back')
  for (const step of await rail.getByTestId('plan-steps-step').all()) await expect(step).toHaveAttribute('data-state', 'reverted')
  await expect(preview.getByTestId('plan-result')).toContainText('Rolled back')
  await expect(page.getByTestId('serial-trace')).not.toHaveAttribute('data-scrubbing', 'true', { timeout: 5000 })
  await page.keyboard.press('Escape')
})

test('the toast of an applied plan offers its rollback; the inserted row unfolds, then folds away', async ({ page }) => {
  await signIn(page)
  const preview = await previewRecord(page, 'e2e-toast', '192.0.2.72')
  await preview.getByTestId('plan-apply').click()
  await expect(preview.getByTestId('plan-result')).toContainText('Applied')
  await preview.getByRole('button', { name: 'Close' }).click()
  const row = page.getByTestId('records-table').locator('tr', { hasText: 'e2e-toast' })
  await expect(row).toHaveAttribute('data-row-phase', 'enter')
  const toast = page.locator('.ui-toast', { hasText: 'Plan applied' })
  await expect(toast).toBeVisible()
  await expect(toast.locator('.fx-toast-ttl')).toBeAttached()
  await toast.getByTestId('toast-rollback-plan').click()
  const again = page.getByTestId('plan-preview')
  await expect(again).toHaveAttribute('data-plan-state', 'rolled_back')
  await expect(again.getByTestId('plan-rail')).toHaveAttribute('data-direction', 'reverse')
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('records-table').locator('tr', { hasText: 'e2e-toast' })).toHaveCount(0)
})

test('a lagging node catches up through a transfer bar and its serial rolls on arrival', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/zones/corp.example.lan?view=internal')
  await page.getByRole('button', { name: 'Status per node' }).click()
  await expect(page.getByTestId('zone-status')).toBeVisible()
  const refresh = async () => {
    await page.getByTestId('zone-more').click()
    await page.getByTestId('zone-refresh').click()
  }
  await event(page, 'transfer', { zone: 'corp.example.lan.', delayMs: 2500 })
  await refresh()
  const serials = page.getByTestId('zone-status-serial')
  await expect.poll(async () => new Set(await serials.evaluateAll((els) => els.map((e) => e.dataset.value))).size).toBe(2)
  await page.waitForTimeout(2700)
  await refresh()
  await expect(page.locator('[data-testid="transfer-bar"][data-run]').first()).toBeAttached()
  await expect.poll(async () => new Set(await serials.evaluateAll((els) => els.map((e) => e.dataset.value))).size).toBe(1)
})

test('a new lease plays DORA in the leases table and on the dashboard', async ({ page }) => {
  await signIn(page)
  await page.goto('/dhcp/v4/leases')
  await expect(page.getByTestId('leases-table').getByTestId('data-table-row').first()).toBeVisible()
  const { ip } = await event(page, 'lease')
  await page.getByTestId('lease-activity').click()
  const row = page.getByTestId('leases-table').locator('tr', { hasText: ip })
  await expect(row).toHaveAttribute('data-row-phase', 'enter')
  await expect(row.getByTestId('dora')).toHaveClass(/is-go/)

  await page.goto('/')
  const latest = page.getByTestId('latest-lease')
  await expect(latest).toBeVisible()
  const next = await event(page, 'lease')
  await expect(latest).toHaveAttribute('data-lease', next.ip)
  await expect(latest.getByTestId('dora')).toHaveClass(/is-go/)
})

test('HA heartbeats trace the ECG; the unsent queue fills on failover and drains on failback', async ({ page }) => {
  await signIn(page)
  await page.goto('/dhcp/v4/ha')
  const beat = page.getByTestId('ha-heartbeat').first()
  await expect(beat).toBeVisible()
  await expect.poll(async () => Number(await beat.getAttribute('data-beats')), { timeout: 12000 }).toBeGreaterThan(0)
  try {
    await event(page, 'ha-failover')
    await expect(beat).toHaveClass(/is-lost/)
    const queue = page.getByTestId('unsent-queue').first()
    await expect.poll(async () => Number(await queue.getAttribute('data-count')), { timeout: 10000 }).toBeGreaterThan(1)
    await expect(queue.locator('.fx-queue-slots > i').first()).toBeAttached()
  } finally {
    await event(page, 'ha-failback')
  }
  await expect(page.getByTestId('unsent-queue').first()).toHaveAttribute('data-draining', 'true')
  await expect(page.getByTestId('unsent-queue').first()).toHaveAttribute('data-count', '0')
  await expect(beat).not.toHaveClass(/is-lost/)
})

test('an alert crosses its threshold, latches on the pool trace, then resolves', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts?state=')
  await expect(page.getByTestId('alerts-table').getByTestId('data-table-row').first()).toBeVisible()
  const opened = await event(page, 'alert')
  const row = page.getByTestId('alerts-table').locator('tr', { hasText: '100% used' }).first()
  await expect(row).toHaveAttribute('data-row-phase', 'enter')
  await row.click()
  const pressure = page.getByTestId('alert-pressure')
  await expect(pressure).toBeVisible()
  await expect(pressure.getByTestId('threshold-trace')).toHaveAttribute('data-latches', 'open')
  await event(page, 'alert-resolve')
  await expect(pressure.getByTestId('threshold-trace')).toHaveAttribute('data-latches', 'held released')
  expect(opened.ok).toBe(true)
  await page.keyboard.press('Escape')
})

test('replication: a pulse crosses the link and the peer configuration version rolls', async ({ page }) => {
  await signIn(page)
  await page.goto('/nodes')
  const link = page.getByTestId('replication-link')
  await expect(link).toBeVisible()
  const { config_version: version } = await event(page, 'replication', { delayMs: 800 })
  await expect(page.getByTestId('replication-self-version').locator('.sr-only')).toHaveText(String(version), { timeout: 15000 })
  await expect(page.getByTestId('replication-peer-version').locator('.sr-only')).toHaveText(String(version), { timeout: 15000 })
  await expect(link).toContainText('All peers in sync')
})

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' })

  test('the rail and the checks change without travel, a transfer has no bar', async ({ page }) => {
    await signIn(page)
    const preview = await previewRecord(page, 'e2e-reduced', '192.0.2.73')
    await preview.getByTestId('plan-apply').click()
    await expect(preview.getByTestId('plan-result')).toContainText('Applied')
    expect(await style(preview.locator('.fx-rail-fill'), 'transitionProperty')).toBe('none')
    expect(await style(preview.locator('.fx-ck.is-done svg path').first(), 'transitionProperty')).toBe('none')
    await preview.getByTestId('plan-rollback').click()
    await expect(preview).toHaveAttribute('data-plan-state', 'rolled_back')
    await page.keyboard.press('Escape')

    await page.goto('/dns/zones/corp.example.lan?view=internal')
    await page.getByRole('button', { name: 'Status per node' }).click()
    await event(page, 'transfer', { zone: 'corp.example.lan.', delayMs: 1500 })
    await page.getByTestId('zone-more').click()
    await page.getByTestId('zone-refresh').click()
    await page.waitForTimeout(1700)
    await page.getByTestId('zone-more').click()
    await page.getByTestId('zone-refresh').click()
    const serials = page.getByTestId('zone-status-serial')
    await expect.poll(async () => new Set(await serials.evaluateAll((els) => els.map((e) => e.dataset.value))).size).toBe(1)
    await expect(page.locator('[data-testid="transfer-bar"][data-run]')).toHaveCount(0)
  })
})

test('motion off: checks are drawn at once and nothing traces', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.motion)).toBe('off')
  try {
    const preview = await previewRecord(page, 'e2e-off', '192.0.2.74')
    await expect(preview.getByTestId('plan-checklist').locator('li[data-state="done"]')).toHaveCount(1)
    expect(await style(preview.getByTestId('plan-checklist').locator('.fx-checklist-rail > i'), 'transitionDuration')).toBe('0s')
    await page.keyboard.press('Escape')
    await page.goto('/dhcp/v4/ha')
    const beat = page.getByTestId('ha-heartbeat').first()
    await expect.poll(async () => Number(await beat.getAttribute('data-beats')), { timeout: 12000 }).toBeGreaterThan(0)
    await expect(page.locator('.fx-ecg-qrs.is-beat')).toHaveCount(0)
  } finally {
    await page.goto('/account')
    await page.getByTestId('pref-animations').getByRole('combobox').click()
    await page.getByRole('option', { name: 'Full' }).click()
    await expect.poll(() => page.evaluate(() => document.documentElement.dataset.motion)).toBe('full')
  }
})
