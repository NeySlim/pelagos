// SPDX-License-Identifier: Apache-2.0
// Clusters of three and four nodes (mock scenarios `three` and `four`): the cluster trace
// draws every node with its HA role and the mesh of links, signals travel to the node they
// concern, the HA page lists the pair and its backups and edits the relationship, the nodes
// page shows the roles, a zone has its secondaries on every peer with a transfer row each,
// and a plan's rail has one chip per node. At 1440 px and at 400 px.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const scenario = (page, name) => page.request.post('/api/v1/_mock/scenario', { data: { name } }).then((r) => r.json())
const event = (page, kind, extra = {}) => page.request.post('/api/v1/_mock/events', { data: { kind, ...extra } }).then((r) => r.json())

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(async ({ page }) => {
  await scenario(page, 'pair')
  expect(errors).toEqual([])
})

test.describe('at 1440 px', () => {
  test.use({ viewport: { width: 1440, height: 900 } })

  test('the cluster trace draws three nodes, their roles and the mesh, and carries the signals', async ({ page }) => {
    await scenario(page, 'three')
    await signIn(page)
    const tile = page.getByTestId('tile-trace')
    const topo = tile.getByTestId('trace-topology')
    await expect(topo).toHaveAttribute('data-nodes', '3')
    const cards = tile.getByTestId('trace-node')
    await expect(cards).toHaveCount(3)
    await expect(cards.nth(0)).toHaveAttribute('data-role', 'primary')
    await expect(cards.nth(1)).toHaveAttribute('data-role', 'standby')
    await expect(cards.nth(2)).toHaveAttribute('data-role', 'backup')
    await expect(cards.nth(2)).toContainText('Backup')
    // Three replication arcs, the HA link of the pair and the feed of the backup.
    const mesh = tile.getByTestId('trace-mesh-links')
    await expect(mesh).toHaveAttribute('data-links', '5')
    await expect(tile.getByTestId('trace-mesh-status')).toContainText('3 nodes in sync')
    await expect(tile.getByTestId('trace-link')).toHaveCount(0)
    // A replicated change reaches both peers: a pulse to each; a zone transfer to each secondary.
    await event(page, 'replication', { delayMs: 200 })
    await expect.poll(async () => Number(await mesh.getAttribute('data-signals')), { timeout: 15000 }).toBeGreaterThanOrEqual(2)
    const before = Number(await mesh.getAttribute('data-signals'))
    await event(page, 'transfer', { delayMs: 200 })
    await expect.poll(async () => Number(await mesh.getAttribute('data-signals')), { timeout: 15000 }).toBeGreaterThanOrEqual(before + 2)
    // Every card sits inside the tile, side by side.
    const boxes = await cards.evaluateAll((els) => els.map((e) => e.getBoundingClientRect().top))
    expect(new Set(boxes.map(Math.round)).size).toBe(1)
  })

  test('the HA page lists the pair and both backups, a backup is promoted through the relationship form', async ({ page }) => {
    await scenario(page, 'four')
    await signIn(page)
    await page.goto('/dhcp/v4/ha')
    const table = page.getByTestId('ha-servers')
    await expect(table.locator('tbody tr')).toHaveCount(4)
    await expect(table).toContainText('Backup')
    const rail = page.getByTestId('ha-rail-server')
    await expect(rail).toHaveCount(4)
    await expect(rail.nth(3)).toHaveAttribute('data-role', 'backup')
    const cards = page.getByTestId('ha-server')
    await expect(cards).toHaveCount(4)
    await expect(cards.nth(2).getByTestId('ha-backup-note')).toBeVisible()
    await expect(cards.nth(2).getByTestId('ha-maintenance-start')).toHaveCount(0)
    // Promote ns3: it takes the standby role, ns2 becomes a backup.
    await cards.nth(2).getByTestId('ha-promote').click()
    const form = page.getByTestId('ha-setup-form')
    await expect(form.getByTestId('ha-setup-server')).toHaveCount(4)
    const roles = await form.getByTestId('ha-setup-role').evaluateAll((els) => els.map((e) => e.value))
    expect(roles).toEqual(['primary', 'backup', 'standby', 'backup'])
    await form.getByRole('button', { name: 'Preview the plan' }).click()
    const preview = page.getByTestId('plan-preview')
    await expect(preview.getByTestId('plan-summary')).toContainText('on 4 servers')
    await preview.getByTestId('plan-confirm-checkbox').check()
    await preview.getByTestId('plan-apply').click()
    await expect(preview.getByTestId('plan-result')).toContainText('Applied')
    // One chip per node on the rail and in the result.
    await expect(preview.getByTestId('plan-steps-step').last().getByTestId('plan-steps-node')).toHaveCount(4)
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('ha-servers').locator('tbody tr').nth(2)).toContainText('Standby')
  })

  test('the nodes page shows the HA roles, a zone has a secondary on each peer and the plan keeps three', async ({ page }) => {
    await scenario(page, 'four')
    await signIn(page)
    await page.goto('/nodes')
    await expect(page.getByTestId('nodes-table').locator('tbody tr')).toHaveCount(4)
    await expect(page.getByTestId('node-ha-roles').first()).toContainText('v4')
    await expect(page.getByTestId('replication-link')).toHaveCount(3)

    await page.goto('/dns/zones/example.lan')
    await page.getByRole('button', { name: /Status per node/ }).click()
    await expect(page.getByTestId('zone-transfer-row')).toHaveCount(3)
    const card = page.getByTestId('zone-secondaries')
    const ids = await page.evaluate(async () => (await (await fetch('/api/v1/nodes')).json()).items.map((n) => n.peer.id))
    await card.getByTestId(`zone-secondary-${ids[3]}`).uncheck()
    await card.getByTestId('zone-secondaries-plan').click()
    const preview = page.getByTestId('plan-preview')
    await expect(preview.getByTestId('plan-summary')).toContainText('secondaries on ns2, ns3')
    await preview.getByTestId('plan-confirm-checkbox').check()
    await preview.getByTestId('plan-apply').click()
    await expect(preview.getByTestId('plan-result')).toContainText('Applied')
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('zone-transfer-row')).toHaveCount(2)
  })
})

test.describe('at 400 px', () => {
  test.use({ viewport: { width: 400, height: 860 } })

  const noOverflow = (page) => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)

  test('four nodes fit the trace tile and the HA page without a horizontal scroll', async ({ page }) => {
    await scenario(page, 'four')
    await signIn(page)
    const tile = page.getByTestId('tile-trace')
    await expect(tile.getByTestId('trace-topology')).toHaveAttribute('data-nodes', '4')
    await expect(tile.getByTestId('trace-node')).toHaveCount(4)
    for (const card of await tile.getByTestId('trace-node').all()) await expect(card).toBeVisible()
    await expect(tile.getByTestId('trace-mesh-status')).toContainText('ns4 behind by 1')
    expect(await noOverflow(page)).toBe(true)

    await page.goto('/dhcp/v4/ha')
    await expect(page.getByTestId('ha-server')).toHaveCount(4)
    await expect(page.getByTestId('ha-rail-server')).toHaveCount(4)
    expect(await noOverflow(page)).toBe(true)
  })

  test('three nodes: the plan rail wraps its chips', async ({ page }) => {
    await scenario(page, 'three')
    await signIn(page)
    await page.goto('/dhcp/v4/ha')
    await page.getByTestId('ha-setup').click()
    const form = page.getByTestId('ha-setup-form')
    await expect(form.getByTestId('ha-setup-server')).toHaveCount(3)
    await form.getByRole('button', { name: 'Preview the plan' }).click()
    const preview = page.getByTestId('plan-preview')
    await expect(preview.getByTestId('plan-target-nodes')).toContainText('ns3')
    await preview.getByTestId('plan-confirm-checkbox').check()
    await preview.getByTestId('plan-apply').click()
    await expect(preview.getByTestId('plan-result')).toContainText('Applied')
    await expect(preview.getByTestId('plan-steps-step').last().getByTestId('plan-steps-node')).toHaveCount(3)
    expect(await noOverflow(page)).toBe(true)
  })
})
