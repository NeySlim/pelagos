// SPDX-License-Identifier: Apache-2.0
// Item 46: the alerts page is the cluster's. Each row names its node, or "Cluster" with the
// nodes reporting it; the node filter keeps a node's alerts and the cluster-wide ones it reports;
// a node whose alerts cannot be read is named above the table and on the dashboard tile.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const event = (page, kind, extra = {}) => page.request.post('/api/v1/_mock/events', { data: { kind, ...extra } }).then((r) => r.json())

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(async ({ page }) => {
  await event(page, 'alerts-peer', { node: 'ns2', down: false })
  expect(errors).toEqual([])
})

test('every alert says where it comes from and the node filter keeps that node', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts')
  const table = page.getByTestId('alerts-table')
  const rsa = table.locator('tr', { hasText: 'rndc-key' })
  await expect(rsa.getByTestId('alert-origin')).toHaveText('ns2')
  const ptr = table.locator('tr', { hasText: '192.0.2.106' }).first()
  await expect(ptr.getByTestId('alert-origin')).toContainText('Cluster')
  await expect(ptr.getByTestId('alert-origin')).toContainText('via ns1')
  const all = await table.getByTestId('alert-origin').count()
  await page.goto('/alerts?node_id=' + (await nodeId(page, 'ns2')))
  await expect(table.locator('tr', { hasText: 'rndc-key' })).toHaveCount(1)
  await expect(table.locator('tr', { hasText: '192.0.2.106' })).toHaveCount(0)
  expect(await table.getByTestId('alert-origin').count()).toBeLessThan(all)
})

test('a node that does not answer is named and its alerts are left out of the counts', async ({ page }) => {
  await signIn(page)
  await page.goto('/alerts')
  const table = page.getByTestId('alerts-table')
  await expect(table.locator('tr', { hasText: 'rndc-key' })).toHaveCount(1)
  await event(page, 'alerts-peer', { node: 'ns2', down: true })
  await page.reload()
  await expect(page.getByTestId('alerts-unavailable')).toContainText('Alerts of ns2 are not shown')
  await expect(table.locator('tr', { hasText: 'rndc-key' })).toHaveCount(0)
  await page.goto('/')
  await expect(page.getByTestId('tile-alerts-unavailable')).toContainText('ns2')
})

async function nodeId(page, name) {
  const res = await page.request.get('/api/v1/nodes')
  const body = await res.json()
  return body.items.find((n) => n.peer.name === name).peer.id
}
