// SPDX-License-Identifier: Apache-2.0
// The Instrument dashboard: the cluster trace draws the measured signals on a canvas on
// the shared loop, the playhead reads the exact sample (pointer or keys), the window
// zooms with its scale bar, Kea heartbeats give an interval and a jitter, a plan lands on
// the events lane, the latest leases land as DORA ticks, the hottest pool has its
// pressure trace, and the motion levels hold.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

const loopStats = (page) => page.evaluate(() => window.__pelagosLoop?.() ?? { active: 0, frames: 0, running: false, p95: 0 })

// A second session drives the mock through the API, as another operator would.
async function api(playwright, baseURL) {
  const ctx = await playwright.request.newContext({ baseURL })
  const login = await ctx.post('/api/v1/auth/login', { data: { username: 'admin', password: 'admin' } })
  const { csrf_token: token } = await login.json()
  const post = async (path, data) => {
    const r = await ctx.post(`/api/v1${path}`, { data, headers: { 'X-CSRF-Token': token } })
    if (!r.ok()) throw new Error(`${path}: ${r.status()}`)
    return r.json()
  }
  return { ctx, post, get: async (path) => (await ctx.get(`/api/v1${path}`)).json() }
}

test('the cluster trace replaces the radar and reads exact samples', async ({ page }) => {
  await signIn(page)
  const tile = page.getByTestId('tile-trace')
  await expect(tile).toBeVisible()
  await expect(page.getByTestId('cluster-radar')).toHaveCount(0)
  const trace = tile.getByTestId('cluster-trace')
  await expect(trace).toHaveAttribute('data-running', 'true')
  await expect(tile.getByTestId('trace-node')).toHaveCount(2)
  await expect(tile.getByTestId('trace-link')).toContainText('in sync')
  // Two polls give a rate: the readouts and the strips fill.
  await expect(tile.getByTestId('trace-dns-rate')).toHaveText(/\d/, { timeout: 20000 })
  await expect(page.getByTestId('dns-strip')).toBeVisible()
  await expect(page.getByTestId('dhcp-strip')).toBeVisible()
  // The playhead: the exact sample under the pointer, then nothing once it leaves.
  const box = await trace.boundingBox()
  await page.mouse.move(box.x + box.width - 30, box.y + box.height * 0.3)
  const readout = tile.getByTestId('cluster-trace-readout')
  await expect(readout).toHaveClass(/is-on/)
  await expect(readout).toContainText('queries/s')
  await expect(readout).toContainText(/-\d+\.\d s/)
  await page.mouse.move(box.x - 40, box.y - 40)
  await expect(readout).not.toHaveClass(/is-on/)
  // The keys: focus reads the newest sample, the arrows step one sample, Home goes oldest.
  await expect(trace).toHaveAttribute('tabindex', '0')
  const count = async () => Number(await tile.getByTestId('trace-count').locator('.sr-only').textContent())
  await expect.poll(count, { timeout: 30000 }).toBeGreaterThanOrEqual(3)
  await trace.focus()
  await expect(readout).toHaveClass(/is-on/)
  await expect(tile.getByTestId('cluster-trace-live')).toContainText('queries/s')
  const ago = async () => Number(/-(\d+\.\d) s/.exec((await readout.textContent()) || '')?.[1])
  const newest = await ago()
  await page.keyboard.press('ArrowLeft')
  await expect.poll(ago).toBeGreaterThan(newest + 2)
  await page.keyboard.press('Home')
  await expect.poll(ago).toBeGreaterThan(newest + 6)
  await page.keyboard.press('Escape')
  await expect(readout).not.toHaveClass(/is-on/)
  // The loop stays within its budget while the trace draws.
  const stats = await loopStats(page)
  expect(stats.running).toBe(true)
  // Scrubbing, polling and a loaded shared host: the 2 ms budget is asserted on the idle page in instrument-motion.spec.js.
  expect(stats.p95).toBeLessThan(5)
})

test('the window zooms with its scale bar and is kept for the session', async ({ page }) => {
  await signIn(page)
  const tile = page.getByTestId('tile-trace')
  const bar = tile.getByTestId('scalebar')
  await expect(bar).toContainText('10 s')
  const width = async () => (await bar.locator('i').boundingBox()).width
  const at90 = await width()
  await tile.getByRole('button', { name: '30 s' }).click()
  await expect(tile.getByTestId('cluster-trace')).toHaveAttribute('data-window', '30000')
  await expect.poll(width).toBeGreaterThan(at90 * 2.5)
  await tile.getByRole('button', { name: '5 min' }).click()
  await expect(bar).toContainText('1 min')
  await page.reload()
  await expect(page.getByTestId('cluster-trace')).toHaveAttribute('data-window', '300000')
  await page.getByTestId('tile-trace').getByRole('button', { name: '90 s' }).click()
})

test('Kea heartbeats give an interval and its jitter', async ({ page }) => {
  await signIn(page)
  // The mock beats every 10 s: two beats measured give an interval.
  await expect(page.getByTestId('trace-heartbeat')).toContainText(/\d+\.\d\d s ±\d+ ms/, { timeout: 35000 })
  // The HA state of this node stands under it (other suites may leave it in maintenance).
  await expect(page.getByTestId('trace-heartbeat')).not.toContainText('measuring')
})

test('a plan lands on the events lane and the link carries the HA change', async ({ page, playwright, baseURL }) => {
  await signIn(page)
  await expect(page.getByTestId('trace-last-event')).toContainText('none yet')
  const ops = await api(playwright, baseURL)
  const nodes = await ops.get('/nodes')
  const ns1 = (nodes.items || nodes).find((n) => n.peer?.name === 'ns1' || n.name === 'ns1')
  const id = ns1.peer?.id || ns1.id
  try {
    const plan = await ops.post('/dhcp/v4/ha/maintenance/plan', { node_id: id, action: 'start' })
    await ops.post(`/plans/${plan.id}/apply`, { confirm: true })
    await expect(page.getByTestId('trace-last-event')).toContainText(/plan \w+ applied|HA ns/)
  } finally {
    const back = await ops.post('/dhcp/v4/ha/maintenance/plan', { node_id: id, action: 'cancel' })
    await ops.post(`/plans/${back.id}/apply`, { confirm: true })
    await ops.ctx.dispose()
  }
  // The marker is under the playhead: hovering it near the right edge reads the event.
  const trace = page.getByTestId('cluster-trace')
  const box = await trace.boundingBox()
  const readout = page.getByTestId('cluster-trace-readout')
  for (let dx = 4; dx < 90; dx += 4) {
    await page.mouse.move(box.x + box.width - 8 - dx, box.y + box.height * 0.85)
    if (/applied|HA ns/.test((await readout.textContent()) || '')) break
  }
  await expect(readout).toContainText(/applied|HA ns/)
})

test('the latest leases land as DORA ticks and the hottest pool has its pressure', async ({ page }) => {
  await signIn(page)
  const latest = page.getByTestId('dhcp-latest')
  await expect(latest).toContainText(/\+\d+ leases?/, { timeout: 20000 })
  await expect(latest.getByTestId('dora')).toHaveClass(/is-on/)
  await expect(latest.getByTestId('dora')).toHaveAttribute('data-gen', /[1-9]/, { timeout: 15000 })
  const pressure = page.getByTestId('pool-pressure')
  await pressure.scrollIntoViewIfNeeded()
  await expect(pressure).toContainText('192.0.2.200 - 192.0.2.219')
  await expect(pressure.getByTestId('threshold-trace')).toContainText('CH2')
})

test('motion off: the trace draws on data only and nothing loops', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  await page.getByTestId('pref-animations').getByRole('combobox').click()
  await page.getByRole('option', { name: 'Off' }).click()
  await page.goto('/')
  try {
    await expect(page.getByTestId('cluster-trace')).toHaveAttribute('data-running', 'false')
    await expect(page.getByTestId('trace-dns-rate')).toHaveText(/\d/, { timeout: 20000 })
    const before = await loopStats(page)
    await page.waitForTimeout(1000)
    const after = await loopStats(page)
    expect(after.active).toBe(0)
    expect(after.frames).toBe(before.frames)
    // A hover still reads the trace: it is a measure, not a motion.
    const box = await page.getByTestId('cluster-trace').boundingBox()
    await page.mouse.move(box.x + box.width - 40, box.y + 30)
    await expect(page.getByTestId('cluster-trace-readout')).toHaveClass(/is-on/)
  } finally {
    await page.goto('/account')
    await page.getByTestId('pref-animations').getByRole('combobox').click()
    await page.getByRole('option', { name: 'Full' }).click()
  }
})

test.describe('reduced motion from the system', () => {
  test.use({ reducedMotion: 'reduce' })

  test('the trace jumps a sample at a time and the strip paper does not slide', async ({ page }) => {
    await signIn(page)
    await expect(page.getByTestId('cluster-trace')).toHaveAttribute('data-running', 'false')
    await expect(page.getByTestId('dns-strip')).toBeVisible({ timeout: 20000 })
    const paper = page.getByTestId('dns-strip').locator('.fx-strip-paper')
    await page.waitForTimeout(4500)
    expect(await paper.evaluate((el) => el.style.transition)).not.toContain('linear')
  })
})

test('the sign-in page writes an empty trace behind the card', async ({ page }) => {
  await page.goto('/login')
  const scene = page.getByTestId('login-scene')
  await expect(scene).toBeAttached()
  await expect(scene.getByTestId('login-trace')).toHaveAttribute('data-running', 'true')
  expect(await page.getByTestId('login-form').evaluate((el) => getComputedStyle(el).backdropFilter)).toBe('none')
})

test.describe('at 400px', () => {
  test.use({ viewport: { width: 400, height: 860 } })

  test('the trace leads the dashboard and fits the phone', async ({ page }) => {
    await signIn(page)
    const first = page.getByTestId('dashboard-stack').locator('[data-testid^="tile-"]').first()
    await expect(first).toHaveAttribute('data-testid', 'tile-trace')
    await expect(page.getByTestId('trace-values')).toBeHidden()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
