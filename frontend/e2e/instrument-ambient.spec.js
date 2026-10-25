// SPDX-License-Identifier: Apache-2.0
// Tile ambient layers: canvases driven by the live rates, registration marks and a refresh
// sweep, gated by the ambient preference and the motion level, on the one shared loop.
import { test, expect } from '@playwright/test'
import { signIn } from './family'

const rootData = (page, key) => page.evaluate((k) => document.documentElement.dataset[k], key)
const style = (locator, prop) => locator.evaluate((el, p) => getComputedStyle(el)[p], prop)

// True when the canvas holds at least one painted (non transparent) pixel.
const painted = (locator) =>
  locator.evaluate((cv) => {
    const data = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height).data
    for (let i = 3; i < data.length; i += 4) if (data[i] > 0) return true
    return false
  })

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(() => expect(errors).toEqual([]))

test('tiles carry canvas layers and registration marks, and the loop runs while they move', async ({ page }) => {
  await signIn(page)
  const dns = page.getByTestId('tile-dns')
  await expect(dns.getByTestId('ambient-wave')).toBeAttached()
  await expect(page.getByTestId('tile-dhcp').getByTestId('ambient-spectrum')).toBeAttached()
  await expect(page.getByTestId('tile-trace').getByTestId('ambient-dots')).toBeAttached()
  await expect(dns.getByTestId('reg-marks')).toBeAttached()
  await expect.poll(() => painted(dns.getByTestId('ambient-wave'))).toBe(true)
  await expect.poll(() => painted(page.getByTestId('tile-trace').getByTestId('ambient-dots'))).toBe(true)
  // The layers sit under the data and never take the pointer.
  expect(await style(dns.getByTestId('ambient-tile'), 'pointerEvents')).toBe('none')
  const before = await page.evaluate(() => window.__pelagosLoop().frames)
  await page.waitForTimeout(600)
  expect(await page.evaluate(() => window.__pelagosLoop().frames)).toBeGreaterThan(before)
})

// A calibration sweep held at `x` (page px) inside the tile: the real layer, animation stopped.
const holdSweep = (tile, x) =>
  tile.evaluate((el, at) => {
    const layer = el.querySelector('.fx-amb-sweep')
    let line = layer.querySelector('.fx-sweep')
    if (!line) {
      line = document.createElement('i')
      line.className = 'fx-sweep'
      layer.appendChild(line)
    }
    const r = el.getBoundingClientRect()
    line.style.animation = 'none'
    line.style.transform = `translateX(${at - r.right + 1}px)`
  }, x)

test('ambient layers stay behind tile content at 1440x900', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await signIn(page)
  const tile = page.getByTestId('tile-dhcp')
  const panel = tile.locator('.dash-stat').first()
  await expect(panel).toBeVisible()
  await page.waitForTimeout(1500) // first-load sweeps are over
  // Stacking: every ambient layer of every tile comes before the body and under it.
  const order = await page.evaluate(() =>
    [...document.querySelectorAll('.dash-tile')].map((t) => {
      const body = t.querySelector(':scope > .tile-handle + div')
      const z = (el) => Number.parseInt(getComputedStyle(el).zIndex, 10) || 0
      return [...t.querySelectorAll(':scope > .fx-amb-tile, :scope > .fx-amb-sweep')].every(
        (layer) => z(layer) < z(body) && Boolean(layer.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING),
      )
    }),
  )
  expect(order.length).toBeGreaterThan(3)
  expect(order.every(Boolean)).toBe(true)
  // The screen graticule lies under the shell content, and tiles are opaque surfaces.
  const screen = await page.evaluate(() => {
    const grid = document.querySelector('[data-testid="ambient-screen"]')
    const content = grid?.nextElementSibling
    const bg = getComputedStyle(document.querySelector('.dash-tile')).backgroundColor
    return { under: Number.parseInt(getComputedStyle(grid).zIndex, 10) < Number.parseInt(getComputedStyle(content).zIndex, 10), bg }
  })
  expect(screen.under).toBe(true)
  expect(screen.bg).not.toMatch(/rgba\(.*,\s*0(\.\d+)?\)$|transparent/)
  // Pixels: a sweep held over a panel leaves the panel untouched, and shows on the bare tile.
  const box = await panel.boundingBox()
  const head = await tile.locator('.tile-handle').boundingBox()
  const x = Math.round(box.x + box.width - 8)
  const inPanel = { x: x - 2, y: Math.round(box.y + 3), width: 5, height: Math.round(box.height - 6) }
  const onTile = { x: x - 2, y: Math.round(head.y + head.height + 3), width: 5, height: 6 }
  const before = [await page.screenshot({ clip: inPanel }), await page.screenshot({ clip: onTile })]
  await holdSweep(tile, x)
  const after = [await page.screenshot({ clip: inPanel }), await page.screenshot({ clip: onTile })]
  expect(after[1].equals(before[1]), 'the held sweep shows on the tile ground').toBe(false)
  expect(after[0].equals(before[0]), 'the held sweep crosses the panel').toBe(true)
})

test('ambient off removes every layer', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  const setAmbient = async (name) => {
    await page.getByTestId('pref-ambient').getByRole('combobox').click()
    await page.getByRole('option', { name }).click()
    await expect.poll(() => rootData(page, 'ambient')).toBe(name.toLowerCase())
  }
  await setAmbient('Off')
  // Nothing else animates on this page: the ambient animator has left the shared loop.
  await expect.poll(() => page.evaluate(() => window.__pelagosLoop().active)).toBe(0)
  try {
    await page.goto('/')
    await expect(page.getByTestId('tile-dns')).toBeVisible()
    for (const id of ['ambient-screen', 'ambient-tile', 'ambient-wave', 'ambient-spectrum', 'ambient-dots', 'reg-marks', 'tile-sweep']) {
      await expect(page.getByTestId(id), id).toHaveCount(0)
    }
  } finally {
    // The mock keeps preferences for the whole run: put the default back.
    await page.goto('/account')
    await setAmbient('On')
  }
})

test('animations off: layers hold one still frame, no ping, no sweep, no loop', async ({ page }) => {
  await signIn(page)
  await page.goto('/account')
  const setMotion = async (name, value) => {
    await page.getByTestId('pref-animations').getByRole('combobox').click()
    await page.getByRole('option', { name }).click()
    await expect.poll(() => rootData(page, 'motion')).toBe(value)
  }
  await setMotion('Off', 'off')
  try {
    await page.goto('/')
    const wave = page.getByTestId('tile-dns').getByTestId('ambient-wave')
    await expect.poll(() => painted(wave)).toBe(true)
    const first = await wave.evaluate((cv) => cv.toDataURL())
    await page.waitForTimeout(1000)
    expect(await wave.evaluate((cv) => cv.toDataURL())).toBe(first)
    expect((await page.evaluate(() => window.__pelagosLoop())).active).toBe(0)
    await expect(page.locator('.fx-sweep.is-go, .fx-regs.is-ping')).toHaveCount(0)
  } finally {
    await page.goto('/account')
    await setMotion('Full', 'full')
  }
})

test('the registration marks do not ping on live samples alone', async ({ page }) => {
  await signIn(page)
  await expect(page.getByTestId('tile-dns').getByTestId('reg-marks')).toBeAttached()
  // Let the first-load sweep finish, then watch across two live samples (4 s each).
  await page.waitForTimeout(1500)
  await page.evaluate(() => {
    window.__pings = 0
    new MutationObserver((list) => {
      for (const m of list) if (m.target.classList?.contains('is-ping') || [...m.addedNodes].some((n) => n.classList?.contains('is-ping'))) window.__pings += 1
    }).observe(document.querySelector('[data-testid="dashboard-grid"]'), { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] })
  })
  await page.waitForTimeout(9000)
  expect(await page.evaluate(() => window.__pings)).toBe(0)
})

test.describe('reduced motion and ambient layers', () => {
  test.use({ reducedMotion: 'reduce' })

  test('draws one static frame and joins no loop', async ({ page }) => {
    await signIn(page)
    const wave = page.getByTestId('tile-dns').getByTestId('ambient-wave')
    await expect(wave).toBeAttached()
    await expect.poll(() => painted(wave)).toBe(true)
    const snapshot = () => wave.evaluate((cv) => cv.toDataURL())
    const first = await snapshot()
    const before = await page.evaluate(() => window.__pelagosLoop())
    await page.waitForTimeout(1000)
    const after = await page.evaluate(() => window.__pelagosLoop())
    expect(after.active).toBe(0)
    expect(after.frames).toBe(before.frames)
    expect(await snapshot()).toBe(first)
    await expect(page.locator('.fx-sweep.is-go, .fx-regs.is-ping')).toHaveCount(0)
  })

  test('the wave is visible through the DNS tile, not hidden under it', async ({ page }) => {
    await signIn(page)
    const panel = page.getByTestId('tile-dns')
    const wave = panel.getByTestId('ambient-wave')
    await expect.poll(() => painted(wave)).toBe(true)
    await page.waitForTimeout(500)
    const shot = () => panel.screenshot({ animations: 'disabled' })
    const on = await shot()
    expect((await shot()).equals(on)).toBe(true)
    await wave.evaluate((cv) => { cv.style.visibility = 'hidden' })
    expect((await shot()).equals(on)).toBe(false)
  })
})
