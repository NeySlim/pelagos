// SPDX-License-Identifier: Apache-2.0
// A read that fails on the network (node restarting, Wi-Fi blink) recovers without a
// reload: quiet retries for a short failure, then an error with Retry, retried again on
// focus. Writes are never sent twice.
import { test, expect } from '@playwright/test'

const API = '/api/v1'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function fault(request, body) {
  const res = await request.post(`${API}/_mock/network`, { data: body })
  return res.json()
}

// Every GET of the operations catalog fails as if the network were down, until undone.
async function cutCatalog(page) {
  const seen = { get: 0 }
  const handler = (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    seen.get += 1
    return route.abort('failed')
  }
  await page.route(`**${API}/dns/ops`, handler)
  return { seen, restore: () => page.unroute(`**${API}/dns/ops`, handler) }
}

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(async ({ request }) => {
  await fault(request, { fail: 0 })
  expect(errors).toEqual([])
})

test('a short outage is retried quietly', async ({ page, request }) => {
  await signIn(page)
  await fault(request, { fail: 2, method: 'GET', path: '/dns/ops', status: 502 })
  await page.goto('/advanced/ops')
  await expect(page.getByTestId('ops-list').locator('[data-op="status"]')).toBeVisible()
  await expect(page.getByTestId('error-notice')).toHaveCount(0)
  expect((await fault(request, {})).dropped).toBe(2)
})

test('a longer outage shows Retry, which recovers the page', async ({ page }) => {
  await signIn(page)
  const cut = await cutCatalog(page)
  await page.goto('/advanced/ops')
  const notice = page.getByTestId('error-notice')
  await expect(notice).toContainText('The server cannot be reached', { timeout: 15000 })
  // Four attempts per load (dev StrictMode mounts the page twice).
  expect(cut.seen.get % 4).toBe(0)
  await cut.restore()
  await notice.getByTestId('error-retry').click()
  await expect(page.getByTestId('ops-list').locator('[data-op="status"]')).toBeVisible()
  await expect(notice).toHaveCount(0)
})

test('the error clears by itself when the window gets the focus back', async ({ page }) => {
  await signIn(page)
  const cut = await cutCatalog(page)
  await page.goto('/advanced/ops')
  await expect(page.getByTestId('error-notice')).toBeVisible({ timeout: 15000 })
  await cut.restore()
  await page.evaluate(() => window.dispatchEvent(new Event('focus')))
  await expect(page.getByTestId('ops-list').locator('[data-op="status"]')).toBeVisible()
  await expect(page.getByTestId('error-notice')).toHaveCount(0)
})

test('a write that fails on the network is not sent again', async ({ page }) => {
  await signIn(page)
  await page.goto('/advanced/ops')
  let posts = 0
  await page.route(`**${API}/dns/ops`, (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    posts += 1
    return route.abort('failed')
  })
  await page.getByTestId('ops-list').locator('[data-op="status"]').click()
  await page.getByTestId('ops-run').click()
  await expect(page.getByTestId('ops-output')).toContainText('The server cannot be reached')
  await page.waitForTimeout(4000)
  expect(posts).toBe(1)
})

test('the code of a page is fetched again after a network failure', async ({ page }) => {
  await signIn(page)
  let aborted = 0
  await page.route('**/pages/advanced/OpsPage.jsx*', (route) => {
    if (aborted >= 2) return route.fallback()
    aborted += 1
    return route.abort('failed')
  })
  // In-app navigation: the page's code is fetched now, not with the first load.
  await page.evaluate(() => {
    window.history.pushState({}, '', '/advanced/ops')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('ops-list').locator('[data-op="status"]')).toBeVisible()
  expect(aborted).toBe(2)
})
