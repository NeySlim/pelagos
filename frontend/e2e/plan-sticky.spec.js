// SPDX-License-Identifier: Apache-2.0
// The plan action bar stays on screen: with a 60-line diff, folded then opened, the
// confirmation checkbox and Apply are visible without scrolling, on a desktop and on
// a phone, in a pair and in a three-node cluster. The record editor shows PlanPreview
// inline (sticky bar, then Roll back in it); HA maintenance shows PlanPreviewModal.
import { test, expect } from '@playwright/test'

const scenario = (page, name) => page.request.post('/api/v1/_mock/scenario', { data: { name } }).then((r) => r.json())

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page).not.toHaveURL(/\/login$/)
}

// Every built plan comes back with a 60-line diff and a confirmation to give.
async function longPlans(page) {
  await page.route(/\/api\/v1\/.*\/plan$/, async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    const response = await route.fetch()
    const plan = await response.json()
    const rows = Array.from({ length: 57 }, (_, i) => `+pad${i}.example.lan. 300 IN A 192.0.2.${i + 100}`)
    plan.diff = ['--- a/example.lan.', '+++ b/example.lan.', '@@ -1,0 +1,57 @@', ...rows].join('\n') + '\n'
    plan.requires_confirmation = true
    plan.requires_confirmation_reasons = ['operation']
    await route.fulfill({ response, json: plan })
  })
}

// Fully inside the viewport: no scrolling needed to reach it.
async function onScreen(page, locator) {
  const box = await locator.boundingBox()
  const { height, width } = page.viewportSize()
  expect(box, 'element is rendered').not.toBeNull()
  expect(box.y).toBeGreaterThanOrEqual(0)
  expect(box.y + box.height).toBeLessThanOrEqual(height)
  expect(box.x + box.width).toBeLessThanOrEqual(width)
}

let errors
test.beforeEach(async ({ page }) => {
  errors = []
  page.on('pageerror', (e) => errors.push(e.message))
})
test.afterEach(async ({ page }) => {
  await scenario(page, 'pair')
  expect(errors).toEqual([])
})

const VIEWPORTS = { desktop: { width: 1440, height: 900 }, phone: { width: 390, height: 844 } }

for (const [device, viewport] of Object.entries(VIEWPORTS)) {
  test.describe(`${device} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport })

    for (const name of ['pair', 'three']) {
      test(`${name}: record editor, the inline bar stays visible over a 60-line diff`, async ({ page }) => {
        await scenario(page, name)
        await signIn(page)
        await longPlans(page)
        await page.goto('/dns/zones/example.lan')
        await page.getByTestId('record-add').click()
        await page.getByTestId('record-owner').fill(`sticky-${device}-${name}`)
        await page.getByTestId('record-rdata').fill(device === 'phone' ? '192.0.2.91' : '192.0.2.92')
        await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()

        const preview = page.getByTestId('plan-preview')
        const footer = preview.getByTestId('plan-footer')
        await expect(footer).toHaveClass(/sticky/)
        const diff = preview.getByTestId('plan-diff')
        await expect(diff).toHaveAttribute('data-open', 'false')
        await expect(diff).toContainText('60 lines')
        const confirm = preview.getByTestId('plan-confirm-checkbox')
        const apply = preview.getByTestId('plan-apply')
        await onScreen(page, confirm)
        await onScreen(page, apply)

        // Opened, the diff scrolls under the bar; the bar does not move off screen.
        await diff.getByRole('button', { name: /Diff/ }).click()
        await expect(diff).toHaveAttribute('data-open', 'true')
        await expect(diff).toContainText('pad56.example.lan.')
        await onScreen(page, confirm)
        await onScreen(page, apply)
        await onScreen(page, preview.getByTestId('plan-close'))
        await onScreen(page, footer)
        await expect(preview.getByTestId('plan-close')).toHaveText('Close')

        await confirm.check()
        await apply.click()
        await expect(preview.getByTestId('plan-result')).toContainText('Applied')
        const rollback = preview.getByTestId('plan-rollback')
        await expect(rollback).toHaveText(/Roll back/)
        await onScreen(page, rollback)
        await rollback.click()
        await expect(preview.getByTestId('plan-result')).toContainText(/Rolled back/i)
      })

      test(`${name}: HA maintenance, the modal footer stays visible over a 60-line diff`, async ({ page }) => {
        await scenario(page, name)
        await signIn(page)
        await longPlans(page)
        await page.goto('/dhcp/v4/ha')
        await page.getByTestId('ha-maintenance-start').first().click()
        await page.getByTestId('confirm-type-input').fill('ns1')
        await page.getByTestId('confirm-button').click()

        // PlanPreviewModal: the bar is pinned under the scrolling body, not sticky.
        const preview = page.getByRole('dialog').getByTestId('plan-preview')
        const footer = preview.getByTestId('plan-footer')
        await expect(footer).not.toHaveClass(/sticky/)
        await expect(preview.locator(':scope > .overflow-y-auto')).toHaveCount(1)
        const diff = preview.getByTestId('plan-diff')
        await expect(diff).toContainText('60 lines')
        const apply = preview.getByTestId('plan-apply')
        await onScreen(page, footer)
        await onScreen(page, apply)
        await diff.getByRole('button', { name: /Diff/ }).click()
        await expect(diff).toHaveAttribute('data-open', 'true')
        await expect(diff).toContainText('pad56.example.lan.')
        await onScreen(page, footer)
        await onScreen(page, apply)
        await apply.click()
        await expect(preview.getByTestId('plan-result')).toBeVisible()
        await onScreen(page, preview.getByTestId('plan-close'))
      })
    }
  })
}
