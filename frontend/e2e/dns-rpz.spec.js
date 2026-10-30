// SPDX-License-Identifier: Apache-2.0
// RPZ subscriptions against the mock server: a category by level with its plan, the memory warning
// on a small node, "why is this domain blocked?", the allow list and the activity counters.
import { test, expect } from '@playwright/test'

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

async function applyPlan(page) {
  const preview = page.getByTestId('plan-preview')
  await expect(preview).toBeVisible()
  const confirm = preview.getByTestId('plan-confirm-checkbox')
  if (await confirm.count()) await confirm.check()
  await preview.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-result')).toContainText('Applied')
  await page.keyboard.press('Escape')
}

test('a category is enabled by level, shown with its size and applied through a plan', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  await expect(page.getByTestId('rpz-categories').getByTestId(/^rpz-category-(ads|security|adult|gambling|bypass|social|piracy|spam_tlds)$/)).toHaveCount(8)
  const ads = page.getByTestId('rpz-category-ads')
  await ads.getByRole('switch').click()
  await ads.getByRole('combobox').first().click()
  await page.getByRole('option', { name: /^Light/ }).click()
  await expect(ads.getByTestId('rpz-size')).toContainText('118 000 entries')
  await expect(ads.getByTestId('rpz-lists')).toContainText('OISD small')
  await expect(ads.getByTestId('rpz-lists')).toContainText('license GPL-3.0')
  await ads.getByTestId('rpz-category-save').click()
  await expect(page.getByTestId('plan-preview')).toContainText('RPZ subscriptions')
  await applyPlan(page)
  await expect(page.getByTestId('rpz-lists-table')).toContainText('OISD small')
  await expect(page.getByTestId('rpz-lists-table')).toContainText('up to date')
  await expect(page.getByTestId('rpz-node').first()).toContainText('configuration applied')
  await expect(page.getByTestId('rpz-apply')).toHaveCount(0)
})

test('a list too big for a small node asks for an acknowledgement', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  const adult = page.getByTestId('rpz-category-adult')
  await adult.getByRole('switch').click()
  await adult.getByRole('combobox').first().click()
  await page.getByRole('option', { name: /^Strict/ }).click()
  await expect(adult.getByTestId('rpz-estimate')).toContainText('too large')
  await expect(adult.getByTestId('rpz-estimate-node').first()).toContainText('of memory at peak')
  const save = adult.getByTestId('rpz-category-save')
  await expect(save).toBeDisabled()
  await adult.getByTestId('rpz-estimate-ack').check()
  await expect(save).toBeEnabled()
})

test('an own list can be added from the subscriptions tab', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  await page.getByTestId('rpz-sub-add').click()
  const modal = page.getByTestId('rpz-sub-modal')
  await modal.getByTestId('rpz-sub-id').fill('my-list')
  await modal.getByTestId('rpz-sub-url').fill('https://lists.example.com/own.txt')
  await modal.getByRole('button', { name: 'Add', exact: true }).click()
  await applyPlan(page)
  await expect(page.getByTestId('rpz-own-table')).toContainText('https://lists.example.com/own.txt')
})

test('the lookup names the list, the category and the rule, and an allowed domain wins', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  // The mock keeps its state between tests: the first one already subscribed to this category.
  const ads = page.getByTestId('rpz-category-ads')
  if ((await ads.getByRole('switch').getAttribute('aria-checked')) !== 'true') {
    await ads.getByRole('switch').click()
    await ads.getByTestId('rpz-category-save').click()
    await applyPlan(page)
  }
  await page.getByRole('button', { name: 'Exceptions' }).click()
  await page.getByTestId('rpz-why-input').fill('ads.tracker.example.net')
  await page.getByTestId('rpz-why-submit').click()
  await expect(page.getByTestId('rpz-why-verdict')).toHaveText('blocked')
  const matches = page.getByTestId('rpz-why-matches')
  await expect(matches).toContainText('Advertising and tracking')
  await expect(matches).toContainText('*.tracker.example.net')
  await page.getByTestId('rpz-why-allow').click()
  await expect(page.getByTestId('rpz-why-verdict')).toHaveText('allowed')
  await expect(page.getByTestId('rpz-allow-table')).toContainText('ads.tracker.example.net')
  await page.getByTestId('rpz-exempt-input').fill('192.0.2.0/24')
  await page.getByTestId('rpz-exempt-add').click()
  await expect(page.getByTestId('rpz-exempt-table')).toContainText('192.0.2.0/24')
})

test('the activity tab counts rewritten answers by category and list', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  await page.getByRole('button', { name: 'Activity' }).click()
  await expect(page.getByTestId('rpz-by-category')).toContainText('Advertising and tracking')
  await expect(page.getByTestId('rpz-category-hits').first()).toContainText('18 342')
  await expect(page.getByTestId('rpz-by-list')).toContainText('OISD small')
  await expect(page.getByTestId('rpz-recent')).toContainText('ads.tracker.example.net')
})

test('the policy zones tab keeps the hand-written zones', async ({ page }) => {
  await signIn(page)
  await page.goto('/dns/rpz')
  await page.getByRole('button', { name: 'Policy zones' }).click()
  await expect(page.getByTestId('rpz-table')).toContainText('rpz.example.lan.')
})
