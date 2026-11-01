// SPDX-License-Identifier: Apache-2.0
// Permission guard against the mock server: a node whose zone folder the services cannot create
// refuses the RPZ plan at plan time with the exact command, the Permissions card shows the path, its
// helper plan fixes it, and the RPZ plan then applies.
import { test, expect } from '@playwright/test'

async function signIn(page, username = 'admin', password = 'admin') {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

const COMMAND = 'install -d -o bind -g bind -m 2775 /etc/bind/cache/pelagos'

test('a refused RPZ plan, the Permissions card, its fix, then the RPZ plan applies', async ({ page }) => {
  await page.request.post('/api/v1/_mock/permissions', { data: { broken: true } })
  try {
    await signIn(page)
    await page.goto('/dns/rpz')
    // A category no other spec touches: the mock keeps its state across specs.
    const gambling = page.getByTestId('rpz-category-gambling')
    await gambling.getByRole('switch').click()
    await page.getByTestId('rpz-categories-save').click()

    // Refused at plan time: the finding names the path and the command, nothing can be applied.
    const preview = page.getByTestId('plan-preview')
    await expect(preview.getByTestId('plan-error')).toContainText('plan refused')
    await expect(preview.getByTestId('plan-error')).toContainText(COMMAND)
    await expect(preview.getByTestId('plan-apply')).toBeDisabled()
    await page.keyboard.press('Escape')

    // The Permissions card of the node: the path, its owner and mode, the command, the fix plan.
    await page.goto('/install/security')
    const card = page.getByTestId('permissions')
    await expect(card.getByTestId('permissions-state')).toContainText('1 path not writable')
    const bad = card.locator('[data-testid="permissions-check"][data-ok="no"]')
    await expect(bad).toContainText('/etc/bind/cache/pelagos')
    await expect(bad).toContainText('bind:bind 0755')
    await expect(bad.getByTestId('permissions-command')).toHaveText(COMMAND)
    await card.getByTestId('permissions-fix').click()
    await card.getByTestId('plan-confirm-checkbox').check()
    await card.getByTestId('plan-apply').click()
    await expect(card.getByTestId('plan-job')).toContainText('100% done', { timeout: 15000 })
    await expect(card.getByTestId('permissions-state')).toContainText('all writable')

    // The same subscription now plans and applies.
    await page.goto('/dns/rpz')
    await page.getByTestId('rpz-apply').click()
    await expect(preview.getByTestId('plan-error')).toHaveCount(0)
    const confirm = preview.getByTestId('plan-confirm-checkbox')
    if (await confirm.count()) await confirm.check()
    await preview.getByTestId('plan-apply').click()
    await expect(page.getByTestId('plan-result')).toContainText('Applied')
  } finally {
    await page.request.post('/api/v1/_mock/permissions', { data: { broken: false } })
  }
})

async function switchLanguage(page, from, to, lang) {
  await page.getByTestId('user-menu').click()
  await page.getByText(from, { exact: true }).hover()
  await page.getByText(to, { exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', lang)
}

test('the Permissions card in French', async ({ page }) => {
  await page.request.post('/api/v1/_mock/permissions', { data: { broken: true } })
  try {
    await signIn(page)
    await switchLanguage(page, 'English', 'Français', 'fr')
    await page.goto('/install/security')
    const card = page.getByTestId('permissions')
    await expect(card.getByTestId('permissions-state')).toContainText('1 chemin non inscriptible')
    await expect(card).toContainText('Dossier de zones /etc/bind/cache/pelagos : ne peut pas être créé')
  } finally {
    if ((await page.locator('html').getAttribute('lang')) === 'fr') await switchLanguage(page, 'Français', 'English', 'en')
    await page.request.post('/api/v1/_mock/permissions', { data: { broken: false } })
  }
})

test('a viewer sees why each DNS action is missing on a zone and on the RPZ page', async ({ page }) => {
  await signIn(page, 'viewer', 'viewer')
  await page.goto('/dns/zones/branch.example.lan')
  const notes = page.getByTestId('zone-read-only-notes')
  await expect(notes).toContainText('write:dns.zones')
  await expect(notes).toContainText('ops:dns')
  await expect(page.getByTestId('zone-note-records')).toContainText('write:dns.records')
  await expect(page.getByTestId('record-add')).toHaveCount(0)
  await expect(page.getByTestId('zone-delete')).toHaveCount(0)
  await page.goto('/dns/rpz')
  await expect(page.getByTestId('rpz-read-only-note')).toContainText('write:dns.config')
  await expect(page.getByTestId('rpz-categories-save')).toHaveCount(0)
  await page.getByRole('button', { name: 'Activity' }).click()
  await expect(page.getByTestId('rpz-read-only-note')).toContainText('write:dns.config')
})

async function signInAs(page, username, password, totp) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill(username)
  await page.getByTestId('login-password').fill(password)
  await page.getByTestId('login-submit').click()
  if (totp) {
    await page.getByTestId('login-totp').fill(totp)
    await page.getByTestId('login-submit').click()
  }
  await expect(page.getByTestId('sidebar')).toBeVisible()
}

// A role without the permission is told why the action is missing (ReadOnlyNote), not left to guess.
for (const [username, password, totp] of [['bob', 'bob', '123456'], ['viewer', 'viewer']]) {
  test(`${username} sees why hosts cannot be created`, async ({ page }) => {
    await signInAs(page, username, password, totp)
    await page.goto('/hosts')
    await expect(page.getByTestId('host-create')).toHaveCount(0)
    await expect(page.getByTestId('host-facets').getByTestId('read-only-note')).toContainText('write:hosts')
  })
}

test('viewer sees why an alert cannot be acknowledged', async ({ page }) => {
  await signInAs(page, 'viewer', 'viewer')
  await page.goto('/alerts')
  await page.getByTestId('alerts-table').getByTestId('data-table-row').first().click()
  const detail = page.getByTestId('alert-detail')
  await expect(detail.getByTestId('read-only-note')).toContainText('write:alerts')
  await expect(detail.getByTestId('alert-ack')).toHaveCount(0)
})

test('alice sees why nodes cannot be enrolled', async ({ page }) => {
  await signInAs(page, 'alice', 'alice')
  await page.goto('/nodes')
  await expect(page.getByTestId('enroll-open')).toHaveCount(0)
  await expect(page.getByTestId('read-only-note')).toContainText('admin:nodes')
})
