// SPDX-License-Identifier: Apache-2.0
// API tokens on a real pair (tests/lab/test_api_tokens_lab.py, item 70): the admin must use a security
// key, so a password alone no longer opens a session; a token created on ns1 with Chrome's virtual
// authenticator answers Bearer calls on ns1 and, once replicated, on ns2; revoked, it fails on both.
// Pages are opened by name (WebAuthn needs the rpId); Bearer calls go to the addresses.
import { writeFileSync } from 'node:fs'
import { test, expect, request as playwrightRequest } from '@playwright/test'

const { NS1_URL, NS1_API, NS2_API, HOST_RULES, LAB_PASSWORD, TOKEN_OUT } = process.env

test.skip(!NS1_URL || !NS1_API || !NS2_API, 'run by tests/lab/test_api_tokens_lab.py')
test.use({ ignoreHTTPSErrors: false, launchOptions: { args: HOST_RULES ? [`--host-resolver-rules=${HOST_RULES}`] : [] } })

async function api(base, token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  return playwrightRequest.newContext({ baseURL: `${base}/api/v1/`, ignoreHTTPSErrors: true, extraHTTPHeaders: headers })
}

async function status(base, token, path = 'nodes') {
  const ctx = await api(base, token)
  const res = await ctx.get(path)
  const out = res.status()
  await ctx.dispose()
  return out
}

test('a token created behind a key works on both nodes until revoked', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })

  // Admin signs in with the password, registers a key, then makes keys mandatory for admins.
  await page.goto(`${NS1_URL}/login`)
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill(LAB_PASSWORD)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.goto(`${NS1_URL}/account`)
  const keys = page.getByTestId('account-keys')
  await keys.getByTestId('key-name-input').fill('Lab key')
  await keys.getByTestId('key-add-submit').click()
  await expect(keys.getByTestId('key-name')).toHaveText('Lab key')
  // In the page: Playwright's own request context does not use Chrome's host mapping.
  const put = await page.evaluate(async () => {
    const { csrf_token: csrf } = await (await fetch('/api/v1/auth/session')).json()
    const res = await fetch('/api/v1/admin/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ auth: { require_webauthn_roles: ['admin'] } }),
    })
    return res.status
  })
  expect(put).toBe(200)

  // The cookie path without the second factor is closed on both nodes: what blocked scripts.
  for (const base of [NS1_API, NS2_API]) {
    await expect
      .poll(async () => {
        const ctx = await api(base)
        const res = await ctx.post('auth/login', { data: { username: 'admin', password: LAB_PASSWORD } })
        const body = await res.json()
        await ctx.dispose()
        return `${res.status()} ${body.code}`
      }, { timeout: 60000 })
      .toBe('401 second_factor_required')
  }

  // Token creation: the browser prompt for a fresh assertion is answered by the virtual authenticator.
  const tokens = page.getByTestId('account-tokens')
  await tokens.getByTestId('token-name-input').fill('lab-script')
  await tokens.getByRole('combobox').click()
  await page.getByRole('option', { name: /Administrator/ }).click()
  await tokens.getByTestId('token-cidrs-input').fill('10.99.0.0/24')
  await tokens.getByTestId('token-add-submit').click()
  const secret = (await page.getByTestId('token-secret').textContent()).trim()
  expect(secret).toMatch(/^pel_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/)
  if (TOKEN_OUT) writeFileSync(TOKEN_OUT, secret)
  await page.getByTestId('token-created-done').click()
  await expect(tokens.getByTestId('token-name')).toHaveText('lab-script')

  // Bearer calls: no cookie, no CSRF, on ns1 at once and on ns2 once replicated.
  expect(await status(NS1_API, secret)).toBe(200)
  await expect.poll(() => status(NS2_API, secret), { timeout: 120000, intervals: [2000] }).toBe(200)
  const ns2 = await api(NS2_API, secret)
  const session = await (await ns2.get('auth/session')).json()
  expect(session.user.username).toBe('admin')
  expect((await ns2.put('dashboard/layout', { data: { layout: [] } })).status()).toBe(200)
  const plan = await ns2.post('dns/zones/plan', {
    data: { change: { op: 'add', target: 'tokens.example.lan.', after: { kind: 'primary', ns: ['ns1.example.lan.'] } } },
  })
  if (plan.ok()) {
    const { id } = await plan.json()
    const apply = await ns2.post(`plans/${id}/apply`, { data: {} })
    expect(apply.status()).toBe(428)
    expect((await ns2.delete(`plans/${id}`)).status()).toBe(204)
  }
  expect((await ns2.get('auth/tokens')).status()).toBe(403)
  await ns2.dispose()
  expect(await status(NS1_API, 'pel_0123456789abcdef_' + 'A'.repeat(43))).toBe(401)

  // Revoked on ns1: refused on both nodes.
  await tokens.getByTestId('token-revoke-open').click()
  await page.getByRole('button', { name: 'Revoke', exact: true }).click()
  await expect(tokens.getByTestId('token-empty')).toBeVisible()
  expect(await status(NS1_API, secret)).toBe(401)
  await expect.poll(() => status(NS2_API, secret), { timeout: 120000, intervals: [2000] }).toBe(401)
})
