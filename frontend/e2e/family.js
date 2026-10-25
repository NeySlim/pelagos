// SPDX-License-Identifier: Apache-2.0
// The mock keeps preferences for the whole run and the server's choice wins at sign-in:
// a suite that needs another theme family sets it there, and puts the default back.
export async function setServerFamily(playwright, baseURL, family) {
  const ctx = await playwright.request.newContext({ baseURL })
  const login = await ctx.post('/api/v1/auth/login', { data: { username: 'admin', password: 'admin' } })
  const { csrf_token: token } = await login.json()
  const r = await ctx.put('/api/v1/account/preferences', { data: { theme_family: family }, headers: { 'X-CSRF-Token': token } })
  if (!r.ok()) throw new Error(`cannot set the theme family: ${r.status()}`)
  await ctx.dispose()
}

export async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await page.locator('[data-testid="sidebar"], .ui-topbar').first().waitFor()
}
