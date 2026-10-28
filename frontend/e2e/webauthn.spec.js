// SPDX-License-Identifier: Apache-2.0
// Security keys with Chrome's virtual authenticator (CDP WebAuthn domain): register a passkey on the
// account page, sign in with it as second factor after the password, then without a password,
// remove it. WebAuthn needs a domain: the page is opened on localhost, the only plain-http origin
// browsers allow.
import { test, expect } from '@playwright/test'

const USER = 'alice'
const local = (baseURL, path) => baseURL.replace('127.0.0.1', 'localhost') + path

async function addAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })
  return { cdp, authenticatorId }
}

async function signOut(page) {
  await page.context().clearCookies()
  await page.goto(page.url().replace(/\/[^/]*$/, '/login'))
}

test.afterAll(async ({ request, baseURL }) => {
  // Other specs sign in as this user with a password only.
  const res = await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: 'admin', password: 'admin' } })
  const { csrf_token: csrf } = await res.json()
  const users = await (await request.get(`${baseURL}/api/v1/admin/users`)).json()
  const id = users.items.find((u) => u.username === USER).id
  await request.delete(`${baseURL}/api/v1/admin/users/${id}/webauthn`, { headers: { 'X-CSRF-Token': csrf } })
})

test('registers a passkey, signs in with it twice, removes it', async ({ page, baseURL }) => {
  const { cdp, authenticatorId } = await addAuthenticator(page)
  await page.goto(local(baseURL, '/login'))
  await page.getByTestId('login-username').fill(USER)
  await page.getByTestId('login-password').fill(USER)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()

  await page.goto(local(baseURL, '/account'))
  const section = page.getByTestId('account-keys')
  await expect(section.getByTestId('key-empty')).toBeVisible()
  await section.getByTestId('key-name-input').fill('Laptop')
  await section.getByTestId('key-add-submit').click()
  await expect(section.getByTestId('key-name')).toHaveText('Laptop')
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  expect(credentials).toHaveLength(1)
  expect(credentials[0].isResidentCredential).toBe(true)
  expect(credentials[0].rpId).toBe('localhost')

  // Password, then the key: the browser prompt is answered by the virtual authenticator.
  await signOut(page)
  await page.getByTestId('login-username').fill(USER)
  await page.getByTestId('login-password').fill(USER)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  let after = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  expect(after.credentials[0].signCount).toBeGreaterThan(credentials[0].signCount)

  // No password at all: a discoverable credential with user verification.
  await signOut(page)
  await page.getByTestId('login-passkey').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  after = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  expect(after.credentials[0].signCount).toBeGreaterThan(credentials[0].signCount + 1)

  await page.goto(local(baseURL, '/account'))
  await section.getByTestId('key-remove-open').click()
  await page.getByTestId('key-remove-password').fill(USER)
  await page.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(section.getByTestId('key-empty')).toBeVisible()

  // The key is gone server side: the password alone signs in again.
  await signOut(page)
  await page.getByTestId('login-username').fill(USER)
  await page.getByTestId('login-password').fill(USER)
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
})
