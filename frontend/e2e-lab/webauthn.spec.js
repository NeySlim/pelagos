// SPDX-License-Identifier: Apache-2.0
// A security key registered on ns1 signs in on ns2 (tests/lab/test_webauthn_lab.py): Chrome's virtual
// authenticator, the nodes opened by their names (HOST_RULES maps them to the lab addresses) with
// their own web certificates trusted, so the browser runs WebAuthn for the rpId example.lan.
import { test, expect } from '@playwright/test'

const { NS1_URL, NS2_URL, HOST_RULES, LAB_PASSWORD } = process.env

test.skip(!NS1_URL || !NS2_URL, 'run by tests/lab/test_webauthn_lab.py')
test.use({ ignoreHTTPSErrors: false, launchOptions: { args: HOST_RULES ? [`--host-resolver-rules=${HOST_RULES}`] : [] } })

async function passwordLogin(page, base) {
  await page.goto(`${base}/login`)
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill(LAB_PASSWORD)
  await page.getByTestId('login-submit').click()
}

test('a key registered on ns1 opens ns2, as second factor and as a passkey', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })

  await passwordLogin(page, NS1_URL)
  await expect(page.getByTestId('sidebar')).toBeVisible()
  await page.goto(`${NS1_URL}/account`)
  const keys = page.getByTestId('account-keys')
  await keys.getByTestId('key-name-input').fill('Lab key')
  await keys.getByTestId('key-add-submit').click()
  await expect(keys.getByTestId('key-name')).toHaveText('Lab key')
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  expect(credentials.map((c) => c.rpId)).toEqual(['example.lan'])

  // ns2: the password, then the key registered on ns1 (the browser prompt answers by itself).
  await page.context().clearCookies()
  await passwordLogin(page, NS2_URL)
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 30000 })
  await page.goto(`${NS2_URL}/account`)
  await expect(keys.getByTestId('key-name')).toHaveText('Lab key')

  // ns2 again, without a password.
  await page.context().clearCookies()
  await page.goto(`${NS2_URL}/login`)
  await page.getByTestId('login-passkey').click()
  await expect(page.getByTestId('sidebar')).toBeVisible({ timeout: 30000 })
  const after = await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  expect(after.credentials[0].signCount).toBeGreaterThanOrEqual(credentials[0].signCount + 2)
})
