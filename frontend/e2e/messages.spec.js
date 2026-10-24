// SPDX-License-Identifier: Apache-2.0
// Backend messages (key + params) render in the UI language; texts sent without a
// key keep the backend's English.
import { test, expect } from '@playwright/test'

// The language is a saved preference of the user: switch it from the menu, and back
// to English afterwards so the other specs keep their English assertions.
async function switchLanguage(page, from, to, lang) {
  await page.getByTestId('user-menu').click()
  await page.getByText(from, { exact: true }).hover()
  await page.getByText(to, { exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', lang)
}

async function signInFrench(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await expect(page.getByTestId('sidebar')).toBeVisible()
  if ((await page.locator('html').getAttribute('lang')) !== 'fr') await switchLanguage(page, 'English', 'Français', 'fr')
}

test.afterEach(async ({ page }) => {
  if ((await page.locator('html').getAttribute('lang')) === 'fr') await switchLanguage(page, 'Français', 'English', 'en')
})

test('alert titles with a message key are translated, others fall back', async ({ page }) => {
  await signInFrench(page)
  await page.goto('/alerts?state=')
  const table = page.getByTestId('alerts-table')
  await expect(table).toContainText('/etc/kea/kea-dhcp-ddns.conf diffère de la configuration d2 en service')
  await expect(table).not.toContainText('differs from the running d2 configuration')
  await expect(table).toContainText('PTR for 192.0.2.106 points to workstation7.example.lan.')
})

test('security findings, plan summary and job steps follow the language', async ({ page }) => {
  await signInFrench(page)
  await page.goto('/install/security')
  const finding = page.locator('[data-finding="stats-public"]')
  await expect(finding).toContainText('Le canal de statistiques écoute sur 0.0.0.0 et autorise tout le monde.')
  await expect(finding).toContainText('Les collecteurs distants des statistiques BIND perdent l\'accès')
  await finding.click()
  await page.getByTestId('security-build').click()
  await expect(page.getByTestId('plan-summary')).toHaveText('correction de sécurité : 1 constat(s)')
  await page.getByTestId('plan-confirm-checkbox').check()
  await page.getByTestId('plan-apply').click()
  await expect(page.getByTestId('plan-job')).toContainText('Vérifier que la configuration n\'a pas changé')
  await expect(page.getByTestId('plan-job')).toContainText('remediate stats-public')
  await page.keyboard.press('Escape')
})
