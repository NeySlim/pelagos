// SPDX-License-Identifier: Apache-2.0
// Specs run by the lab tier against a real node (backend/tests/lab), never by the mock suite.
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  workers: 1,
  timeout: 300000,
  reporter: 'list',
  use: { baseURL: process.env.TEST_URL, ignoreHTTPSErrors: true, screenshot: 'only-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
