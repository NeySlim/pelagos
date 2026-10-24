// SPDX-License-Identifier: Apache-2.0
// Smoke tests run against the mock server through the Vite dev server.
// Ports come from the environment so parallel runs on a shared host do not collide.
import { defineConfig, devices } from '@playwright/test'

const mockPort = process.env.MOCK_PORT || '8481'
const vitePort = process.env.VITE_PORT || '5173'
const baseURL = process.env.TEST_URL || `http://127.0.0.1:${vitePort}`

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 60000,
  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: process.env.TEST_URL
    ? undefined
    : [
        {
          command: `node mock/server.mjs --port ${mockPort}`,
          url: `http://127.0.0.1:${mockPort}/api/v1/health`,
          reuseExistingServer: false,
          timeout: 30000,
        },
        {
          command: `npx vite --port ${vitePort} --strictPort --host 127.0.0.1`,
          url: baseURL,
          reuseExistingServer: false,
          timeout: 60000,
          env: { VITE_API_MOCK: '1', MOCK_PORT: mockPort },
        },
      ],
})
