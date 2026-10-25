// SPDX-License-Identifier: Apache-2.0
// Documentation screenshots against the mock server, dark and light. The theme family is
// Instrument unless SCREENSHOT_FAMILY names another; SCREENSHOT_VIEWPORT=WxH changes the size.
// SCREENSHOT_SCENES=nodes,dhcp-ha takes only the named scenes.
// Usage (from frontend/): node e2e/screenshots.mjs [output dir, default ../docs/images]
// Starts its own mock and Vite servers on free ports, so it runs next to other servers.
import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { createServer } from 'node:net'
import { resolve } from 'node:path'
import { chromium } from '@playwright/test'

const out = resolve(process.argv[2] || '../docs/images')
const FAMILY = process.env.SCREENSHOT_FAMILY || 'instrument'
// The dashboard rates fill their window from live polls of the mock's growing counters.
const LIVE_WAIT_MS = Number(process.env.SCREENSHOT_LIVE_WAIT_MS || 60000)
const [vw, vh] = (process.env.SCREENSHOT_VIEWPORT || '1440x900').split('x').map(Number)
const VIEWPORT = { width: vw, height: vh }

function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer()
    srv.unref()
    srv.on('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })
}

async function waitFor(url, timeoutMs = 60000) {
  const end = Date.now() + timeoutMs
  while (Date.now() < end) {
    try {
      const res = await fetch(url)
      if (res.ok) return
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 300))
  }
  throw new Error(`${url} did not answer`)
}

function start(cmd, args, env = {}) {
  const child = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'ignore', 'inherit'] })
  child.on('exit', (code) => {
    if (code && !child.stopping) console.error(`${cmd} ${args.join(' ')} exited with ${code}`)
  })
  return child
}

async function signIn(page) {
  await page.goto('/login')
  await page.getByTestId('login-username').fill('admin')
  await page.getByTestId('login-password').fill('admin')
  await page.getByTestId('login-submit').click()
  await page.getByTestId('sidebar').waitFor()
}

async function settle(page) {
  await page.getByTestId('data-table-loading').waitFor({ state: 'detached' }).catch(() => {})
  // Charts and transitions finish drawing.
  await page.waitForTimeout(1200)
}

// [file name, steps]: each scene starts signed in, on a fresh page of the scheme.
const SCENES = [
  ['dashboard', async (page) => {
    await page.goto('/')
    await page.getByTestId('tile-node').first().waitFor()
    await page.locator('[data-testid=dns-strip], [data-testid=stippled-area-chart]').first().waitFor({ timeout: 30000 })
    await page.waitForTimeout(LIVE_WAIT_MS)
  }],
  ['zone-plan', async (page) => {
    await page.goto('/dns/zones/example.lan')
    await page.getByTestId('records-table').waitFor()
    await page.getByTestId('record-add').click()
    await page.getByTestId('record-owner').fill('www2')
    await page.getByTestId('record-rdata').fill('192.0.2.80')
    await page.getByTestId('record-editor').getByRole('button', { name: 'Preview the plan' }).click()
    await page.getByTestId('plan-diff').waitFor()
  }],
  ['dhcp-subnets', async (page) => {
    await page.goto('/dhcp/v4/subnets')
    await page.getByTestId('subnets-table').waitFor()
  }],
  ['host-card', async (page) => {
    // A host with a lease, a reservation, its records and one open inconsistency.
    await page.goto('/hosts?q=pc7')
    await page.getByTestId('hosts-table').getByTestId('data-table-row').first().click()
    await page.getByTestId('host-card').waitFor()
  }],
  ['alerts', async (page) => {
    await page.goto('/alerts')
    await page.getByTestId('alerts-table').getByTestId('data-table-row').first().waitFor()
  }],
  ['nodes', async (page) => {
    await page.goto('/nodes')
    await page.getByTestId('nodes-table').getByTestId('data-table-row').first().waitFor()
  }],
  ['security-audit', async (page) => {
    await page.goto('/install/security')
    await page.getByTestId('security-finding').first().waitFor()
  }],
  ['dhcp-ha', async (page) => {
    await page.goto('/dhcp/v4/ha')
    await page.getByTestId('ha-server').first().waitFor()
  }],
]
const ONLY = (process.env.SCREENSHOT_SCENES || '').split(',').filter(Boolean)
const SELECTED = ONLY.length ? SCENES.filter(([name]) => ONLY.includes(name)) : SCENES

async function main() {
  mkdirSync(out, { recursive: true })
  const mockPort = await freePort()
  const vitePort = await freePort()
  const base = `http://127.0.0.1:${vitePort}`
  const servers = [
    start(process.execPath, ['mock/server.mjs', '--port', String(mockPort)]),
    // Vite's own entry point, not npx: killing the child must stop the server itself.
    start(process.execPath, ['node_modules/vite/bin/vite.js', '--port', String(vitePort), '--strictPort', '--host', '127.0.0.1'], {
      VITE_API_MOCK: '1',
      MOCK_PORT: String(mockPort),
    }),
  ]
  const browser = await chromium.launch()
  try {
    await waitFor(`http://127.0.0.1:${mockPort}/api/v1/health`)
    await waitFor(base)
    for (const scheme of ['dark', 'light']) {
      const context = await browser.newContext({
        baseURL: base,
        viewport: VIEWPORT,
        colorScheme: scheme,
        locale: 'en-US',
      })
      await context.addInitScript((family) => {
        localStorage.setItem('pelagos-theme-family', family)
        localStorage.setItem('pelagos-theme-mode', 'system')
        localStorage.setItem('i18nextLng', 'en')
      }, FAMILY)
      const page = await context.newPage()
      await signIn(page)
      for (const [name, steps] of SELECTED) {
        await steps(page)
        await settle(page)
        const file = resolve(out, `${name}-${scheme}.png`)
        await page.screenshot({ path: file })
        console.log(file)
        await page.keyboard.press('Escape')
      }
      await context.close()
    }
  } finally {
    await browser.close()
    for (const child of servers) {
      child.stopping = true
      child.kill()
    }
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
