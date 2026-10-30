// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The mock's Kea migration (section 28): prepare, migrate with the HA states moving, rollback, the
// automatic return when a step of the window fails, and the second permission of the plans.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createMockServer } from './server.mjs'

let mock
let base

async function session(username, password) {
  const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) })
  const body = await res.json()
  const cookie = res.headers.get('set-cookie').split(';')[0]
  return async (method, path, data) => {
    const r = await fetch(`${base}${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': body.csrf_token },
      body: data === undefined ? undefined : JSON.stringify(data),
    })
    return { status: r.status, data: r.status === 204 ? null : await r.json() }
  }
}

beforeEach(async () => {
  mock = createMockServer({ quiet: true, jobStepMs: 1 })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
})

afterEach(async () => {
  await mock.close()
})

async function until(check) {
  for (let i = 0; i < 400; i += 1) {
    const value = await check()
    if (value) return value
    await new Promise((r) => setTimeout(r, 5))
  }
  throw new Error('timed out')
}

async function runPhase(admin, id, phase) {
  const plan = await admin('POST', `/install/kea-migration/${id}/plan`, { phase })
  expect(plan.status).toBe(200)
  expect(plan.data).toMatchObject({ scope: 'kea.migration', requires_confirmation: true, summary_message: { key: `plan.kea_migration.${phase}` } })
  const applied = await admin('POST', `/plans/${plan.data.id}/apply`, { confirm: true })
  expect(applied.status).toBe(202)
  return until(async () => {
    const job = (await admin('GET', `/jobs/${applied.data.id}`)).data
    return ['done', 'failed'].includes(job.state) && job
  })
}

describe('mock Kea migration', () => {
  it('prepares, migrates and rolls back a pair', async () => {
    const admin = await session('admin', 'admin')
    const report = (await admin('POST', '/install/kea-migration/analyze', { series: '3.2', source: 'isc' })).data
    expect((await admin('POST', `/install/kea-migration/${report.id}/plan`, { phase: 'migrate' })).status).toBe(404)
    let job = await runPhase(admin, report.id, 'prepare')
    expect(job.state).toBe('done')
    expect(job.steps[0].label_message.key).toBe('job.step.kea_migration.archive')
    let m = (await admin('GET', `/install/kea-migration/${report.id}`)).data
    expect(m).toMatchObject({ state: 'prepared', phase: 'prepare', rollback_possible: false, outage_max_seconds: 180 })
    expect(m.nodes.every((n) => n.rollback_ready && n.archive_id && !('packages_before' in n))).toBe(true)
    expect((await admin('POST', `/install/kea-migration/${report.id}/plan`, { phase: 'rollback' })).status).toBe(409)

    job = await runPhase(admin, report.id, 'migrate')
    expect(job.state).toBe('done')
    m = (await admin('GET', '/install/kea-migration')).data.current
    expect(m).toMatchObject({ state: 'migrated', stage: 'done', rollback_possible: true })
    expect(m.outage_seconds).toBeGreaterThanOrEqual(0)
    expect(m.nodes.map((n) => n.to_version)).toEqual(m.nodes.map(() => m.target_version))
    expect(mock.state.ha.v4.map((s) => s.state)).toEqual(['hot-standby', 'hot-standby'])

    job = await runPhase(admin, report.id, 'rollback')
    m = (await admin('GET', `/install/kea-migration/${report.id}`)).data
    expect(m).toMatchObject({ state: 'rolled_back', phase: 'rollback' })
    expect(m.nodes.every((n) => n.status === 'rolled_back' && n.to_version === '2.6.3')).toBe(true)
  })

  it('goes back automatically when the window fails', async () => {
    const admin = await session('admin', 'admin')
    const report = (await admin('POST', '/install/kea-migration/analyze', { series: '3.2', source: 'isc' })).data
    await runPhase(admin, report.id, 'prepare')
    await fetch(`${base}/_mock/kea-migration`, { method: 'POST', body: JSON.stringify({ fail_at: 'kea-mig-wait-partner-down' }) })
    const job = await runPhase(admin, report.id, 'migrate')
    expect(job.state).toBe('failed')
    const m = (await admin('GET', `/install/kea-migration/${report.id}`)).data
    expect(m).toMatchObject({ state: 'rolled_back', error_step: 'kea-mig-wait-partner-down' })
    expect(mock.state.ha.v4.map((s) => s.state)).toEqual(['hot-standby', 'hot-standby'])
  })

  it('needs ops:dhcp.ha besides admin:install', async () => {
    const admin = await session('admin', 'admin')
    const report = (await admin('POST', '/install/kea-migration/analyze', { series: '3.2', source: 'isc' })).data
    expect((await admin('POST', `/install/kea-migration/${report.id}/plan`, { phase: 'other' })).status).toBe(400)
    const viewer = await session('viewer', 'viewer')
    expect((await viewer('POST', `/install/kea-migration/${report.id}/plan`, { phase: 'prepare' })).status).toBe(403)
  })
})
