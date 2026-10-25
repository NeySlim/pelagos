// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach } from 'vitest'
import {
  appliedSteps, auditPhase, buildSteps, estimateMs, finishApply, finishRollback, jobSteps, localApplied, localReverted, peerApplied, recordDuration, resetEstimates, reverseFillMs, startApply, startRollback,
} from './planTrace'
import { emitPlanEvent, onPlanEvent, planZone, recalledApply, rememberApply } from './planEvents'

const plan = (targets = ['n1', 'n2', 'n3']) => ({ id: 'P1', node_id: 'n1', target_node_ids: targets, scope: 'dns.rrset', changes: [{ target: 'example.lan./www/A' }] })
const states = (steps) => steps.map((s) => [s.id, s.state, s.nodes.map((n) => n.state).join(',')])
const ok = (results) => ({ state: 'applied', results: results.map(([node_id, okay = true, rolled_back = false]) => ({ node_id, ok: okay, rolled_back })) })

beforeEach(() => resetEstimates())

describe('plan rail', () => {
  it('builds the local, peers and result steps from the targets', () => {
    expect(states(buildSteps(plan()))).toEqual([
      ['local', 'pending', 'pending'],
      ['peers', 'pending', 'pending,pending'],
      ['result', 'pending', 'pending,pending,pending'],
    ])
    const alone = buildSteps(plan(['n1']))
    expect(alone.map((s) => s.id)).toEqual(['local', 'result'])
    expect(alone[0].kind).toBe('apply')
    // A plan built here for another node only rechecks the preconditions locally.
    const remote = buildSteps(plan(['n2']))
    expect(remote[0].kind).toBe('recheck')
    expect(remote[1].nodes.map((n) => n.id)).toEqual(['n2'])
  })

  it('finishes each peer chip when that peer answers (plans step events)', () => {
    let steps = localApplied(startApply(buildSteps(plan()), 1000), 1300)
    steps = peerApplied(steps, 'n2', true, 1900)
    expect(states(steps)[1]).toEqual(['peers', 'running', 'done,running'])
    expect(steps[1].nodes[0].ms).toBe(600)
    expect(steps[1].nodes[1].startedAt).toBe(1900)
    steps = peerApplied(steps, 'n3', true, 2200)
    expect(states(steps)[1]).toEqual(['peers', 'done', 'done,done'])
    expect(steps[1].nodes[1].ms).toBe(300)
    // A repeated or unknown event changes nothing; the ApplyResult keeps the measured times.
    expect(peerApplied(steps, 'n3', true, 9000)).toBe(steps)
    expect(peerApplied(steps, 'nX', true, 9000)).toBe(steps)
    steps = finishApply(steps, ok([['n1'], ['n2'], ['n3']]), 2500)
    expect(steps[1].nodes.map((n) => n.ms)).toEqual([600, 300])
    // A failing peer stops the walk: the next one never starts.
    let failing = localApplied(startApply(buildSteps(plan()), 0), 100)
    failing = peerApplied(failing, 'n2', false, 400)
    expect(states(failing)[1]).toEqual(['peers', 'failed', 'failed,pending'])
  })

  it('follows the local audit entry, then the result, with measured durations', () => {
    let steps = startApply(buildSteps(plan()), 1000)
    expect(states(steps)[0]).toEqual(['local', 'running', 'running'])
    steps = localApplied(steps, 1400)
    expect(steps[0].nodes[0].ms).toBe(400)
    expect(states(steps).slice(0, 2)).toEqual([
      ['local', 'done', 'done'],
      ['peers', 'running', 'running,pending'],
    ])
    expect(estimateMs('local')).toBeLessThan(450)
    steps = finishApply(steps, ok([['n1'], ['n2'], ['n3']]), 2000)
    expect(states(steps)).toEqual([
      ['local', 'done', 'done'],
      ['peers', 'done', 'done,done'],
      ['result', 'done', 'done,done,done'],
    ])
    expect(steps[1].nodes[0].ms).toBe(600)
  })

  it('a failing peer stops the rail; nodes rolled back after it are reverted', () => {
    const steps = finishApply(startApply(buildSteps(plan()), 0), { state: 'rolled_back', results: [
      { node_id: 'n1', ok: true, rolled_back: false },
      { node_id: 'n2', ok: false, rolled_back: false },
      { node_id: 'n1', ok: true, rolled_back: true },
    ] }, 500)
    expect(steps[0].nodes[0].state).toBe('reverted')
    expect(steps[1].nodes.map((n) => n.state)).toEqual(['failed', 'pending'])
    expect(steps[1].state).toBe('failed')
  })

  it('walks back on rollback: results first, peers, then the local node', () => {
    const applied = finishApply(startApply(buildSteps(plan()), 0), ok([['n1'], ['n2'], ['n3']]), 1000)
    let steps = startRollback(applied, 2000)
    expect(states(steps)).toEqual([
      ['local', 'done', 'done'],
      ['peers', 'running', 'done,done'],
      ['result', 'reverted', 'reverted,reverted,reverted'],
    ])
    steps = localReverted(steps, 2300)
    expect(states(steps).map((s) => s[1])).toEqual(['reverted', 'reverted', 'reverted'])
    const failed = finishRollback(startRollback(applied, 0), { state: 'failed', results: [{ node_id: 'n2', ok: false }] }, 100)
    expect(failed[1].nodes.map((n) => n.state)).toEqual(['failed', 'reverted'])
    // Without a local audit entry the peers' share is unknown: the rail walks back on the estimate.
    expect(reverseFillMs(applied, 'peers')).toBe(Math.round(estimateMs('peer') * 0.7))
    const measured = finishApply(localApplied(startApply(buildSteps(plan()), 0), 400), ok([['n1'], ['n2'], ['n3']]), 1000)
    expect(reverseFillMs(measured, 'peers')).toBe(420)
  })

  it('a plan applied out of sight walks back from a full rail', () => {
    const steps = finishRollback(startRollback(appliedSteps(plan()), 0), { state: 'rolled_back', results: [] }, 10)
    expect(states(steps).map((s) => s[1])).toEqual(['reverted', 'reverted', 'reverted'])
  })

  it('learns node durations as an average', () => {
    recordDuration('peer', 1000)
    recordDuration('peer', 1000)
    expect(estimateMs('peer')).toBeGreaterThan(650)
    recordDuration('peer', Number.NaN)
    expect(estimateMs('peer')).toBeLessThan(1000)
  })

  it('reads node audit entries and job steps', () => {
    const entry = (verb, extra = {}) => ({ plan_id: 'P1', node_id: 'n1', request: { entry: 'node', verb }, ...extra })
    expect(auditPhase(entry('apply'), 'P1', 'n1')).toBe('apply')
    expect(auditPhase(entry('rollback'), 'P1', 'n1')).toBe('rollback')
    expect(auditPhase(entry('apply'), 'P2', 'n1')).toBeNull()
    expect(auditPhase(entry('apply', { node_id: 'n2' }), 'P1', 'n1')).toBeNull()
    expect(auditPhase({ plan_id: 'P1', request: { entry: 'summary' } }, 'P1')).toBeNull()
    const job = { steps: [
      { name: 'backup', state: 'done', started_at: '2026-10-25T10:00:00Z', finished_at: '2026-10-25T10:00:01.250Z' },
      { name: 'reload', state: 'running', started_at: '2026-10-25T10:00:01Z' },
      { name: 'verify', state: 'queued' },
    ] }
    expect(jobSteps(job).map((s) => [s.state, s.ms])).toEqual([['done', 1250], ['running', undefined], ['pending', undefined]])
  })
})

describe('plan events', () => {
  it('tells listeners, keeps the last applies and names the zone of a DNS plan', () => {
    const seen = []
    const off = onPlanEvent((e) => seen.push(e.type))
    emitPlanEvent({ type: 'applied', plan: plan() })
    off()
    emitPlanEvent({ type: 'rolled-back', plan: plan() })
    expect(seen).toEqual(['applied'])
    rememberApply('P1', { at: 5 })
    expect(recalledApply('P1')).toEqual({ at: 5 })
    expect(recalledApply('nope')).toBeNull()
    expect(planZone(plan())).toBe('example.lan.')
    expect(planZone({ scope: 'dhcp.subnet', changes: [{ target: 'subnet4/1' }] })).toBeNull()
  })
})
