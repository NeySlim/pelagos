// SPDX-License-Identifier: Apache-2.0
// The step rail of a plan apply and its rollback, from the events the UI really receives
// (architecture section 6): the apply request leaves, the building node rechecks the
// preconditions and applies locally (its audit entry arrives on the `audit` topic), the
// peers apply through replication one after the other, and the ApplyResult closes it.
// A rollback walks the same path backwards: peers first, then the local node.
// Durations are measured, never invented; a running chip fills over the last measured
// duration of the same kind (an estimate, shown only as motion).

const DEFAULT_MS = { local: 450, peer: 650 }
const estimates = { ...DEFAULT_MS }

// Exponential average of measured node durations, per kind: what a running chip fills over.
export function estimateMs(kind) {
  return Math.round(estimates[kind] ?? DEFAULT_MS.peer)
}

export function recordDuration(kind, ms) {
  if (!(ms > 0) || !Number.isFinite(ms)) return
  estimates[kind] = estimates[kind] === undefined ? ms : estimates[kind] * 0.6 + ms * 0.4
}

export function resetEstimates() {
  Object.assign(estimates, DEFAULT_MS)
}

const node = (id, kind, state = 'pending') => ({ id, kind, state, startedAt: null, ms: null })

// Steps of the rail: `local` (self rechecks and applies, or only rechecks when it is not a
// target), `peers` (every other target, in apply order) and `result` (one chip per target).
export function buildSteps(plan, selfId = plan?.node_id) {
  const targets = plan?.target_node_ids?.length ? plan.target_node_ids : [selfId]
  const local = selfId && targets.includes(selfId)
  const peers = targets.filter((id) => id !== selfId)
  const steps = [{ id: 'local', kind: local ? 'apply' : 'recheck', state: 'pending', ms: null, nodes: [node(selfId, 'local')] }]
  if (peers.length) steps.push({ id: 'peers', kind: 'replicate', state: 'pending', ms: null, nodes: peers.map((id) => node(id, 'peer')) })
  steps.push({ id: 'result', kind: 'result', state: 'pending', ms: null, nodes: targets.map((id) => node(id, 'result')) })
  return steps
}

// The rail of a plan already applied when this view did not see it run: every step done,
// durations unknown.
export function appliedSteps(plan, selfId = plan?.node_id) {
  return buildSteps(plan, selfId).map((s) => ({ ...s, state: 'done', nodes: s.nodes.map((n) => ({ ...n, state: 'done' })) }))
}

const clone = (steps) => steps.map((s) => ({ ...s, nodes: s.nodes.map((n) => ({ ...n })) }))

function stepOf(steps, id) {
  return steps.find((s) => s.id === id)
}

function startNode(n, now) {
  n.state = 'running'
  n.startedAt = now
}

function finishNode(n, now, state = 'done') {
  n.state = state
  if (n.startedAt !== null && now !== null) n.ms = Math.max(0, now - n.startedAt)
  if (state === 'done' && n.kind !== 'result') recordDuration(n.kind, n.ms)
}

function settleStep(step, now) {
  const states = step.nodes.map((n) => n.state)
  if (states.includes('failed')) step.state = 'failed'
  else if (states.every((s) => s === 'done')) step.state = 'done'
  else if (states.every((s) => s === 'reverted')) step.state = 'reverted'
  else if (states.some((s) => s === 'running')) step.state = 'running'
  if (step.state === 'done' && step.startedAt !== undefined && step.startedAt !== null) step.ms = now - step.startedAt
}

// The apply request left: the local step runs.
export function startApply(steps, now) {
  const out = clone(steps)
  const local = stepOf(out, 'local')
  local.state = 'running'
  local.startedAt = now
  startNode(local.nodes[0], now)
  return out
}

// The local node finished (its audit entry for this plan arrived): the peers start.
export function localApplied(steps, now) {
  const out = clone(steps)
  const local = stepOf(out, 'local')
  if (local.state !== 'running') return steps
  finishNode(local.nodes[0], now)
  settleStep(local, now)
  const peers = stepOf(out, 'peers')
  if (peers) {
    peers.state = 'running'
    peers.startedAt = now
    startNode(peers.nodes[0], now)
  } else {
    const result = stepOf(out, 'result')
    result.state = 'running'
    result.startedAt = now
    result.nodes.forEach((n) => startNode(n, now))
  }
  return out
}

// A peer answered (a `plans`/`step` event for it, done or failed): its chip finishes now, with
// the measured duration, and the next peer starts. Unknown or already finished nodes change
// nothing, so a late event after the ApplyResult is harmless.
export function peerApplied(steps, nodeId, ok, now) {
  const peers = stepOf(steps, 'peers')
  const idx = peers ? peers.nodes.findIndex((n) => n.id === nodeId) : -1
  if (idx < 0 || !['pending', 'running'].includes(peers.nodes[idx].state)) return steps
  let out = steps
  if (stepOf(out, 'local').state === 'running') out = localApplied(out, now)
  else out = clone(out)
  const step = stepOf(out, 'peers')
  const n = step.nodes[idx]
  if (n.state === 'pending') n.startedAt = n.startedAt ?? now
  finishNode(n, now, ok ? 'done' : 'failed')
  const next = step.nodes.find((x) => x.state === 'pending')
  if (next && ok) startNode(next, now)
  settleStep(step, now)
  return out
}

// The ApplyResult: every node gets its outcome. A node rolled back after a failure elsewhere
// is `reverted`, a failing node `failed`; an untouched peer stays pending.
export function finishApply(steps, result, now) {
  let out = steps
  if (stepOf(out, 'local').state === 'running') out = localApplied(out, now)
  else out = clone(out)
  const outcome = new Map((result?.results || []).filter((r) => !r.rolled_back).map((r) => [r.node_id, r]))
  const reverted = new Set((result?.results || []).filter((r) => r.rolled_back && r.ok).map((r) => r.node_id))
  const failedPlan = result?.state && result.state !== 'applied'
  for (const step of out) {
    if (!step.startedAt && step.state === 'pending') {
      step.startedAt = now
    }
    for (const n of step.nodes) {
      const r = outcome.get(n.id)
      if (n.state === 'pending' || n.state === 'running') {
        if (r === undefined && step.id !== 'result') continue
        if (n.state === 'pending') n.startedAt = n.startedAt ?? now
        const ok = r ? r.ok : !failedPlan
        finishNode(n, now, ok ? 'done' : 'failed')
      }
      if (reverted.has(n.id) && n.state === 'done' && step.id !== 'result') n.state = 'reverted'
    }
    settleStep(step, now)
    if (step.state === 'running' && !step.nodes.some((n) => n.state === 'running')) step.state = failedPlan ? 'failed' : 'pending'
  }
  return out
}

// Rollback: the result step empties at once, then the peers revert one after the other
// (last applied first), and the local node last.
export function startRollback(steps, now) {
  const out = clone(steps)
  const result = stepOf(out, 'result')
  result.nodes.forEach((n) => {
    n.state = 'reverted'
  })
  result.state = 'reverted'
  const peers = stepOf(out, 'peers')
  const first = peers || stepOf(out, 'local')
  first.state = 'running'
  first.startedAt = now
  const last = first.nodes[first.nodes.length - 1]
  last.startedAt = now
  return out
}

// The local rollback audit entry arrived: every peer has reverted before it.
export function localReverted(steps, now) {
  const out = clone(steps)
  const peers = stepOf(out, 'peers')
  if (peers) {
    peers.nodes.forEach((n) => {
      if (n.state === 'done') n.state = 'reverted'
    })
    settleStep(peers, now)
  }
  const local = stepOf(out, 'local')
  if (local.nodes[0].state === 'done') local.nodes[0].state = 'reverted'
  settleStep(local, now)
  return out
}

export function finishRollback(steps, result, now) {
  const out = clone(steps)
  const outcome = new Map((result?.results || []).map((r) => [r.node_id, r]))
  for (const step of out) {
    for (const n of step.nodes) {
      if (n.state !== 'done' && n.state !== 'running') continue
      const r = outcome.get(n.id)
      n.state = r && !r.ok ? 'failed' : 'reverted'
    }
    settleStep(step, now)
  }
  return out
}

// Which rail step a reverse walk is on, for the fill timing: 0.7 times its apply duration.
export function reverseFillMs(steps, id) {
  const step = steps.find((s) => s.id === id)
  if (!step) return 0
  const ms = step.nodes.reduce((sum, n) => sum + (n.ms || 0), 0)
  return Math.round((ms || estimateMs('peer')) * 0.7)
}

// A step output or error as text: a server that sends an object (a step's {record, output}) must
// never reach React as a child (minified error #31).
export function outputText(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (typeof value === 'object') {
    for (const key of ['output', 'error', 'message', 'text']) {
      if (typeof value[key] === 'string') return value[key]
    }
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }
  return String(value)
}

// Job steps (install, import, security remediation) as rail steps, with measured durations.
const JOB_STATES = { queued: 'pending', pending: 'pending', running: 'running', done: 'done', failed: 'failed', skipped: 'pending' }
export function jobSteps(job) {
  return (job?.steps || []).map((s, i) => {
    const started = s.started_at ? Date.parse(s.started_at) : null
    const finished = s.finished_at ? Date.parse(s.finished_at) : null
    return {
      id: s.name || String(i),
      state: JOB_STATES[s.state] || 'pending',
      ms: started !== null && finished !== null && finished >= started ? finished - started : undefined,
      output: outputText(s.output),
      step: s,
    }
  })
}

// A node audit entry ({"entry": "node", "verb"} in its request) is this node's own apply or
// rollback of the plan; the summary entry written at the end is not.
export function auditPhase(entry, planId, nodeId) {
  if (!entry || !planId || entry.plan_id !== planId) return null
  if (nodeId && entry.node_id && entry.node_id !== nodeId) return null
  const req = entry.request || {}
  if (req.entry !== 'node') return null
  return req.verb === 'rollback' ? 'rollback' : req.verb === 'apply' ? 'apply' : null
}
