// SPDX-License-Identifier: Apache-2.0
// Plan building blocks for the mock: a small line diff, plan objects with
// preconditions and validations, and the apply/rollback/job lifecycle of
// architecture section 6.
import { iso, ulid } from './data.mjs'

// Unified diff of two texts (LCS on lines, fine for the small payloads of the mock).
export function unifiedDiff(before, after, label = 'config') {
  const a = before ? before.split('\n') : []
  const b = after ? after.split('\n') : []
  const n = a.length
  const m = b.length
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0))
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  const lines = []
  let i = 0
  let j = 0
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      lines.push(` ${a[i]}`)
      i += 1
      j += 1
    } else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) {
      lines.push(`+${b[j]}`)
      j += 1
    } else {
      lines.push(`-${a[i]}`)
      i += 1
    }
  }
  if (!lines.some((l) => l.startsWith('+') || l.startsWith('-'))) return ''
  return `--- a/${label}\n+++ b/${label}\n@@ -1,${n} +1,${m} @@\n${lines.join('\n')}\n`
}

export function jsonText(value) {
  return value === null || value === undefined ? '' : JSON.stringify(value, null, 2)
}

export function rrsetText(rrset) {
  if (!rrset) return ''
  return rrset.rdata.map((r) => `${rrset.name} ${rrset.ttl} IN ${rrset.rtype} ${r}`).join('\n')
}

const CONFIRM_SCOPES = new Set(['dhcp.ha', 'dhcp.lease', 'security'])

// spec: { scope, engine, summary, summary_message?, changes, diff, targets, preconditions?, validations?,
//         requires_confirmation?, apply(), rollback?(), job? }
export function createPlan(state, user, spec) {
  const created = Date.now()
  const ttl = (state.settings.plans?.ttl_seconds || 600) * 1000
  const targets = spec.targets || [state.selfId]
  const validations =
    spec.validations ||
    targets.map((node_id) => ({ ok: true, tool: spec.tool || 'dnspython', output: '', node_id }))
  const failed = validations.some((v) => !v.ok)
  const plan = {
    id: ulid(created),
    created_at: iso(created),
    created_by: user.username,
    node_id: state.selfId,
    scope: spec.scope,
    engine: spec.engine ?? null,
    summary: spec.summary,
    summary_message: spec.summary_message ?? null,
    changes: spec.changes || [],
    diff: spec.diff || '',
    preconditions: spec.preconditions || [],
    validations,
    target_node_ids: targets,
    requires_confirmation: spec.requires_confirmation ?? CONFIRM_SCOPES.has(spec.scope),
    state: failed ? 'failed' : 'validated',
    expires_at: iso(created + ttl),
    error: failed ? 'Validation failed' : null,
  }
  state.plans.set(plan.id, { plan, apply: spec.apply, rollback: spec.rollback, job: spec.job, creator: user.username })
  state.emit?.('plans', 'validated', planPhase(state, plan, plan.state))
  return plan
}

// Payloads of the `plans` topic beyond the ApplyResult (section 18, as PlanService sends them).
export function planPhase(state, plan, phase) {
  return {
    plan_id: plan.id,
    scope: plan.scope,
    state: phase,
    origin_node_id: plan.node_id || state.selfId,
    target_node_ids: [...(plan.target_node_ids || [state.selfId])],
    validations: (plan.validations || []).map((v) => ({ tool: v.tool, node_id: v.node_id ?? null, ok: v.ok })),
  }
}

export function planStep(state, plan, nodeId, verb, ok = null, message = null) {
  const data = { plan_id: plan.id, scope: plan.scope, node_id: nodeId, origin_node_id: state.selfId, verb, state: ok === null ? 'running' : ok ? 'done' : 'failed' }
  if (ok !== null) Object.assign(data, { ok, outcome_unknown: false, message, duration_ms: state.applyNodeMs || 0 })
  return data
}

export function isExpired(plan) {
  return new Date(plan.expires_at).getTime() <= Date.now()
}

function nodeResults(state, plan, ok, message, auditIds) {
  return plan.target_node_ids.map((node_id) => ({
    node_id,
    ok,
    message: ok ? message || 'applied' : message || 'failed',
    rolled_back: false,
    audit_ids: auditIds,
  }))
}

export function auditEntry(state, user, { action, target, engine = null, plan_id = null, diff = null, result = 'ok', message = null, request = {}, response = {} }) {
  const ts = Date.now()
  const entry = {
    id: ulid(ts),
    ts: iso(ts),
    node_id: state.selfId,
    user: user ? user.username : 'system',
    action,
    target,
    engine,
    plan_id,
    request,
    response,
    diff,
    result,
    message,
    client_ip: '192.0.2.99',
  }
  state.audit.unshift(entry)
  return entry
}

// Permission needed to apply or roll back a plan, by scope (section 17).
export const SCOPE_PERMISSIONS = {
  'dns.rrset': 'write:dns.records',
  'dns.zone': 'write:dns.zones',
  'dns.config': 'write:dns.config',
  'dns.key': 'write:dns.config',
  'dns.acl': 'write:dns.config',
  'dhcp.subnet': 'write:dhcp.subnets',
  'dhcp.shared_network': 'write:dhcp.subnets',
  'dhcp.class': 'write:dhcp.classes',
  'dhcp.options': 'write:dhcp.options',
  'dhcp.ddns': 'write:dhcp.options',
  'dhcp.reservation': 'write:dhcp.reservations',
  'dhcp.lease': 'ops:dhcp.leases',
  'dhcp.ha': 'ops:dhcp.ha',
  'dhcp.config': 'write:dhcp.config',
  'd2.config': 'write:dhcp.config',
  host: 'write:hosts',
  install: 'admin:install',
  import: 'admin:install',
  security: 'admin:install',
}

function can(user, permission) {
  const perms = user?.permissions || []
  return perms.includes('*') || perms.includes(permission)
}

export function isAdmin(user) {
  return can(user, '*') || (user?.roles || []).includes('admin')
}

// Unknown scopes fall back to admin only.
function scopeDenied(user, plan) {
  const permission = SCOPE_PERMISSIONS[plan.scope]
  if (permission ? can(user, permission) : isAdmin(user)) return null
  return { status: 403, code: 'forbidden', detail: `requires ${permission || 'admin'}` }
}

const INITIAL_CONFIG_HASH = 'a1b2c3d4e5f6'

// Current config hash of an engine (or scope); every apply touching it moves it.
export function configHash(state, subject) {
  state.configHashes ||= {}
  return state.configHashes[subject] ?? INITIAL_CONFIG_HASH
}

function bumpConfigHashes(state, plan) {
  for (const p of plan.preconditions) {
    if (p.kind !== 'config_hash') continue
    const next = (parseInt(configHash(state, p.subject), 16) + 1).toString(16).padStart(12, '0')
    state.configHashes[p.subject] = next
  }
}

// First soa_serial or config_hash precondition that no longer holds, if any.
function movedPrecondition(state, plan) {
  return plan.preconditions.find((p) => {
    if (p.kind === 'soa_serial') return String(state.soaSerial(state.records[p.subject])) !== p.value
    if (p.kind === 'config_hash') return configHash(state, p.subject) !== p.value
    return false
  })
}

// Returns { status, body } for POST /plans/{id}/apply.
export function applyPlan(state, user, id, confirm, emit) {
  const held = state.plans.get(id)
  if (!held) return { status: 404, code: 'not_found', detail: `plan ${id} not found` }
  const { plan } = held
  const denied = scopeDenied(user, plan)
  if (denied) return denied
  if (isExpired(plan) && plan.state !== 'applied') {
    plan.state = 'expired'
    return { status: 410, code: 'plan_expired', detail: 'plan expired' }
  }
  if (plan.state !== 'validated') return { status: 409, code: 'plan_state', detail: `plan is ${plan.state}` }
  if (plan.requires_confirmation && !confirm) {
    return { status: 428, code: 'confirmation_required', detail: 'this plan requires {"confirm": true}' }
  }
  const moved = movedPrecondition(state, plan)
  if (moved) {
    return { status: 409, code: 'precondition_failed', detail: `${moved.kind} of ${moved.subject} moved since the plan was built` }
  }
  plan.state = 'applying'
  emit('plans', 'applying', planPhase(state, plan, 'applying'))
  if (held.job) {
    bumpConfigHashes(state, plan)
    return { status: 202, body: startJob(state, user, held, emit) }
  }
  const first = plan.target_node_ids[0] || state.selfId
  emit('plans', 'step', planStep(state, plan, first, 'apply'))
  let message = 'applied'
  try {
    message = held.apply?.() || 'applied'
  } catch (err) {
    plan.state = 'failed'
    plan.error = err.message
    const entry = auditEntry(state, user, { action: `${plan.scope}.apply`, target: plan.changes[0]?.target || plan.scope, engine: plan.engine, plan_id: plan.id, diff: plan.diff, result: 'error', message: err.message })
    emit('plans', 'step', planStep(state, plan, first, 'apply', false, err.message))
    const result = { plan_id: plan.id, state: 'failed', results: nodeResults(state, plan, false, err.message, [entry.id]), finished_at: iso(Date.now()) }
    emit('plans', 'failed', result)
    return { status: 200, body: result }
  }
  bumpConfigHashes(state, plan)
  plan.state = 'applied'
  // Rollback stays allowed for the plan TTL after apply.
  plan.expires_at = iso(Date.now() + (state.settings.plans?.ttl_seconds || 600) * 1000)
  // The node entry of section 6: its request names the entry kind and the verb.
  const entry = auditEntry(state, user, { action: `${plan.scope}.apply`, target: plan.changes[0]?.target || plan.scope, engine: plan.engine, plan_id: plan.id, diff: plan.diff, request: { entry: 'node', verb: 'apply' } })
  emit('audit', 'entry', entry)
  emit('plans', 'step', planStep(state, plan, first, 'apply', true, message))
  for (const node of plan.target_node_ids.slice(1)) {
    emit('plans', 'step', planStep(state, plan, node, 'apply'))
    emit('plans', 'step', planStep(state, plan, node, 'apply', true, message))
  }
  const result = { plan_id: plan.id, state: 'applied', results: nodeResults(state, plan, true, message, [entry.id]), finished_at: iso(Date.now()) }
  emit('plans', 'applied', result)
  return { status: 200, body: result }
}

export function rollbackPlan(state, user, id, emit) {
  const held = state.plans.get(id)
  if (!held) return { status: 404, code: 'not_found', detail: `plan ${id} not found` }
  const { plan } = held
  const denied = scopeDenied(user, plan)
  if (denied) return denied
  if (plan.state !== 'applied') return { status: 409, code: 'plan_state', detail: `plan is ${plan.state}` }
  if (isExpired(plan)) return { status: 410, code: 'plan_expired', detail: 'plan expired' }
  if (!held.rollback) return { status: 501, code: 'not_supported', detail: 'this plan cannot be rolled back' }
  emit('plans', 'rolling_back', planPhase(state, plan, 'rolling_back'))
  const order = [...plan.target_node_ids].reverse()
  for (const node of order.slice(0, -1)) {
    emit('plans', 'step', planStep(state, plan, node, 'rollback'))
    emit('plans', 'step', planStep(state, plan, node, 'rollback', true, 'rolled back'))
  }
  const last = order[order.length - 1] || state.selfId
  emit('plans', 'step', planStep(state, plan, last, 'rollback'))
  held.rollback()
  bumpConfigHashes(state, plan)
  plan.state = 'rolled_back'
  const entry = auditEntry(state, user, { action: `${plan.scope}.rollback`, target: plan.changes[0]?.target || plan.scope, engine: plan.engine, plan_id: plan.id, diff: plan.diff, result: 'rolled_back', request: { entry: 'node', verb: 'rollback' } })
  emit('audit', 'entry', entry)
  emit('plans', 'step', planStep(state, plan, last, 'rollback', true, 'rolled back'))
  const result = {
    plan_id: plan.id,
    state: 'rolled_back',
    results: plan.target_node_ids.map((node_id) => ({ node_id, ok: true, message: 'rolled back', rolled_back: true, audit_ids: [entry.id] })),
    finished_at: iso(Date.now()),
  }
  emit('plans', 'rolled_back', result)
  return { status: 200, body: result }
}

// Long-running scopes (install, import, security): steps advance on a timer.
function startJob(state, user, held, emit) {
  // A step is a name, or {name, label, label_message} like the backend's installer jobs.
  const steps = held.job.map((s) => ({ ...(typeof s === 'string' ? { name: s } : s), state: 'queued', output: '', started_at: null, finished_at: null }))
  const job = { id: ulid(), plan_id: held.plan.id, state: 'queued', progress: 0, steps, created_at: iso(Date.now()), finished_at: null, error: null }
  state.jobs.set(job.id, job)
  let index = 0
  const tick = () => {
    if (index > 0) {
      const prev = job.steps[index - 1]
      prev.state = 'done'
      prev.output = 'ok'
      prev.finished_at = iso(Date.now())
    }
    if (index >= job.steps.length) {
      job.state = 'done'
      job.progress = 100
      job.finished_at = iso(Date.now())
      held.plan.state = 'applied'
      held.apply?.()
      const entry = auditEntry(state, user, { action: `${held.plan.scope}.apply`, target: held.plan.scope, plan_id: held.plan.id, diff: held.plan.diff })
      emit('audit', 'entry', entry)
      emit('jobs', 'done', job)
      return
    }
    job.state = 'running'
    job.steps[index].state = 'running'
    job.steps[index].started_at = iso(Date.now())
    job.progress = Math.round((index / job.steps.length) * 100)
    index += 1
    emit('jobs', 'progress', job)
    const timer = setTimeout(tick, state.jobStepMs ?? 400)
    timer.unref?.()
  }
  tick()
  return job
}
