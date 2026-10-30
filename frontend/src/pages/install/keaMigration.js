// SPDX-License-Identifier: Apache-2.0
// Pure helpers of the Kea migration screen (architecture section 26): target choice, finding
// groups by severity then node, per node summaries of the report.

export const SEVERITIES = ['blocking', 'converted', 'behavior', 'info']
export const SEVERITY_VARIANT = { blocking: 'danger', behavior: 'warning', converted: 'primary', info: 'secondary' }
export const ENGINE_ORDER = ['kea4', 'kea6', 'd2', 'ca']

export const targetKey = (t) => `${t.series}/${t.source}`

// The recommended available target, else the first available one, else none.
export function defaultTarget(targets = []) {
  const ok = targets.filter((t) => t.available)
  return (ok.find((t) => t.recommended) || ok[0] || null)
}

export function parseTarget(key) {
  const [series, source] = String(key || '').split('/')
  return series && source ? { series, source } : null
}

// [[node_id, findings]] in report order, findings in engine order.
function byNode(report, findings) {
  const order = report.node_ids || []
  const rank = (id) => (order.indexOf(id) === -1 ? order.length : order.indexOf(id))
  const nodes = [...new Set(findings.map((f) => f.node_id || ''))].sort((a, b) => rank(a) - rank(b))
  return nodes.map((id) => [id, findings.filter((f) => (f.node_id || '') === id)
    .sort((a, b) => ENGINE_ORDER.indexOf(a.engine) - ENGINE_ORDER.indexOf(b.engine))])
}

// [[severity, [[node_id, findings]]]] in severity order, empty groups out; the findings of an
// unused daemon (`unused`) are left to unusedFindings.
export function groupFindings(report) {
  if (!report) return []
  const used = (report.findings || []).filter((f) => !f.unused)
  return SEVERITIES.map((severity) => [severity, byNode(report, used.filter((f) => f.severity === severity))])
    .filter(([, nodes]) => nodes.length)
}

// [[node_id, findings]] of the daemons whose unit is neither active nor enabled: info only.
export function unusedFindings(report) {
  return report ? byNode(report, (report.findings || []).filter((f) => f.unused)) : []
}

// Whether the node reports the daemon unused (unit neither active nor enabled).
export const engineUnused = (report, nodeId, engine) => report?.units?.[nodeId]?.[engine]?.used === false

// Engines of a node that have a diff or a validation, in engine order.
export function nodeEngines(report, nodeId) {
  const names = new Set([...Object.keys(report?.diffs?.[nodeId] || {}), ...Object.keys(report?.validation?.[nodeId] || {})])
  return ENGINE_ORDER.filter((e) => names.has(e))
}

// Whether every engine of every analyzed node was really validated by the target's binaries.
export function fullyValidated(report) {
  const nodes = (report?.node_ids || []).filter((id) => !(report.unreachable || []).includes(id))
  return nodes.length > 0 && nodes.every((id) => {
    const all = Object.entries(report.validation?.[id] || {})
    return all.length > 0 && all.filter(([e]) => !engineUnused(report, id, e)).every(([, r]) => r.mode === 'dry_run' && r.ok)
  })
}

// Engines of an inventory node whose series ISC no longer maintains.
export const obsoleteEngines = (node) => Object.entries(node?.engines || {}).filter(([, e]) => e.maintained === false).map(([name]) => name)

// Counts by severity without the findings of unused daemons, shown in their own section.
export function usedCounts(report) {
  const counts = { ...(report?.counts || {}) }
  const unused = (report?.findings || []).filter((f) => f.unused && f.severity in counts)
  unused.forEach((f) => { counts[f.severity] -= 1 })
  return counts
}

// Migration wizard (architecture section 28): the replicated record drives the three steps, the
// timeline of times 1 to 3, the measured outage and which plans may be built now.
export const ACTIVE_STATES = ['preparing', 'migrating', 'rolling_back']
export const REPLACEABLE_STATES = ['prepared', 'prepare_failed', 'migrated', 'rolled_back']
export const STAGES = ['standby', 'window', 'primary']
export const WIZARD_STEPS = ['prepare', 'migrate', 'verify']
export const STATE_VARIANT = {
  preparing: 'primary', prepared: 'success', prepare_failed: 'danger', migrating: 'primary', migrated: 'success',
  failed: 'danger', rolling_back: 'warning', rolled_back: 'secondary',
}
export const NODE_STATUS_VARIANT = { pending: 'outline', running: 'primary', done: 'success', failed: 'danger', rolled_back: 'secondary' }

export const isActive = (m) => Boolean(m) && ACTIVE_STATES.includes(m.state)

// The wizard step the record stands at.
export function wizardStep(m) {
  if (!m || m.state === 'preparing' || m.state === 'prepare_failed') return 'prepare'
  if (m.state === 'prepared' || m.state === 'migrating' || (m.state === 'failed' && m.phase === 'migrate')) return 'migrate'
  return 'verify'
}

// {prepare, migrate, verify} -> pending | running | done | failed
export function wizardStates(m) {
  const out = { prepare: 'pending', migrate: 'pending', verify: 'pending' }
  if (!m) return out
  const at = wizardStep(m)
  WIZARD_STEPS.slice(0, WIZARD_STEPS.indexOf(at)).forEach((s) => { out[s] = 'done' })
  if (m.state === 'preparing' || m.state === 'migrating' || m.state === 'rolling_back') out[at] = 'running'
  else if (m.state === 'prepare_failed' || m.state === 'failed') out[at] = 'failed'
  else if (m.state === 'prepared') out[at] = 'pending'
  else out[at] = 'done'
  return out
}

// Index of the record's stage: 0 to 2 for times 1 to 3, 3 once done, -1 before time 1.
const stageIndex = (m) => (m?.stage === 'done' ? STAGES.length : STAGES.indexOf(m?.stage ?? ''))

// [{id, state}] for times 1 to 3, plus the return to the previous series once one ran.
export function timeline(m) {
  const items = STAGES.map((id) => ({ id, state: 'pending' }))
  if (!m || m.phase === 'prepare') return items
  const idx = stageIndex(m)
  if (m.phase === 'migrate') {
    if (m.state === 'migrated') return items.map((s) => ({ ...s, state: 'done' }))
    return items.map((s, i) => ({
      ...s,
      state: i < idx ? 'done' : i > idx ? 'pending' : m.state === 'failed' ? 'failed' : m.state === 'migrating' ? 'running' : 'pending',
    }))
  }
  // A return: the times reached are undone; the one that failed stays marked.
  const back = items.map((s, i) => ({
    ...s,
    state: i < idx ? 'reverted' : i === idx ? (m.error_step ? 'failed' : 'reverted') : 'pending',
  }))
  const rollback = m.state === 'rolling_back' ? 'running' : m.state === 'rolled_back' ? 'done' : m.state === 'failed' ? 'failed' : 'pending'
  return [...back, { id: 'rollback', state: rollback }]
}

// The DHCP outage: measured once the standby serves alone, counted live during the window.
export function outage(m, now = Date.now()) {
  if (!m) return null
  if (m.outage_seconds !== null && m.outage_seconds !== undefined) return { seconds: m.outage_seconds, live: false }
  if (m.outage_started_at && (m.state === 'migrating' || m.state === 'rolling_back')) {
    const start = Date.parse(m.outage_started_at)
    if (Number.isFinite(start)) return { seconds: Math.max(0, (now - start) / 1000), live: true }
  }
  return null
}

// Why a plan of `phase` cannot be built now (null: it can), as core/kea_migration.phase_allowed.
export function planBlocker(m, analysis, phase) {
  if (phase === 'prepare') {
    if (!analysis) return 'noAnalysis'
    if (analysis.blocking) return 'blocking'
    if (m && !REPLACEABLE_STATES.includes(m.state)) return 'busy'
    return null
  }
  if (!m) return 'noMigration'
  if (phase === 'migrate') return m.state === 'prepared' || (m.state === 'failed' && m.phase === 'migrate') ? null : 'notPrepared'
  if (phase === 'rollback') return m.rollback_possible ? null : 'noRollback'
  return 'unknown'
}

// The id a phase's plan is built on: the analysis for prepare, the migration otherwise.
export const planId = (m, analysis, phase) => (phase === 'prepare' ? analysis?.id : m?.id)

// Job step key of a helper or driver step (domain/messages.py `job.step.kea_migration.*`).
export const stepMessageKey = (step) => `job.step.kea_migration.${String(step).replace(/^kea-mig-/, '').replaceAll('-', '_')}`

// The HA state of a v4 `ha` event for a node of the migration (null when it is not one).
export function haUpdate(m, data) {
  if (!m || !data?.node_id || (data.family && data.family !== 'v4')) return null
  return m.nodes?.some((n) => n.node_id === data.node_id) ? { node_id: data.node_id, state: data.state } : null
}
