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
