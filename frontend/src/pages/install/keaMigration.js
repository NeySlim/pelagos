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

// [[severity, [[node_id, findings]]]] in severity order, nodes in report order, empty groups out.
export function groupFindings(report) {
  if (!report) return []
  const order = report.node_ids || []
  const rank = (id) => (order.indexOf(id) === -1 ? order.length : order.indexOf(id))
  return SEVERITIES.map((severity) => {
    const mine = (report.findings || []).filter((f) => f.severity === severity)
    const nodes = [...new Set(mine.map((f) => f.node_id || ''))].sort((a, b) => rank(a) - rank(b))
    return [severity, nodes.map((id) => [id, mine.filter((f) => (f.node_id || '') === id)
      .sort((a, b) => ENGINE_ORDER.indexOf(a.engine) - ENGINE_ORDER.indexOf(b.engine))])]
  }).filter(([, nodes]) => nodes.length)
}

// Engines of a node that have a diff or a validation, in engine order.
export function nodeEngines(report, nodeId) {
  const names = new Set([...Object.keys(report?.diffs?.[nodeId] || {}), ...Object.keys(report?.validation?.[nodeId] || {})])
  return ENGINE_ORDER.filter((e) => names.has(e))
}

// Whether every engine of every analyzed node was really validated by the target's binaries.
export function fullyValidated(report) {
  const nodes = (report?.node_ids || []).filter((id) => !(report.unreachable || []).includes(id))
  return nodes.length > 0 && nodes.every((id) => {
    const v = Object.values(report.validation?.[id] || {})
    return v.length > 0 && v.every((r) => r.mode === 'dry_run' && r.ok)
  })
}

// Engines of an inventory node whose series ISC no longer maintains.
export const obsoleteEngines = (node) => Object.entries(node?.engines || {}).filter(([, e]) => e.maintained === false).map(([name]) => name)
