// SPDX-License-Identifier: Apache-2.0
// Selection and ordering of security findings (GET /install/security).

export const SEVERITY_ORDER = ['critical', 'warning', 'info']

export function sortFindings(findings) {
  const rank = (s) => {
    const i = SEVERITY_ORDER.indexOf(s)
    return i < 0 ? SEVERITY_ORDER.length : i
  }
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity) || String(a.subject).localeCompare(String(b.subject)))
}

export const toggleId = (selected, id) => (selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id])

export const allSelected = (selected, ids) => ids.length > 0 && ids.every((id) => selected.includes(id))

// The Kea shared TSIG key rotates in three steps (add, switch D2, remove), whichever engine reported it.
export const isDualKey = (finding) => finding?.kind === 'weak_shared_kea_key'

// The backend refuses a plan that includes a finding without automatic remediation.
export const isRemediable = (finding) => finding?.remediable !== false

// A finding is unique per node: the same id may be reported by several nodes.
export const findingKey = (finding) => `${finding.node_id || ''}|${finding.id}`

export const isExcepted = (finding) => Boolean(finding?.exception)

// Selectable on the page: fixable automatically and not kept as the admin's choice.
export const remediableIds = (findings) => findings.filter((f) => isRemediable(f) && !isExcepted(f)).map(findingKey)

// A managed_drift finding offers adopt and restore: the chosen one (restore by default) rides on the id.
export const driftAction = (finding, actions = {}) => {
  const offered = finding?.actions || []
  const chosen = actions[findingKey(finding)]
  return offered.includes(chosen) ? chosen : offered.includes('restore') ? 'restore' : offered[0]
}

const planId = (finding, actions) => (finding.actions?.length ? `${finding.id}#${driftAction(finding, actions)}` : finding.id)

// The body of POST /install/security/plan for the selected keys: {node id: [finding ids]}, or the
// plain id list when the findings carry no node (this node only).
export function planSelection(findings, keys, actions = {}) {
  const chosen = findings.filter((f) => keys.includes(findingKey(f)))
  if (chosen.every((f) => !f.node_id)) return chosen.map((f) => planId(f, actions))
  const out = {}
  for (const f of chosen) (out[f.node_id] ||= []).push(planId(f, actions))
  return out
}

// The exception key for one finding: this node only (first key) or every node (the bare id).
export const exceptionKey = (finding, everyNode) => {
  const keys = finding.exception_keys || [finding.id]
  return everyNode ? keys[keys.length - 1] : keys[0]
}
