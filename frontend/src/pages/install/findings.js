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
