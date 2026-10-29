// SPDX-License-Identifier: Apache-2.0
// Permission guard checks (GET /install/permissions): the failed ones and the security findings
// (installer path_access) the privileged helper can fix.

export function failedChecks(checks) {
  return (checks || []).filter((c) => !c.ok)
}

export function fixableIds(checks) {
  return [...new Set(failedChecks(checks).map((c) => c.finding_id).filter(Boolean))]
}
