// SPDX-License-Identifier: Apache-2.0
// What the tiles derive from GET /dashboard/summary beyond its raw lists.

// DHCP family the HA, DDNS and pool links open: v4 unless no node runs kea-dhcp4
// and one runs kea-dhcp6 (node modules, else the engines of this node).
export function dhcpFamily(summary) {
  const modules = (summary?.nodes || []).map((n) => n.peer?.modules || {})
  const engines = summary?.engines || {}
  const has = (engine) => modules.some((m) => m[engine]) || Boolean(engines[engine])
  return !has('kea4') && has('kea6') ? 'v6' : 'v4'
}

// Pool thresholds: GET /dashboard/summary `thresholds` first, then the [settings]
// alert values (admins), then the alert defaults 80 / 95.
export function poolThresholds(summary, settings) {
  const fromSummary = summary?.thresholds || {}
  const pick = (...values) => values.find((v) => typeof v === 'number')
  return {
    warn: pick(fromSummary.pool_warning_percent, fromSummary.alerts_pool_warning_percent, settings?.alerts_pool_warning_percent) ?? 80,
    full: pick(fromSummary.pool_critical_percent, fromSummary.alerts_pool_critical_percent, settings?.alerts_pool_critical_percent) ?? 95,
  }
}
