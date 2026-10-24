// SPDX-License-Identifier: Apache-2.0
// Alert vocabulary (architecture section 15) and where an alert's subject leads.

export const SEVERITIES = ['critical', 'warning', 'info']
export const STATES = ['open', 'acked', 'resolved']
export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']
export const KINDS = [
  'pool_near_full', 'pool_full', 'serial_divergence', 'secondary_stale', 'zone_error', 'ha_degraded',
  'ha_partner_down', 'ha_transition', 'd2_errors', 'daemon_down', 'peer_offline', 'config_divergence',
  'lease_without_record', 'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip',
  'insecure_key', 'insecure_listener',
]
export const INCONSISTENCY_KINDS = new Set(['lease_without_record', 'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip'])

const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 }
export const bySeverity = (a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3)

// Subjects are "ip:<addr>", "mac:<mac>", "name:<fqdn>/<type>", "zone:<zone>[@view]",
// "kea4:subnet:<id>:pool:<range>", "ha:<engine>", "peer:<id>", "d2:updates", ...
export function subjectLink(alert) {
  const subject = String(alert?.subject || '')
  const [kind, ...rest] = subject.split(':')
  const value = rest.join(':')
  if ((kind === 'ip' || kind === 'mac') && value) return { to: `/hosts?q=${encodeURIComponent(value)}`, label: 'openHost' }
  if (kind === 'name' && value) return { to: `/hosts?q=${encodeURIComponent(value.split('/')[0].replace(/\.$/, ''))}`, label: 'openHost' }
  if (kind === 'zone' && value) {
    const [zone, view] = value.split('@')
    const path = `/dns/zones/${encodeURIComponent(zone.replace(/\.$/, ''))}`
    return { to: view ? `${path}?view=${encodeURIComponent(view)}` : path, label: 'openZone' }
  }
  if ((kind === 'kea4' || kind === 'kea6') && rest[0] === 'subnet') return { to: `/dhcp/${kind === 'kea6' ? 'v6' : 'v4'}/subnets`, label: null }
  if (kind === 'ha' && value) return { to: `/dhcp/${value === 'kea6' ? 'v6' : 'v4'}/ha`, label: null }
  if (kind === 'peer') return { to: '/nodes', label: null }
  if (kind === 'd2') return { to: '/dhcp/v4/ddns', label: null }
  return null
}

// Final output of a finished job: the "result" step the jobs service appends.
export const jobResult = (job) => (job?.steps || []).find((s) => s.name === 'result')?.output ?? null
